import { loadEnv, cfg } from "../shared/config.js";
loadEnv();
console.log("[OAuth server] mode =>", cfg());

import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";
import { SignJWT, jwtVerify } from "jose";

const app = express();

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// === Config ===
const ISSUER = "http://localhost:9092";
const HMAC_SECRET = new TextEncoder().encode("dev-secret-please-change"); // shared secret for HS256 (demo)

// For now, single demo client; later, load from DB or config
const CLIENTS = new Map([
  [
    "demo-client",
    {
      redirect_uris: [
        "http://localhost:9200/callback", // AI Agent (direct)
        "http://localhost:9300/callback", // Gateway (future)
      ],
    },
  ],
]);

// authz request storage: code -> metadata
const AUTHZ = new Map();

// === OAuth Metadata (RFC 8414) ===
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    introspection_endpoint: `${ISSUER}/introspect`,
    code_challenge_methods_supported: ["S256"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["echo:read", "tickets:read"],
    redirect_uris_supported: Array.from(
      new Set([...CLIENTS.values()].flatMap((c) => c.redirect_uris))
    ),
  });
});

// === /authorize (Authorization Code + PKCE, auto-consent for demo) ===
app.get("/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = "echo:read",
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  if (response_type !== "code")
    return res.status(400).send("unsupported response_type");

  const client = CLIENTS.get(client_id);
  if (!client) return res.status(400).send("unknown client_id");

  if (!client.redirect_uris.includes(redirect_uri))
    return res.status(400).send("invalid redirect_uri");

  if (code_challenge_method !== "S256" || !code_challenge)
    return res.status(400).send("PKCE S256 required");

  // Auto-approve consent (demo)
  const code = crypto.randomBytes(24).toString("base64url");
  AUTHZ.set(code, {
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

// === /token (Code -> Access Token JWT HS256) ===
app.post("/token", async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const entry = AUTHZ.get(code);
  if (!entry) return res.status(400).json({ error: "invalid_grant" });

  if (entry.client_id !== client_id)
    return res.status(400).json({ error: "invalid_client" });

  if (entry.redirect_uri !== redirect_uri)
    return res.status(400).json({ error: "invalid_request" });

  // Verify PKCE (S256)
  const expected = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest()
    .toString("base64url");
  if (expected !== entry.code_challenge)
    return res
      .status(400)
      .json({ error: "invalid_grant", error_description: "bad pkce" });

  AUTHZ.delete(code);

  // Mint JWT
  const accessToken = await new SignJWT({
    scope: entry.scope,
    aud: "mcp-demo", // the RS will check this
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(ISSUER)
    .setSubject("user-123")
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(HMAC_SECRET);

  return res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 900,
    scope: entry.scope,
  });
});

// === /introspect (RFC 7662-style) ===
// Accepts application/x-www-form-urlencoded with `token` (access token).
// For demo we allow no client auth; you can tighten later (Basic auth, mTLS, JWT client assertion).
// === /introspect (RFC 7662-ish, dev-friendly) ===
app.post("/introspect", async (req, res) => {
  try {
    // 1) Try body "token=" (x-www-form-urlencoded)
    let token = req.body?.token;

    // 2) Or Authorization: Bearer <token>
    if (!token) {
      const auth = req.get("authorization") || req.get("Authorization");
      if (auth && auth.toLowerCase().startsWith("bearer ")) {
        token = auth.slice(7).trim();
      }
    }

    if (!token) {
      return res.status(400).json({
        active: false,
        error: "invalid_request",
        error_description: "missing token",
      });
    }

    // Verify HS256 JWT and extract claims
    const { payload } = await jwtVerify(token, HMAC_SECRET, {
      issuer: ISSUER,
      // audience: "mcp-demo", // uncomment to enforce aud at the AS
    });

    return res.json({
      active: true,
      token_type: "access_token",
      scope: payload.scope || "",
      sub: payload.sub,
      aud: payload.aud,
      iss: payload.iss || ISSUER,
      iat: payload.iat,
      exp: payload.exp,
    });
  } catch (err) {
    return res.json({
      active: false,
      error: err?.name || "invalid_token",
      error_description: err?.message || "verification failed",
    });
  }
});

app.listen(9092, () => {
  console.log("Authorization Server listening on :9092");
});