/*
	•	exposes RFC 8414 metadata (and now also advertises a registration_endpoint);
	•	supports Dynamic Client Registration (RFC 7591) at /register (simple, dev-friendly, no auth);
	•	accepts a resource indicator (RFC 8707 style) on /authorize and /token, and mints the aud claim from it (falls back to mcp-demo if omitted);
	•	implements Authorization Code + PKCE flow and introspection.
*/


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
const HMAC_SECRET = new TextEncoder().encode("dev-secret-please-change"); // HS256 (demo)
const DEFAULT_AUDIENCE = "mcp-demo"; // RS identifier used if no resource indicator was provided

// In‑memory demo client registry (client_id -> { redirect_uris: [...] })
const CLIENTS = new Map([
  [
    "demo-client",
    {
      redirect_uris: [
        "http://localhost:9200/callback", // AI Agent (direct)
        "http://localhost:9300/callback", // Gateway (future)
        "http://localhost:9400/oauth/callback", // Gateway Phase 1
      ],
    },
  ],
]);

// Authorization request storage: code -> metadata
const AUTHZ = new Map();

// Utility: tiny helper to normalize "resource" from query/body.
// RFC 8707 allows multiple; for the demo we accept one string and ignore extras.
function pickResource(input) {
  if (!input) return undefined;
  if (Array.isArray(input)) return input[0];
  return String(input);
}

// === Authorization Server Metadata (RFC 8414) ===
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    introspection_endpoint: `${ISSUER}/introspect`,
    registration_endpoint: `${ISSUER}/register`, // advertise DCR
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["echo:read", "tickets:read"],
    // not standard, but handy to document where callbacks should be (demo)
    redirect_uris_supported: Array.from(
      new Set([...CLIENTS.values()].flatMap((c) => c.redirect_uris))
    ),
  });
});

// === Dynamic Client Registration (RFC 7591, dev-friendly) ===
// Accepts JSON: { redirect_uris: [ "...", ... ], client_name?, token_endpoint_auth_method? }
// For demo we do no AS-side auth and issue "public" clients (no client_secret).
app.post("/register", (req, res) => {
  const { redirect_uris, client_name } = req.body || {};
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({
      error: "invalid_client_metadata",
      error_description: "redirect_uris (array) is required",
    });
  }

  const client_id = `client-${crypto.randomBytes(8).toString("hex")}`;
  CLIENTS.set(client_id, { redirect_uris });

  // Minimal RFC 7591 response (public client; no secret)
  // client_id_issued_at and registration_client_uri omitted for simplicity
  return res.status(201).json({
    client_id,
    client_name: client_name || client_id,
    redirect_uris,
    token_endpoint_auth_method: "none",
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

  // RFC 8707 resource indicator (optional)
  const resource = pickResource(req.query.resource);

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
    resource, // stash audience hint from the authorization request
  });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

// === /token (Code -> Access Token JWT HS256) ===
app.post("/token", async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body;

  // RFC 8707 resource indicator (optional, can override/confirm)
  const resourceFromTokenReq = pickResource(req.body.resource);

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
    .update(code_verifier || "")
    .digest()
    .toString("base64url");
  if (expected !== entry.code_challenge)
    return res
      .status(400)
      .json({ error: "invalid_grant", error_description: "bad pkce" });

  AUTHZ.delete(code);

  // Decide audience:
  // 1) prefer resource from token request (explicit), else
  // 2) resource from authorization request (if any), else
  // 3) default audience for the RS.
  const aud = resourceFromTokenReq || entry.resource || DEFAULT_AUDIENCE;

  // Mint JWT
  const accessToken = await new SignJWT({
    scope: entry.scope,
    aud, // RS will check this
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

// === /introspect (RFC 7662-ish, dev-friendly) ===
app.post("/introspect", async (req, res) => {
  try {
    // 1) Try body "token=" (x-www-form-urlencoded or JSON)
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
      // You may enforce audience at the AS as well:
      // audience: DEFAULT_AUDIENCE,
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