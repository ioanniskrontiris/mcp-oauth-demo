import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";
import { SignJWT } from "jose";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const ISSUER = "http://localhost:9092";
const HMAC_SECRET = new TextEncoder().encode("dev-secret-please-change"); // shared with RS
const CLIENTS = new Map([
  // client_id -> { redirect_uris: [...] }
  ["demo-client", { redirect_uris: ["http://localhost:9200/callback"] }],
]);

// authz request storage: code -> { client_id, redirect_uri, scope, code_challenge, code_challenge_method, state }
const AUTHZ = new Map();

/** RFC 8414 metadata */
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    code_challenge_methods_supported: ["S256"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["echo:read"]
  });
});

/** /authorize - auto-consent + PKCE support */
app.get("/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = "echo:read",
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  if (response_type !== "code") return res.status(400).send("unsupported response_type");
  const client = CLIENTS.get(client_id);
  if (!client) return res.status(400).send("unknown client_id");
  if (!client.redirect_uris.includes(redirect_uri)) return res.status(400).send("invalid redirect_uri");
  if (code_challenge_method !== "S256" || !code_challenge) return res.status(400).send("PKCE S256 required");

  // auto-approve consent (demo)
  const code = crypto.randomBytes(24).toString("base64url");
  AUTHZ.set(code, { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

/** /token - code -> access_token (JWT HS256) */
app.post("/token", async (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    code_verifier
  } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }
  const entry = AUTHZ.get(code);
  if (!entry) return res.status(400).json({ error: "invalid_grant" });

  // basic checks
  if (entry.client_id !== client_id) return res.status(400).json({ error: "invalid_client" });
  if (entry.redirect_uri !== redirect_uri) return res.status(400).json({ error: "invalid_request" });

  // verify PKCE S256
  const expected = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest()
    .toString("base64url");
  if (expected !== entry.code_challenge) return res.status(400).json({ error: "invalid_grant", error_description: "bad pkce" });

  AUTHZ.delete(code);

  // mint JWT
  const accessToken = await new SignJWT({
    scope: entry.scope,
    aud: "mcp-demo",           // audience the RS will check
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(ISSUER)
    .setSubject("user-123")    // demo subject
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(HMAC_SECRET);

  return res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 900,
    scope: entry.scope
  });
});

app.listen(9092, () => {
  console.log("Authorization Server listening on :9092");
});