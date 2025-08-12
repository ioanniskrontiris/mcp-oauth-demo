/*
	1.	Treat authorization_servers entries as full metadata URLs (per RFC 9728); if a server ever returns a base URL, normalize it.
	2.	Carry the resource indicator learned from the RS metadata into both /authorize and /token requests, so the AS mints a token whose aud matches the RS.
*/


import fetch from "node-fetch";
import express from "express";
import open from "open";
import crypto from "node:crypto";

const RS_BASE = "http://localhost:9091";
const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:9200/callback";

// --- helpers ---
function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function sha256Base64url(str) {
  return crypto.createHash("sha256").update(str).digest("base64url");
}


/**
 * Discover the Protected Resource Metadata (RFC 9728) by
 * provoking a 401 and parsing WWW-Authenticate's resource_metadata.
 */
async function discoverResourceMetadata() {
const firstUrl = `${RS_BASE}/mcp/echo?msg=hello`;
const r1 = await fetch(firstUrl);
console.log("[DISCOVER] First request URL:", firstUrl, "status:", r1.status);
  if (r1.status !== 401) {
    throw new Error(`expected 401, got ${r1.status}`);
  }
  const www = r1.headers.get("www-authenticate") || "";
  console.log("[DISCOVER] WWW-Authenticate:", www);
  const match = www.match(/resource_metadata="([^"]+)"/i);
  if (!match) throw new Error("no resource_metadata in WWW-Authenticate");
  const metaUrl = match[1];
  console.log("[DISCOVER] Fetching resource metadata:", metaUrl);
  const r2 = await fetch(metaUrl);
  const ct = r2.headers.get("content-type") || "";
  console.log("[DISCOVER] RS metadata status:", r2.status, "content-type:", ct);
  if (!ct.includes("application/json")) {
    const txt = await r2.text();
      throw new Error(`RS metadata not JSON (status ${r2.status}):\n` + txt.slice(0, 500));
    }
  return r2.json(); // { resource, authorization_servers: [...], ... }
}

/**
 * Accept either a *full* AS metadata URL or a base URL,
 * and return the AS metadata JSON (RFC 8414).
 */
async function discoverASMetadata(asInput) {
  let asMetaUrl = asInput;
  const wellKnown = "/.well-known/oauth-authorization-server";
  if (!asMetaUrl.endsWith(wellKnown)) {
    asMetaUrl = new URL(wellKnown, asInput).toString();
  }
  const r = await fetch(asMetaUrl);
  if (!r.ok) {
    throw new Error(`failed to fetch AS metadata ${asMetaUrl}: ${r.status}`);
  }
  return r.json();
}

async function startCallbackServer() {
  return new Promise((resolve) => {
    const app = express();
    const server = app.listen(9200, () =>
      console.log("Client callback listening on :9200")
    );

    app.get("/callback", (req, res) => {
      const { code, state } = req.query;
      res.send("You can close this tab now. ✅");
      server.close();
      resolve({ code, state });
    });
  });
}

async function main() {
  // 1) RS → PRM → AS metadata
  const rsMeta = await discoverResourceMetadata();
  const resource = rsMeta.resource; // RS identifier / audience (e.g., "mcp-demo")
  if (!resource) throw new Error("PRM missing `resource` identifier");

  const asMetaUrl = rsMeta.authorization_servers?.[0];
  if (!asMetaUrl) throw new Error("PRM missing `authorization_servers`");
  const asMeta = await discoverASMetadata(asMetaUrl);

  // 2) PKCE
  const code_verifier = base64url(crypto.randomBytes(32));
  const code_challenge = sha256Base64url(code_verifier);
  const state = base64url(crypto.randomBytes(16));
  const scope = "echo:read";

  // 3) start callback waiter
  const waitForCode = startCallbackServer();

  // 4) open browser to /authorize (include OAuth 2.1 resource indicator)
  const authUrl = new URL(asMeta.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", scope);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", code_challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("resource", resource);

  console.log("Opening browser for login/consent…", authUrl.toString());
  await open(authUrl.toString());

  // 5) receive code
  const { code, state: returnedState } = await waitForCode;
  if (returnedState !== state) throw new Error("state mismatch");

  // 6) token exchange (bind the same resource)
  const tokenResp = await fetch(asMeta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier,
      resource, // important: matches the RS identifier from PRM
    }),
  });
  const tokenJson = await tokenResp.json();
  console.log("Token response:", tokenJson);

  if (!tokenResp.ok) {
    throw new Error(`token error: ${tokenResp.status} ${JSON.stringify(tokenJson)}`);
  }

  const accessToken = tokenJson.access_token;

  // 7) call MCP endpoint
  const call = await fetch(`${RS_BASE}/mcp/echo?msg=hello`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await call.json();
  console.log("MCP echo response:", data);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});