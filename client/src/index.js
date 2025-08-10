import fetch from "node-fetch";
import express from "express";
import open from "open";
import crypto from "node:crypto";

const RS_BASE = "http://localhost:9091";
const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:9200/callback";

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function sha256Base64url(str) {
  return crypto.createHash("sha256").update(str).digest("base64url");
}

async function discoverResourceMetadata() {
  const r1 = await fetch(`${RS_BASE}/mcp/echo?msg=hello`);
  if (r1.status !== 401) {
    throw new Error(`expected 401, got ${r1.status}`);
  }
  const www = r1.headers.get("www-authenticate") || "";
  const match = www.match(/resource_metadata="([^"]+)"/);
  if (!match) throw new Error("no resource_metadata in WWW-Authenticate");
  const metaUrl = match[1];
  const r2 = await fetch(metaUrl);
  return r2.json();
}

async function discoverASMetadata(asBase) {
  const r = await fetch(`${asBase}/.well-known/oauth-authorization-server`);
  return r.json();
}

async function startCallbackServer() {
  return new Promise((resolve) => {
    const app = express();
    const server = app.listen(9200, () => console.log("Client callback on :9200"));

    app.get("/callback", (req, res) => {
      const { code, state } = req.query;
      res.send("You can close this tab now. ✅");
      server.close();
      resolve({ code, state });
    });
  });
}

async function main() {
  // 1) discover RS -> AS
  const rsMeta = await discoverResourceMetadata();
  const asBase = rsMeta.authorization_servers[0];
  const asMeta = await discoverASMetadata(asBase);

  // 2) PKCE
  const code_verifier = base64url(crypto.randomBytes(32));
  const code_challenge = sha256Base64url(code_verifier);
  const state = base64url(crypto.randomBytes(16));
  const scope = "echo:read";

  // 3) start callback waiter
  const waitForCode = startCallbackServer();

  // 4) open browser to /authorize
  const authUrl = new URL(asMeta.authorization_endpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", scope);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", code_challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  console.log("Opening browser for login/consent…", authUrl.toString());
  await open(authUrl.toString());

  // 5) receive code
  const { code, state: returnedState } = await waitForCode;
  if (returnedState !== state) throw new Error("state mismatch");

  // 6) token exchange
  const tokenResp = await fetch(asMeta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier
    })
  });
  const tokenJson = await tokenResp.json();
  console.log("Token response:", tokenJson);

  const accessToken = tokenJson.access_token;

  // 7) call MCP endpoint
  const call = await fetch(`${RS_BASE}/mcp/echo?msg=hello`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await call.json();
  console.log("MCP echo response:", data);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});