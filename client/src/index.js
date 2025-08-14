// client/src/index.js
import http from "node:http";
import crypto from "node:crypto";
import fetch from "node-fetch";
import open from "open";

const GW_BASE   = process.env.GW_BASE   || "http://localhost:9400";
const RS_BASE   = process.env.RS_BASE   || "http://localhost:9091";
const CLIENT_ID = process.env.CLIENT_ID || "demo-client";

// Local redirect URI for this client
const CLIENT_PORT = Number(process.env.CLIENT_PORT || 9200);
const REDIRECT_URI = `http://localhost:${CLIENT_PORT}/callback`;

// Simple b64url helpers
function b64url(buf) { return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }

// PKCE helpers
function makePkce() {
  const code_verifier = b64url(crypto.randomBytes(32));
  const code_challenge = b64url(crypto.createHash("sha256").update(code_verifier).digest());
  return { code_verifier, code_challenge };
}

// Start a temporary HTTP server to catch the OAuth redirect
function awaitCallbackOnce() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try {
        if (req.method !== "GET") { res.statusCode = 405; return res.end("Method Not Allowed"); }
        const url = new URL(req.url || "", `http://localhost:${CLIENT_PORT}`);
        if (url.pathname !== "/callback") { res.statusCode = 404; return res.end("Not Found"); }

        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        if (!code) { res.statusCode = 400; return res.end("Missing code"); }
        if (!state) { res.statusCode = 400; return res.end("Missing state"); }

        res.statusCode = 200;
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.end("<h2>Thanks! You can return to the terminal.</h2>");

        server.close(() => resolve({ code, state }));
      } catch (e) {
        try { res.statusCode = 500; res.end("Error"); } catch {}
        server.close(() => reject(e));
      }
    });
    server.listen(CLIENT_PORT, () => {
      // no-op; we resolve in the request handler
    });
  });
}

// Discover AS metadata from an authorize URL (to get token_endpoint)
async function discoverASFromAuthorizeUrl(authorizeUrl) {
  const authURL = new URL(authorizeUrl);
  const asOrigin = authURL.origin;
  const wellKnown = `${asOrigin}/.well-known/oauth-authorization-server`;
  const r = await fetch(wellKnown);
  if (!r.ok) throw new Error(`AS discovery failed ${r.status}`);
  return r.json();
}

async function main() {
  // 1) Prepare PKCE
  const { code_verifier, code_challenge } = makePkce();

  // 2) Ask gateway to start auth session (GW does RS→AS discovery & policy)
  const startRes = await fetch(`${GW_BASE}/session/start`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      rs_base: RS_BASE,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_challenge,
      scope: "echo:read",
      toolId: "mcp.echo",
      agentId: "agent-demo",
    }),
  });
  if (!startRes.ok) {
    const t = await startRes.text().catch(() => "");
    throw new Error(`/session/start failed ${startRes.status} ${t}`);
  }
  const { sid, authorize_url } = await startRes.json();
  if (!authorize_url) throw new Error("No authorize_url from gateway");

  console.log("Opening browser for login/consent…", authorize_url);
  // 3) Spin up the local callback server and open the browser
  const cbWait = awaitCallbackOnce();
  await open(authorize_url);

  // 4) Wait for the AS redirect (code + state)
  const { code, state } = await cbWait;
  console.log("Got code & state from AS");

  // 5) (Optional) Verify state with gateway
  const v = await fetch(`${GW_BASE}/state/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ state }),
  }).then(r => r.json());
  if (!v?.ok) throw new Error(`state verification failed: ${v?.error || "unknown"}`);

  // 6) Discover token_endpoint from the authorize_url's AS
  const asMeta = await discoverASFromAuthorizeUrl(authorize_url);
  const token_endpoint = asMeta.token_endpoint;
  if (!token_endpoint) throw new Error("No token_endpoint in AS metadata");

  // 7) Exchange code ↔ token (client talks directly to AS)
  const tokenRes = await fetch(token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier,
      // optional: resource param if you want to pin audience here too
      // resource: "mcp-demo",
    }),
  });

  if (!tokenRes.ok) {
    const t = await tokenRes.text().catch(() => "");
    throw new Error(`Token exchange failed ${tokenRes.status} ${t}`);
  }
  const token = await tokenRes.json();
  const access_token = token.access_token;
  if (!access_token) throw new Error("No access_token from AS");

  console.log("Access token acquired. Calling RS…");

  // 8) Call the RS directly with the token
  const echoUrl = new URL("/mcp/echo", RS_BASE);
  echoUrl.searchParams.set("msg", "hello");

  const rsResp = await fetch(echoUrl.toString(), {
    headers: { Authorization: `Bearer ${access_token}` },
  });

  if (!rsResp.ok) {
    const t = await rsResp.text().catch(() => "");
    throw new Error(`RS error ${rsResp.status}: ${t}`);
  }
  const data = await rsResp.json();
  console.log("MCP echo response:", data);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});