// gateway/src/index.js
import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";
import fetch from "node-fetch";
import "dotenv/config";

import { signState, verifyState } from "./crypto.js";

// -----------------------------
// Config
// -----------------------------
const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

// In-memory sessions (sid -> session data)
const SESSION = new Map();

function sid() { return crypto.randomBytes(16).toString("hex"); }
function now() { return Math.floor(Date.now() / 1000); }

const GW_BASE     = process.env.GW_BASE      || "http://localhost:9400";
const UPSTREAM_RS = process.env.UPSTREAM_RS  || "http://localhost:9091"; // where we will probe /mcp/echo
const RS_META     = process.env.RS_META      || ""; // optional fallback e.g. http://localhost:9091/.well-known/oauth-protected-resource
const ADP_BASE    = process.env.ADP_BASE     || "http://localhost:9500"; // Client Authorizer (ADP)

// Minimal HTML helper
function html(body) {
  return `<!doctype html><meta charset="utf-8" />
  <style>body{font:16px/1.5 system-ui;margin:2rem}
  code,pre{background:#f6f8fa;padding:.15rem .35rem;border-radius:.35rem}
  button{padding:.6rem 1rem;cursor:pointer}
  .muted{color:#666}</style>
  ${body}`;
}

// -----------------------------
// RS/AS discovery helpers
// -----------------------------
function extractResourceMetadata(wwwAuthenticate) {
  if (!wwwAuthenticate) return null;
  const match = wwwAuthenticate.match(/resource_metadata="([^"]+)"/i);
  return match ? match[1] : null;
}

/**
 * Discover RS Protected Resource Metadata using spec’d flow:
 *  1) GET {UPSTREAM_RS}/mcp/echo (no token)
 *  2) Expect 401 with WWW-Authenticate containing resource_metadata="..."
 *  3) GET that metadata URL (RFC 9728)
 * Falls back to RS_META if probing fails.
 */
async function discoverProtectedResourceMetadata() {
  try {
    const probeUrl = new URL("/mcp/echo?probe=1", UPSTREAM_RS).toString();
    const r1 = await fetch(probeUrl);
    const www = r1.headers.get("www-authenticate") || "";
    const metaUrl = extractResourceMetadata(www);

    if (metaUrl) {
      const r2 = await fetch(metaUrl);
      if (!r2.ok) throw new Error(`RS metadata fetch failed ${r2.status}`);
      const rsMeta = await r2.json();
      return { rsMeta, metaUrl, discovered: true };
    }

    if (RS_META) {
      const r2 = await fetch(RS_META);
      if (!r2.ok) throw new Error(`Fallback RS_META fetch failed ${r2.status}`);
      const rsMeta = await r2.json();
      return { rsMeta, metaUrl: RS_META, discovered: false };
    }

    throw new Error("No resource_metadata in WWW-Authenticate and no RS_META fallback configured");
  } catch (err) {
    if (RS_META) {
      const r = await fetch(RS_META);
      if (!r.ok) throw new Error(`Fallback RS_META fetch failed ${r.status}`);
      const rsMeta = await r.json();
      return { rsMeta, metaUrl: RS_META, discovered: false };
    }
    throw err;
  }
}

async function fetchASMetadata(asHint) {
  let url;
  try {
    const u = new URL(asHint);
    if (u.pathname.endsWith("/.well-known/oauth-authorization-server")) {
      url = u.toString();
    } else {
      url = new URL("/.well-known/oauth-authorization-server", u.origin).toString();
    }
  } catch {
    url = `${asHint.replace(/\/+$/, "")}/.well-known/oauth-authorization-server`;
  }
  const r = await fetch(url);
  if (!r.ok) throw new Error(`AS metadata fetch failed ${r.status}`);
  return r.json();
}

// -----------------------------
// ADP helpers (evaluate & consent)
// -----------------------------
async function adpEvaluate({ subject, agentId, toolId, audience, requested_scopes }) {
  const r = await fetch(`${ADP_BASE}/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject, agentId, toolId, audience, requested_scopes })
  });
  if (!r.ok) throw new Error(`ADP /evaluate failed ${r.status}`);
  return r.json(); // { allow:boolean, scopes:string[], obligations?:{...} }
}

async function adpConsent({ subject, agentId, toolId, audience, scopes, explicit }) {
  const r = await fetch(`${ADP_BASE}/consent`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject, agentId, toolId, audience, scopes, explicit })
  });
  if (!r.ok) throw new Error(`ADP /consent failed ${r.status}`);
  return r.json(); // { allow:boolean, record_id?:string, reason?:string }
}

// pick any ready session (Phase-1 simplicity)
function getReadySession() {
  for (const s of SESSION.values()) {
    if (s.ready && s.access_token) return s;
  }
  return null;
}

// -----------------------------
// Session bootstrap
// -----------------------------
/**
 * POST /session/start
 *  - Discover RS (401 → WWW-Authenticate → resource_metadata)
 *  - Fetch RS metadata (RFC 9728)
 *  - Fetch AS metadata (RFC 8414)
 *  - Call ADP /evaluate (decides/filters scopes)
 *  - Call ADP /consent explicit:false (decides auto-consent)
 *  - Create session (PKCE + HMAC-bound state)
 *  - If ADP approved auto-consent → build AS authorize URL
 *    else → return link to gateway /consent page
 */
app.post("/session/start", async (_req, res) => {
  try {
    // 1) RS discovery
    const { rsMeta, metaUrl, discovered } = await discoverProtectedResourceMetadata();
    console.log(`[gateway] RS metadata from ${discovered ? "WWW-Authenticate" : "fallback"}: ${metaUrl}`);

    // 2) AS discovery
    const asMetaHint = rsMeta.authorization_servers?.[0];
    if (!asMetaHint) return res.status(500).json({ error: "no_as_in_rs_metadata" });
    const as = await fetchASMetadata(asMetaHint);

    // 3) Evaluate with ADP (subject/agent/tool are simple placeholders for now)
    const audience = rsMeta.resource || "mcp-demo";
    const requested_scopes = ["echo:read"]; // ask for what the client needs
    const evalResp = await adpEvaluate({
      subject: "user-123",
      agentId: "agent-demo",
      toolId: "mcp.echo",
      audience,
      requested_scopes
    });

    if (!evalResp.allow) {
      return res.status(403).json({ error: "denied_by_policy" });
    }

    // Normalize scopes from ADP (fall back to requested if ADP omitted)
    const scopesList = Array.isArray(evalResp.scopes) && evalResp.scopes.length > 0
      ? evalResp.scopes
      : requested_scopes.slice();
    const scopeStr = scopesList.join(" ");

    // 4) Ask ADP if consent can be auto-approved (explicit:false)
    const consentAuto = await adpConsent({
      subject: "user-123",
      agentId: "agent-demo",
      toolId: "mcp.echo",
      audience,
      scopes: scopesList,
      explicit: false
    });
    const autoApprove = !!consentAuto.allow;

    // 5) PKCE + Session
    const code_verifier = crypto.randomBytes(32).toString("base64url");
    const code_challenge = crypto.createHash("sha256").update(code_verifier).digest("base64url");
    const s = sid();
    const n = crypto.randomBytes(8).toString("hex");

    const upstream =
      rsMeta?.gateway?.upstream_resource
        || UPSTREAM_RS;

    const statePayload = { sid: s, iat: now(), aud: audience, scope: scopeStr, n };
    const state = signState(statePayload);

    SESSION.set(s, {
      s, n, rs: rsMeta, as, audience, upstream,
      scopesList, scopeStr,
      code_verifier, code_challenge, state,
      ready: false,
      // tokens filled after callback
    });

    // 6) Build next hop based on consent decision
    let authorize_url;
    if (autoApprove) {
      // Go straight to AS /authorize
      const u = new URL(as.authorization_endpoint);
      u.searchParams.set("response_type", "code");
      u.searchParams.set("client_id", "demo-client");
      u.searchParams.set("redirect_uri", `${GW_BASE}/oauth/callback`);
      u.searchParams.set("scope", scopeStr);
      u.searchParams.set("state", state);
      u.searchParams.set("code_challenge", code_challenge);
      u.searchParams.set("code_challenge_method", "S256");
      // Send resource indicator so AS mints the correct aud
      u.searchParams.set("resource", audience);
      authorize_url = u.toString();
    } else {
      // Require explicit consent at gateway UI
      authorize_url = `${GW_BASE}/consent?sid=${s}`;
    }

    return res.json({ sid: s, authorize_url });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "start_failed", detail: String(e?.message || e) });
  }
});

// -----------------------------
// Consent UI (explicit path)
// -----------------------------
/**
 * GET /consent?sid=...
 *  - Shows a tiny confirmation page
 *  - On Approve, POST /consent/approve to record consent at ADP, then redirect to AS /authorize
 */
app.get("/consent", (req, res) => {
  const s = SESSION.get(req.query.sid);
  if (!s) return res.status(404).send(html("<h2>Session not found</h2>"));
  res.send(html(`
    <h2>Approve access?</h2>
    <p>Tool (aud): <code>${s.audience}</code></p>
    <p>Scopes: <code>${s.scopeStr}</code></p>
    <form action="/consent/approve" method="post">
      <input type="hidden" name="sid" value="${s.s}">
      <button type="submit">Approve & continue</button>
    </form>
    <p class="muted">This records explicit consent with the Authorizer, then sends you to the AS.</p>
  `));
});

// Parse urlencoded form (for the POST below)
app.use(express.urlencoded({ extended: false }));

app.post("/consent/approve", async (req, res) => {
  try {
    const s = SESSION.get(req.body.sid);
    if (!s) return res.status(404).send(html("<h2>Session not found</h2>"));

    // Record explicit consent at ADP
    await adpConsent({
      subject: "user-123",
      agentId: "agent-demo",
      toolId: "mcp.echo",
      audience: s.audience,
      scopes: s.scopesList,
      explicit: true
    });

    // Build AS authorize URL using ADP-approved scopes from the session
    const u = new URL(s.as.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", "demo-client");
    u.searchParams.set("redirect_uri", `${GW_BASE}/oauth/callback`);
    u.searchParams.set("scope", s.scopeStr);
    u.searchParams.set("state", s.state);
    u.searchParams.set("code_challenge", s.code_challenge);
    u.searchParams.set("code_challenge_method", "S256");
    u.searchParams.set("resource", s.audience);

    // Redirect to the AS for the normal OAuth flow
    res.redirect(u.toString());
  } catch (e) {
    console.error(e);
    res.status(500).send(html("<h2>Consent error</h2>"));
  }
});

// -----------------------------
// OAuth redirect_uri (callback at gateway)
// -----------------------------
/**
 * GET /oauth/callback
 *  - Verify HMAC-bound state
 *  - Exchange code at AS (confirm resource)
 *  - Mark session ready (gateway still holds token for proxying in Phase-1)
 */
app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const v = verifyState(state);
    if (!v.ok) return res.status(400).send(html(`<h2>Invalid state: ${v.err}</h2>`));

    const { sid: s } = v.json;
    const sess = SESSION.get(s);
    if (!sess) return res.status(400).send(html("<h2>Unknown session</h2>"));

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: `${GW_BASE}/oauth/callback`,
      client_id: "demo-client",
      code_verifier: sess.code_verifier,
      // Confirm resource to bind correct aud
      resource: sess.audience
    });

    const tok = await fetch(sess.as.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body
    });
    if (!tok.ok) {
      const t = await tok.text();
      return res.status(500).send(html(`<h2>Token exchange failed</h2><pre>${t}</pre>`));
    }
    const j = await tok.json();

    sess.access_token = j.access_token;
    sess.refresh_token = j.refresh_token;
    sess.expires_in = j.expires_in;
    sess.obtained_at = Date.now();
    sess.ready = true;

    res.send(html("<h2>Done.</h2><p>You can close this tab.</p>"));
  } catch (e) {
    console.error(e);
    res.status(500).send(html("<h2>Callback error</h2>"));
  }
});

// -----------------------------
// Client polling + RS proxy
// -----------------------------
app.get("/session/status", (_req, res) => {
  const ready = !!getReadySession();
  res.json({ ready });
});

/**
 * GET /mcp/echo
 *  - If no ready session: ask client to start OAuth via /session/start
 *  - Else: forward to RS /mcp/echo with stored bearer
 */
app.get("/mcp/echo", async (req, res) => {
  const sess = getReadySession();
  if (!sess) {
    return res.status(401).json({ error: "login_required" });
  }

  try {
    const url = new URL("/mcp/echo", sess.upstream);
    for (const [k, v] of Object.entries(req.query)) {
      url.searchParams.set(k, String(v));
    }

    const r = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${sess.access_token}` }
    });

    if (r.status === 401 || r.status === 403) {
      // Token no longer valid upstream → force re-auth
      sess.ready = false;
      sess.access_token = undefined;
      sess.refresh_token = undefined;
      const text = await r.text().catch(() => "");
      return res.status(401).json({ error: "login_required", detail: text });
    }

    const text = await r.text(); // consume once
    try {
      const json = JSON.parse(text);
      return res.status(r.status).json(json);
    } catch {
      res.status(r.status).type(r.headers.get("content-type") || "text/plain").send(text);
    }
  } catch (e) {
    console.error("proxy /mcp/echo error", e);
    res.status(502).json({ error: "bad_gateway" });
  }
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));

// ---- Debug helpers (DEV ONLY) ------------------------------------

// pick any ready session (we already have getReadySession)
function b64urlToJson(b64url) {
  try {
    const json = Buffer.from(b64url, "base64url").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// Show the access token the gateway currently holds (and its decoded header/payload)
app.get("/debug/token", (_req, res) => {
  const sess = getReadySession();
  if (!sess || !sess.access_token) {
    return res.status(404).json({ error: "no_session_or_token" });
  }
  const [hdr, pl, sig] = String(sess.access_token).split(".");
  const header  = b64urlToJson(hdr);
  const payload = b64urlToJson(pl);
  return res.json({
    token: sess.access_token,
    header,
    payload,
    has_signature: Boolean(sig)
  });
});

// Ask the AS to introspect the token the gateway holds
app.get("/debug/introspect", async (_req, res) => {
  const sess = getReadySession();
  if (!sess || !sess.access_token) {
    return res.status(404).json({ error: "no_session_or_token" });
  }
  try {
    const r = await fetch(sess.as.introspection_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: sess.access_token })
    });
    const as_json = await r.json().catch(async () => ({ raw: await r.text() }));
    return res.json({ ok: r.ok, status: r.status, as_introspection: as_json });
  } catch (e) {
    return res.status(502).json({ error: "introspection_error", detail: String(e?.message || e) });
  }
});

// Clear in-memory sessions (force a fresh OAuth run on next call)
app.post("/debug/session/reset", (_req, res) => {
  SESSION.clear();
  res.json({ ok: true, cleared: true });
});

// gateway/src/index.js (add after /mcp/echo)
app.get("/mcp/tickets", async (req, res) => {
  const sess = getReadySession();
  if (!sess) return res.status(401).json({ error: "login_required" });

  try {
    const url = new URL("/tickets", sess.upstream);
    const r = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${sess.access_token}` }
    });

    if (r.status === 401 || r.status === 403) {
      sess.ready = false;
      sess.access_token = undefined;
      return res.status(401).json({ error: "login_required" });
    }

    const text = await r.text();
    try {
      return res.status(r.status).json(JSON.parse(text));
    } catch {
      res.status(r.status).type(r.headers.get("content-type") || "text/plain").send(text);
    }
  } catch (e) {
    console.error("proxy /mcp/tickets error", e);
    res.status(502).json({ error: "bad_gateway" });
  }
});

const PORT = process.env.PORT || 9400;
app.listen(PORT, () => {
  console.log(`Gateway listening on :${PORT}`);
  console.log(`UPSTREAM_RS: ${UPSTREAM_RS}`);
  if (RS_META) console.log(`RS_META fallback: ${RS_META}`);
  console.log(`ADP_BASE: ${ADP_BASE}`);
});