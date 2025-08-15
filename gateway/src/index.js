// gateway/src/index.js
import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";
import fetch from "node-fetch";
import "dotenv/config";

import { signState, verifyState } from "./crypto.js";

// -----------------------------
// App & config
// -----------------------------
const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

const SESSION = new Map(); // sid -> session

function sid() { return crypto.randomBytes(16).toString("hex"); }
function nowSec() { return Math.floor(Date.now() / 1000); }

const GW_BASE     = process.env.GW_BASE      || "http://localhost:9400";
const UPSTREAM_RS = process.env.UPSTREAM_RS  || "http://localhost:9091";
const RS_META     = process.env.RS_META      || ""; // optional fallback to PRM URL
const ADP_BASE    = process.env.ADP_BASE     || "http://localhost:9500";

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
async function adpEvaluate({ subject, agentId, toolId, audience, requested_scopes, context }) {
  const r = await fetch(`${ADP_BASE}/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject, agentId, toolId, audience, requested_scopes, context })
  });
  if (!r.ok) throw new Error(`ADP /evaluate failed ${r.status}`);
  return r.json(); // { allow, scopes, obligations? }
}

async function adpConsent({ subject, agentId, toolId, audience, scopes, explicit }) {
  const r = await fetch(`${ADP_BASE}/consent`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject, agentId, toolId, audience, scopes, explicit })
  });
  if (!r.ok) throw new Error(`ADP /consent failed ${r.status}`);
  return r.json(); // { allow, record_id?, reason? }
}

// -----------------------------
// Session selection (by scope)
// -----------------------------
// replace old getReadySession with these helpers
function listReadySessions() {
  return Array.from(SESSION.values()).filter(s => s.ready && s.access_token);
}

function getSessionForScope(requiredScope) {
  // choose the freshest session whose scope list includes the required scope
  const candidates = listReadySessions().filter(s =>
    (s.scopesList ? s.scopesList : String(s.scope || "").split(/\s+/))
      .includes(requiredScope)
  );
  // prefer the newest by obtained_at
  candidates.sort((a, b) => (b.obtained_at || 0) - (a.obtained_at || 0));
  return candidates[0] || null;
}

// keep a generic “any ready” check for /session/status polling
function hasAnyReadySession() {
  return listReadySessions().length > 0;
}

// -----------------------------
// Session bootstrap
// -----------------------------
/**
 * POST /session/start
 *  Body (demo): { toolId, scope, context }
 */
app.post("/session/start", async (req, res) => {
  try {
    const {
      toolId = "payments.charge",        // human label for what the agent is doing
      scope  = "payments:charge",        // the actual OAuth scope requested
      context = {}                       // { orderId, amount_cents, merchant_id, ... }
    } = req.body || {};

    // 1) RS/AS discovery
    const { rsMeta } = await discoverProtectedResourceMetadata();
    const asMetaHint = rsMeta.authorization_servers?.[0];
    if (!asMetaHint) return res.status(500).json({ error: "no_as_in_rs_metadata" });
    const as = await fetchASMetadata(asMetaHint);

    // 2) Ask ADP to evaluate with context
    const audience = rsMeta.resource || "mcp-demo";
    const evalResp = await adpEvaluate({
      subject: "user-123",
      agentId: "agent-demo",
      toolId,
      audience,
      requested_scopes: [scope],
      context
    });
    if (!evalResp.allow) return res.status(403).json({ error: "denied_by_policy" });

    const scopesList = Array.isArray(evalResp.scopes) && evalResp.scopes.length
      ? evalResp.scopes
      : [scope];
    const scopeStr = scopesList.join(" ");

    // 3) PKCE + session
    const code_verifier = crypto.randomBytes(32).toString("base64url");
    const code_challenge = crypto.createHash("sha256").update(code_verifier).digest("base64url");
    const s = sid();
    const n = crypto.randomBytes(8).toString("hex");

    // bind context via digest (defense-in-depth)
    const ctxDigest = crypto.createHash("sha256")
      .update(JSON.stringify(context))
      .digest("base64url");

    const upstream = rsMeta?.gateway?.upstream_resource || UPSTREAM_RS;

    const statePayload = { sid: s, iat: nowSec(), aud: audience, scope: scopeStr, n, ctx: ctxDigest };
    const state = signState(statePayload);

    SESSION.set(s, {
      s, n,
      rs: rsMeta,
      as,
      scope: scopeStr,          // space-joined
      scopesList,               // array form
      audience,
      upstream,
      toolId,
      context,
      obligations: evalResp.obligations || {},
      obligations_issued_at: Date.now(),
      code_verifier, code_challenge, state,
      ready: false,
    });

    // 4) Auto-consent log (demo). If you want explicit, send user to /consent?sid=...
    await adpConsent({
      subject: "user-123",
      agentId: "agent-demo",
      toolId,
      audience,
      scopes: scopesList,
      explicit: false
    });

    const u = new URL(as.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", "demo-client");
    u.searchParams.set("redirect_uri", `${GW_BASE}/oauth/callback`);
    u.searchParams.set("scope", scopeStr);
    u.searchParams.set("state", state);
    u.searchParams.set("code_challenge", code_challenge);
    u.searchParams.set("code_challenge_method", "S256");
    u.searchParams.set("resource", audience);

    return res.json({ sid: s, authorize_url: u.toString() });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "start_failed", detail: String(e?.message || e) });
  }
});

// -----------------------------
// Consent UI (explicit path)
// -----------------------------
app.get("/consent", (req, res) => {
  const s = SESSION.get(req.query.sid);
  if (!s) return res.status(404).send(html("<h2>Session not found</h2>"));
  res.send(html(`
    <h2>Approve access?</h2>
    <p>Tool: <code>${s.toolId}</code></p>
    <p>Audience: <code>${s.audience}</code></p>
    <p>Scopes: <code>${s.scope}</code></p>
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

    await adpConsent({
      subject: "user-123",
      agentId: "agent-demo",
      toolId: s.toolId,
      audience: s.audience,
      scopes: s.scopesList,
      explicit: true
    });

    const u = new URL(s.as.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", "demo-client");
    u.searchParams.set("redirect_uri", `${GW_BASE}/oauth/callback`);
    u.searchParams.set("scope", s.scope);
    u.searchParams.set("state", s.state);
    u.searchParams.set("code_challenge", s.code_challenge);
    u.searchParams.set("code_challenge_method", "S256");
    u.searchParams.set("resource", s.audience);

    res.redirect(u.toString());
  } catch (e) {
    console.error(e);
    res.status(500).send(html("<h2>Consent error</h2>"));
  }
});

// -----------------------------
// OAuth redirect_uri (callback at gateway)
// -----------------------------
app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res
        .status(400)
        .send(html(`<h2>Authorization error</h2><p><code>${String(error)}</code>: ${String(error_description || "")}</p>`));
    }

    const v = verifyState(state);
    if (!v.ok) {
      return res.status(400).send(html(`<h2>Invalid state</h2><pre>${v.err}</pre>`));
    }

    const { sid: s, aud: audFromState, scope: scopeFromState } = v.json || {};
    const sess = SESSION.get(s);
    if (!sess) {
      return res.status(400).send(html("<h2>Unknown or expired session</h2>"));
    }
    if (sess.used) {
      return res.status(400).send(html("<h2>Session already completed</h2>"));
    }
    if (audFromState !== sess.audience || scopeFromState !== sess.scope) {
      return res.status(400).send(html("<h2>Session/state mismatch</h2>"));
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: `${GW_BASE}/oauth/callback`,
      client_id: "demo-client",
      code_verifier: sess.code_verifier,
      resource: sess.audience
    });

    const tok = await fetch(sess.as.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body
    });

    if (!tok.ok) {
      const t = await tok.text().catch(() => "");
      return res
        .status(502)
        .send(html(`<h2>Token exchange failed</h2><pre>${t || `AS returned ${tok.status}`}</pre>`));
    }

    const j = await tok.json().catch(() => ({}));
    if (!j.access_token) {
      return res.status(502).send(html("<h2>No access_token in token response</h2>"));
    }

    sess.access_token = j.access_token;
    sess.refresh_token = j.refresh_token;
    sess.expires_in = typeof j.expires_in === "number" ? j.expires_in : 900;
    sess.obtained_at = Date.now();
    sess.expires_at = sess.obtained_at + sess.expires_in * 1000;

    sess.code_verifier = undefined;
    sess.used = true;
    sess.ready = true;

    res.send(html("<h2>All set 🎉</h2><p>You can close this tab and return to the app.</p>"));
  } catch (e) {
    console.error("oauth/callback error:", e);
    res.status(500).send(html("<h2>Callback error</h2><pre>See gateway logs</pre>"));
  }
});

// -----------------------------
// MCP helpers (echo, tickets, payments)
// -----------------------------

// Echo needs an echo:read token
app.get("/mcp/echo", async (req, res) => {
  const sess = getSessionForScope("echo:read");
  if (!sess) return res.status(401).json({ error: "login_required" });

  try {
    const url = new URL("/mcp/echo", sess.upstream);
    for (const [k, v] of Object.entries(req.query)) {
      url.searchParams.set(k, String(v));
    }

    const r = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${sess.access_token}` }
    });

    if (r.status === 401 || r.status === 403) {
      sess.ready = false;
      sess.access_token = undefined;
      return res.status(401).json({ error: "login_required" });
    }

    const text = await r.text();
    try { return res.status(r.status).json(JSON.parse(text)); }
    catch { return res.status(r.status).type(r.headers.get("content-type") || "text/plain").send(text); }
  } catch (e) {
    console.error("proxy /mcp/echo error", e);
    res.status(502).json({ error: "bad_gateway" });
  }
});

// Tickets need tickets:read
app.get("/mcp/tickets", async (_req, res) => {
  const sess = getSessionForScope("tickets:read");
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
    try { return res.status(r.status).json(JSON.parse(text)); }
    catch { return res.status(r.status).type(r.headers.get("content-type") || "text/plain").send(text); }
  } catch (e) {
    console.error("proxy /mcp/tickets error", e);
    res.status(502).json({ error: "bad_gateway" });
  }
});

// Wallet token (minimal disclosure) — demo only
const WALLET_PM_TOKEN = process.env.WALLET_PM_TOKEN || "pm_demo_visa_xxx";

// Pay an order — requires payments:charge; enforce obligations then forward to RS /orders/:id/pay
// Pay an order — requires payments:charge; enforce obligations then forward to RS /orders/:id/pay
app.post("/mcp/pay", async (req, res) => {
  const sess = getSessionForScope("payments:charge");
  if (!sess) return res.status(401).json({ error: "login_required" });

  const { orderId, amount_cents, merchant_id } = req.body || {};
  if (!orderId) {
    return res.status(400).json({ error: "invalid_request", detail: "orderId required" });
  }

  // Enforce obligations from ADP
  const ob = sess.obligations || {};

  // Bind order
  if (ob.bind_order && String(orderId) !== String(ob.bind_order)) {
    return res.status(403).json({ error: "obligation_violation", detail: "orderId mismatch" });
  }

  // Amount cap
  if (Number.isInteger(ob.max_amount_cents) && Number.isInteger(amount_cents) &&
      Number(amount_cents) > ob.max_amount_cents) {
    return res.status(403).json({ error: "obligation_violation", detail: "amount exceeds max" });
  }

  // Merchant allowlist
  if (Array.isArray(ob.merchant_allowlist) && ob.merchant_allowlist.length > 0) {
    if (!merchant_id || !ob.merchant_allowlist.includes(merchant_id)) {
      return res.status(403).json({ error: "obligation_violation", detail: "merchant not allowed" });
    }
  }

  // TTL on obligations
  if (Number.isInteger(ob.ttl)) {
    const issuedAt = sess.obligations_issued_at || sess.obtained_at || Date.now();
    const ageSec = Math.floor((Date.now() - issuedAt) / 1000);
    if (ageSec > ob.ttl) {
      // force re-auth
      sess.ready = false;
      sess.access_token = undefined;
      return res.status(401).json({ error: "session_obligation_ttl_expired" });
    }
  }

  // Forward to RS: POST /orders/:id/pay
  try {
    const url = new URL(`/orders/${encodeURIComponent(orderId)}/pay`, sess.upstream).toString();
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        Authorization: `Bearer ${sess.access_token}`
      },
      // Body is optional for your RS; include details for logging / future proofs
      body: JSON.stringify({
        amount_cents,
        merchant_id,
        payment_method_token: WALLET_PM_TOKEN   // minimal disclosure: TES injects PM token
      })
    });

    if (r.status === 401 || r.status === 403) {
      sess.ready = false;
      sess.access_token = undefined;
      const text = await r.text().catch(() => "");
      return res.status(401).json({ error: "login_required", detail: text });
    }

    const text = await r.text();
    try {
      return res.status(r.status).json(JSON.parse(text));
    } catch {
      return res
        .status(r.status)
        .type(r.headers.get("content-type") || "text/plain")
        .send(text);
    }
  } catch (e) {
    console.error("proxy /mcp/pay error", e);
    return res.status(502).json({ error: "bad_gateway" });
  }
});

// -----------------------------
// Debug helpers (DEV ONLY)
// -----------------------------
function b64urlToJson(b64url) {
  try {
    const json = Buffer.from(b64url, "base64url").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

app.get("/session/status", (_req, res) => {
  res.json({ ready: hasAnyReadySession() });
});

app.get("/debug/token", (req, res) => {
  const scope = req.query.scope ? String(req.query.scope) : undefined;
  const sess = getReadySession(scope);
  if (!sess || !sess.access_token) {
    return res.status(404).json({ error: "no_session_or_token", scope });
  }
  const [hdr, pl, sig] = String(sess.access_token).split(".");
  const b64urlToJson = (b) => {
    try { return JSON.parse(Buffer.from(b, "base64url").toString("utf8")); }
    catch { return null; }
  };
  return res.json({
    scope: sess.scope,
    toolId: sess.toolId,
    token: sess.access_token,
    header: b64urlToJson(hdr),
    payload: b64urlToJson(pl),
    has_signature: Boolean(sig)
  });
});

app.get("/debug/introspect", async (req, res) => {
  const scope = req.query.scope ? String(req.query.scope) : undefined;
  const sess = getReadySession(scope);
  if (!sess || !sess.access_token) {
    return res.status(404).json({ error: "no_session_or_token", scope });
  }
  try {
    const r = await fetch(sess.as.introspection_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: sess.access_token })
    });
    const as_json = await r.json().catch(async () => ({ raw: await r.text() }));
    return res.json({ ok: r.ok, status: r.status, as_introspection: as_json, scope: sess.scope, toolId: sess.toolId });
  } catch (e) {
    return res.status(502).json({ error: "introspection_error", detail: String(e?.message || e) });
  }
});

app.post("/debug/session/reset", (_req, res) => {
  SESSION.clear();
  res.json({ ok: true, cleared: true });
});

app.get("/demo", (_req, res) => {
  const sessions = Array.from(SESSION.values()).map(s => ({
    sid: s.s,
    toolId: s.toolId,
    audience: s.audience,
    scope: s.scope,
    ready: s.ready,
    obligations: s.obligations,
    obtained_at: s.obtained_at,
    expires_at: s.expires_at
  }));
  res.type("html").send(`
  <!doctype html><meta charset="utf-8"/>
  <style>body{font:16px/1.5 system-ui;margin:2rem} pre{background:#f6f8fa;padding:10px;border-radius:8px}</style>
  <h1>Gateway Sessions</h1>
  <pre>${JSON.stringify(sessions, null, 2)}</pre>
  `);
});

// -----------------------------
const PORT = process.env.PORT || 9400;
app.listen(PORT, () => {
  console.log(`Gateway listening on :${PORT}`);
  console.log(`UPSTREAM_RS: ${UPSTREAM_RS}`);
  if (RS_META) console.log(`RS_META fallback: ${RS_META}`);
  console.log(`ADP_BASE: ${ADP_BASE}`);
});