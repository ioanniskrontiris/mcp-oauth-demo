// gateway/src/index.js
import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";
import fetch from "node-fetch";
import 'dotenv/config';

import { signState, verifyState } from "./crypto.js";
import { shouldAutoConsent } from "./consentHook.js";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

// In‑memory sessions (sid -> session data)
const SESSION = new Map();

function sid() { return crypto.randomBytes(16).toString("hex"); }
function now() { return Math.floor(Date.now() / 1000); }

const GW_BASE = process.env.GW_BASE || "http://localhost:9400";
const RS_META = process.env.RS_META || "http://localhost:9091/.well-known/oauth-protected-resource";

// Minimal HTML helper
function html(body) {
  return `<!doctype html><meta charset="utf-8" />
  <style>body{font:16px/1.4 system-ui;margin:2rem} button{padding:.6rem 1rem}</style>
  ${body}`;
}

// pick any ready session (Phase‑1 simplicity)
function getReadySession() {
  for (const s of SESSION.values()) {
    if (s.ready && s.access_token) return s;
  }
  return null;
}

/**
 * POST /session/start
 *  - discover RS -> AS (from RS metadata)
 *  - create session, PKCE
 *  - build signed state bound to sid
 *  - consent hook: redirect either to AS authorize or our /consent
 */
app.post("/session/start", async (_req, res) => {
  try {
    const rs = await fetch(RS_META).then(r => {
      if (!r.ok) throw new Error(`RS metadata fetch failed ${r.status}`);
      return r.json();
    });

    const asMetaUrl = rs.authorization_servers?.[0];
    if (!asMetaUrl) return res.status(500).json({ error: "no_as" });

    const as = await fetch(asMetaUrl).then(r => {
      if (!r.ok) throw new Error(`AS metadata fetch failed ${r.status}`);
      return r.json();
    });

    // PKCE
    const code_verifier = crypto.randomBytes(32).toString("base64url");
    const code_challenge = crypto.createHash("sha256").update(code_verifier).digest("base64url");

    // Session
    const scope = "echo:read";
    const audience = rs.resource || "mcp-demo";
    const s = sid();
    const n = crypto.randomBytes(8).toString("hex");

    // figure upstream RS base (preferred: metadata.gateway.upstream_resource)
    const upstream =
      rs?.gateway?.upstream_resource
        || new URL(RS_META).origin; // fallback: same origin as metadata

    const statePayload = { sid: s, iat: now(), aud: audience, scope, n };
    const state = signState(statePayload);

    SESSION.set(s, {
      s, n, rs, as, scope, audience, upstream,
      code_verifier, code_challenge, state,
      ready: false,
      // tokens will be filled after callback
    });

    // Consent hook (V0)
    const { allow } = await shouldAutoConsent({
      scope, aud: audience, toolId: "mcp.echo", agentId: "agent-demo"
    });

    let authorize_url;
    if (allow) {
      const u = new URL(as.authorization_endpoint);
      u.searchParams.set("response_type", "code");
      u.searchParams.set("client_id", "demo-client");
      u.searchParams.set("redirect_uri", `${GW_BASE}/oauth/callback`);
      u.searchParams.set("scope", scope);
      u.searchParams.set("state", state);
      u.searchParams.set("code_challenge", code_challenge);
      u.searchParams.set("code_challenge_method", "S256");
      authorize_url = u.toString();
    } else {
      authorize_url = `${GW_BASE}/consent?sid=${s}`;
    }

    res.json({ sid: s, authorize_url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "start_failed" });
  }
});

/**
 * GET /consent?sid=...
 *  - tiny page: user clicks Approve, then we jump to AS /authorize
 */
app.get("/consent", (req, res) => {
  const s = SESSION.get(req.query.sid);
  if (!s) return res.status(404).send(html("<h2>Session not found</h2>"));

  const u = new URL(s.as.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", "demo-client");
  u.searchParams.set("redirect_uri", `${GW_BASE}/oauth/callback`);
  u.searchParams.set("scope", s.scope);
  u.searchParams.set("state", s.state);
  u.searchParams.set("code_challenge", s.code_challenge);
  u.searchParams.set("code_challenge_method", "S256");

  res.send(html(`
    <h2>Approve access?</h2>
    <p>Tool: <b>${s.audience}</b> &nbsp; Scope: <code>${s.scope}</code></p>
    <form action="${u.toString()}" method="get">
      <button type="submit">Approve & continue</button>
    </form>
  `));
});

/**
 * OAuth redirect_uri
 *  - verify signed state
 *  - exchange code at AS
 *  - mark session ready
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
      code_verifier: sess.code_verifier
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

/**
 * GET /session/status
 *  - simple readiness flag for Phase‑1 polling
 */
app.get("/session/status", (_req, res) => {
  const ready = !!getReadySession();
  res.json({ ready });
});

/**
 * GET /mcp/echo
 *  - if no ready session: tell client to start auth
 *  - else forward to RS /mcp/echo with stored bearer
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

    // If upstream rejects token, reset session so client re‑auths
    if (r.status === 401 || r.status === 403) {
      sess.ready = false;
      sess.access_token = undefined;
      sess.refresh_token = undefined;
      return res.status(401).json({ error: "login_required" });
    }

    const text = await r.text(); // consume once
    // try JSON, fall back to text
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

const PORT = process.env.PORT || 9400;
app.listen(PORT, () => {
  console.log(`Gateway listening on :${PORT}`);
  console.log(`RS metadata: ${RS_META}`);
});