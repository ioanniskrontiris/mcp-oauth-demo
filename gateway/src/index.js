// gateway/src/index.js
import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";
import fetch from "node-fetch";
import "dotenv/config";

import { signState, verifyState } from "./crypto.js";
import { shouldAutoConsent } from "./consentHook.js";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

// In-memory sessions (sid -> context only; no tokens here)
const SESSION = new Map();

function sid() { return crypto.randomBytes(16).toString("hex"); }
function now() { return Math.floor(Date.now() / 1000); }

const GW_BASE = process.env.GW_BASE || "http://localhost:9400";
const DEFAULT_RS_META = process.env.RS_META || "http://localhost:9091/.well-known/oauth-protected-resource";

// Minimal HTML helper
function html(body) {
  return `<!doctype html><meta charset="utf-8" />
  <style>body{font:16px/1.4 system-ui;margin:2rem} button{padding:.6rem 1rem}</style>
  ${body}`;
}

/**
 * POST /session/start
 * Body:
 * {
 *   rs_base: "http://localhost:9091",
 *   client_id: "demo-client",
 *   redirect_uri: "http://localhost:9200/callback",
 *   code_challenge: "<S256>",
 *   scope: "echo:read",
 *   toolId: "mcp.echo",
 *   agentId: "agent-demo"
 * }
 *
 * Returns: { sid, authorize_url }
 */
app.post("/session/start", async (req, res) => {
  try {
    const {
      rs_base,
      client_id,
      redirect_uri,
      code_challenge,
      scope = "echo:read",
      toolId = "mcp.echo",
      agentId = "agent-demo",
    } = req.body || {};

    if (!client_id || !redirect_uri || !code_challenge) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "client_id, redirect_uri, code_challenge required",
      });
    }

    // 1) Discover RS -> AS
    const rsMetaUrl = rs_base
      ? `${rs_base}/.well-known/oauth-protected-resource`
      : DEFAULT_RS_META;

    const rs = await fetch(rsMetaUrl).then((r) => {
      if (!r.ok) throw new Error(`RS metadata fetch failed ${r.status}`);
      return r.json();
    });

    const asMetaUrl = rs.authorization_servers?.[0];
    if (!asMetaUrl) return res.status(502).json({ error: "no_as_from_rs" });

    const as = await fetch(asMetaUrl).then((r) => {
      if (!r.ok) throw new Error(`AS metadata fetch failed ${r.status}`);
      return r.json();
    });

    // 2) Policy evaluation (dummy auto-consent or explicit UI)
    const audience = rs.resource || "mcp-demo";
    const approval = await shouldAutoConsent({
      scope,
      aud: audience,
      toolId,
      agentId,
      rsMetaUrl,
      asMetaUrl,
    });
    if (!approval.allow) {
      // Require explicit consent via our gateway page
      const s = sid();
      const n = crypto.randomBytes(8).toString("hex");
      const statePayload = { sid: s, iat: now(), aud: audience, scope, toolId, agentId, n };
      const state = signState(statePayload);

      SESSION.set(s, {
        s,
        n,
        audience,
        scope,
        toolId,
        agentId,
        rs,
        as,
        client_id,
        redirect_uri,
        code_challenge,
        state,
      });

      return res.json({ sid: s, authorize_url: `${GW_BASE}/consent?sid=${s}` });
    }

    // 3) Auto-approve path: mint state, hand back AS authorize URL directly
    const s = sid();
    const n = crypto.randomBytes(8).toString("hex");
    const statePayload = { sid: s, iat: now(), aud: audience, scope, toolId, agentId, n };
    const state = signState(statePayload);

    SESSION.set(s, {
      s,
      n,
      audience,
      scope,
      toolId,
      agentId,
      rs,
      as,
      client_id,
      redirect_uri,
      code_challenge,
      state,
    });

    const u = new URL(as.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", client_id);
    u.searchParams.set("redirect_uri", redirect_uri);
    u.searchParams.set("scope", scope);
    u.searchParams.set("state", state);
    // Optional: resource indicator for audience binding
    if (audience) u.searchParams.set("resource", audience);
    u.searchParams.set("code_challenge", code_challenge);
    u.searchParams.set("code_challenge_method", "S256");

    return res.json({ sid: s, authorize_url: u.toString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "start_failed" });
  }
});

/**
 * GET /consent?sid=...
 * Very small page: on "Approve" it redirects to AS /authorize with the client's redirect_uri & code_challenge.
 */
app.get("/consent", (req, res) => {
  const s = SESSION.get(req.query.sid);
  if (!s) return res.status(404).send(html("<h2>Session not found</h2>"));

  const u = new URL(s.as.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", s.client_id);
  u.searchParams.set("redirect_uri", s.redirect_uri);
  u.searchParams.set("scope", s.scope);
  u.searchParams.set("state", s.state);
  if (s.audience) u.searchParams.set("resource", s.audience);
  u.searchParams.set("code_challenge", s.code_challenge);
  u.searchParams.set("code_challenge_method", "S256");

  res.send(
    html(`
      <h2>Approve access?</h2>
      <p>Tool: <b>${s.audience}</b> &nbsp; Scope: <code>${s.scope}</code></p>
      <form action="${u.toString()}" method="get">
        <button type="submit">Approve & continue</button>
      </form>
    `)
  );
});

/**
 * POST /state/verify
 * Body: { state }
 * Returns: { ok:true, ...claims } or { ok:false, error }
 */
app.post("/state/verify", (req, res) => {
  try {
    const { state } = req.body || {};
    const v = verifyState(state);
    if (!v.ok) return res.status(400).json({ ok: false, error: v.err });
    return res.json({ ok: true, ...v.json });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "verify_failed" });
  }
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 9400;
app.listen(PORT, () => {
  console.log(`Gateway (TES) listening on :${PORT}`);
  console.log(`Default RS metadata (fallback): ${DEFAULT_RS_META}`);
});