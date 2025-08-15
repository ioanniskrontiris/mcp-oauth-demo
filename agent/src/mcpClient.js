// agent/src/mcpClient.js
import fetch from "node-fetch";
import open from "open";

const GW_BASE = process.env.GW_BASE || "http://localhost:9400";

export class MCPClient {
  async ensureSession({ toolId, scope, context = {} } = {}) {
    if (!toolId || !scope) {
      throw new Error("ensureSession requires { toolId, scope }");
    }

    const start = await fetch(`${GW_BASE}/session/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ toolId, scope, context }),
    });

    // Handle policy denials or other errors with readable messages
    if (start.status === 403) {
      const err = await start.text().catch(() => "");
      throw new Error(`/session/start denied 403 ${err}`);
    }
    if (!start.ok) {
      const text = await start.text().catch(() => "");
      throw new Error(`/session/start failed ${start.status} ${text}`);
    }

    const { authorize_url } = await start.json();

    // If the gateway says there's nothing to open, just verify readiness quickly
    if (!authorize_url) {
      const s = await fetch(`${GW_BASE}/session/status`);
      const j = await s.json().catch(() => ({}));
      if (!j.ready) {
        throw new Error("Gateway reported no authorize_url but session not ready");
      }
      return;
    }

    console.log("Opening browser for login/consent…", authorize_url);
    await open(authorize_url);

    // Poll gateway until token ready (with a soft cap)
    process.stdout.write("Waiting for gateway session");
    const started = Date.now();
    while (true) {
      await new Promise((r) => setTimeout(r, 800));
      const s = await fetch(`${GW_BASE}/session/status`);
      const j = await s.json().catch(() => ({}));
      process.stdout.write(".");
      if (j.ready) break;
      if (Date.now() - started > 120_000) { // 2 minutes safety cap
        throw new Error("Timed out waiting for gateway session");
      }
    }
    console.log("\n✅ Gateway session ready.");
  }

  tools = {
    // GET /mcp/echo?q=...
    echo: async ({ msg }) => {
      const r = await fetch(`${GW_BASE}/mcp/echo?q=${encodeURIComponent(msg)}`);
      if (r.status === 401) {
        const t = await r.text().catch(() => "");
        throw new Error(`/mcp/echo failed 401 ${t}`);
      }
      if (!r.ok) throw new Error(`/mcp/echo failed ${r.status}`);
      return r.json();
    },

    // GET /mcp/tickets
    tickets: async () => {
      const r = await fetch(`${GW_BASE}/mcp/tickets`);
      if (r.status === 401) {
        const t = await r.text().catch(() => "");
        throw new Error(`/mcp/tickets failed 401 ${t}`);
      }
      if (!r.ok) throw new Error(`/mcp/tickets failed ${r.status}`);
      return r.json();
    },

    // POST /mcp/pay  { orderId, amount_cents, merchant_id }
    pay: async ({ orderId, amount_cents, merchant_id }) => {
      const r = await fetch(`${GW_BASE}/mcp/pay`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ orderId, amount_cents, merchant_id }),
      });
      if (r.status === 401) {
        const t = await r.text().catch(() => "");
        throw new Error(`/mcp/pay failed 401 ${t}`);
      }
      if (!r.ok) {
        const t = await r.text().catch(() => "");
        throw new Error(`/mcp/pay failed ${r.status} ${t}`);
      }
      return r.json();
    },
  };

    // --- Debug helpers (use existing gateway endpoints) ---
  async currentToken() {
    const r = await fetch(`${GW_BASE}/debug/token`);
    if (!r.ok) return null;
    return r.json().catch(() => null); // { token, header, payload, has_signature }
  }

  async introspect() {
    const r = await fetch(`${GW_BASE}/debug/introspect`);
    if (!r.ok) return null;
    return r.json().catch(() => null); // { ok, status, as_introspection: {...} }
  }
}