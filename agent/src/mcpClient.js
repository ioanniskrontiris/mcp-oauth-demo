// agent/src/mcpClient.js
import fetch from "node-fetch";
import open from "open";

const GW_BASE = process.env.GW_BASE || "http://localhost:9400";

export class MCPClient {
  constructor(opts = {}) {
    this.gwBase = opts.gwBase || GW_BASE;
  }

  async _sessionReady() {
    const r = await fetch(`${this.gwBase}/session/status`);
    if (!r.ok) return false;
    const j = await r.json().catch(() => ({}));
    return !!j.ready;
  }

  async ensureSession() {
    // Fast path
    if (await this._sessionReady()) return;

    // Ask gateway to start an auth session
    const start = await fetch(`${this.gwBase}/session/start`, { method: "POST" });
    if (!start.ok) {
      const t = await start.text().catch(() => "");
      throw new Error(`/session/start failed ${start.status} ${t}`);
    }
    const { authorize_url } = await start.json();
    if (!authorize_url) throw new Error("gateway did not return authorize_url");

    // Send user to the AS (gateway orchestrates)
    await open(authorize_url);

    // Poll until ready
    process.stdout.write("Waiting for gateway session");
    /* eslint-disable no-constant-condition */
    while (true) {
      await new Promise((r) => setTimeout(r, 800));
      if (await this._sessionReady()) break;
      process.stdout.write(".");
    }
    /* eslint-enable no-constant-condition */
    console.log("\n✅ Gateway session ready.");
  }

  tools = {
    echo: async ({ msg }) => {
      const url = new URL("/mcp/echo", this.gwBase);
      url.searchParams.set("msg", String(msg ?? "hello"));

      const r = await fetch(url.toString());
      if (r.status === 401) {
        // Try to parse once
        const ct = r.headers.get("content-type") || "";
        const body = ct.includes("application/json") ? await r.json().catch(() => null) : null;

        // If the gateway says auth is needed, ensure session and retry once
        if (body && body.error === "login_required") {
          await this.ensureSession();
          const retry = await fetch(url.toString());
          if (!retry.ok) {
            const txt = await retry.text().catch(() => "");
            throw new Error(`/mcp/echo failed ${retry.status} ${txt}`);
          }
          return retry.json();
        }

        const text = body ? JSON.stringify(body) : await r.text().catch(() => "");
        throw new Error(`/mcp/echo failed 401 ${text}`);
      }

      if (!r.ok) {
        const text = await r.text().catch(() => "");
        throw new Error(`/mcp/echo failed ${r.status} ${text}`);
      }
      return r.json();
    },
  };
}