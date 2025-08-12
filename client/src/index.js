import fetch from "node-fetch";
import open from "open";

const GW_BASE = process.env.GW_BASE || "http://localhost:9400";

async function callEcho() {
  const r = await fetch(`${GW_BASE}/mcp/echo?msg=hello`);

  if (r.status === 401) {
    // Try to parse JSON once
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      const body = await r.json().catch(() => null);

      if (body && body.error === "login_required") {
        // 1) Ask gateway to start a session
        const start = await fetch(`${GW_BASE}/session/start`, { method: "POST" });
        if (!start.ok) {
          const text = await start.text().catch(() => "");
          throw new Error(`/session/start failed ${start.status} ${text}`);
        }
        const { authorize_url } = await start.json();
        console.log("Opening browser for login/consent…", authorize_url);

        // 2) Send the user to the AS (via the gateway’s orchestrated URL)
        await open(authorize_url);

        // 3) Poll until the gateway says the session is ready
        process.stdout.write("Waiting for gateway session");
        while (true) {
          await new Promise((resolve) => setTimeout(resolve, 800));
          const s = await fetch(`${GW_BASE}/session/status`);
          if (!s.ok) {
            const t = await s.text().catch(() => "");
            throw new Error(`/session/status failed ${s.status} ${t}`);
          }
          const j = await s.json().catch(() => ({}));
          process.stdout.write(".");
          if (j.ready) break;
        }
        console.log("\nReady. Retrying call…");

        // 4) Retry the protected call now that the gateway has a token
        return callEcho();
      }

      // 401 but not login_required → stop here; don't fall through and re-read body
      throw new Error(
        `401 from gateway: ${body ? JSON.stringify(body) : "(no json body)"}`
      );
    } else {
      // Non-JSON 401; read text once and throw
      const text = await r.text().catch(() => "");
      throw new Error(`401 from gateway (non-JSON): ${text}`);
    }
  }

  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`Gateway error ${r.status}: ${text}`);
  }

  // Success path: read body once
  const data = await r.json();
  console.log("MCP echo response:", data);
}

(async () => {
  try {
    await callEcho();
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();