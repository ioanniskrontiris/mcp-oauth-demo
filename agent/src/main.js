// agent/src/main.js
import { MCPClient } from "./mcpClient.js";

// tiny ANSI helpers (no deps)
const c = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

function card(title, lines = []) {
  const width = Math.max(title.length + 4, ...lines.map((l) => l.length + 4), 26);
  const top = "┌" + "─".repeat(width - 2) + "┐";
  const bot = "└" + "─".repeat(width - 2) + "┘";
  const center = (txt) => {
    const pad = width - 2 - txt.length;
    const left = Math.floor(pad / 2);
    const right = pad - left;
    return "│" + " ".repeat(left) + txt + " ".repeat(right) + "│";
  };
  const line = (txt) => "│ " + txt.padEnd(width - 4) + " │";
  console.log(top);
  console.log(center(c.bold(title)));
  console.log("├" + "─".repeat(width - 2) + "┤");
  if (lines.length === 0) console.log(line(""));
  for (const l of lines) console.log(line(l));
  console.log(bot);
}

async function run() {
  const client = new MCPClient();

  try {
    console.log(c.cyan("🟢 Agent booting…"));

    // === 1) ECHO SESSION ===
    console.log(c.yellow("▶️  ensureSession: echo"));
    await client.ensureSession({
      toolId: "mcp.echo",
      scope: "echo:read",
      context: {},
    });
    console.log(c.green("✅ echo session ok"));

    card("ECHO PASSPORT", [
      "scope: echo:read",
      "capabilities:",
      `  ${c.green("✓")} say hello`,
      `  ${c.red("✗")} list tickets`,
      `  ${c.red("✗")} take payments`,
    ]);

    console.log(c.yellow("▶️  call echo"));
    const echoRes = await client.tools.echo({ msg: "hello" });
    console.log(c.green("✅ echo:"), echoRes);

    // === 2) TICKETS SESSION ===
    console.log(c.yellow("\n▶️  ensureSession: tickets"));
    await client.ensureSession({
      toolId: "tickets.list",
      scope: "tickets:read",
      context: {},
    });
    console.log(c.green("✅ tickets session ok"));

    card("TICKETS PASSPORT", [
      "scope: tickets:read",
      "capabilities:",
      `  ${c.green("✓")} list tickets`,
      `  ${c.red("✗")} take payments`,
    ]);

    console.log(c.yellow("▶️  list tickets"));
    const ticketsRes = await client.tools.tickets();
    const tickets = Array.isArray(ticketsRes?.tickets) ? ticketsRes.tickets : [];
    console.log(c.green(`✅ tickets: ${tickets.length} found`));
    for (const t of tickets) {
      console.log("  •", c.dim(`${t.id}`), "-", t.title || t.summary || "ticket");
    }

    // === 2.5) INTENTIONAL CHEAT ATTEMPT (PROVE LEAST PRIVILEGE) ===
    console.log(c.yellow("\n▶️  (demo) try to pay using ONLY tickets token — should be BLOCKED"));
    try {
      // intentionally DO NOT ensure payments session yet
      await client.tools.pay({ orderId: "order-1001", amount_cents: 1200, merchant_id: "mcp-tix" });
      console.log(c.red("⚠️  Unexpected: payment succeeded without payments:charge scope"));
    } catch (err) {
      console.log(c.green("✅ blocked as expected:"), c.bold(String(err.message || err)));
      card("BLOCKED OPERATION", [
        c.red("Attempt: payments with tickets token"),
        "reason: insufficient_scope / session not suitable",
        "enforced by: Gateway (TES) scope & obligations guard",
      ]);
    }

    // === 3) PAYMENTS SESSION (least privilege + obligations) ===
    const orderId = "order-1001";
    const amount_cents = 1200;
    const merchant_id = "mcp-tix";

    console.log(c.yellow("\n▶️  ensureSession: payments (least privilege)"));
    await client.ensureSession({
      toolId: "payments.charge",
      scope: "payments:charge",
      context: { orderId, amount_cents, merchant: merchant_id },
    });
    console.log(c.green("✅ payment session ok"));

    card("PAYMENTS PASSPORT", [
      "scope: payments:charge",
      "obligations (from ADP):",
      `  - bind_order = ${orderId}`,
      `  - max_amount_cents = 2000 (demo)`,
      `  - merchant_allowlist = [mcp-tix]`,
      `  - ttl = 300s`,
    ]);

    console.log(c.yellow("▶️  pay order"));
    const payRes = await client.tools.pay({ orderId, amount_cents, merchant_id });
    console.log(c.green("✅ payment result:"), payRes);

    console.log(c.bold(c.green("\n🎉 Demo complete — audience & least-privilege enforced at every step")));
  } catch (err) {
    console.error(c.red("❌ Agent error:"), err);
    process.exit(1);
  }
}

run();