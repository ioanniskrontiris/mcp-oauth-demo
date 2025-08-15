// server/src/index.js
//
// What this file does now:
//  • Serves Protected Resource Metadata (RFC 9728) at /.well-known/oauth-protected-resource
//    and advertises the new scope "payments:charge".
//  • Returns 401 with WWW-Authenticate containing resource_metadata (for discovery).
//  • Introspects access tokens at your AS and enforces audience + scope.
//  • Keeps tickets endpoints (scope: tickets:read).
//  • Adds a minimal Orders API:
//      - POST /orders                 (auth; create pending order)
//      - GET  /orders/:id             (auth; fetch order)
//      - POST /orders/:id/pay         (requires scope: payments:charge; flips status to "paid")
//
// Notes:
//  - Fine-grained checks (amount caps, merchant allowlists) will be enforced by the Gateway (TES)
//    in Phase 3 via obligations. RS keeps a clean OAuth scope gate.
//

import express from "express";
import morgan from "morgan";
import cors from "cors";
import { listTickets, getTicket } from "./ticketsRepo.js";

const app = express();

app.use(cors());
app.use(morgan("dev"));
app.use(express.json({ limit: "256kb" }));

/**
 * Config – points at your AS and identifies this RS ("resource"/audience)
 */
const INTROSPECT_URL =
  process.env.AUTH_INTROSPECT_URL || "http://localhost:9092/introspect";
const AS_METADATA_URL =
  process.env.AS_METADATA_URL ||
  "http://localhost:9092/.well-known/oauth-authorization-server";
const EXPECTED_AUD = process.env.EXPECTED_AUD || "mcp-demo"; // RS identifier (audience)

/**
 * Protected Resource Metadata (RFC 9728)
 */
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: EXPECTED_AUD,
    authorization_servers: [AS_METADATA_URL],
    // Hints for clients/UIs (not normative)
    scopes_supported: ["echo:read", "tickets:read", "payments:charge"],
    introspection_endpoint: INTROSPECT_URL
  });
});

/**
 * Helper: attach a standards-friendly 401 with WWW-Authenticate
 * Includes resource_metadata so MCP clients can discover PRM after unauthenticated call.
 */
function unauthorized(res, details) {
  const prm = new URL(
    "/.well-known/oauth-protected-resource",
    `http://localhost:${process.env.PORT || 9091}`
  ).toString();

  const header = [
    `Bearer realm="${EXPECTED_AUD}"`,
    `error="invalid_token"`,
    details ? `error_description="${String(details).replace(/"/g, "'")}"` : null,
    `resource_metadata="${prm}"`
  ]
    .filter(Boolean)
    .join(", ");

  res.setHeader("WWW-Authenticate", header);
  return res.status(401);
}

/**
 * Helper: parse bearer
 */
function parseBearer(req) {
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}

/**
 * Helper: check space-delimited scope list "a b c"
 */
function hasScope(introspection, needed) {
  const set = new Set((introspection.scope || "").split(/\s+/).filter(Boolean));
  return needed.split(/\s+/).every((s) => set.has(s));
}

/**
 * Middleware factory: introspect token and attach req.auth.
 */
async function requireAuth(requiredScope) {
  return async (req, res, next) => {
    try {
      const token = parseBearer(req);
      if (!token) {
        return unauthorized(res, "missing bearer").json({
          error: "invalid_token",
          error_description: "missing bearer"
        });
      }

      const body = new URLSearchParams({ token });
      const r = await fetch(INTROSPECT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      if (!r.ok) {
        const text = await r.text().catch(() => "");
        return unauthorized(res, `AS ${r.status}`).json({
          error: "introspection_failed",
          error_description: `AS returned ${r.status}: ${text}`
        });
      }

      const data = await r.json();

      if (!data.active) {
        return unauthorized(res, "inactive token").json({ error: "inactive_token" });
      }

      if (data.aud && data.aud !== EXPECTED_AUD) {
        return unauthorized(res, "bad audience").json({
          error: "bad_audience",
          expected: EXPECTED_AUD,
          got: data.aud
        });
      }

      if (requiredScope && !hasScope(data, requiredScope)) {
        return res
          .status(403)
          .json({ error: "insufficient_scope", required: requiredScope });
      }

      req.auth = data; // {sub, scope, aud, iat, exp, ...}
      next();
    } catch (err) {
      console.error("auth error", err);
      return unauthorized(res, "auth error").json({ error: "auth_error" });
    }
  };
}

/**
 * Optional separate scope guard if you want to compose requireAuth + requireScope
 */
function requireScope(scope) {
  return (req, res, next) => {
    const scopes = (req.auth?.scope || "").split(" ").filter(Boolean);
    if (!scopes.includes(scope)) {
      return res.status(403).json({ error: "insufficient_scope", required: scope });
    }
    next();
  };
}

// ------------------------
// Tickets (existing demo)
// ------------------------
app.get("/tickets", await requireAuth("tickets:read"), (_req, res) => {
  res.json({ tickets: listTickets() });
});

app.get("/tickets/:id", await requireAuth("tickets:read"), (req, res) => {
  const t = getTicket(req.params.id);
  if (!t) return res.status(404).json({ error: "not_found" });
  res.json(t);
});

// ------------------------
// Orders (new, minimal)
// ------------------------
/**
 * In-memory order store for the demo.
 * In real life: DB with proper idempotency, currency/amount checks, ledger, etc.
 */
// --- Demo orders store (in-memory) ---
const ORDERS = new Map([
  ["order-1001", {
    id: "order-1001",
    amount_cents: 1200,
    currency: "USD",
    merchant_id: "mcp-tix",
    status: "created",
    created_at: Date.now()
  }],
]);

app.get("/orders/:id", (req, res) => {
  const o = ORDERS.get(String(req.params.id));
  if (!o) return res.status(404).json({ error: "order_not_found" });
  res.json(o);
});

app.post("/orders", express.json(), (req, res) => {
  const { id, amount_cents, currency = "USD", merchant_id = "mcp-tix" } = req.body || {};
  if (!id || !Number.isInteger(amount_cents)) {
    return res.status(400).json({ error: "invalid_request" });
  }
  if (ORDERS.has(id)) return res.status(409).json({ error: "order_exists" });
  const o = { id, amount_cents, currency, merchant_id, status: "created", created_at: Date.now() };
  ORDERS.set(id, o);
  res.status(201).json(o);
});
/**
 * POST /orders
 * Create a pending order the agent intends to pay.
 * Auth required (any authenticated scope is fine; we reuse tickets:read here).
 */
app.post("/orders", await requireAuth("tickets:read"), (req, res) => {
  const {
    amount_cents,
    currency = "EUR",
    merchant = "AcmeTickets",
    items = []
  } = req.body || {};

  const amt = Number(amount_cents);
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "invalid_amount" });
  }

  const id = String(NEXT_ORDER_ID++);
  const order = {
    id,
    amount_cents: amt,
    currency: String(currency || "EUR"),
    merchant: String(merchant || "AcmeTickets"),
    items: Array.isArray(items) ? items : [],
    status: "created",
    created_by: req.auth?.sub || "anonymous"
  };
  ORDERS.set(id, order);
  res.status(201).json(order);
});

/**
 * GET /orders/:id
 * Fetch an order (auth required).
 */
app.get("/orders/:id", await requireAuth("tickets:read"), (req, res) => {
  const o = ORDERS.get(String(req.params.id));
  if (!o) return res.status(404).json({ error: "order_not_found" });
  res.json(o);
});

/**
 * POST /orders/:id/pay
 * Charge the order. Requires scope payments:charge.
 * For now RS only checks scope + order status. (TES will enforce obligations later.)
 */
app.post(
  "/orders/:id/pay",
  await requireAuth("payments:charge"),
  (req, res) => {
    const id = String(req.params.id);
    const o = ORDERS.get(id);
    if (!o) return res.status(404).json({ error: "order_not_found" });
    if (o.status !== "created") {
      return res.status(409).json({ error: "invalid_state", status: o.status });
    }

    // (In Phase 3, TES will have enforced: correct order id, amount caps, merchant allowlist, TTL, etc.)
    o.status = "paid";
    o.paid_at = Date.now();
    o.paid_by = req.auth?.sub || "unknown";

    return res.json({
      paymentId: `pay_${id}_${o.paid_at}`,
      status: "succeeded",
      order: o
    });
  }
);

app.get("/demo", (_req, res) => {
  res.type("html").send(`
  <!doctype html>
  <meta charset="utf-8"/>
  <title>Ticketing RS Demo</title>
  <style>body{font:16px/1.5 system-ui;margin:2rem} code{background:#f6f8fa;padding:2px 6px;border-radius:4px}</style>
  <h1>Ticketing RS Demo</h1>
  <p>This page shows what's on the RS side.</p>
  <h2>Tickets</h2>
  <pre id="tickets"></pre>
  <h2>Orders</h2>
  <pre id="orders"></pre>
  <script>
    Promise.all([
      fetch('/tickets', { headers: { 'Accept':'application/json' } }).then(r=>r.json()).catch(()=>({})),
      fetch('/orders', { headers: { 'Accept':'application/json' } }).then(r=>r.json()).catch(()=>({}))
    ]).then(([t,o])=>{
      tickets.textContent = JSON.stringify(t, null, 2);
      orders.textContent = JSON.stringify(o, null, 2);
    });
  </script>
  `);
});
// ------------------------
// MCP-ish echo (unchanged)
// ------------------------
app.get("/mcp/echo", await requireAuth("echo:read"), (req, res) => {
  const q = req.query.q ?? req.query.msg ?? "hello";
  res.json({
    ok: true,
    echo: String(q),
    user: req.auth?.sub,
    scope: req.auth?.scope
  });
});

// ------------------------
// Health
// ------------------------
app.get("/healthz", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 9091;
app.listen(PORT, () => {
  console.log(`Resource Server listening on :${PORT}`);
  console.log(`Using introspection: ${INTROSPECT_URL}`);
  console.log(
    `Protected Resource Metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`
  );
});