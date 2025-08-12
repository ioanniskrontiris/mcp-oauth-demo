// server/src/index.js
import { loadEnv, cfg } from "../shared/config.js";
loadEnv();
console.log("[MCP server] mode =>", cfg());

import express from "express";
import morgan from "morgan";
import cors from "cors";
// server/src/index.js
// server/src/index.js
import { listTickets, getTicket } from "./ticketsRepo.js";



const app = express();

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

/**
 * Config – point to your AS
 */
const INTROSPECT_URL =
  process.env.AUTH_INTROSPECT_URL || "http://localhost:9092/introspect";
const EXPECTED_AUD = process.env.EXPECTED_AUD || "mcp-demo";


// --- scope guard (you likely already have this in the file) ---
function requireScope(scope) {
  return (req, res, next) => {
    const scopes = (req.auth?.scope || "").split(" ").filter(Boolean);
    if (!scopes.includes(scope)) {
      return res.status(403).json({ error: "insufficient_scope", required: scope });
    }
    next();
  };
}

// --- Tickets endpoints ---
app.get("/tickets", requireScope("tickets:read"), (req, res) => {
  res.json({ tickets: listTickets() });
});

app.get("/tickets/:id", requireScope("tickets:read"), (req, res) => {
  const t = getTicket(req.params.id);
  if (!t) return res.status(404).json({ error: "not_found" });
  res.json(t);
});


/**
 * Helper: parse bearer
 */
function parseBearer(req) {
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}

/**
 * Helper: check scope list "a b c"
 */
function hasScope(introspection, needed) {
  const set = new Set((introspection.scope || "").split(/\s+/).filter(Boolean));
  return needed.split(/\s+/).every(s => set.has(s));
}

/**
 * Middleware: introspect and attach req.auth
 */
async function requireAuth(requiredScope) {
  return async (req, res, next) => {
    try {
      const token = parseBearer(req);
      if (!token) {
        return res
          .status(401)
          .json({ error: "invalid_token", error_description: "missing bearer" });
      }

      const body = new URLSearchParams({ token });
      const r = await fetch(INTROSPECT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      if (!r.ok) {
        const text = await r.text();
        return res.status(401).json({
          error: "introspection_failed",
          error_description: `AS returned ${r.status}: ${text}`
        });
      }

      const data = await r.json();

      if (!data.active) {
        return res.status(401).json({ error: "inactive_token" });
      }

      if (data.aud && data.aud !== EXPECTED_AUD) {
        return res
          .status(401)
          .json({ error: "bad_audience", expected: EXPECTED_AUD, got: data.aud });
      }

      if (requiredScope && !hasScope(data, requiredScope)) {
        return res.status(403).json({ error: "insufficient_scope", required: requiredScope });
      }

      // success – attach to request for handlers
      req.auth = data; // {sub, scope, aud, iat, exp, ...}
      next();
    } catch (err) {
      console.error("auth error", err);
      res.status(401).json({ error: "auth_error" });
    }
  };
}

/**
 * Protected MCP-ish echo (needs echo:read)
 */
app.get("/mcp/echo", await requireAuth("echo:read"), (req, res) => {
  const q = req.query.q || "hello";
  res.json({
    ok: true,
    echo: String(q),
    user: req.auth?.sub,
    scope: req.auth?.scope
  });
});

/**
 * Health
 */
app.get("/healthz", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 9091;
app.listen(PORT, () => {
  console.log(`Resource Server listening on :${PORT}`);
  console.log(`Using introspection: ${INTROSPECT_URL}`);
});