// server/src/index.js
import express from "express";
import morgan from "morgan";
import cors from "cors";
import { listTickets, getTicket } from "./ticketsRepo.js";

const app = express();

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

/**
 * Config – point to your AS and identify this RS ("resource" / audience)
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
    scopes_supported: ["echo:read", "tickets:read"],
    introspection_endpoint: INTROSPECT_URL,
  });
});

/**
 * Helper: attach a standards-friendly 401 with WWW-Authenticate
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
    `resource_metadata="${prm}"`,
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
 * Helper: check scope list "a b c"
 */
function hasScope(introspection, needed) {
  const set = new Set((introspection.scope || "").split(/\s+/).filter(Boolean));
  return needed.split(/\s+/).every((s) => set.has(s));
}

/**
 * Middleware factory: introspect token and attach req.auth
 */
function requireAuth(requiredScope) {
  return async (req, res, next) => {
    try {
      const token = parseBearer(req);
      if (!token) {
        return unauthorized(res, "missing bearer").json({
          error: "invalid_token",
          error_description: "missing bearer",
        });
      }

      const body = new URLSearchParams({ token });
      const r = await fetch(INTROSPECT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      if (!r.ok) {
        const text = await r.text();
        return unauthorized(res, `AS ${r.status}`).json({
          error: "introspection_failed",
          error_description: `AS returned ${r.status}: ${text}`,
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
          got: data.aud,
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
 * Optional separate scope guard (if you ever compose middlewares)
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

// --- Tickets endpoints (auth + scope) ---
app.get("/tickets", requireAuth("tickets:read"), (req, res) => {
  res.json({ tickets: listTickets() });
});

app.get("/tickets/:id", requireAuth("tickets:read"), (req, res) => {
  const t = getTicket(req.params.id);
  if (!t) return res.status(404).json({ error: "not_found" });
  res.json(t);
});

/**
 * Protected MCP-ish echo (needs echo:read)
 */
app.get("/mcp/echo", requireAuth("echo:read"), (req, res) => {
  const q = req.query.q || "hello";
  res.json({
    ok: true,
    echo: String(q),
    user: req.auth?.sub,
    scope: req.auth?.scope,
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
  console.log(
    `Protected Resource Metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`
  );
});