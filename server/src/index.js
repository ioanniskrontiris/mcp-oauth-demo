// server/src/index.js

/*
	•	Serves Protected Resource Metadata at /.well-known/oauth-protected-resource with an authorization_servers array pointing to your AS metadata URL.
	•	Emits a WWW-Authenticate header on 401 that includes a resource_metadata parameter (so MCP clients can discover metadata after an unauthenticated call).
	•	Keeps your introspection flow and scope checks.
	•	Uses the EXPECTED_AUD as the RS identifier and advertises it in the metadata so clients can pass it as the OAuth resource indicator (which your AS already respects by minting aud).
*/

/*
1.	401 with WWW-Authenticate
Any unauthenticated call returns WWW-Authenticate: Bearer ... resource_metadata="http://localhost:9091/.well-known/oauth-protected-resource". Your MCP client can read that header, fetch the PRM, then learn the authorization server(s) to contact.
2.	Protected Resource Metadata (RFC 9728)
The RS publishes:
	•	authorization_servers: [ "http://localhost:9092/.well-known/oauth-authorization-server" ]
	•	resource: "mcp-demo" (the identifier clients pass as OAuth resource, which your AS now uses to set aud)
3.	End‑to‑end audience binding
Client learns resource → sends resource in /authorize and /token → AS mints aud → RS enforces aud === EXPECTED_AUD.
*/

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
 * This tells clients which authorization server(s) protect this resource
 * and what identifier ("resource") to use as an audience.
 */
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: EXPECTED_AUD,
    authorization_servers: [AS_METADATA_URL],
    // Nice-to-have hints (non-normative but useful for clients/UI)
    scopes_supported: ["echo:read", "tickets:read"],
    introspection_endpoint: INTROSPECT_URL,
  });
});

/**
 * Helper: attach a standards-friendly 401 with WWW-Authenticate
 * We include resource_metadata so MCP clients can discover the PRM URL
 * immediately after an unauthenticated request.
 */
function unauthorized(res, details) {
  const prm = new URL(
    "/.well-known/oauth-protected-resource",
    `http://localhost:${process.env.PORT || 9091}`
  ).toString();

  // Example per our MCP doc: clients parse resource_metadata from header.
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
 * Middleware factory: introspect token and attach req.auth.
 * If `requiredScope` is passed, verify scopes here; otherwise handlers can check later.
 */
async function requireAuth(requiredScope) {
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

      // success – attach to request for handlers
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

// --- Tickets endpoints (auth + scope) ---
app.get("/tickets", await requireAuth("tickets:read"), (req, res) => {
  res.json({ tickets: listTickets() });
});

app.get("/tickets/:id", await requireAuth("tickets:read"), (req, res) => {
  const t = getTicket(req.params.id);
  if (!t) return res.status(404).json({ error: "not_found" });
  res.json(t);
});

/**
 * Protected MCP-ish echo (needs echo:read)
 */
app.get("/mcp/echo", await requireAuth("echo:read"), (req, res) => {
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