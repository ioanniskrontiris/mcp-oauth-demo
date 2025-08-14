// ADP/src/index.js
import express from "express";
import morgan from "morgan";
import cors from "cors";
import crypto from "node:crypto";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

/**
 * In-memory Delegation Store
 * Keyed by `${subject}|${agentId}|${toolId}`
 * Each record:
 *  {
 *    id,           // stable identifier
 *    subject,      // user
 *    agentId,      // agent instance / client
 *    toolId,       // MCP tool identifier
 *    scopes,       // array<string>
 *    issued_at,    // unix seconds
 *    not_after     // unix seconds (expiry)
 *  }
 */
const store = new Map();
const key = (subject, agentId, toolId) => `${subject}|${agentId}|${toolId}`;
const nowSec = () => Math.floor(Date.now() / 1000);

// --- Seed a default delegation so your current demo keeps working ---
seed({
  subject: "user-123",
  agentId: "agent-demo",
  toolId: "mcp.echo",
  scopes: ["echo:read"],
  // year 3000
  not_after: 32503680000
});

function seed({ subject, agentId, toolId, scopes, not_after }) {
  const id = `del-${crypto.randomBytes(8).toString("hex")}`;
  const rec = {
    id,
    subject,
    agentId,
    toolId,
    scopes: Array.from(new Set(scopes || [])).sort(),
    issued_at: nowSec(),
    not_after: Number(not_after) || (nowSec() + 3600) // default 1h if missing
  };
  store.set(key(subject, agentId, toolId), rec);
  return rec;
}

function getDelegation(subject, agentId, toolId) {
  const rec = store.get(key(subject, agentId, toolId));
  if (!rec) return null;
  if (rec.not_after <= nowSec()) return null; // expired
  return rec;
}

// --------------------------
// Delegations Management API
// --------------------------

/**
 * GET /delegations
 * Optional filters: ?subject=&agentId=&toolId=
 */
app.get("/delegations", (req, res) => {
  const { subject, agentId, toolId } = req.query || {};
  const list = Array.from(store.values()).filter(d => {
    if (subject && d.subject !== subject) return false;
    if (agentId && d.agentId !== agentId) return false;
    if (toolId && d.toolId !== toolId) return false;
    return true;
  });
  res.json({ delegations: list });
});

/**
 * POST /delegations
 * Body: { subject, agentId, toolId, scopes: string[], not_after?: number }
 * Upserts by (subject,agentId,toolId)
 */
app.post("/delegations", (req, res) => {
  const { subject, agentId, toolId, scopes, not_after } = req.body || {};
  if (!subject || !agentId || !toolId) {
    return res.status(400).json({ error: "invalid_request", error_description: "subject, agentId, toolId are required" });
  }
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return res.status(400).json({ error: "invalid_request", error_description: "scopes (array) is required" });
  }
  const existing = store.get(key(subject, agentId, toolId));
  if (existing) {
    existing.scopes = Array.from(new Set(scopes)).sort();
    existing.not_after = Number(not_after) || existing.not_after || (nowSec() + 3600);
    return res.status(200).json({ updated: existing });
  }
  const created = seed({ subject, agentId, toolId, scopes, not_after });
  return res.status(201).json({ created });
});

/**
 * DELETE /delegations/:id
 * Deletes by record id (not by composite key).
 */
app.delete("/delegations/:id", (req, res) => {
  const { id } = req.params;
  let removed = false;
  for (const [k, v] of store.entries()) {
    if (v.id === id) {
      store.delete(k);
      removed = true;
      break;
    }
  }
  if (!removed) return res.status(404).json({ error: "not_found" });
  res.json({ ok: true });
});

// ---------------------------------
// Policy Evaluation & Consent (MVP)
// ---------------------------------

/**
 * POST /evaluate
 * Input:  { subject, agentId, toolId, audience, requested_scopes: string[] }
 * Output: { allow: boolean, scopes: string[], obligations?: object }
 *
 * Logic:
 *  - If a non-expired delegation exists → allow and return intersection(requested, delegated)
 *    (fallback to delegated scopes if intersection empty).
 *  - If none exists → allow (for now) but only the requested scopes (you can tighten later).
 */
app.post("/evaluate", (req, res) => {
  const {
    subject = "user-123",
    agentId = "agent-demo",
    toolId  = "mcp.echo",
    audience,
    requested_scopes = []
  } = req.body || {};

  const del = getDelegation(subject, agentId, toolId);

  let allowedScopes = requested_scopes;
  if (del) {
    const delegated = new Set(del.scopes);
    const inter = requested_scopes.filter(s => delegated.has(s));
    allowedScopes = inter.length > 0 ? inter : del.scopes.slice();
  } // else keep requested_scopes as-is (current permissive mode)

  return res.json({
    allow: true,
    scopes: allowedScopes,
    obligations: {} // placeholder for future policy outputs
  });
});

/**
 * POST /consent
 * Input:  { subject, agentId, toolId, audience, scopes: string[], explicit?: boolean }
 * Output: { approved: boolean, record_id?: string, reason?: string }
 *
 * Logic:
 *  - If delegation exists and covers ALL scopes → auto-approve.
 *  - Else if explicit === true → approve and “record” it (return record_id).
 *  - Else → approved:false, reason:"explicit_required".
 */
app.post("/consent", (req, res) => {
  const {
    subject = "user-123",
    agentId = "agent-demo",
    toolId  = "mcp.echo",
    audience,
    scopes = [],
    explicit = false
  } = req.body || {};

  const del = getDelegation(subject, agentId, toolId);
  if (del) {
    const delegated = new Set(del.scopes);
    const allCovered = scopes.every(s => delegated.has(s));
    if (allCovered) {
      return res.json({ approved: true, record_id: `auto-${Date.now()}` });
    }
  }

  if (explicit) {
    return res.json({ approved: true, record_id: `exp-${Date.now()}` });
  }

  return res.json({ approved: false, reason: "explicit_required" });
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));

const PORT = process.env.ADP_PORT || 9500;
app.listen(PORT, () => {
  console.log(`ADP (Client Authorizer) listening on :${PORT}`);
});