import express from "express";
import morgan from "morgan";
import cors from "cors";
import fs from "node:fs/promises";
import path from "node:path";
import initSqlJs from "sql.js";
import { importJWK, jwtVerify } from "jose";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json({ limit: "512kb" }));

// ---------- DB bootstrap (sql.js; pure JS, no native builds) ----------
const DATA_DIR = path.resolve(process.cwd(), "data");
const DB_PATH  = path.join(DATA_DIR, "adp.sqlite");

let SQL; // sql.js module
let db;  // Database instance

function nowSec() { return Math.floor(Date.now() / 1000); }

async function ensureDir(p) {
  try { await fs.mkdir(p, { recursive: true }); } catch {}
}

async function saveDb() {
  const data = db.export(); // Uint8Array
  await ensureDir(DATA_DIR);
  await fs.writeFile(DB_PATH, data);
}

async function openDb() {
  SQL = await initSqlJs(); // loads WASM
  let buf = null;
  try { buf = await fs.readFile(DB_PATH); } catch {}
  db = new SQL.Database(buf || undefined);

  // Base table (unchanged)
  db.run(`
    CREATE TABLE IF NOT EXISTS delegations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject TEXT NOT NULL,
      agentId TEXT NOT NULL,
      toolId TEXT NOT NULL,
      scopes TEXT NOT NULL,
      not_after INTEGER NOT NULL,
      issuer TEXT,
      jws TEXT,
      inserted_at INTEGER NOT NULL
    )
  `);

  // ✅ Only add 'constraints' column if it's missing
  const ti = db.prepare(`PRAGMA table_info(delegations)`);
  let hasConstraints = false;
  try {
    while (ti.step()) {
      const row = ti.getAsObject();
      if (String(row.name) === "constraints") { hasConstraints = true; break; }
    }
  } finally {
    ti.free();
  }
  if (!hasConstraints) {
    db.run(`ALTER TABLE delegations ADD COLUMN constraints TEXT`);
  }

  // Indexes
  db.run(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_delegations_key
      ON delegations(subject, agentId, toolId)
  `);
  db.run(`
    CREATE INDEX IF NOT EXISTS ix_delegations_not_after
      ON delegations(not_after)
  `);

  await saveDb();
}

function selectOne(sql, params = []) {
  const stmt = db.prepare(sql);
  try {
    stmt.bind(params);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return null;
  } catch (e) {
    stmt.free();
    throw e;
  }
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  try {
    stmt.bind(params);
    stmt.step();
    stmt.free();
  } catch (e) {
    stmt.free();
    throw e;
  }
}

// ---------- POST /delegations  (seed a signed credential) ----------
// Body:
// { "jws": "<compact JWS>", "public_jwk": { ... } }
// Payload must include: { subject, agentId, toolId, scopes: string[], not_after?: number, exp?: number, iss? }
app.post("/delegations", async (req, res) => {
  try {
    const { jws, public_jwk } = req.body || {};
    if (!jws || !public_jwk) {
      return res.status(400).json({ error: "invalid_request", detail: "jws and public_jwk required" });
    }

    // Verify signature and parse payload
    const key = await importJWK(public_jwk);
    const { payload } = await jwtVerify(jws, key, {
      algorithms: ["EdDSA", "ES256", "RS256"],
      clockTolerance: "5s"
    });

    const {
      subject, agentId, toolId, scopes,
      not_after: notAfterFromPayload,  // preferred explicit field
      iss, exp,                        // fallback if not_after absent
      constraints                      // OPTIONAL policy constraints
    } = payload || {};

    // Basic required fields
    if (typeof subject !== "string" || !subject ||
        typeof agentId !== "string" || !agentId ||
        typeof toolId  !== "string" || !toolId  ||
        !Array.isArray(scopes) || scopes.some(s => typeof s !== "string" || !s)) {
      return res.status(400).json({ error: "invalid_credential_payload" });
    }

    // Resolve expiry: prefer not_after; else exp
    const not_after = Number.isFinite(notAfterFromPayload) ? notAfterFromPayload
                     : (Number.isFinite(exp) ? exp : undefined);
    if (!Number.isFinite(not_after)) {
      return res.status(400).json({ error: "missing_not_after" });
    }
    if (not_after <= nowSec()) {
      return res.status(400).json({ error: "expired_credential" });
    }

    // Validate constraints (very lightweight; extend as you add policies)
    let constraintsJson = null;
    if (constraints !== undefined) {
      if (constraints && typeof constraints === "object" && !Array.isArray(constraints)) {
        // Example fields you may support now:
        // - max_amount_cents: integer > 0
        // - merchants: array of strings
        const c = { ...constraints };
        if (c.max_amount_cents !== undefined) {
          const n = Number(c.max_amount_cents);
          if (!Number.isInteger(n) || n <= 0) {
            return res.status(400).json({ error: "invalid_constraints", detail: "max_amount_cents must be positive integer" });
          }
          c.max_amount_cents = n;
        }
        if (c.merchants !== undefined) {
          if (!Array.isArray(c.merchants) || c.merchants.some(m => typeof m !== "string" || !m)) {
            return res.status(400).json({ error: "invalid_constraints", detail: "merchants must be array of non-empty strings" });
          }
        }
        // You can add more fields later (e.g., bind_order, currency allowlist, ttl, etc.)
        constraintsJson = JSON.stringify(c);
      } else if (constraints === null) {
        constraintsJson = null;
      } else {
        return res.status(400).json({ error: "invalid_constraints", detail: "constraints must be an object or null" });
      }
    }

    // Upsert for (subject, agentId, toolId)
    const existing = selectOne(
      `SELECT id FROM delegations WHERE subject=? AND agentId=? AND toolId=?`,
      [subject, agentId, toolId]
    );

    if (existing) {
      run(
        `UPDATE delegations
           SET scopes=?, not_after=?, issuer=?, jws=?, inserted_at=?, constraints=?
         WHERE id=?`,
        [JSON.stringify(scopes), not_after, iss || null, jws, nowSec(), constraintsJson, existing.id]
      );
    } else {
      run(
        `INSERT INTO delegations (subject, agentId, toolId, scopes, not_after, issuer, jws, inserted_at, constraints)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [subject, agentId, toolId, JSON.stringify(scopes), not_after, iss || null, jws, nowSec(), constraintsJson]
      );
    }

    await saveDb();
    return res.status(201).json({
      ok: true,
      subject, agentId, toolId, scopes, not_after,
      constraints: constraintsJson ? JSON.parse(constraintsJson) : null
    });
  } catch (e) {
    console.error("POST /delegations error:", e);
    return res.status(400).json({ error: "bad_delegation", detail: String(e?.message || e) });
  }
});

app.post("/evaluate", (req, res) => {
  const {
    subject = "user-123",
    agentId,
    toolId,
    audience,                   // kept for future policy
    requested_scopes = [],
    context = {}                // e.g., { orderId, amount_cents, currency, merchant }
  } = req.body || {};

  // Normalize requested scopes (array of unique strings)
  const reqScopes = Array.isArray(requested_scopes)
    ? [...new Set(requested_scopes.filter(s => typeof s === "string" && s.trim()))]
    : [];

  // Pull any stored delegation
  const row = selectOne(
    `SELECT * FROM delegations
       WHERE subject=? AND agentId=? AND toolId=? AND not_after > ?`,
    [subject, agentId, toolId, nowSec()]
  );

  // Default decision (DEMO): allow even without delegation.
  // Flip this to false when you’re ready to require explicit delegation.
  const DEMO_ALLOW_WITHOUT_DELEGATION = true;

  let allow = !!row || DEMO_ALLOW_WITHOUT_DELEGATION;
  let allowedScopes = reqScopes.slice();
  let obligations = {};

  if (row) {
    // Intersect requested scopes with delegated scopes
    let delegatedScopes = [];
    try { delegatedScopes = JSON.parse(row.scopes || "[]"); } catch {}
    const delegated = new Set(
      Array.isArray(delegatedScopes) ? delegatedScopes.filter(s => typeof s === "string" && s) : []
    );

    const intersection = reqScopes.filter(s => delegated.has(s));
    // Choose a clear behavior: either deny if empty, or fall back.
    if (intersection.length > 0) {
      allowedScopes = intersection;
    } else {
      // For demo: fall back to delegated scopes; otherwise you might set allow=false
      allowedScopes = [...delegated];
      if (allowedScopes.length === 0) {
        allow = false; // nothing usable
      }
    }

    // Parse constraints (defensively)
    let C = {};
    try { C = row.constraints ? JSON.parse(row.constraints) : {}; } catch {}

    // Normalize context inputs
    const amount_cents = Number.isFinite(context.amount_cents) ? Math.trunc(context.amount_cents) : undefined;
    const merchant      = typeof context.merchant === "string" ? context.merchant : undefined;

    // Enforce constraints: amount cap and merchant allowlist
    const maxAmountCents = Number.isInteger(C.max_amount_cents) ? C.max_amount_cents : undefined;
    const allowedMerchants = Array.isArray(C.merchants)
      ? C.merchants.filter(m => typeof m === "string" && m)
      : undefined;

    if (allow && typeof amount_cents === "number" && typeof maxAmountCents === "number" && amount_cents > maxAmountCents) {
      allow = false;
    }
    if (allow && merchant && allowedMerchants && !allowedMerchants.includes(merchant)) {
      allow = false;
    }

    if (allow) {
      obligations = {};
      if (context.orderId) obligations.bind_order = String(context.orderId);
      if (typeof maxAmountCents === "number") obligations.max_amount_cents = maxAmountCents;
      if (allowedMerchants) obligations.merchant_allowlist = allowedMerchants;
      obligations.ttl = 900; // short demo window
    }
  } else {
    // No delegation case (demo behavior)
    if (DEMO_ALLOW_WITHOUT_DELEGATION) {
      obligations = {};
      if (context.orderId) obligations.bind_order = String(context.orderId);
      obligations.ttl = 900;
    } else {
      allow = false;
      allowedScopes = [];
      obligations = {};
    }
  }

  return res.json({
    allow,
    scopes: allowedScopes,
    obligations,
    as_hints: []
  });
});

// ---------- POST /consent  ----------
app.post("/consent", (req, res) => {
  const {
    subject = "user-123",
    agentId,
    toolId,
    audience,
    scopes = [],
    explicit = false
  } = req.body || {};

  const reqScopes = Array.isArray(scopes)
    ? scopes.filter(s => typeof s === "string" && s)
    : [];

  const row = selectOne(
    `SELECT * FROM delegations
       WHERE subject=? AND agentId=? AND toolId=? AND not_after > ?`,
    [subject, agentId, toolId, nowSec()]
  );

  if (row) {
    let delegatedArr = [];
    try { delegatedArr = JSON.parse(row.scopes || "[]"); } catch {}
    const delegated = new Set(
      Array.isArray(delegatedArr) ? delegatedArr.filter(s => typeof s === "string" && s) : []
    );
    const allCovered = reqScopes.every(s => delegated.has(s));
    if (allCovered) {
      return res.json({ allow: true, record_id: `auto-${Date.now()}` });
    }
    // else fall through to explicit branch
  }

  if (explicit) {
    return res.json({ allow: true, record_id: `exp-${Date.now()}` });
  }

  return res.json({ allow: false, reason: "explicit_required" });
});

// ---------- Dev helpers ----------
app.get("/delegations", (_req, res) => {
  const stmt = db.prepare(`SELECT id, subject, agentId, toolId, scopes, not_after, issuer, inserted_at
                           FROM delegations ORDER BY inserted_at DESC`);
  const rows = [];
  try {
    while (stmt.step()) rows.push(stmt.getAsObject());
  } finally {
    stmt.free();
  }
  res.json({ count: rows.length, rows });
});

app.delete("/delegations", (req, res) => {
  const { subject, agentId, toolId } = req.body || {};
  if (!subject || !agentId || !toolId) {
    return res.status(400).json({ error: "invalid_request", detail: "subject, agentId, toolId required" });
  }
  run(`DELETE FROM delegations WHERE subject=? AND agentId=? AND toolId=?`, [subject, agentId, toolId]);
  saveDb().then(() => res.json({ ok: true }));
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));

// ---------- Boot ----------
const PORT = process.env.ADP_PORT || 9500;
openDb().then(() => {
  app.listen(PORT, () => {
    console.log(`ADP (Client Authorizer) listening on :${PORT}`);
    console.log(`DB: ${DB_PATH}`);
  });
}).catch(err => {
  console.error("Failed to open DB:", err);
  process.exit(1);
});