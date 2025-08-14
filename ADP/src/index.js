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

  // Table
  db.run(`
    CREATE TABLE IF NOT EXISTS delegations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject TEXT NOT NULL,
      agentId TEXT NOT NULL,
      toolId TEXT NOT NULL,
      scopes TEXT NOT NULL,          -- JSON string of array
      not_after INTEGER NOT NULL,    -- epoch seconds
      issuer TEXT,                   -- who issued the cred
      jws TEXT,                      -- compact JWS as received
      inserted_at INTEGER NOT NULL
    )
  `);

  // Indexes (✅ keep inside openDb so db is initialized)
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

    const key = await importJWK(public_jwk);
    const { payload } = await jwtVerify(jws, key, {
      algorithms: ["EdDSA", "ES256", "RS256"],
      clockTolerance: "5s"
    });

    const {
      subject, agentId, toolId, scopes,
      not_after: notAfterFromPayload,
      iss, exp
    } = payload || {};

    if (typeof subject !== "string" || !subject ||
        typeof agentId !== "string" || !agentId ||
        typeof toolId !== "string"  || !toolId ||
        !Array.isArray(scopes) || scopes.some(s => typeof s !== "string" || !s)) {
      return res.status(400).json({ error: "invalid_credential_payload" });
    }

    const not_after = Number.isFinite(notAfterFromPayload) ? notAfterFromPayload
                     : (Number.isFinite(exp) ? exp : undefined);

    if (!Number.isFinite(not_after)) {
      return res.status(400).json({ error: "missing_not_after" });
    }
    if (not_after <= nowSec()) {
      return res.status(400).json({ error: "expired_credential" });
    }

    // Upsert for (subject, agentId, toolId)
    const existing = selectOne(
      `SELECT id FROM delegations WHERE subject=? AND agentId=? AND toolId=?`,
      [subject, agentId, toolId]
    );
    if (existing) {
      run(
        `UPDATE delegations
           SET scopes=?, not_after=?, issuer=?, jws=?, inserted_at=?
         WHERE id=?`,
        [JSON.stringify(scopes), not_after, iss || null, jws, nowSec(), existing.id]
      );
    } else {
      run(
        `INSERT INTO delegations (subject, agentId, toolId, scopes, not_after, issuer, jws, inserted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [subject, agentId, toolId, JSON.stringify(scopes), not_after, iss || null, jws, nowSec()]
      );
    }

    await saveDb();
    return res.status(201).json({ ok: true, subject, agentId, toolId, scopes, not_after });
  } catch (e) {
    console.error("POST /delegations error:", e);
    return res.status(400).json({ error: "bad_delegation", detail: String(e?.message || e) });
  }
});

// ---------- POST /evaluate  (DB-backed) ----------
app.post("/evaluate", (req, res) => {
  const {
    subject = "user-123",
    agentId,
    toolId,
    audience,
    requested_scopes = []
  } = req.body || {};

  const reqScopes = Array.isArray(requested_scopes)
    ? requested_scopes.filter(s => typeof s === "string" && s)
    : [];

  const row = selectOne(
    `SELECT * FROM delegations
       WHERE subject=? AND agentId=? AND toolId=? AND not_after > ?`,
    [subject, agentId, toolId, nowSec()]
  );

  let allow = true;
  let allowedScopes = reqScopes;

  if (row) {
    let delegatedArr = [];
    try { delegatedArr = JSON.parse(row.scopes || "[]"); } catch {}
    const delegated = new Set(
      Array.isArray(delegatedArr) ? delegatedArr.filter(s => typeof s === "string" && s) : []
    );
    const intersection = reqScopes.filter(s => delegated.has(s));
    allowedScopes = intersection.length ? intersection : Array.from(delegated);
  }

  return res.json({
    allow,
    scopes: allowedScopes,
    obligations: {},
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