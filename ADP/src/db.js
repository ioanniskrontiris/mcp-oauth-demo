// adp/src/db.js
import Database from "better-sqlite3";

const DB_PATH = process.env.ADP_DB || "adp.sqlite";
export const db = new Database(DB_PATH);

// schema (idempotent)
db.exec(`
CREATE TABLE IF NOT EXISTS keys (
  issuer TEXT NOT NULL,
  kid    TEXT NOT NULL,
  jwk    TEXT NOT NULL,
  PRIMARY KEY (issuer, kid)
);

CREATE TABLE IF NOT EXISTS delegations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  subject       TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  tool_id       TEXT NOT NULL,
  scopes_json   TEXT NOT NULL,        -- JSON array of strings
  not_after     INTEGER NOT NULL,     -- epoch seconds (exp)
  issuer        TEXT NOT NULL,
  kid           TEXT NOT NULL,
  jti           TEXT,
  issued_at     INTEGER,
  created_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deleg_subject ON delegations(subject);
CREATE INDEX IF NOT EXISTS idx_deleg_agent_tool ON delegations(agent_id, tool_id);
`);

export function upsertKey({ issuer, kid, jwk }) {
  db.prepare(`
    INSERT INTO keys (issuer, kid, jwk)
    VALUES (@issuer, @kid, @jwk)
    ON CONFLICT(issuer, kid) DO UPDATE SET jwk=excluded.jwk
  `).run({ issuer, kid, jwk: JSON.stringify(jwk) });
}

export function findKey(issuer, kid) {
  const row = db.prepare(`SELECT jwk FROM keys WHERE issuer=? AND kid=?`).get(issuer, kid);
  return row ? JSON.parse(row.jwk) : null;
}

export function insertDelegation(rec) {
  const {
    subject, agent_id, tool_id, scopes, not_after,
    issuer, kid, jti, issued_at
  } = rec;
  return db.prepare(`
    INSERT INTO delegations
      (subject, agent_id, tool_id, scopes_json, not_after, issuer, kid, jti, issued_at, created_at)
    VALUES
      (@subject, @agent_id, @tool_id, @scopes_json, @not_after, @issuer, @kid, @jti, @issued_at, @created_at)
  `).run({
    subject,
    agent_id,
    tool_id,
    scopes_json: JSON.stringify(scopes),
    not_after,
    issuer,
    kid,
    jti: jti || null,
    issued_at: issued_at || null,
    created_at: Math.floor(Date.now() / 1000)
  });
}

export function listDelegations() {
  return db.prepare(`SELECT * FROM delegations ORDER BY id DESC`).all();
}

export function deleteDelegation(id) {
  db.prepare(`DELETE FROM delegations WHERE id=?`).run(id);
}

export function findCoveringDelegation({ subject, agentId, toolId, neededScopes }) {
  const now = Math.floor(Date.now()/1000);
  const rows = db.prepare(`
    SELECT * FROM delegations
    WHERE subject=? AND agent_id=? AND tool_id=? AND not_after > ?
    ORDER BY not_after DESC
  `).all(subject, agentId, toolId, now);

  for (const r of rows) {
    const scopes = JSON.parse(r.scopes_json || "[]");
    const set = new Set(scopes);
    const covers = neededScopes.every(s => set.has(s));
    if (covers) return { row: r, scopes };
  }
  return null;
}