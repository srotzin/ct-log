// SQLite schema and helpers.

import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

// On Render, CT_DB_PATH should point inside the mounted persistent disk.
// Default to ./data/ct.db for local dev.
const DB_PATH = process.env.CT_DB_PATH || path.resolve(process.cwd(), 'data', 'ct.db');

// Ensure parent dir exists (Render disk mount may be empty on first boot).
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS entries (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  leaf_hash BLOB NOT NULL UNIQUE,
  payload BLOB NOT NULL,
  agent_did TEXT,
  prev_receipt_hash BLOB,
  receipt_kind TEXT,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_did_seq ON entries(agent_did, seq);
CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries(ts);

CREATE TABLE IF NOT EXISTS tree_heads (
  epoch INTEGER PRIMARY KEY AUTOINCREMENT,
  tree_size INTEGER NOT NULL,
  root BLOB NOT NULL,
  ts INTEGER NOT NULL,
  sig BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS vestigium (
  did TEXT NOT NULL,
  depth INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  leaf_hash BLOB NOT NULL,
  prev_hash BLOB,
  ts INTEGER NOT NULL,
  PRIMARY KEY (did, depth)
);
CREATE INDEX IF NOT EXISTS idx_vestigium_did ON vestigium(did, depth DESC);
`);

// Idempotent migration: add pq_sig column to tree_heads if it doesn't exist.
function columnExists(table, col) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all();
  return rows.some(r => r.name === col);
}
if (!columnExists('tree_heads', 'pq_sig')) {
  db.exec(`ALTER TABLE tree_heads ADD COLUMN pq_sig BLOB`);
}

export const stmts = {
  insertEntry: db.prepare(`
    INSERT INTO entries (leaf_hash, payload, agent_did, prev_receipt_hash, receipt_kind, ts)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  getEntryByHash: db.prepare(`SELECT * FROM entries WHERE leaf_hash = ?`),
  getEntryBySeq: db.prepare(`SELECT * FROM entries WHERE seq = ?`),
  getAllLeafHashes: db.prepare(`SELECT leaf_hash FROM entries ORDER BY seq ASC`),
  countEntries: db.prepare(`SELECT COUNT(*) AS n FROM entries`),
  getEntriesRange: db.prepare(`SELECT seq, leaf_hash, payload, agent_did, receipt_kind, ts FROM entries WHERE seq >= ? AND seq <= ? ORDER BY seq ASC`),

  insertTreeHead: db.prepare(`
    INSERT INTO tree_heads (tree_size, root, ts, sig, pq_sig) VALUES (?, ?, ?, ?, ?)
  `),
  latestTreeHead: db.prepare(`SELECT * FROM tree_heads ORDER BY epoch DESC LIMIT 1`),
  treeHeadBySize: db.prepare(`SELECT * FROM tree_heads WHERE tree_size = ? ORDER BY epoch DESC LIMIT 1`),

  insertVestigium: db.prepare(`
    INSERT OR IGNORE INTO vestigium (did, depth, seq, leaf_hash, prev_hash, ts)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  latestVestigium: db.prepare(`
    SELECT * FROM vestigium WHERE did = ? ORDER BY depth DESC LIMIT 1
  `),
  vestigiumDepth: db.prepare(`
    SELECT COALESCE(MAX(depth), 0) AS depth FROM vestigium WHERE did = ?
  `),
  vestigiumRange: db.prepare(`
    SELECT * FROM vestigium WHERE did = ? AND depth >= ? ORDER BY depth ASC LIMIT ?
  `),
};
