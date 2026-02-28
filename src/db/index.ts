import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { mkdirSync } from "fs";
import { randomBytes } from "crypto";
import * as schema from "./schema.js";

mkdirSync("data", { recursive: true });
export const sqlite: import("better-sqlite3").Database = new Database("data/domains.db");
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("busy_timeout = 30000");

export const db = drizzle(sqlite, { schema });

const migrations = `
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  api_key_hash TEXT UNIQUE NOT NULL,
  referral_code TEXT UNIQUE NOT NULL,
  referred_by TEXT,
  tier TEXT NOT NULL DEFAULT 'free',
  balance_usd REAL NOT NULL DEFAULT 0,
  total_spent REAL NOT NULL DEFAULT 0,
  total_domains INTEGER NOT NULL DEFAULT 0,
  deposit_index INTEGER NOT NULL DEFAULT 0,
  total_deposited REAL NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_active INTEGER
);

CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  domain_name TEXT UNIQUE NOT NULL,
  njalla_domain TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  registered_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER,
  auto_renew INTEGER NOT NULL DEFAULT 1,
  cost_usd REAL NOT NULL,
  price_usd REAL NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS dns_records (
  id TEXT PRIMARY KEY,
  domain_id TEXT NOT NULL REFERENCES domains(id),
  agent_id TEXT NOT NULL REFERENCES agents(id),
  record_type TEXT NOT NULL,
  name TEXT NOT NULL,
  content TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 3600,
  njalla_record_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  type TEXT NOT NULL,
  amount REAL NOT NULL,
  balance_after REAL NOT NULL,
  description TEXT NOT NULL,
  domain_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS referral_earnings (
  id TEXT PRIMARY KEY,
  referrer_id TEXT NOT NULL,
  referred_id TEXT NOT NULL,
  fee_amount REAL NOT NULL,
  commission_amount REAL NOT NULL,
  domain_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS referral_withdrawals (
  id TEXT PRIMARY KEY,
  referrer_id TEXT NOT NULL,
  amount REAL NOT NULL,
  address TEXT NOT NULL,
  tx_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS deposit_addresses (
  agent_id TEXT NOT NULL REFERENCES agents(id),
  chain TEXT NOT NULL,
  address TEXT NOT NULL,
  PRIMARY KEY (agent_id, chain)
);

CREATE TABLE IF NOT EXISTS deposits (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  chain TEXT NOT NULL,
  token TEXT NOT NULL,
  amount_raw REAL NOT NULL,
  amount_usd REAL NOT NULL,
  swap_fee REAL NOT NULL DEFAULT 0,
  tx_hash TEXT,
  wagyu_tx TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  confirmations INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  credited_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_domains_agent ON domains(agent_id);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain_id);
CREATE INDEX IF NOT EXISTS idx_dns_agent ON dns_records(agent_id);
CREATE INDEX IF NOT EXISTS idx_transactions_agent ON transactions(agent_id);
CREATE INDEX IF NOT EXISTS idx_deposits_agent ON deposits(agent_id);
CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status);
`;

export function runMigrations() {
  sqlite.exec(migrations);
  // Fix old agents table: make api_key nullable and add new columns (SQLite table rebuild)
  try {
    const info = sqlite.prepare("PRAGMA table_info(agents)").all() as { name: string; notnull: number }[];
    const apiKeyCol = info.find(c => c.name === "api_key");
    if (apiKeyCol && apiKeyCol.notnull === 1) {
      // Recreate agents table without NOT NULL on api_key (disable FKs for drop)
      sqlite.pragma("foreign_keys = OFF");
      sqlite.prepare("DROP TABLE IF EXISTS agents_new").run();
      sqlite.prepare("CREATE TABLE agents_new (id TEXT PRIMARY KEY, api_key TEXT UNIQUE, api_key_hash TEXT UNIQUE, referral_code TEXT UNIQUE, referred_by TEXT, tier TEXT NOT NULL DEFAULT 'free', balance_usdc REAL NOT NULL DEFAULT 0, balance_usd REAL NOT NULL DEFAULT 0, total_spent REAL NOT NULL DEFAULT 0, total_domains INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_active INTEGER)").run();
      sqlite.prepare("INSERT OR IGNORE INTO agents_new (id, api_key, balance_usdc, created_at) SELECT id, api_key, balance_usdc, created_at FROM agents").run();
      sqlite.prepare("DROP TABLE agents").run();
      sqlite.prepare("ALTER TABLE agents_new RENAME TO agents").run();
      sqlite.pragma("foreign_keys = ON");
    }
  } catch { /* already migrated or agents_new already exists */ }

  // Add missing columns to old agents table (idempotent)
  const addColumns = [
    "ALTER TABLE agents ADD COLUMN api_key_hash TEXT",
    "ALTER TABLE agents ADD COLUMN referral_code TEXT",
    "ALTER TABLE agents ADD COLUMN referred_by TEXT",
    "ALTER TABLE agents ADD COLUMN tier TEXT NOT NULL DEFAULT 'free'",
    "ALTER TABLE agents ADD COLUMN balance_usd REAL NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN total_spent REAL NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN total_domains INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN deposit_index INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN total_deposited REAL NOT NULL DEFAULT 0",
    "ALTER TABLE agents ADD COLUMN last_active INTEGER",
    // Add missing columns to domains table
    "ALTER TABLE domains ADD COLUMN njalla_domain TEXT",
    "ALTER TABLE domains ADD COLUMN expires_at INTEGER",
    "ALTER TABLE domains ADD COLUMN cost_usd REAL NOT NULL DEFAULT 0",
    "ALTER TABLE domains ADD COLUMN price_usd REAL NOT NULL DEFAULT 0",
  ];
  for (const stmt of addColumns) {
    try { sqlite.exec(stmt); } catch { /* already exists */ }
  }
  // Migrate api_key → api_key_hash if agents table has old api_key column
  try {
    const info = sqlite.prepare("PRAGMA table_info(agents)").all() as { name: string }[];
    const hasApiKey = info.some(c => c.name === "api_key");
    const hasApiKeyHash = info.some(c => c.name === "api_key_hash");
    if (hasApiKey && hasApiKeyHash) {
      // Copy old api_key into api_key_hash for old agents (store plaintext as hash placeholder)
      sqlite.exec("UPDATE agents SET api_key_hash = api_key WHERE api_key_hash IS NULL AND api_key IS NOT NULL");
    }
    // Generate referral codes for old agents missing them
    const agentsMissingCode = sqlite.prepare("SELECT id FROM agents WHERE referral_code IS NULL").all() as { id: string }[];
    for (const a of agentsMissingCode) {
      const code = `ref_${randomBytes(4).toString("hex")}`;
      sqlite.prepare("UPDATE agents SET referral_code = ? WHERE id = ?").run(code, a.id);
    }
    // Assign sequential deposit_index to agents that still have index 0 (deduplication)
    const agentsIdx0 = sqlite.prepare("SELECT id FROM agents WHERE deposit_index = 0 ORDER BY created_at ASC").all() as { id: string }[];
    if (agentsIdx0.length > 1) {
      // More than one agent at index 0 — reassign sequentially starting from 0
      agentsIdx0.forEach((a, i) => {
        sqlite.prepare("UPDATE agents SET deposit_index = ? WHERE id = ?").run(i, a.id);
      });
    }
  } catch { /* migration already done */ }
}
