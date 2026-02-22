import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { mkdirSync } from "fs";
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

CREATE INDEX IF NOT EXISTS idx_domains_agent ON domains(agent_id);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);
CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain_id);
CREATE INDEX IF NOT EXISTS idx_dns_agent ON dns_records(agent_id);
CREATE INDEX IF NOT EXISTS idx_transactions_agent ON transactions(agent_id);
`;

export function runMigrations() {
  sqlite.exec(migrations);
}
