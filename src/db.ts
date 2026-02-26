import Database from "better-sqlite3";
import { mkdirSync } from "fs";

mkdirSync("data", { recursive: true });

export const sqlite: import("better-sqlite3").Database = new Database("data/domains.db");
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("busy_timeout = 30000");
sqlite.pragma("foreign_keys = ON");

const migrations = `
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  api_key TEXT UNIQUE NOT NULL,
  balance_usdc REAL NOT NULL DEFAULT 0,
  referrer_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id),
  domain_name TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  expiry TEXT,
  registered_at INTEGER NOT NULL DEFAULT (unixepoch()),
  njalla_registered INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS referral_earnings (
  id TEXT PRIMARY KEY,
  referrer_id TEXT NOT NULL,
  referred_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  amount_usdc REAL NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents(api_key);
CREATE INDEX IF NOT EXISTS idx_domains_agent ON domains(agent_id);
CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_ref_earnings_referrer ON referral_earnings(referrer_id);
`;

export function runMigrations() {
  sqlite.exec(migrations);
}

// ─── Agent queries ───

export function getAgentByKey(apiKey: string) {
  return sqlite.prepare("SELECT * FROM agents WHERE api_key = ?").get(apiKey) as Agent | undefined;
}

export function getAgentById(id: string) {
  return sqlite.prepare("SELECT * FROM agents WHERE id = ?").get(id) as Agent | undefined;
}

export function createAgent(id: string, apiKey: string, referrerId?: string) {
  sqlite.prepare(
    "INSERT INTO agents (id, api_key, balance_usdc, referrer_id) VALUES (?, ?, 0, ?)"
  ).run(id, apiKey, referrerId ?? null);
}

export function creditAgent(agentId: string, amount: number) {
  sqlite.prepare("UPDATE agents SET balance_usdc = balance_usdc + ? WHERE id = ?").run(amount, agentId);
}

export function debitAgent(agentId: string, amount: number): boolean {
  const stmt = sqlite.prepare(`
    UPDATE agents SET balance_usdc = balance_usdc - ?
    WHERE id = ? AND balance_usdc >= ?
  `);
  const result = stmt.run(amount, agentId, amount);
  return result.changes > 0;
}

// ─── Domain queries ───

export function getDomainByName(domainName: string) {
  return sqlite.prepare("SELECT * FROM domains WHERE domain_name = ?").get(domainName) as Domain | undefined;
}

export function getDomainsByAgent(agentId: string) {
  return sqlite.prepare("SELECT * FROM domains WHERE agent_id = ?").all(agentId) as Domain[];
}

export function getDomainForAgent(domainName: string, agentId: string) {
  return sqlite.prepare(
    "SELECT * FROM domains WHERE domain_name = ? AND agent_id = ?"
  ).get(domainName, agentId) as Domain | undefined;
}

export function insertDomain(id: string, agentId: string, domainName: string, expiry: string | null, njallaRegistered: number) {
  sqlite.prepare(`
    INSERT INTO domains (id, agent_id, domain_name, status, expiry, njalla_registered)
    VALUES (?, ?, ?, 'active', ?, ?)
  `).run(id, agentId, domainName, expiry, njallaRegistered);
}

// ─── Referral queries ───

export function insertReferralEarning(id: string, referrerId: string, referredId: string, domain: string, amount: number) {
  sqlite.prepare(`
    INSERT INTO referral_earnings (id, referrer_id, referred_id, domain, amount_usdc)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, referrerId, referredId, domain, amount);
}

export function getReferralEarnings(referrerId: string) {
  return sqlite.prepare(
    "SELECT * FROM referral_earnings WHERE referrer_id = ? ORDER BY created_at DESC"
  ).all(referrerId) as ReferralEarning[];
}

export function getReferralCount(referrerId: string): number {
  const row = sqlite.prepare(
    "SELECT COUNT(DISTINCT referred_id) as cnt FROM referral_earnings WHERE referrer_id = ?"
  ).get(referrerId) as { cnt: number };
  return row.cnt;
}

export function getReferralDomainCount(referrerId: string): number {
  const row = sqlite.prepare(
    "SELECT COUNT(*) as cnt FROM referral_earnings WHERE referrer_id = ?"
  ).get(referrerId) as { cnt: number };
  return row.cnt;
}

// ─── Types ───

export interface Agent {
  id: string;
  api_key: string;
  balance_usdc: number;
  referrer_id: string | null;
  created_at: number;
}

export interface Domain {
  id: string;
  agent_id: string;
  domain_name: string;
  status: string;
  expiry: string | null;
  registered_at: number;
  njalla_registered: number;
}

export interface ReferralEarning {
  id: string;
  referrer_id: string;
  referred_id: string;
  domain: string;
  amount_usdc: number;
  created_at: number;
}
