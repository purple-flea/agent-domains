import { sqliteTable, text, real, integer, index, primaryKey } from "drizzle-orm/sqlite-core";

export const agents = sqliteTable("agents", {
  id: text("id").primaryKey(),
  apiKeyHash: text("api_key_hash").unique().notNull(),
  referralCode: text("referral_code").unique().notNull(),
  referredBy: text("referred_by"),
  tier: text("tier").default("free").notNull(), // free, pro, whale
  balanceUsd: real("balance_usd").default(0).notNull(),
  totalSpent: real("total_spent").default(0).notNull(),
  totalDomains: integer("total_domains").default(0).notNull(),
  depositIndex: integer("deposit_index").default(0).notNull(), // HD wallet derivation index
  totalDeposited: real("total_deposited").default(0).notNull(),
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
  lastActive: integer("last_active"),
});

export const domains = sqliteTable("domains", {
  id: text("id").primaryKey(),
  agentId: text("agent_id").notNull().references(() => agents.id),
  domainName: text("domain_name").unique().notNull(),
  njallaDomain: text("njalla_domain"), // Njalla's internal ref
  status: text("status").default("active").notNull(), // active, expired, pending, failed
  registeredAt: integer("registered_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
  expiresAt: integer("expires_at"),
  autoRenew: integer("auto_renew").default(1).notNull(),
  costUsd: real("cost_usd").notNull(), // what we paid Njalla
  priceUsd: real("price_usd").notNull(), // what the agent paid (with markup)
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
}, (table) => [
  index("idx_domains_agent").on(table.agentId),
  index("idx_domains_status").on(table.status),
  index("idx_domains_name").on(table.domainName),
]);

export const dnsRecords = sqliteTable("dns_records", {
  id: text("id").primaryKey(),
  domainId: text("domain_id").notNull().references(() => domains.id),
  agentId: text("agent_id").notNull().references(() => agents.id),
  recordType: text("record_type").notNull(), // A, CNAME, MX, TXT, AAAA
  name: text("name").notNull(), // subdomain or @
  content: text("content").notNull(), // IP or target
  ttl: integer("ttl").default(3600).notNull(),
  njallaRecordId: text("njalla_record_id"), // Njalla's record ID
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
  updatedAt: integer("updated_at"),
}, (table) => [
  index("idx_dns_domain").on(table.domainId),
  index("idx_dns_agent").on(table.agentId),
]);

export const transactions = sqliteTable("transactions", {
  id: text("id").primaryKey(),
  agentId: text("agent_id").notNull().references(() => agents.id),
  type: text("type").notNull(), // deposit, domain_purchase, domain_renewal, refund
  amount: real("amount").notNull(),
  balanceAfter: real("balance_after").notNull(),
  description: text("description").notNull(),
  domainId: text("domain_id"),
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
}, (table) => [
  index("idx_transactions_agent").on(table.agentId),
]);

export const referralEarnings = sqliteTable("referral_earnings", {
  id: text("id").primaryKey(),
  referrerId: text("referrer_id").notNull(),
  referredId: text("referred_id").notNull(),
  feeAmount: real("fee_amount").notNull(), // the markup amount
  commissionAmount: real("commission_amount").notNull(), // 20% of markup
  domainId: text("domain_id"),
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
});

export const referralWithdrawals = sqliteTable("referral_withdrawals", {
  id: text("id").primaryKey(),
  referrerId: text("referrer_id").notNull(),
  amount: real("amount").notNull(),
  address: text("address").notNull(),
  txHash: text("tx_hash"),
  status: text("status").default("pending").notNull(),
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
});

// ─── Crypto deposit tables ───

export const depositAddresses = sqliteTable("deposit_addresses", {
  agentId: text("agent_id").notNull().references(() => agents.id),
  chain: text("chain").notNull(),
  address: text("address").notNull(),
}, (t) => [
  primaryKey({ columns: [t.agentId, t.chain] }),
]);

export const deposits = sqliteTable("deposits", {
  id: text("id").primaryKey(),
  agentId: text("agent_id").notNull().references(() => agents.id),
  chain: text("chain").notNull(),
  token: text("token").notNull(),
  amountRaw: real("amount_raw").notNull(),
  amountUsd: real("amount_usd").notNull(),
  swapFee: real("swap_fee").default(0).notNull(),
  txHash: text("tx_hash"),
  wagyuTx: text("wagyu_tx"),
  status: text("status").default("pending").notNull(), // pending | credited | failed
  confirmations: integer("confirmations").default(0).notNull(),
  createdAt: integer("created_at").$defaultFn(() => Math.floor(Date.now() / 1000)).notNull(),
  creditedAt: integer("credited_at"),
}, (t) => [
  index("idx_deposits_agent").on(t.agentId),
  index("idx_deposits_status").on(t.status),
]);
