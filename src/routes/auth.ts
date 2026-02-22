import { Hono } from "hono";
import { randomBytes } from "crypto";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { eq } from "drizzle-orm";
import { hashApiKey, agentAuth } from "../middleware/auth.js";
import type { AppEnv } from "../types.js";

const app = new Hono<AppEnv>();

app.post("/register", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const referralCode = body.referral_code as string | undefined;

  const agentId = `ag_${randomBytes(6).toString("hex")}`;
  const apiKey = `sk_domains_${randomBytes(24).toString("hex")}`;
  const keyHash = hashApiKey(apiKey);
  const myReferralCode = `ref_${randomBytes(4).toString("hex")}`;

  let referrerId: string | null = null;
  if (referralCode) {
    const referrer = db.select().from(schema.agents)
      .where(eq(schema.agents.referralCode, referralCode)).get();
    if (referrer) referrerId = referrer.id;
  }

  db.insert(schema.agents).values({
    id: agentId,
    apiKeyHash: keyHash,
    referralCode: myReferralCode,
    referredBy: referrerId,
  }).run();

  return c.json({
    agent_id: agentId,
    api_key: apiKey,
    referral_code: myReferralCode,
    tier: "free",
    balance_usd: 0,
    pricing: {
      markup: "20% on base domain cost",
      example: "A $10.00/yr domain costs you $12.00/yr",
      referral_commission: "20% of our markup goes to your referrer",
    },
    message: "Store your API key securely — it cannot be recovered.",
    next_steps: [
      "POST /v1/auth/deposit — add funds to your account",
      "GET /v1/domains/search?q=example.com — search for domains",
      "POST /v1/domains/register — register a domain",
      "GET /v1/domains — list your domains",
      "POST /v1/dns/records — manage DNS records",
    ],
  }, 201);
});

app.get("/account", agentAuth, (c) => {
  const agent = c.get("agent") as typeof schema.agents.$inferSelect;
  return c.json({
    agent_id: agent.id,
    tier: agent.tier,
    balance_usd: Math.round(agent.balanceUsd * 100) / 100,
    total_spent: Math.round(agent.totalSpent * 100) / 100,
    total_domains: agent.totalDomains,
    referral_code: agent.referralCode,
    created_at: new Date(agent.createdAt * 1000).toISOString(),
  });
});

app.post("/deposit", agentAuth, async (c) => {
  const agentId = c.get("agentId") as string;
  const body = await c.req.json().catch(() => ({}));
  const amount = body.amount as number;

  if (!amount || amount <= 0 || amount > 10000) {
    return c.json({ error: "invalid_amount", message: "Amount must be between $0.01 and $10,000" }, 400);
  }

  const agent = db.select().from(schema.agents).where(eq(schema.agents.id, agentId)).get();
  if (!agent) return c.json({ error: "not_found" }, 404);

  const newBalance = Math.round((agent.balanceUsd + amount) * 100) / 100;

  db.update(schema.agents)
    .set({ balanceUsd: newBalance })
    .where(eq(schema.agents.id, agentId))
    .run();

  const txId = `tx_${randomBytes(8).toString("hex")}`;
  db.insert(schema.transactions).values({
    id: txId,
    agentId,
    type: "deposit",
    amount,
    balanceAfter: newBalance,
    description: `Deposit of $${amount.toFixed(2)}`,
  }).run();

  return c.json({
    transaction_id: txId,
    amount_deposited: amount,
    balance_usd: newBalance,
    note: "In production, deposits would be processed via crypto payment. For now, balance is credited directly.",
  });
});

export default app;
