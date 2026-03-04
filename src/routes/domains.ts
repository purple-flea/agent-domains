import { Hono } from "hono";
import { randomBytes } from "crypto";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { eq, and, sql } from "drizzle-orm";
import { agentAuth } from "../middleware/auth.js";
import {
  searchDomains,
  checkAvailability,
  registerDomain,
  applyMarkup,
  getMarkupAmount,
  MARKUP_PERCENTAGE,
} from "../engine/njalla.js";
import type { AppEnv } from "../types.js";

// EUR → USD conversion rate (fixed; ECB approximate)
const USD_PER_EUR = 1.08;

const app = new Hono<AppEnv>();

app.use("/*", agentAuth);

// ─── Search domains ───
app.get("/search", async (c) => {
  const query = c.req.query("q") || c.req.query("domain");
  if (!query) {
    return c.json({ error: "missing_query", message: "Provide ?q=example.com or ?domain=example.com" }, 400);
  }

  try {
    const results = await searchDomains(query);
    const available = results.filter(r => r.status === "available");
    const unavailable = results.filter(r => r.status !== "available");

    return c.json({
      query,
      total: results.length,
      available: available.length,
      currency: "EUR",
      markup: `${MARKUP_PERCENTAGE}%`,
      results: results.slice(0, 50).map(r => ({
        domain: r.name,
        available: r.status === "available",
        base_price_eur: r.price,
        price_eur: r.priceWithMarkup,
        ...(r.status === "available" ? {
          register: `POST /v1/domains/register { "domain": "${r.name}" }`,
        } : {}),
      })),
    });
  } catch (err: any) {
    return c.json({ error: "search_failed", message: err.message }, 500);
  }
});

// ─── Bulk check availability (up to 20 domains in parallel) ───
app.post("/bulk-check", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const domains: unknown = body.domains;

  if (!Array.isArray(domains) || domains.length === 0) {
    return c.json({ error: "invalid_domains", message: "Provide { domains: [\"example.com\", ...] }" }, 400);
  }

  if (domains.length > 20) {
    return c.json({ error: "too_many_domains", message: "Maximum 20 domains per bulk-check call" }, 400);
  }

  const names = (domains as string[]).map((d) => String(d).toLowerCase().trim()).filter(Boolean);

  const results = await Promise.allSettled(
    names.map(async (domain) => {
      const result = await checkAvailability(domain);
      return { domain, ...result };
    })
  );

  const checked = results.map((r, i) => {
    if (r.status === "fulfilled") {
      const v = r.value;
      return {
        domain: names[i],
        available: v.available,
        base_price_eur: v.price ?? null,
        price_eur: v.priceWithMarkup ?? null,
        ...(v.available ? { register: `POST /v1/domains/register { "domain": "${names[i]}" }` } : {}),
        error: null as string | null,
      };
    } else {
      return {
        domain: names[i],
        available: false,
        base_price_eur: null as number | null,
        price_eur: null as number | null,
        error: "lookup_failed" as string | null,
      };
    }
  });

  const availableCount = checked.filter(r => r.available).length;
  const errorCount = checked.filter(r => r.error).length;

  return c.json({
    total: checked.length,
    available: availableCount,
    unavailable: checked.length - availableCount - errorCount,
    errors: errorCount,
    currency: "EUR",
    markup: `${MARKUP_PERCENTAGE}%`,
    results: checked.map(r => {
      const { error, ...rest } = r;
      return error ? { ...rest, error } : rest;
    }),
  });
});

// ─── Check availability ───
app.get("/check", async (c) => {
  const domain = c.req.query("domain");
  if (!domain) {
    return c.json({ error: "missing_domain", message: "Provide ?domain=example.com" }, 400);
  }

  try {
    const result = await checkAvailability(domain);
    return c.json({
      domain,
      available: result.available,
      base_price_eur: result.price,
      price_eur: result.priceWithMarkup,
      markup: `${MARKUP_PERCENTAGE}%`,
      currency: "EUR",
    });
  } catch (err: any) {
    return c.json({ error: "check_failed", message: err.message }, 500);
  }
});

// ─── Register a domain ───
app.post("/register", async (c) => {
  const agentId = c.get("agentId") as string;
  const body = await c.req.json().catch(() => ({}));
  const domainName = (body.domain as string)?.toLowerCase()?.trim();

  if (!domainName || !domainName.includes(".")) {
    return c.json({ error: "invalid_domain", message: "Provide a valid domain name (e.g. example.com)" }, 400);
  }

  // Check availability first
  let availability;
  try {
    availability = await checkAvailability(domainName);
  } catch (err: any) {
    return c.json({ error: "availability_check_failed", message: err.message }, 500);
  }

  if (!availability.available) {
    return c.json({
      error: "domain_unavailable",
      domain: domainName,
      message: `${domainName} is not available for registration`,
      suggestion: "Try searching for alternative domains with GET /v1/domains/search?q=...",
    }, 400);
  }

  if (!availability.price) {
    return c.json({ error: "price_unavailable", message: "Could not determine price for this domain" }, 500);
  }

  const baseCost = availability.price;
  const agentPriceEur = applyMarkup(baseCost);
  const markupAmountEur = getMarkupAmount(baseCost);

  // Convert EUR prices to USD for balance deduction
  const baseCostUsd = Math.round(baseCost * USD_PER_EUR * 100) / 100;
  const agentPriceUsd = Math.round(agentPriceEur * USD_PER_EUR * 100) / 100;
  const markupAmountUsd = Math.round(markupAmountEur * USD_PER_EUR * 100) / 100;

  // Check agent USD balance
  const agent = db.select().from(schema.agents).where(eq(schema.agents.id, agentId)).get();
  if (!agent) return c.json({ error: "not_found" }, 404);

  if (agent.balanceUsd < agentPriceUsd) {
    return c.json({
      error: "insufficient_balance",
      balance_usd: Math.round(agent.balanceUsd * 100) / 100,
      required_usd: agentPriceUsd,
      required_eur: agentPriceEur,
      shortfall_usd: Math.round((agentPriceUsd - agent.balanceUsd) * 100) / 100,
      exchange_rate: `1 EUR = ${USD_PER_EUR} USD`,
      suggestion: "POST /v1/auth/deposit-address { chain: 'base' } to add funds",
    }, 400);
  }

  // Register with Njalla
  let njallaResult;
  try {
    njallaResult = await registerDomain(domainName);
  } catch (err: any) {
    return c.json({ error: "registration_failed", message: err.message }, 500);
  }

  // Debit agent balance and record everything in a transaction
  const domainId = `dom_${randomBytes(8).toString("hex")}`;
  const txId = `tx_${randomBytes(8).toString("hex")}`;
  const newBalance = Math.round((agent.balanceUsd - agentPriceUsd) * 100) / 100;
  const expiresAt = Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60; // 1 year default

  db.transaction((tx) => {
    tx.insert(schema.domains).values({
      id: domainId,
      agentId,
      domainName,
      njallaDomain: njallaResult.domain,
      status: "active",
      expiresAt,
      costUsd: baseCostUsd,
      priceUsd: agentPriceUsd,
    }).run();

    tx.update(schema.agents).set({
      balanceUsd: newBalance,
      totalSpent: sql`${schema.agents.totalSpent} + ${agentPriceUsd}`,
      totalDomains: sql`${schema.agents.totalDomains} + 1`,
      lastActive: Math.floor(Date.now() / 1000),
    }).where(eq(schema.agents.id, agentId)).run();

    tx.insert(schema.transactions).values({
      id: txId,
      agentId,
      type: "domain_purchase",
      amount: -agentPriceUsd,
      balanceAfter: newBalance,
      description: `Registered ${domainName} (€${agentPriceEur.toFixed(2)} = $${agentPriceUsd.toFixed(2)})`,
      domainId,
    }).run();

    if (agent.referredBy) {
      const refEarningId = `re_${randomBytes(8).toString("hex")}`;
      const commission = Math.round(markupAmountUsd * 0.20 * 100) / 100;
      tx.insert(schema.referralEarnings).values({
        id: refEarningId,
        referrerId: agent.referredBy,
        referredId: agentId,
        feeAmount: markupAmountUsd,
        commissionAmount: commission,
        domainId,
      }).run();
    }
  });

  return c.json({
    domain_id: domainId,
    domain: domainName,
    status: "active",
    expires_at: new Date(expiresAt * 1000).toISOString(),
    cost: {
      base_price_eur: baseCost,
      base_price_usd: baseCostUsd,
      markup: `${MARKUP_PERCENTAGE}%`,
      total_charged_eur: agentPriceEur,
      total_charged_usd: agentPriceUsd,
      exchange_rate: `1 EUR = ${USD_PER_EUR} USD`,
    },
    balance_usd: newBalance,
    transaction_id: txId,
    next_steps: [
      `POST /v1/dns/records — add DNS records (A, CNAME)`,
      `GET /v1/domains/${domainId} — view domain details`,
      `GET /v1/domains — list all your domains`,
    ],
  }, 201);
});

// ─── Expiring domains (auth) ───
app.get("/expiring", (c) => {
  const agentId = c.get("agentId") as string;
  const daysParam = Math.min(parseInt(c.req.query("days") || "90", 10), 365);
  const nowTs = Math.floor(Date.now() / 1000);
  const cutoffTs = nowTs + daysParam * 86400;

  const expiring = db.select().from(schema.domains)
    .where(and(
      eq(schema.domains.agentId, agentId),
      sql`${schema.domains.expiresAt} IS NOT NULL AND ${schema.domains.expiresAt} <= ${cutoffTs} AND ${schema.domains.expiresAt} > ${nowTs}`
    ))
    .all();

  const enriched = expiring
    .sort((a, b) => (a.expiresAt ?? 0) - (b.expiresAt ?? 0))
    .map(d => {
      const expiresTs = d.expiresAt ?? 0;
      const daysLeft = Math.max(0, Math.floor((expiresTs - nowTs) / 86400));
      return {
        domain_id: d.id,
        domain: d.domainName,
        expires_at: new Date(expiresTs * 1000).toISOString(),
        days_remaining: daysLeft,
        auto_renew: d.autoRenew === 1,
        urgency: daysLeft <= 7 ? "critical" : daysLeft <= 30 ? "high" : "moderate",
        action: d.autoRenew === 1
          ? "Auto-renew is ON — domain will renew automatically"
          : `PUT /v1/domains/${d.id}/auto-renew { "enabled": true } to enable auto-renew`,
      };
    });

  const critical = enriched.filter(d => d.urgency === "critical").length;
  const urgent = enriched.filter(d => d.urgency === "high").length;

  return c.json({
    total_expiring_in_days: daysParam,
    count: enriched.length,
    critical_count: critical,
    high_count: urgent,
    domains: enriched,
    tip: critical > 0
      ? `${critical} domain(s) expire in 7 days! Enable auto-renew or renew manually immediately.`
      : enriched.length === 0
      ? `No domains expiring in the next ${daysParam} days`
      : `${enriched.length} domain(s) expiring in the next ${daysParam} days`,
  });
});

// ─── List agent's domains ───
app.get("/", (c) => {
  const agentId = c.get("agentId") as string;

  const agentDomains = db.select().from(schema.domains)
    .where(eq(schema.domains.agentId, agentId))
    .all();

  return c.json({
    total: agentDomains.length,
    domains: agentDomains.map(d => ({
      domain_id: d.id,
      domain: d.domainName,
      status: d.status,
      registered_at: new Date(d.registeredAt * 1000).toISOString(),
      expires_at: d.expiresAt ? new Date(d.expiresAt * 1000).toISOString() : null,
      auto_renew: d.autoRenew === 1,
      price_paid: d.priceUsd,
    })),
  });
});

// ─── Get domain details ───
app.get("/:id", (c) => {
  const agentId = c.get("agentId") as string;
  const domainId = c.req.param("id");

  const domain = db.select().from(schema.domains)
    .where(and(eq(schema.domains.id, domainId), eq(schema.domains.agentId, agentId)))
    .get();

  if (!domain) {
    return c.json({ error: "not_found", message: "Domain not found or doesn't belong to you" }, 404);
  }

  const records = db.select().from(schema.dnsRecords)
    .where(eq(schema.dnsRecords.domainId, domainId))
    .all();

  return c.json({
    domain_id: domain.id,
    domain: domain.domainName,
    status: domain.status,
    registered_at: new Date(domain.registeredAt * 1000).toISOString(),
    expires_at: domain.expiresAt ? new Date(domain.expiresAt * 1000).toISOString() : null,
    auto_renew: domain.autoRenew === 1,
    price_paid: domain.priceUsd,
    dns_records: records.map(r => ({
      record_id: r.id,
      type: r.recordType,
      name: r.name,
      content: r.content,
      ttl: r.ttl,
    })),
  });
});

export default app;
