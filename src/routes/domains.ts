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
  const agentPrice = applyMarkup(baseCost);
  const markupAmount = getMarkupAmount(baseCost);

  // Check agent balance
  const agent = db.select().from(schema.agents).where(eq(schema.agents.id, agentId)).get();
  if (!agent) return c.json({ error: "not_found" }, 404);

  if (agent.balanceUsd < agentPrice) {
    return c.json({
      error: "insufficient_balance",
      balance_eur: Math.round(agent.balanceUsd * 100) / 100,
      required_eur: agentPrice,
      shortfall_eur: Math.round((agentPrice - agent.balanceUsd) * 100) / 100,
      suggestion: "POST /v1/auth/deposit to add funds",
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
  const newBalance = Math.round((agent.balanceUsd - agentPrice) * 100) / 100;
  const expiresAt = Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60; // 1 year default

  db.transaction((tx) => {
    tx.insert(schema.domains).values({
      id: domainId,
      agentId,
      domainName,
      njallaDomain: njallaResult.domain,
      status: "active",
      expiresAt,
      costUsd: baseCost,
      priceUsd: agentPrice,
    }).run();

    tx.update(schema.agents).set({
      balanceUsd: newBalance,
      totalSpent: sql`${schema.agents.totalSpent} + ${agentPrice}`,
      totalDomains: sql`${schema.agents.totalDomains} + 1`,
      lastActive: Math.floor(Date.now() / 1000),
    }).where(eq(schema.agents.id, agentId)).run();

    tx.insert(schema.transactions).values({
      id: txId,
      agentId,
      type: "domain_purchase",
      amount: -agentPrice,
      balanceAfter: newBalance,
      description: `Registered ${domainName} (€${agentPrice.toFixed(2)})`,
      domainId,
    }).run();

    if (agent.referredBy) {
      const refEarningId = `re_${randomBytes(8).toString("hex")}`;
      const commission = Math.round(markupAmount * 0.20 * 100) / 100;
      tx.insert(schema.referralEarnings).values({
        id: refEarningId,
        referrerId: agent.referredBy,
        referredId: agentId,
        feeAmount: markupAmount,
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
      markup: `${MARKUP_PERCENTAGE}%`,
      total_charged_eur: agentPrice,
    },
    balance_eur: newBalance,
    transaction_id: txId,
    next_steps: [
      `POST /v1/dns/records — add DNS records (A, CNAME)`,
      `GET /v1/domains/${domainId} — view domain details`,
      `GET /v1/domains — list all your domains`,
    ],
  }, 201);
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
