import { Hono } from "hono";
import { randomBytes } from "crypto";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { eq, sql } from "drizzle-orm";
import { hashApiKey, agentAuth } from "../middleware/auth.js";
import type { AppEnv } from "../types.js";

const app = new Hono<AppEnv>();

// ─── Wallet service config ───

const WALLET_SERVICE_URL = process.env.WALLET_SERVICE_URL || "http://localhost:3002";
const WALLET_SERVICE_KEY = process.env.WALLET_SERVICE_KEY;

// ─── Supported chains for deposit-address endpoint ───

const SUPPORTED_CHAINS = ["base", "ethereum", "bsc", "arbitrum", "solana", "bitcoin", "tron", "monero"] as const;
type SupportedChain = typeof SUPPORTED_CHAINS[number];

const CHAIN_INFO: Record<SupportedChain, {
  send_token: string;
  auto_swap: boolean;
  swap_fee: string;
  minimum: string;
  note: string;
  send_instructions: string;
}> = {
  base: {
    send_token: "USDC",
    auto_swap: false,
    swap_fee: "0%",
    minimum: "$0.50",
    note: "Direct USDC on Base — fastest and cheapest",
    send_instructions: "Send USDC (Base network) to this address",
  },
  ethereum: {
    send_token: "ETH or USDC/USDT",
    auto_swap: true,
    swap_fee: "0.1–0.3%",
    minimum: "$0.50 equivalent",
    note: "ETH or stablecoins auto-swapped to Base USDC via Wagyu",
    send_instructions: "Send ETH, USDC, or USDT (Ethereum mainnet) to this address",
  },
  bsc: {
    send_token: "BNB or USDT/USDC",
    auto_swap: true,
    swap_fee: "0.1–0.3%",
    minimum: "$0.50 equivalent",
    note: "BNB or BSC stablecoins auto-swapped to Base USDC via Wagyu",
    send_instructions: "Send BNB, USDT, or USDC (BSC network) to this address",
  },
  arbitrum: {
    send_token: "ETH or USDC/USDT",
    auto_swap: true,
    swap_fee: "0.1–0.3%",
    minimum: "$0.50 equivalent",
    note: "ETH or Arbitrum stablecoins auto-swapped to Base USDC via Wagyu",
    send_instructions: "Send ETH, USDC, or USDT (Arbitrum One) to this address",
  },
  solana: {
    send_token: "SOL",
    auto_swap: true,
    swap_fee: "0.1–0.3%",
    minimum: "$0.50 equivalent",
    note: "SOL auto-swapped to Base USDC via Wagyu (allow up to 10 minutes)",
    send_instructions: "Send SOL to this Solana address",
  },
  bitcoin: {
    send_token: "BTC",
    auto_swap: true,
    swap_fee: "0.1–0.5% + mining fees",
    minimum: "$1.00 equivalent",
    note: "BTC swapped to Base USDC via Wagyu (allow 30–60 minutes for confirmations)",
    send_instructions: "Send BTC to this Bitcoin address",
  },
  tron: {
    send_token: "USDT TRC-20",
    auto_swap: false,
    swap_fee: "0%",
    minimum: "$0.50",
    note: "Send USDT on Tron network — swept and converted to Base USDC",
    send_instructions: "Send USDT (TRC-20) to this Tron address",
  },
  monero: {
    send_token: "XMR",
    auto_swap: true,
    swap_fee: "0.1–0.3%",
    minimum: "$0.50 equivalent",
    note: "Private XMR deposits — auto-swapped to Base USDC via Wagyu",
    send_instructions: "Send XMR to this Monero primary address",
  },
};

app.post("/register", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const referralCode = body.referral_code as string | undefined;

  const agentId = `ag_${randomBytes(6).toString("hex")}`;
  const apiKey = `sk_domains_${randomBytes(24).toString("hex")}`;
  const keyHash = hashApiKey(apiKey);
  const myReferralCode = `ref_${randomBytes(4).toString("hex")}`;

  // Get next deposit index for HD wallet derivation
  const maxIndex = db
    .select({ max: sql<number>`COALESCE(MAX(deposit_index), -1)` })
    .from(schema.agents)
    .get();
  const depositIndex = (maxIndex?.max ?? -1) + 1;

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
    depositIndex,
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
      "POST /v1/auth/deposit-address { chain: 'base' } — get a USDC deposit address",
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
    total_deposited: Math.round(agent.totalDeposited * 100) / 100,
    total_domains: agent.totalDomains,
    referral_code: agent.referralCode,
    created_at: new Date(agent.createdAt * 1000).toISOString(),
  });
});

// ─── Deposit Address (real crypto) ───

app.post("/deposit-address", agentAuth, async (c) => {
  const agentId = c.get("agentId") as string;
  const agent = c.get("agent") as typeof schema.agents.$inferSelect;
  const body = await c.req.json().catch(() => ({})) as { chain?: string };
  const chain = (body.chain ?? "base") as SupportedChain;

  if (!SUPPORTED_CHAINS.includes(chain)) {
    return c.json({
      error: "unsupported_chain",
      supported: SUPPORTED_CHAINS,
      suggestion: "Use 'base' for lowest fees (USDC on Base)",
    }, 400);
  }

  // Return existing address if already generated for this agent+chain
  const existing = db.select()
    .from(schema.depositAddresses)
    .where(eq(schema.depositAddresses.agentId, agentId))
    .all()
    .find(a => a.chain === chain);

  if (existing) {
    const info = CHAIN_INFO[chain];
    return c.json({
      chain,
      address: existing.address,
      send_token: info.send_token,
      send_instructions: info.send_instructions,
      auto_swap: info.auto_swap,
      swap_fee: info.swap_fee,
      minimum: info.minimum,
      note: info.note,
      withdrawals: "USDC on Base only — all deposits converted to USD balance",
    });
  }

  // Request new address from wallet service
  let address: string | undefined;
  try {
    const resp = await fetch(`${WALLET_SERVICE_URL}/v1/wallet/internal/create`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Service-Key": WALLET_SERVICE_KEY!,
      },
      body: JSON.stringify({
        agent_id: agentId,
        chain,
        index: agent.depositIndex,
      }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      console.error(`[deposit-address] Wallet service error:`, err);
      return c.json({
        error: "wallet_service_error",
        message: "Failed to generate deposit address",
        suggestion: "Try again or contact support",
      }, 502);
    }

    const walletData = await resp.json() as { address?: string; addresses?: Array<{ chain: string; address: string }> | Record<string, string> };
    const addrList = Array.isArray(walletData.addresses) ? walletData.addresses : [];
    // EVM chains share same derived address — map bsc/arbitrum → ethereum key
    const evmChains = ["base", "ethereum", "bsc", "arbitrum"];
    const lookupChain = evmChains.includes(chain) ? "base" : chain;
    address = (walletData.addresses as Record<string, string>)?.[lookupChain]
           || (walletData.addresses as Record<string, string>)?.[chain]
           || addrList.find((a: any) => a.chain === lookupChain)?.address
           || addrList.find((a: any) => a.chain === chain)?.address
           || walletData.address;

    if (!address) {
      return c.json({
        error: "wallet_service_error",
        message: "Wallet service returned no address for this chain",
      }, 502);
    }
  } catch (err) {
    console.error(`[deposit-address] Wallet service unreachable:`, err);
    return c.json({
      error: "wallet_service_unavailable",
      message: "Wallet service is not reachable",
      suggestion: "Try again in a moment",
    }, 503);
  }

  // Store in deposit_addresses table
  db.insert(schema.depositAddresses).values({
    agentId,
    chain,
    address,
  }).run();

  const info = CHAIN_INFO[chain];
  return c.json({
    chain,
    address,
    send_token: info.send_token,
    send_instructions: info.send_instructions,
    auto_swap: info.auto_swap,
    swap_fee: info.swap_fee,
    minimum: info.minimum,
    note: info.note,
    withdrawals: "USDC on Base only — all deposits converted to USD balance",
  });
});

// ─── Supported chains info (public) ───

app.get("/supported-chains", (c) => {
  return c.json({
    chains: SUPPORTED_CHAINS.map(chain => ({
      chain,
      ...CHAIN_INFO[chain],
    })),
    note: "All deposits are converted to USD balance. Domains are priced in EUR (1 EUR = 1.08 USD).",
  });
});

// ─── List deposits ───

app.get("/deposits", agentAuth, (c) => {
  const agentId = c.get("agentId") as string;
  const agentDeposits = db.select()
    .from(schema.deposits)
    .where(eq(schema.deposits.agentId, agentId))
    .all();

  return c.json({
    total: agentDeposits.length,
    deposits: agentDeposits.map(d => ({
      id: d.id,
      chain: d.chain,
      token: d.token,
      amount_usd: Math.round(d.amountUsd * 100) / 100,
      swap_fee: d.swapFee,
      status: d.status,
      created_at: new Date(d.createdAt * 1000).toISOString(),
      credited_at: d.creditedAt ? new Date(d.creditedAt * 1000).toISOString() : null,
    })),
  });
});

// ─── Legacy stub deposit (kept for backward compatibility) ───

app.post("/deposit", agentAuth, async (c) => {
  return c.json({
    error: "deprecated",
    message: "Direct balance top-ups are no longer supported.",
    action: "POST /v1/auth/deposit-address { chain: 'base' } to get a USDC deposit address",
    supported_chains: SUPPORTED_CHAINS,
  }, 410);
});

export default app;
