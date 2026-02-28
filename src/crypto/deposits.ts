import { randomUUID } from "crypto";
import { randomBytes } from "crypto";
import { ethers } from "ethers";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { eq, sql, and, isNotNull } from "drizzle-orm";
import { getUsdcBalance, TREASURY_ADDRESS, ensureGasForSweep } from "./chain.js";

// ─── Config ───

const WALLET_SERVICE_URL = process.env.WALLET_SERVICE_URL || "http://localhost:3002";
const WALLET_SERVICE_KEY = process.env.WALLET_SERVICE_KEY;
if (!WALLET_SERVICE_KEY) console.warn("[WARN] WALLET_SERVICE_KEY not set — deposit sweeps will fail");
const WAGYU_API_KEY = process.env.WAGYU_API_KEY || "";
if (!WAGYU_API_KEY) console.warn("[WARN] WAGYU_API_KEY not set — Wagyu swap orders will fail");

const POLL_INTERVAL_MS = 60_000;          // 60 seconds — Base USDC
const NON_BASE_POLL_INTERVAL_MS = 90_000; // 90 seconds — non-Base chains
const WAGYU_POLL_INTERVAL_MS = 30_000;    // 30 seconds — pending Wagyu swaps
const MIN_DEPOSIT_USD = 0.50;

// ─── Supported non-Base deposit chains ───

export const SUPPORTED_DEPOSIT_CHAINS = [
  "ethereum", "bsc", "arbitrum", "solana", "bitcoin", "tron", "monero",
] as const;

type NonBaseChain = typeof SUPPORTED_DEPOSIT_CHAINS[number];

// EVM chains with full Wagyu auto-swap support
const EVM_SWAP_CHAINS: NonBaseChain[] = ["ethereum", "bsc", "arbitrum"];

// RPC URLs for non-Base EVM chains
const EVM_RPC: Record<string, string> = {
  ethereum: "https://eth.llamarpc.com",
  bsc: "https://bsc-dataseed.binance.org",
  arbitrum: "https://arb1.arbitrum.io/rpc",
};

// ERC-20 token addresses on non-Base EVM chains
const EVM_TOKENS: Record<string, Record<string, string>> = {
  ethereum: {
    USDC: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    USDT: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  },
  bsc: {
    USDT: "0x55d398326f99059fF775485246999027B3197955",
    USDC: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
  },
  arbitrum: {
    USDC: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    USDT: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
  },
};

// Wagyu chain IDs
const WAGYU_CHAIN_IDS: Record<string, number> = {
  ethereum: 1,
  bsc: 56,
  base: 8453,
  arbitrum: 42161,
  solana: 1151111081099710,
  bitcoin: 20000000000001,
  monero: 0,
};

// Base USDC address (Wagyu destination token)
const BASE_USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

// Minimum raw deposit thresholds per chain (to filter dust)
const MIN_NATIVE_WEI = ethers.parseEther("0.002"); // 0.002 ETH/BNB
const MIN_ERC20_RAW = 500000n; // 0.5 USDC/USDT (6 decimals)

// ─── EVM deposit detection ───

const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
];

interface EvmDepositInfo {
  amountRaw: bigint;
  token: string;
  tokenAddress: string;
  decimals: number;
  amountUsd: number;
}

async function detectEvmDeposit(chain: string, address: string): Promise<EvmDepositInfo | null> {
  try {
    const provider = new ethers.JsonRpcProvider(EVM_RPC[chain]);

    const tokens = EVM_TOKENS[chain] ?? {};
    for (const [symbol, tokenAddr] of Object.entries(tokens)) {
      const contract = new ethers.Contract(tokenAddr, ERC20_ABI, provider);
      const balance: bigint = await contract.balanceOf(address);
      if (balance >= MIN_ERC20_RAW) {
        const amountUsd = Number(balance) / 1e6;
        return { amountRaw: balance, token: symbol, tokenAddress: tokenAddr, decimals: 6, amountUsd };
      }
    }

    const nativeBalance = await provider.getBalance(address);
    if (nativeBalance >= MIN_NATIVE_WEI) {
      const nativeToken = chain === "bsc" ? "BNB" : "ETH";
      const priceUsd = await getNativeTokenPrice(nativeToken);
      const amountUsd = parseFloat(ethers.formatEther(nativeBalance)) * priceUsd;
      if (amountUsd >= MIN_DEPOSIT_USD) {
        return { amountRaw: nativeBalance, token: nativeToken, tokenAddress: "native", decimals: 18, amountUsd };
      }
    }

    return null;
  } catch (err) {
    console.error(`[deposit-monitor] EVM balance check failed for ${chain}:${address}:`, (err as Error).message);
    return null;
  }
}

// ─── Bitcoin deposit detection ───

async function detectBitcoinDeposit(address: string): Promise<number | null> {
  try {
    const res = await fetch(`https://mempool.space/api/address/${address}`, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return null;
    const data = await res.json() as any;
    const sats =
      (data.chain_stats?.funded_txo_sum ?? 0) - (data.chain_stats?.spent_txo_sum ?? 0) +
      (data.mempool_stats?.funded_txo_sum ?? 0) - (data.mempool_stats?.spent_txo_sum ?? 0);
    return sats / 1e8;
  } catch {
    return null;
  }
}

// ─── Solana deposit detection ───

async function detectSolanaDeposit(address: string): Promise<number | null> {
  try {
    const res = await fetch("https://api.mainnet-beta.solana.com", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getBalance", params: [address] }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const data = await res.json() as any;
    return (data.result?.value ?? 0) / 1e9;
  } catch {
    return null;
  }
}

// ─── Tron deposit detection (USDT TRC-20) ───

async function detectTronDeposit(address: string): Promise<number | null> {
  try {
    const balRes = await fetch(`https://api.trongrid.io/v1/accounts/${address}`, { signal: AbortSignal.timeout(10_000) });
    if (!balRes.ok) return null;
    const balData = await balRes.json() as any;
    const trc20 = balData.data?.[0]?.trc20 ?? [];
    const usdt = trc20.find((t: any) => t["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"]);
    if (!usdt) return null;
    return Number(usdt["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"]) / 1e6;
  } catch {
    return null;
  }
}

// ─── Price fetching (for native tokens) ───

const _priceCache: Record<string, { price: number; fetchedAt: number }> = {};
const PRICE_CACHE_TTL = 5 * 60 * 1000; // 5 min

async function getNativeTokenPrice(symbol: string): Promise<number> {
  const cached = _priceCache[symbol];
  if (cached && Date.now() - cached.fetchedAt < PRICE_CACHE_TTL) return cached.price;

  const coinMap: Record<string, string> = { ETH: "ethereum", BNB: "binancecoin", SOL: "solana", BTC: "bitcoin" };
  const coinId = coinMap[symbol];
  if (!coinId) return 0;

  try {
    const res = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${coinId}&vs_currencies=usd`, {
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return _priceCache[symbol]?.price ?? 0;
    const data = await res.json() as any;
    const price = data[coinId]?.usd ?? 0;
    _priceCache[symbol] = { price, fetchedAt: Date.now() };
    return price;
  } catch {
    return _priceCache[symbol]?.price ?? 0;
  }
}

// ─── Wagyu swap API ───

interface WagyuOrder {
  orderId: string;
  depositAddress: string;
  depositChain: string;
  depositToken: string;
  depositTokenSymbol: string;
  depositAmount: string;
  expectedOutput: string;
  expiresAt: string;
  status: string;
}

async function createWagyuOrder(
  fromChain: string,
  fromToken: string,
  fromAmountRaw: bigint,
): Promise<WagyuOrder | null> {
  const fromChainId = WAGYU_CHAIN_IDS[fromChain];
  if (fromChainId === undefined) {
    console.error(`[wagyu] No chain ID for ${fromChain}`);
    return null;
  }

  try {
    const body = {
      fromChainId,
      toChainId: WAGYU_CHAIN_IDS.base,
      fromToken,
      toToken: BASE_USDC_ADDRESS,
      fromAmount: fromAmountRaw.toString(),
      toAddress: TREASURY_ADDRESS,
    };

    const res = await fetch("https://api.wagyu.xyz/v1/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(WAGYU_API_KEY ? { "X-API-KEY": WAGYU_API_KEY } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`[wagyu] Order creation failed (${res.status}): ${errText}`);
      return null;
    }

    return await res.json() as WagyuOrder;
  } catch (err) {
    console.error(`[wagyu] Order creation error:`, (err as Error).message);
    return null;
  }
}

async function checkWagyuStatus(orderId: string): Promise<{ status: string; outputAmount?: string } | null> {
  try {
    const res = await fetch(`https://api.wagyu.xyz/v1/order/${orderId}`, {
      headers: WAGYU_API_KEY ? { "X-API-KEY": WAGYU_API_KEY } : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const data = await res.json() as any;
    return { status: data.status, outputAmount: data.outputAmount ?? data.expectedOutput };
  } catch {
    return null;
  }
}

// ─── Wallet service sweep ───

async function sweepViaWalletService(
  agentId: string,
  chain: string,
  toAddress: string,
  token: string,
  amountRaw: bigint,
): Promise<boolean> {
  try {
    const resp = await fetch(`${WALLET_SERVICE_URL}/v1/wallet/sweep`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Service-Key": WALLET_SERVICE_KEY!,
      },
      body: JSON.stringify({
        agent_id: agentId,
        chain,
        to_address: toAddress,
        token,
        amount: amountRaw.toString(),
      }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({})) as any;
      console.error(`[sweep] Wallet service sweep failed for ${agentId} on ${chain}:`, err.error ?? err.message);
      return false;
    }

    return true;
  } catch (err) {
    console.error(`[sweep] Wallet service unreachable:`, (err as Error).message);
    return false;
  }
}

// ─── Credit deposit to agent balance ───

function creditDeposit(
  agentId: string,
  depositId: string,
  chain: string,
  token: string,
  amountRaw: number,
  amountUsd: number,
  swapFee: number,
  txHash: string,
  wagyuTx?: string,
): void {
  const existing = db.select({ id: schema.deposits.id })
    .from(schema.deposits)
    .where(eq(schema.deposits.id, depositId))
    .get();

  if (existing) {
    db.update(schema.deposits)
      .set({ status: "credited", creditedAt: Math.floor(Date.now() / 1000) })
      .where(eq(schema.deposits.id, depositId))
      .run();
  } else {
    db.insert(schema.deposits).values({
      id: depositId,
      agentId,
      chain,
      token,
      amountRaw,
      amountUsd,
      swapFee,
      txHash,
      wagyuTx,
      status: "credited",
      confirmations: 1,
      creditedAt: Math.floor(Date.now() / 1000),
    }).run();
  }

  // Get current balance before update (for transaction record)
  const agentBefore = db.select({ balanceUsd: schema.agents.balanceUsd })
    .from(schema.agents)
    .where(eq(schema.agents.id, agentId))
    .get();

  const newBalance = Math.round(((agentBefore?.balanceUsd ?? 0) + amountUsd) * 100) / 100;

  db.update(schema.agents)
    .set({
      balanceUsd: sql`${schema.agents.balanceUsd} + ${amountUsd}`,
      totalDeposited: sql`${schema.agents.totalDeposited} + ${amountUsd}`,
    })
    .where(eq(schema.agents.id, agentId))
    .run();

  // Record in transactions table
  const txId = `tx_${randomBytes(8).toString("hex")}`;
  db.insert(schema.transactions).values({
    id: txId,
    agentId,
    type: "deposit",
    amount: amountUsd,
    balanceAfter: newBalance,
    description: `Deposit via ${chain} ${token}: $${amountUsd.toFixed(2)}`,
  }).run();

  console.log(`[deposit-monitor] Credited $${amountUsd.toFixed(2)} (${chain} ${token}) to ${agentId}`);
}

// ─── Poll Base USDC deposits ───

let baseRunning = false;

async function pollBaseDeposits(): Promise<void> {
  if (baseRunning) return;
  baseRunning = true;

  try {
    const addresses = db
      .select()
      .from(schema.depositAddresses)
      .where(eq(schema.depositAddresses.chain, "base"))
      .all();

    for (const addr of addresses) {
      try {
        const balance = await getUsdcBalance(addr.address);

        if (balance < MIN_DEPOSIT_USD) continue;

        // Deduplicate: check if we already credited this balance
        const existingCreditedDeposit = db
          .select()
          .from(schema.deposits)
          .where(
            and(
              eq(schema.deposits.agentId, addr.agentId),
              eq(schema.deposits.chain, "base"),
              eq(schema.deposits.status, "credited"),
            )
          )
          .all()
          .find((d) => Math.abs(d.amountUsd - balance) < 0.01);

        if (existingCreditedDeposit) continue;

        const depositId = `dep_${randomUUID().slice(0, 12)}`;
        const amountUsd = Math.round(balance * 100) / 100;

        creditDeposit(addr.agentId, depositId, "base", "USDC", balance, amountUsd, 0, `poll_${Date.now()}`);

        console.log(`[deposit-monitor] Credited $${amountUsd} USDC to ${addr.agentId} from ${addr.address}`);

        // Ensure gas for sweep, then sweep to treasury
        try {
          await ensureGasForSweep(addr.address);
        } catch (gasErr) {
          console.warn(`[deposit-monitor] Gas top-up failed for ${addr.address}: ${(gasErr as Error).message}`);
        }

        try {
          await fetch(`${WALLET_SERVICE_URL}/v1/wallet/sweep`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Service-Key": WALLET_SERVICE_KEY!,
            },
            body: JSON.stringify({
              from_address: addr.address,
              to_address: TREASURY_ADDRESS,
              chain: "base",
              token: "USDC",
            }),
          });
          console.log(`[deposit-monitor] Sweep requested for ${addr.address} → treasury`);
        } catch (sweepErr) {
          console.error(`[deposit-monitor] SWEEP FAILED for ${addr.address} — manual sweep required: ${(sweepErr as Error).message}`);
        }
      } catch (addrErr) {
        console.error(`[deposit-monitor] Error checking ${addr.address}:`, addrErr);
      }
    }
  } catch (err) {
    console.error("[deposit-monitor] Base poll error:", err);
  } finally {
    baseRunning = false;
  }
}

// ─── Poll non-Base chains ───

let nonBaseRunning = false;

async function pollNonBaseDeposits(): Promise<void> {
  if (nonBaseRunning) return;
  nonBaseRunning = true;

  try {
    for (const chain of SUPPORTED_DEPOSIT_CHAINS) {
      const addresses = db
        .select()
        .from(schema.depositAddresses)
        .where(eq(schema.depositAddresses.chain, chain))
        .all();

      for (const addr of addresses) {
        try {
          await detectAndQueueDeposit(chain, addr.agentId, addr.address);
        } catch (err) {
          console.error(`[deposit-monitor] Error checking ${chain}:${addr.address}:`, (err as Error).message);
        }
      }
    }
  } catch (err) {
    console.error("[deposit-monitor] Non-base poll error:", err);
  } finally {
    nonBaseRunning = false;
  }
}

async function detectAndQueueDeposit(chain: NonBaseChain, agentId: string, address: string): Promise<void> {
  // ── EVM chains (ethereum, bsc, arbitrum) ──
  if (EVM_SWAP_CHAINS.includes(chain as any)) {
    const deposit = await detectEvmDeposit(chain, address);
    if (!deposit || deposit.amountUsd < MIN_DEPOSIT_USD) return;

    const existing = db
      .select()
      .from(schema.deposits)
      .where(and(
        eq(schema.deposits.agentId, agentId),
        eq(schema.deposits.chain, chain),
      ))
      .all()
      .find((d) => Math.abs(d.amountRaw - Number(deposit.amountRaw)) < Number(deposit.amountRaw) * 0.01);

    if (existing) return;

    console.log(`[deposit-monitor] Detected ${ethers.formatUnits(deposit.amountRaw, deposit.decimals)} ${deposit.token} on ${chain} for ${agentId}`);

    const order = await createWagyuOrder(
      chain,
      deposit.tokenAddress === "native" ? deposit.token : deposit.tokenAddress,
      deposit.amountRaw,
    );

    if (!order) {
      console.error(`[deposit-monitor] Failed to create Wagyu order for ${agentId} ${chain} deposit`);
      return;
    }

    const depositId = `dep_${randomUUID().slice(0, 12)}`;
    const expectedUsd = Number(order.expectedOutput) / 1e6;
    const swapFee = Math.max(0, deposit.amountUsd - expectedUsd);

    db.insert(schema.deposits).values({
      id: depositId,
      agentId,
      chain,
      token: deposit.token,
      amountRaw: Number(deposit.amountRaw),
      amountUsd: expectedUsd,
      swapFee: Math.round(swapFee * 100) / 100,
      txHash: `wagyu_order_${order.orderId}`,
      wagyuTx: order.orderId,
      status: "pending",
      confirmations: 0,
    }).run();

    console.log(`[deposit-monitor] Wagyu order ${order.orderId} created — sweeping ${deposit.token} to Wagyu`);

    await sweepViaWalletService(
      agentId,
      chain,
      order.depositAddress,
      deposit.tokenAddress === "native" ? deposit.token : deposit.tokenAddress,
      deposit.amountRaw,
    );

    return;
  }

  // ── Bitcoin ──
  if (chain === "bitcoin") {
    const btcAmount = await detectBitcoinDeposit(address);
    if (btcAmount === null || btcAmount < 0.00005) return;
    const priceUsd = await getNativeTokenPrice("BTC");
    const amountUsd = btcAmount * priceUsd;
    if (amountUsd < MIN_DEPOSIT_USD) return;

    const existing = db.select().from(schema.deposits)
      .where(and(eq(schema.deposits.agentId, agentId), eq(schema.deposits.chain, "bitcoin")))
      .all().find(d => Math.abs(d.amountRaw - btcAmount) < btcAmount * 0.01);
    if (existing) return;

    console.log(`[deposit-monitor] BTC deposit detected: ${btcAmount} BTC (~$${amountUsd.toFixed(2)}) for ${agentId}`);
    db.insert(schema.deposits).values({
      id: `dep_${randomUUID().slice(0, 12)}`,
      agentId,
      chain: "bitcoin",
      token: "BTC",
      amountRaw: btcAmount,
      amountUsd: Math.round(amountUsd * 100) / 100,
      swapFee: 0,
      txHash: `pending_btc_${Date.now()}`,
      status: "pending",
      confirmations: 0,
    }).run();
    return;
  }

  // ── Solana ──
  if (chain === "solana") {
    const solAmount = await detectSolanaDeposit(address);
    if (solAmount === null || solAmount < 0.01) return;
    const priceUsd = await getNativeTokenPrice("SOL");
    const amountUsd = solAmount * priceUsd;
    if (amountUsd < MIN_DEPOSIT_USD) return;

    const existing = db.select().from(schema.deposits)
      .where(and(eq(schema.deposits.agentId, agentId), eq(schema.deposits.chain, "solana")))
      .all().find(d => Math.abs(d.amountRaw - solAmount) < solAmount * 0.01);
    if (existing) return;

    console.log(`[deposit-monitor] SOL deposit detected: ${solAmount} SOL (~$${amountUsd.toFixed(2)}) for ${agentId}`);
    db.insert(schema.deposits).values({
      id: `dep_${randomUUID().slice(0, 12)}`,
      agentId,
      chain: "solana",
      token: "SOL",
      amountRaw: solAmount,
      amountUsd: Math.round(amountUsd * 100) / 100,
      swapFee: 0,
      txHash: `pending_sol_${Date.now()}`,
      status: "pending",
      confirmations: 0,
    }).run();
    return;
  }

  // ── Tron (USDT TRC-20) ──
  if (chain === "tron") {
    const usdtAmount = await detectTronDeposit(address);
    if (usdtAmount === null || usdtAmount < MIN_DEPOSIT_USD) return;

    const existing = db.select().from(schema.deposits)
      .where(and(eq(schema.deposits.agentId, agentId), eq(schema.deposits.chain, "tron")))
      .all().find(d => Math.abs(d.amountRaw - usdtAmount) < usdtAmount * 0.01);
    if (existing) return;

    console.log(`[deposit-monitor] USDT TRC-20 deposit detected: $${usdtAmount} for ${agentId}`);
    db.insert(schema.deposits).values({
      id: `dep_${randomUUID().slice(0, 12)}`,
      agentId,
      chain: "tron",
      token: "USDT",
      amountRaw: usdtAmount,
      amountUsd: Math.round(usdtAmount * 100) / 100,
      swapFee: 0,
      txHash: `pending_tron_${Date.now()}`,
      status: "pending",
      confirmations: 0,
    }).run();
    return;
  }

  // ── Monero — handled via separate XMR sync; skip polling here ──
}

// ─── Poll pending Wagyu swap orders ───

let wagyuRunning = false;

async function checkPendingWagyuSwaps(): Promise<void> {
  if (wagyuRunning) return;
  wagyuRunning = true;

  try {
    const pending = db
      .select()
      .from(schema.deposits)
      .where(
        and(
          eq(schema.deposits.status, "pending"),
          isNotNull(schema.deposits.wagyuTx),
        )
      )
      .all()
      .filter(d => d.wagyuTx != null && !d.wagyuTx.startsWith("pending_"));

    for (const deposit of pending) {
      try {
        const statusResult = await checkWagyuStatus(deposit.wagyuTx!);
        if (!statusResult) continue;

        const { status, outputAmount } = statusResult;

        if (status === "completed" || status === "success") {
          const usdReceived = outputAmount
            ? Math.round((Number(outputAmount) / 1e6) * 100) / 100
            : deposit.amountUsd;

          const swapFee = Math.max(0, Math.round((deposit.amountUsd - usdReceived) * 100) / 100);

          creditDeposit(
            deposit.agentId,
            deposit.id,
            deposit.chain,
            deposit.token,
            deposit.amountRaw,
            usdReceived,
            swapFee,
            deposit.txHash ?? "",
            deposit.wagyuTx ?? undefined,
          );

          console.log(`[wagyu] Swap ${deposit.wagyuTx} completed — credited $${usdReceived} to ${deposit.agentId}`);

        } else if (status === "failed" || status === "expired" || status === "refunded") {
          console.warn(`[wagyu] Swap ${deposit.wagyuTx} ${status} — marking deposit as failed`);
          db.update(schema.deposits)
            .set({ status: "failed" })
            .where(eq(schema.deposits.id, deposit.id))
            .run();
        }
      } catch (err) {
        console.error(`[wagyu] Status check error for ${deposit.wagyuTx}:`, (err as Error).message);
      }
    }
  } catch (err) {
    console.error("[wagyu] Pending swap check error:", err);
  } finally {
    wagyuRunning = false;
  }
}

// ─── Timer handles ───

let baseTimer: ReturnType<typeof setInterval> | null = null;
let nonBaseTimer: ReturnType<typeof setInterval> | null = null;
let wagyuTimer: ReturnType<typeof setInterval> | null = null;

// ─── Start the deposit monitor ───

export function startDepositMonitor(): void {
  console.log(`[deposit-monitor] Starting — polling Base USDC every ${POLL_INTERVAL_MS / 1000}s`);
  console.log(`[deposit-monitor] Non-Base chains: ${SUPPORTED_DEPOSIT_CHAINS.join(", ")} — polling every ${NON_BASE_POLL_INTERVAL_MS / 1000}s`);

  setTimeout(() => pollBaseDeposits(), 10_000);
  baseTimer = setInterval(pollBaseDeposits, POLL_INTERVAL_MS);

  setTimeout(() => pollNonBaseDeposits(), 30_000);
  nonBaseTimer = setInterval(pollNonBaseDeposits, NON_BASE_POLL_INTERVAL_MS);

  setTimeout(() => checkPendingWagyuSwaps(), 20_000);
  wagyuTimer = setInterval(checkPendingWagyuSwaps, WAGYU_POLL_INTERVAL_MS);
}

// ─── Stop the deposit monitor ───

export function stopDepositMonitor(): void {
  [baseTimer, nonBaseTimer, wagyuTimer].forEach(t => t && clearInterval(t));
  baseTimer = nonBaseTimer = wagyuTimer = null;
  console.log("[deposit-monitor] Stopped");
}
