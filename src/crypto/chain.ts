import { ethers } from "ethers";

// ─── Constants ───

export const BASE_RPC = "https://mainnet.base.org";
export const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const TREASURY_ADDRESS = "0x632881b5f5384e872d8b701dd23f08e63a52faee";
export const USDC_DECIMALS = 6;

// Minimal ERC-20 ABI for balanceOf + transfer
const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
];

// ─── Provider ───

let _provider: ethers.JsonRpcProvider | null = null;

export function getProvider(): ethers.JsonRpcProvider {
  if (!_provider) {
    _provider = new ethers.JsonRpcProvider(BASE_RPC);
  }
  return _provider;
}

// ─── USDC Contract (read-only) ───

export function getUsdcContract(): ethers.Contract {
  return new ethers.Contract(USDC_ADDRESS, ERC20_ABI, getProvider());
}

// ─── USDC Contract (with signer, for treasury sends) ───

export function getTreasurySigner(): ethers.Wallet {
  const pk = process.env.TREASURY_PRIVATE_KEY;
  if (!pk) {
    throw new Error("TREASURY_PRIVATE_KEY env var not set");
  }
  return new ethers.Wallet(pk, getProvider());
}

export function getUsdcWithSigner(): ethers.Contract {
  return new ethers.Contract(USDC_ADDRESS, ERC20_ABI, getTreasurySigner());
}

// ─── Read USDC balance for an address (returns USD amount as number) ───

export async function getUsdcBalance(address: string): Promise<number> {
  const usdc = getUsdcContract();
  const raw: bigint = await usdc.balanceOf(address);
  return Number(raw) / 10 ** USDC_DECIMALS;
}

// ─── Send USDC from treasury to a destination address ───

export async function sendUsdc(
  toAddress: string,
  amountUsd: number
): Promise<{ txHash: string; amount: number }> {
  const usdc = getUsdcWithSigner();
  const rawAmount = BigInt(Math.floor(amountUsd * 10 ** USDC_DECIMALS));

  const tx = await usdc.transfer(toAddress, rawAmount);
  const receipt = await tx.wait();

  return {
    txHash: receipt.hash,
    amount: amountUsd,
  };
}

// ─── Ensure a Base deposit address has enough ETH for gas ───
// Sends 0.0002 ETH from treasury if address has < 0.0001 ETH

export async function ensureGasForSweep(depositAddress: string): Promise<void> {
  const provider = getProvider();
  const balance = await provider.getBalance(depositAddress);
  const MIN_ETH = ethers.parseEther("0.0001");

  if (balance >= MIN_ETH) return; // already has enough

  console.log(`[chain] ${depositAddress} has insufficient gas (${ethers.formatEther(balance)} ETH) — topping up`);

  const treasury = getTreasurySigner();
  const topUpAmount = ethers.parseEther("0.0002");

  // Check treasury has ETH to send
  const treasuryEthBal = await provider.getBalance(treasury.address);
  if (treasuryEthBal < topUpAmount) {
    console.warn(`[chain] Treasury ${treasury.address} has insufficient ETH for gas top-up`);
    return;
  }

  const tx = await treasury.sendTransaction({
    to: depositAddress,
    value: topUpAmount,
  });
  await tx.wait();
  console.log(`[chain] Topped up ${depositAddress} with 0.0002 ETH for gas (tx: ${tx.hash})`);
}
