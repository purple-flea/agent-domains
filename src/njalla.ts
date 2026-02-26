/**
 * Njalla API client
 * Endpoint: https://njal.la/api/1/
 * Auth: Authorization: Njalla <token>
 */

const NJALLA_BASE = process.env.NJALLA_API_URL || "https://njal.la/api/1/";
const NJALLA_TOKEN = process.env.NJALLA_API_KEY || "";
if (!NJALLA_TOKEN) console.warn("[WARN] NJALLA_API_KEY not set — domain registration will fail");

// ─── TLD Pricing (USDC, includes 20% markup) ───

export const TLD_PRICES: Record<string, number> = {
  "com": 18,
  "net": 18,
  "org": 18,
  "io": 54,
  "ai": 102,
  "co": 36,
  "xyz": 14.40,
  "app": 24,
  "dev": 18,
  "vc": 72,
  "cx": 48,
  "club": 14.40,
  "site": 18,
  "online": 18,
  "tech": 42,
  "me": 24,
  "cc": 30,
  "info": 18,
  "biz": 18,
};

export function getTldPrice(domain: string): number | null {
  const parts = domain.split(".");
  if (parts.length < 2) return null;
  const tld = parts[parts.length - 1].toLowerCase();
  return TLD_PRICES[tld] ?? null;
}

export function getTldFromDomain(domain: string): string | null {
  const parts = domain.split(".");
  if (parts.length < 2) return null;
  return parts[parts.length - 1].toLowerCase();
}

// ─── Core JSON-RPC request ───

export interface NjallaError {
  code: number;
  message: string;
}

export interface NjallaResponse<T = any> {
  jsonrpc?: string;
  result?: T;
  error?: NjallaError;
  id?: string | number;
}

export async function njallaCall<T = any>(method: string, params: Record<string, any> = {}): Promise<T> {
  const res = await fetch(NJALLA_BASE, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Njalla ${NJALLA_TOKEN}`,
    },
    body: JSON.stringify({ method, params }),
  });

  if (!res.ok) {
    throw new Error(`Njalla HTTP error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json() as NjallaResponse<T>;

  if (data.error) {
    const err = new Error(`Njalla: ${data.error.message}`) as any;
    err.njallaCode = data.error.code;
    throw err;
  }

  return data.result as T;
}

// ─── Domain methods ───

export interface NjallaDomain {
  name: string;
  status: string;
  expiry?: string;
  autorenew?: boolean;
}

export async function listDomains(): Promise<NjallaDomain[]> {
  const result = await njallaCall<{ domains: NjallaDomain[] }>("list-domains", {});
  return result.domains ?? [];
}

export async function getDomain(domain: string): Promise<Record<string, any>> {
  return await njallaCall("get-domain", { domain });
}

export async function registerDomain(domain: string): Promise<any> {
  return await njallaCall("register-domain", { domain });
}

// ─── DNS Record methods ───

export interface NjallaRecord {
  id: string | number;
  name: string;
  type: string;
  content: string;
  ttl: number;
  prio?: number;
}

export async function listRecords(domain: string): Promise<NjallaRecord[]> {
  const result = await njallaCall<{ records: NjallaRecord[] }>("list-records", { domain });
  return result.records ?? [];
}

export async function addRecord(
  domain: string,
  type: string,
  name: string,
  content: string,
  ttl: number = 300
): Promise<NjallaRecord> {
  return await njallaCall<NjallaRecord>("add-record", { domain, type, name, content, ttl });
}

export async function removeRecord(domain: string, id: string | number): Promise<any> {
  return await njallaCall("remove-record", { domain, id });
}
