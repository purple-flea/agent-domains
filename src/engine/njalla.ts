/**
 * Njalla API client
 * Base URL: https://njal.la/api/1/
 *
 * Njalla uses JSON-RPC 2.0. All requests are POST to the base URL.
 * Auth is via Authorization: Njalla <token> header.
 * Prices from Njalla are in EUR.
 */

const NJALLA_BASE = "https://njal.la/api/1/";
const NJALLA_TOKEN = process.env.NJALLA_API_KEY || "b6bbc702ef3f18ee67c4923fbc3b2e48851e5cbc";

const MARKUP_RATE = 0.20; // 20% markup on domain costs

export interface NjallaResponse {
  jsonrpc: string;
  result?: any;
  error?: { code: number; message: string };
  id?: string;
}

async function njallaRequest(method: string, params: Record<string, any> = {}): Promise<NjallaResponse> {
  const body = { method, params };

  const res = await fetch(NJALLA_BASE, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Njalla ${NJALLA_TOKEN}`,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(`Njalla API error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json() as NjallaResponse;

  if (data.error) {
    throw new Error(`Njalla: ${data.error.message} (code: ${data.error.code})`);
  }

  return data;
}

// ─── Domain Search & Availability ───

export interface DomainSearchResult {
  name: string;
  status: "available" | "unavailable";
  price?: number;
  priceWithMarkup?: number;
  currency?: string;
}

/**
 * Search for domains using Njalla's find-domains method.
 * If query includes a TLD (e.g. "example.com"), returns that specific domain.
 * If query is just a name (e.g. "example"), returns results across all TLDs.
 */
export async function searchDomains(query: string): Promise<DomainSearchResult[]> {
  const data = await njallaRequest("find-domains", { query });
  const domains = data.result?.domains || [];

  return domains.map((d: any) => {
    const price = d.price ? Number(d.price) : undefined;
    const priceWithMarkup = price ? Math.round(price * (1 + MARKUP_RATE) * 100) / 100 : undefined;

    return {
      name: d.name,
      status: d.status === "available" ? "available" as const : "unavailable" as const,
      price,
      priceWithMarkup,
      currency: "EUR",
    };
  });
}

export async function checkAvailability(domain: string): Promise<{ available: boolean; price?: number; priceWithMarkup?: number }> {
  // Use find-domains with the specific domain (includes TLD) for a targeted check
  const results = await searchDomains(domain);
  const match = results.find(r => r.name === domain.toLowerCase());

  if (!match) {
    return { available: false };
  }

  return {
    available: match.status === "available",
    price: match.price,
    priceWithMarkup: match.priceWithMarkup,
  };
}

// ─── Domain Registration ───

export interface RegisterResult {
  domain: string;
  taskId?: string;
}

export async function registerDomain(domain: string): Promise<RegisterResult> {
  const data = await njallaRequest("register-domain", { domain });
  return {
    domain,
    taskId: data.result,
  };
}

// ─── List Domains ───

export interface NjallaDomain {
  name: string;
  status: string;
  expiry?: string;
  autorenew?: boolean;
}

export async function listDomains(): Promise<NjallaDomain[]> {
  const data = await njallaRequest("list-domains");
  const domains = data.result?.domains || [];

  return domains.map((d: any) => ({
    name: d.name,
    status: d.status,
    expiry: d.expiry,
    autorenew: d.autorenew,
  }));
}

export async function getDomainInfo(domain: string): Promise<any> {
  const data = await njallaRequest("get-domain", { domain });
  return data.result;
}

// ─── DNS Record Management ───

export interface DnsRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  ttl: number;
  priority?: number;
}

export async function listRecords(domain: string): Promise<DnsRecord[]> {
  const data = await njallaRequest("list-records", { domain });
  const records = data.result?.records || [];

  return records.map((r: any) => ({
    id: String(r.id),
    type: r.type,
    name: r.name || "@",
    content: r.content,
    ttl: r.ttl || 3600,
    priority: r.prio || r.priority,
  }));
}

export async function addRecord(
  domain: string,
  type: string,
  name: string,
  content: string,
  ttl: number = 3600,
  priority?: number
): Promise<DnsRecord> {
  const params: Record<string, any> = { domain, type, name, content, ttl };
  if (priority !== undefined) params.prio = priority;

  const data = await njallaRequest("add-record", params);
  const result = data.result;

  return {
    id: result?.id ? String(result.id) : "",
    type,
    name,
    content,
    ttl,
    priority,
  };
}

export async function editRecord(
  domain: string,
  recordId: string,
  content: string,
  ttl?: number
): Promise<DnsRecord> {
  const params: Record<string, any> = { domain, id: recordId, content };
  if (ttl !== undefined) params.ttl = ttl;

  const data = await njallaRequest("edit-record", params);
  const result = data.result;

  return {
    id: recordId,
    type: result?.type || "",
    name: result?.name || "",
    content,
    ttl: ttl || result?.ttl || 3600,
  };
}

export async function removeRecord(domain: string, recordId: string): Promise<boolean> {
  await njallaRequest("remove-record", { domain, id: recordId });
  return true;
}

// ─── Pricing ───

export function applyMarkup(basePrice: number): number {
  return Math.round(basePrice * (1 + MARKUP_RATE) * 100) / 100;
}

export function getMarkupAmount(basePrice: number): number {
  return Math.round(basePrice * MARKUP_RATE * 100) / 100;
}

export const MARKUP_PERCENTAGE = MARKUP_RATE * 100;
