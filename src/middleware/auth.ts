import { createHash } from "crypto";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { eq } from "drizzle-orm";
import type { Context, Next } from "hono";

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export async function agentAuth(c: Context, next: Next) {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) {
    return c.json({ error: "unauthorized", message: "Provide Authorization: Bearer <api_key>" }, 401);
  }
  const key = auth.slice(7);
  const hash = hashApiKey(key);
  const agent = db.select().from(schema.agents).where(eq(schema.agents.apiKeyHash, hash)).get();
  if (!agent) return c.json({ error: "invalid_key" }, 401);
  c.set("agentId", agent.id);
  c.set("agent", agent);
  return next();
}
