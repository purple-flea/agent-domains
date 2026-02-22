import { Hono } from "hono";
import { randomBytes } from "crypto";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { eq, and } from "drizzle-orm";
import { agentAuth } from "../middleware/auth.js";
import {
  addRecord as njallaAddRecord,
  editRecord as njallaEditRecord,
  removeRecord as njallaRemoveRecord,
  listRecords as njallaListRecords,
} from "../engine/njalla.js";
import type { AppEnv } from "../types.js";

const app = new Hono<AppEnv>();

app.use("/*", agentAuth);

const VALID_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT"];

function validateRecordContent(type: string, content: string): string | null {
  switch (type) {
    case "A": {
      const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipv4.test(content)) return "Invalid IPv4 address";
      const parts = content.split(".").map(Number);
      if (parts.some(p => p > 255)) return "Invalid IPv4 address";
      return null;
    }
    case "AAAA": {
      const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
      if (!ipv6.test(content)) return "Invalid IPv6 address";
      return null;
    }
    case "CNAME": {
      if (!content.includes(".")) return "CNAME must be a valid hostname";
      return null;
    }
    case "MX": {
      if (!content.includes(".")) return "MX must be a valid hostname";
      return null;
    }
    case "TXT": {
      if (content.length > 4096) return "TXT record too long (max 4096 chars)";
      return null;
    }
    default:
      return `Unsupported record type: ${type}`;
  }
}

// ─── Add DNS record ───
app.post("/records", async (c) => {
  const agentId = c.get("agentId") as string;
  const body = await c.req.json().catch(() => ({}));

  const domainId = body.domain_id as string;
  const recordType = (body.type as string)?.toUpperCase();
  const name = (body.name as string) || "@";
  const content = body.content as string;
  const ttl = (body.ttl as number) || 3600;
  const priority = body.priority as number | undefined;

  if (!domainId) {
    return c.json({ error: "missing_domain_id", message: "Provide domain_id" }, 400);
  }

  if (!recordType || !VALID_RECORD_TYPES.includes(recordType)) {
    return c.json({
      error: "invalid_record_type",
      message: `Record type must be one of: ${VALID_RECORD_TYPES.join(", ")}`,
    }, 400);
  }

  if (!content) {
    return c.json({ error: "missing_content", message: "Provide content (IP address, hostname, etc.)" }, 400);
  }

  // Validate content format
  const validationError = validateRecordContent(recordType, content);
  if (validationError) {
    return c.json({ error: "invalid_content", message: validationError }, 400);
  }

  if (ttl < 60 || ttl > 86400) {
    return c.json({ error: "invalid_ttl", message: "TTL must be between 60 and 86400 seconds" }, 400);
  }

  // Verify domain belongs to agent
  const domain = db.select().from(schema.domains)
    .where(and(eq(schema.domains.id, domainId), eq(schema.domains.agentId, agentId)))
    .get();

  if (!domain) {
    return c.json({ error: "not_found", message: "Domain not found or doesn't belong to you" }, 404);
  }

  // Add record via Njalla
  let njallaRecord;
  try {
    njallaRecord = await njallaAddRecord(domain.domainName, recordType, name, content, ttl, priority);
  } catch (err: any) {
    return c.json({ error: "dns_add_failed", message: err.message }, 500);
  }

  // Store locally
  const recordId = `rec_${randomBytes(8).toString("hex")}`;
  db.insert(schema.dnsRecords).values({
    id: recordId,
    domainId,
    agentId,
    recordType,
    name,
    content,
    ttl,
    njallaRecordId: njallaRecord.id || null,
  }).run();

  return c.json({
    record_id: recordId,
    domain: domain.domainName,
    type: recordType,
    name,
    content,
    ttl,
    ...(priority !== undefined ? { priority } : {}),
    message: `${recordType} record added to ${domain.domainName}`,
  }, 201);
});

// ─── List DNS records for a domain ───
app.get("/records", async (c) => {
  const agentId = c.get("agentId") as string;
  const domainId = c.req.query("domain_id");

  if (!domainId) {
    return c.json({ error: "missing_domain_id", message: "Provide ?domain_id=..." }, 400);
  }

  // Verify domain belongs to agent
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
    domain: domain.domainName,
    domain_id: domainId,
    total: records.length,
    records: records.map(r => ({
      record_id: r.id,
      type: r.recordType,
      name: r.name,
      content: r.content,
      ttl: r.ttl,
    })),
  });
});

// ─── Edit DNS record ───
app.put("/records/:recordId", async (c) => {
  const agentId = c.get("agentId") as string;
  const recordId = c.req.param("recordId");
  const body = await c.req.json().catch(() => ({}));

  const content = body.content as string;
  const ttl = body.ttl as number | undefined;

  if (!content) {
    return c.json({ error: "missing_content", message: "Provide content to update" }, 400);
  }

  // Find the record
  const record = db.select().from(schema.dnsRecords)
    .where(and(eq(schema.dnsRecords.id, recordId), eq(schema.dnsRecords.agentId, agentId)))
    .get();

  if (!record) {
    return c.json({ error: "not_found", message: "DNS record not found or doesn't belong to you" }, 404);
  }

  // Validate content
  const validationError = validateRecordContent(record.recordType, content);
  if (validationError) {
    return c.json({ error: "invalid_content", message: validationError }, 400);
  }

  if (ttl !== undefined && (ttl < 60 || ttl > 86400)) {
    return c.json({ error: "invalid_ttl", message: "TTL must be between 60 and 86400 seconds" }, 400);
  }

  // Get domain name for Njalla
  const domain = db.select().from(schema.domains)
    .where(eq(schema.domains.id, record.domainId))
    .get();

  if (!domain) {
    return c.json({ error: "domain_not_found" }, 404);
  }

  // Update via Njalla
  if (record.njallaRecordId) {
    try {
      await njallaEditRecord(domain.domainName, record.njallaRecordId, content, ttl);
    } catch (err: any) {
      return c.json({ error: "dns_edit_failed", message: err.message }, 500);
    }
  }

  // Update locally
  db.update(schema.dnsRecords).set({
    content,
    ttl: ttl || record.ttl,
    updatedAt: Math.floor(Date.now() / 1000),
  }).where(eq(schema.dnsRecords.id, recordId)).run();

  return c.json({
    record_id: recordId,
    domain: domain.domainName,
    type: record.recordType,
    name: record.name,
    content,
    ttl: ttl || record.ttl,
    message: "DNS record updated",
  });
});

// ─── Delete DNS record ───
app.delete("/records/:recordId", async (c) => {
  const agentId = c.get("agentId") as string;
  const recordId = c.req.param("recordId");

  const record = db.select().from(schema.dnsRecords)
    .where(and(eq(schema.dnsRecords.id, recordId), eq(schema.dnsRecords.agentId, agentId)))
    .get();

  if (!record) {
    return c.json({ error: "not_found", message: "DNS record not found or doesn't belong to you" }, 404);
  }

  const domain = db.select().from(schema.domains)
    .where(eq(schema.domains.id, record.domainId))
    .get();

  if (!domain) {
    return c.json({ error: "domain_not_found" }, 404);
  }

  // Remove via Njalla
  if (record.njallaRecordId) {
    try {
      await njallaRemoveRecord(domain.domainName, record.njallaRecordId);
    } catch (err: any) {
      return c.json({ error: "dns_delete_failed", message: err.message }, 500);
    }
  }

  // Remove locally
  db.delete(schema.dnsRecords).where(eq(schema.dnsRecords.id, recordId)).run();

  return c.json({
    deleted: true,
    record_id: recordId,
    domain: domain.domainName,
    message: `${record.recordType} record for ${record.name} deleted`,
  });
});

export default app;
