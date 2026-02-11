/**
 * Hash-chained audit logging for tamper detection
 *
 * Each entry contains a SHA-256 hash of:
 * sequenceNumber + timestamp + tool + host + agent + verdict + previousHash
 *
 * First entry has previousHash = "GENESIS"
 * Chain verification detects any tampering or missing entries
 */

import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { PolicyContext, PolicyVerdict, SentinelMode, AuditEntry, AuditVerificationResult, AuditRow } from './types.js';
import { redactAndSerialize } from './redaction.js';

const GENESIS_HASH = 'GENESIS';

/**
 * Compute SHA-256 hash for an audit entry
 *
 * @param sequenceNumber - Entry sequence number
 * @param timestamp - Unix timestamp (ms)
 * @param tool - Tool name
 * @param host - Host identifier
 * @param agent - Agent identifier
 * @param verdict - Verdict (allowed/denied/asked)
 * @param previousHash - Hash of previous entry
 * @returns SHA-256 hash (hex)
 */
function computeHash(
  sequenceNumber: number,
  timestamp: number,
  tool: string,
  host: string,
  agent: string,
  verdict: string,
  previousHash: string,
): string {
  const data = `${sequenceNumber}|${timestamp}|${tool}|${host}|${agent}|${verdict}|${previousHash}`;
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Get the last audit sequence number
 *
 * @param db - Database connection
 * @returns Last sequence number (0 if no entries)
 */
function getLastSequenceNumber(db: Database.Database): number {
  const result = db.prepare('SELECT MAX(sequence_number) as seq FROM audit_log').get() as { seq: number | null };
  return result.seq ?? 0;
}

/**
 * Get the last audit entry hash
 *
 * @param db - Database connection
 * @returns Last entry hash (GENESIS if no entries)
 */
function getLastHash(db: Database.Database): string {
  const result = db.prepare('SELECT hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1').get() as { hash: string } | undefined;
  return result?.hash ?? GENESIS_HASH;
}

/**
 * Create a new audit entry (write-ahead logging)
 *
 * This should be called BEFORE forwarding the request to openclaw-mcp.
 * The responseStatus and errorMessage can be updated later via updateAuditEntry.
 *
 * @param db - Database connection
 * @param context - Policy evaluation context
 * @param verdict - Policy verdict
 * @param mode - Current sentinel mode
 * @returns Created audit entry
 */
export function createAuditEntry(
  db: Database.Database,
  context: PolicyContext,
  verdict: PolicyVerdict,
  mode: SentinelMode,
): AuditEntry {
  const sequenceNumber = getLastSequenceNumber(db) + 1;
  const previousHash = getLastHash(db);
  const timestamp = Date.now();

  // Determine verdict string
  const verdictStr = verdict.requiresConfirmation
    ? 'asked'
    : verdict.allowed
      ? 'allowed'
      : 'denied';

  // Compute hash
  const hash = computeHash(
    sequenceNumber,
    timestamp,
    context.tool,
    context.host,
    context.agent,
    verdictStr,
    previousHash,
  );

  // Redact and serialize arguments
  const argumentsJson = redactAndSerialize(context.arguments);
  const riskFactorsJson = JSON.stringify(verdict.riskFactors);

  // Insert entry
  const stmt = db.prepare(`
    INSERT INTO audit_log (
      sequence_number, timestamp, tool, host, agent, arguments, verdict, action,
      matched_rule_id, risk_score, risk_factors, mode, hash, previous_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const info = stmt.run(
    sequenceNumber,
    timestamp,
    context.tool,
    context.host,
    context.agent,
    argumentsJson,
    verdictStr,
    verdict.action,
    verdict.matchedRuleId ?? null,
    verdict.riskScore,
    riskFactorsJson,
    mode,
    hash,
    previousHash,
  );

  return {
    id: info.lastInsertRowid as number,
    sequenceNumber,
    timestamp,
    tool: context.tool,
    host: context.host,
    agent: context.agent,
    arguments: argumentsJson,
    verdict: verdictStr as 'allowed' | 'denied' | 'asked',
    action: verdict.action,
    matchedRuleId: verdict.matchedRuleId,
    riskScore: verdict.riskScore,
    riskFactors: riskFactorsJson,
    mode,
    hash,
    previousHash,
  };
}

/**
 * Update an audit entry with response status
 *
 * Called after forwarding to openclaw-mcp completes (or times out).
 *
 * @param db - Database connection
 * @param id - Audit entry ID
 * @param update - Fields to update
 */
export function updateAuditEntry(
  db: Database.Database,
  id: number,
  update: { responseStatus?: 'success' | 'error' | 'timeout'; errorMessage?: string },
): void {
  const stmt = db.prepare(`
    UPDATE audit_log SET
      response_status = COALESCE(?, response_status),
      error_message = COALESCE(?, error_message)
    WHERE id = ?
  `);

  stmt.run(update.responseStatus ?? null, update.errorMessage ?? null, id);
}

/**
 * Verify the integrity of the audit chain
 *
 * Walks the entire chain and recomputes hashes to detect tampering.
 *
 * @param db - Database connection
 * @returns Verification result with any broken chain entries
 */
export function verifyAuditChain(db: Database.Database): AuditVerificationResult {
  const entries = db.prepare('SELECT * FROM audit_log ORDER BY sequence_number ASC').all() as AuditRow[];

  const brokenChains: Array<{
    sequenceNumber: number;
    expectedHash: string;
    actualHash: string;
  }> = [];

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const expectedPreviousHash = i === 0 ? GENESIS_HASH : entries[i - 1].hash;

    // Check previous hash link
    if (entry.previous_hash !== expectedPreviousHash) {
      brokenChains.push({
        sequenceNumber: entry.sequence_number,
        expectedHash: expectedPreviousHash,
        actualHash: entry.previous_hash,
      });
    }

    // Recompute hash
    const computedHash = computeHash(
      entry.sequence_number,
      entry.timestamp,
      entry.tool,
      entry.host,
      entry.agent,
      entry.verdict,
      entry.previous_hash,
    );

    if (computedHash !== entry.hash) {
      brokenChains.push({
        sequenceNumber: entry.sequence_number,
        expectedHash: computedHash,
        actualHash: entry.hash,
      });
    }
  }

  return {
    valid: brokenChains.length === 0,
    totalEntries: entries.length,
    brokenChains,
  };
}

/**
 * Query audit log with filters
 *
 * @param db - Database connection
 * @param options - Query options
 * @returns Array of audit entries
 */
export function queryAuditLog(
  db: Database.Database,
  options: {
    limit?: number;
    offset?: number;
    tool?: string;
    host?: string;
    agent?: string;
    verdict?: 'allowed' | 'denied' | 'asked';
    startTime?: number;
    endTime?: number;
  } = {},
): AuditEntry[] {
  const limit = options.limit ?? 100;
  const offset = options.offset ?? 0;

  let sql = 'SELECT * FROM audit_log WHERE 1=1';
  const params: unknown[] = [];

  if (options.tool) {
    sql += ' AND tool = ?';
    params.push(options.tool);
  }

  if (options.host) {
    sql += ' AND host = ?';
    params.push(options.host);
  }

  if (options.agent) {
    sql += ' AND agent = ?';
    params.push(options.agent);
  }

  if (options.verdict) {
    sql += ' AND verdict = ?';
    params.push(options.verdict);
  }

  if (options.startTime) {
    sql += ' AND timestamp >= ?';
    params.push(options.startTime);
  }

  if (options.endTime) {
    sql += ' AND timestamp <= ?';
    params.push(options.endTime);
  }

  sql += ' ORDER BY sequence_number DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const rows = db.prepare(sql).all(...params) as AuditRow[];

  return rows.map((row) => ({
    id: row.id,
    sequenceNumber: row.sequence_number,
    timestamp: row.timestamp,
    tool: row.tool,
    host: row.host,
    agent: row.agent,
    arguments: row.arguments,
    verdict: row.verdict as 'allowed' | 'denied' | 'asked',
    action: row.action as 'allow' | 'deny' | 'ask' | 'log-only',
    matchedRuleId: row.matched_rule_id,
    riskScore: row.risk_score,
    riskFactors: row.risk_factors,
    mode: row.mode as SentinelMode,
    responseStatus: row.response_status as 'success' | 'error' | 'timeout' | undefined,
    errorMessage: row.error_message,
    hash: row.hash,
    previousHash: row.previous_hash,
  }));
}
