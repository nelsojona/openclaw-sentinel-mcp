/**
 * Audit tools for OpenClaw Sentinel
 *
 * Provides comprehensive audit log querying and verification:
 * - Query with filters
 * - Tail recent entries
 * - Statistics
 * - Chain verification
 * - Export
 * - Retention management
 */

import type Database from 'better-sqlite3';
import type { AuditEntry, AuditVerificationResult } from '../types.js';
import { queryAuditLog, verifyAuditChain } from '../audit-log.js';

/**
 * Query audit log with comprehensive filters
 */
export function query(
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
  return queryAuditLog(db, options);
}

/**
 * Get most recent N audit entries (tail)
 */
export function tail(db: Database.Database, limit: number = 100): AuditEntry[] {
  return queryAuditLog(db, { limit, offset: 0 });
}

/**
 * Get audit log statistics
 */
export function getAuditStats(
  db: Database.Database,
): {
  totalEntries: number;
  firstEntryTime: number | null;
  lastEntryTime: number | null;
  avgRiskScore: number;
  verdictDistribution: { allowed: number; denied: number; asked: number };
  modeDistribution: Record<string, number>;
  responseStatusDistribution: { success: number; error: number; timeout: number; pending: number };
} {
  const countRow = db.prepare('SELECT COUNT(*) as count FROM audit_log').get() as { count: number };
  const totalEntries = countRow.count;

  const firstRow = db.prepare('SELECT timestamp FROM audit_log ORDER BY sequence_number ASC LIMIT 1').get() as
    | { timestamp: number }
    | undefined;
  const lastRow = db.prepare('SELECT timestamp FROM audit_log ORDER BY sequence_number DESC LIMIT 1').get() as
    | { timestamp: number }
    | undefined;

  const avgRow = db.prepare('SELECT AVG(risk_score) as avg FROM audit_log').get() as { avg: number | null };
  const avgRiskScore = avgRow.avg ?? 0;

  // Verdict distribution
  const allowedCount =
    (db.prepare('SELECT COUNT(*) as count FROM audit_log WHERE verdict = ?').get('allowed') as { count: number })
      ?.count ?? 0;
  const deniedCount =
    (db.prepare('SELECT COUNT(*) as count FROM audit_log WHERE verdict = ?').get('denied') as { count: number })
      ?.count ?? 0;
  const askedCount =
    (db.prepare('SELECT COUNT(*) as count FROM audit_log WHERE verdict = ?').get('asked') as { count: number })
      ?.count ?? 0;

  // Mode distribution
  const modeRows = db.prepare('SELECT mode, COUNT(*) as count FROM audit_log GROUP BY mode').all() as Array<{
    mode: string;
    count: number;
  }>;
  const modeDistribution: Record<string, number> = {};
  for (const { mode, count } of modeRows) {
    modeDistribution[mode] = count;
  }

  // Response status distribution
  const successCount =
    (
      db
        .prepare('SELECT COUNT(*) as count FROM audit_log WHERE response_status = ?')
        .get('success') as { count: number }
    )?.count ?? 0;
  const errorCount =
    (db.prepare('SELECT COUNT(*) as count FROM audit_log WHERE response_status = ?').get('error') as { count: number })
      ?.count ?? 0;
  const timeoutCount =
    (
      db
        .prepare('SELECT COUNT(*) as count FROM audit_log WHERE response_status = ?')
        .get('timeout') as { count: number }
    )?.count ?? 0;
  const pendingCount =
    (
      db
        .prepare('SELECT COUNT(*) as count FROM audit_log WHERE response_status IS NULL')
        .get() as { count: number }
    )?.count ?? 0;

  return {
    totalEntries,
    firstEntryTime: firstRow?.timestamp ?? null,
    lastEntryTime: lastRow?.timestamp ?? null,
    avgRiskScore,
    verdictDistribution: {
      allowed: allowedCount,
      denied: deniedCount,
      asked: askedCount,
    },
    modeDistribution,
    responseStatusDistribution: {
      success: successCount,
      error: errorCount,
      timeout: timeoutCount,
      pending: pendingCount,
    },
  };
}

/**
 * Verify audit chain integrity
 */
export function verify(db: Database.Database): AuditVerificationResult {
  return verifyAuditChain(db);
}

/**
 * Export audit log entries as JSON
 */
export function exportAuditLog(
  db: Database.Database,
  options: {
    startTime?: number;
    endTime?: number;
    limit?: number;
  } = {},
): string {
  const entries = queryAuditLog(db, {
    startTime: options.startTime,
    endTime: options.endTime,
    limit: options.limit ?? 100000,
  });

  return JSON.stringify(entries, null, 2);
}

/**
 * Delete audit log entries older than a retention period
 */
export function applyRetention(
  db: Database.Database,
  retentionMs: number,
): { deletedCount: number; oldestRemainingTime: number | null } {
  const cutoffTime = Date.now() - retentionMs;

  // Count entries to be deleted
  const countRow = db
    .prepare('SELECT COUNT(*) as count FROM audit_log WHERE timestamp < ?')
    .get(cutoffTime) as { count: number };
  const deletedCount = countRow.count;

  // Delete old entries
  db.prepare('DELETE FROM audit_log WHERE timestamp < ?').run(cutoffTime);

  // Get oldest remaining entry
  const oldestRow = db.prepare('SELECT timestamp FROM audit_log ORDER BY sequence_number ASC LIMIT 1').get() as
    | { timestamp: number }
    | undefined;

  return {
    deletedCount,
    oldestRemainingTime: oldestRow?.timestamp ?? null,
  };
}
