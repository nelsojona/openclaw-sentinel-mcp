/**
 * Monitoring tools for OpenClaw Sentinel
 *
 * Provides real-time visibility into sentinel operations:
 * - Live event stream
 * - Statistics aggregation
 * - Top offenders/victims
 * - Host health status
 * - Bandwidth usage
 * - Mode inspection
 */

import type Database from 'better-sqlite3';
import type { SentinelMode, AuditEntry, AuditRow } from '../types.js';
import { queryAuditLog } from '../audit-log.js';
import { getState as getCircuitState } from '../circuit-breaker.js';

/**
 * Get live event stream (most recent N events)
 */
export function getLiveEvents(db: Database.Database, limit: number = 50): AuditEntry[] {
  return queryAuditLog(db, { limit, offset: 0 });
}

/**
 * Get aggregated statistics for a time window
 */
export function getStats(
  db: Database.Database,
  startTime: number,
  endTime: number,
): {
  totalEvents: number;
  allowed: number;
  denied: number;
  asked: number;
  avgRiskScore: number;
  uniqueTools: number;
  uniqueHosts: number;
  uniqueAgents: number;
  topRiskFactors: Array<{ factor: string; count: number }>;
} {
  const events = queryAuditLog(db, { startTime, endTime, limit: 100000 });

  const allowed = events.filter((e) => e.verdict === 'allowed').length;
  const denied = events.filter((e) => e.verdict === 'denied').length;
  const asked = events.filter((e) => e.verdict === 'asked').length;

  const totalRiskScore = events.reduce((sum, e) => sum + e.riskScore, 0);
  const avgRiskScore = events.length > 0 ? totalRiskScore / events.length : 0;

  const uniqueTools = new Set(events.map((e) => e.tool)).size;
  const uniqueHosts = new Set(events.map((e) => e.host)).size;
  const uniqueAgents = new Set(events.map((e) => e.agent)).size;

  // Aggregate risk factors
  const riskFactorCounts = new Map<string, number>();
  for (const event of events) {
    try {
      const factors = JSON.parse(event.riskFactors) as Array<{ factor: string }>;
      for (const { factor } of factors) {
        riskFactorCounts.set(factor, (riskFactorCounts.get(factor) ?? 0) + 1);
      }
    } catch {
      // Skip malformed JSON
    }
  }

  const topRiskFactors = Array.from(riskFactorCounts.entries())
    .map(([factor, count]) => ({ factor, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    totalEvents: events.length,
    allowed,
    denied,
    asked,
    avgRiskScore,
    uniqueTools,
    uniqueHosts,
    uniqueAgents,
    topRiskFactors,
  };
}

/**
 * Get top offenders (agents with most denials) or victims (most targeted hosts)
 */
export function getTopEntities(
  db: Database.Database,
  entityType: 'tool' | 'host' | 'agent',
  startTime: number,
  endTime: number,
  limit: number = 10,
): Array<{ entity: string; denials: number; allowed: number; riskScore: number }> {
  const events = queryAuditLog(db, { startTime, endTime, limit: 100000 });

  const entityStats = new Map<string, { denials: number; allowed: number; totalRiskScore: number; count: number }>();

  for (const event of events) {
    const entity = entityType === 'tool' ? event.tool : entityType === 'host' ? event.host : event.agent;

    const stats = entityStats.get(entity) ?? { denials: 0, allowed: 0, totalRiskScore: 0, count: 0 };
    if (event.verdict === 'denied') {
      stats.denials++;
    } else if (event.verdict === 'allowed') {
      stats.allowed++;
    }
    stats.totalRiskScore += event.riskScore;
    stats.count++;
    entityStats.set(entity, stats);
  }

  return Array.from(entityStats.entries())
    .map(([entity, stats]) => ({
      entity,
      denials: stats.denials,
      allowed: stats.allowed,
      riskScore: stats.count > 0 ? stats.totalRiskScore / stats.count : 0,
    }))
    .sort((a, b) => b.denials - a.denials)
    .slice(0, limit);
}

/**
 * Get host health status (circuit breaker states)
 */
export function getHostHealth(
  db: Database.Database,
): Array<{ host: string; state: string; failureCount: number; lastFailure: number | null }> {
  const rows = db.prepare('SELECT * FROM circuit_breakers ORDER BY host ASC').all() as Array<{
    host: string;
    state: string;
    failure_count: number;
    last_failure: number | null;
  }>;

  return rows.map((row) => ({
    host: row.host,
    state: getCircuitState(db, row.host),
    failureCount: row.failure_count,
    lastFailure: row.last_failure,
  }));
}

/**
 * Get bandwidth usage (events per time bucket)
 */
export function getBandwidthUsage(
  db: Database.Database,
  startTime: number,
  endTime: number,
  bucketSizeMs: number = 60000, // 1 minute
): Array<{ timestamp: number; count: number }> {
  const events = queryAuditLog(db, { startTime, endTime, limit: 100000 });

  const buckets = new Map<number, number>();

  for (const event of events) {
    const bucketTimestamp = Math.floor(event.timestamp / bucketSizeMs) * bucketSizeMs;
    buckets.set(bucketTimestamp, (buckets.get(bucketTimestamp) ?? 0) + 1);
  }

  return Array.from(buckets.entries())
    .map(([timestamp, count]) => ({ timestamp, count }))
    .sort((a, b) => a.timestamp - b.timestamp);
}

/**
 * Get current sentinel mode
 */
export function getCurrentMode(db: Database.Database): SentinelMode {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get('mode') as { value: string } | undefined;
  return (row?.value as SentinelMode) ?? 'silent-allow';
}
