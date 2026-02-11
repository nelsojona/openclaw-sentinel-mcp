/**
 * Integration tests for monitoring and audit tools
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initializeDatabase } from '../database.js';
import { createAuditEntry } from '../audit-log.js';
import type { PolicyContext, PolicyVerdict } from '../types.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  getLiveEvents,
  getStats,
  getTopEntities,
  getHostHealth,
  getBandwidthUsage,
  getCurrentMode,
} from '../tools/monitor.js';
import { query, tail, getAuditStats, verify, exportAuditLog, applyRetention } from '../tools/audit.js';
import { recordFailure, recordSuccess } from '../circuit-breaker.js';

describe('Monitoring & Audit Integration', () => {
  let dbPath: string;
  let tempDir: string;
  let db: ReturnType<typeof initializeDatabase>;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sentinel-test-'));
    dbPath = join(tempDir, 'test.db');
    db = initializeDatabase(dbPath);
  });

  afterEach(() => {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  const createContext = (tool = 'test_tool', host = 'hyperion', agent = 'user@test'): PolicyContext => ({
    tool,
    host,
    agent,
    arguments: { foo: 'bar' },
    timestamp: Date.now(),
  });

  const createVerdict = (allowed = true, riskScore = 0): PolicyVerdict => ({
    allowed,
    action: allowed ? 'allow' : 'deny',
    reason: 'test',
    riskScore,
    riskFactors: [],
    requiresConfirmation: false,
  });

  describe('Monitor Tools', () => {
    it('should get live events stream', () => {
      // Create some test events
      for (let i = 0; i < 10; i++) {
        createAuditEntry(db.db, createContext(`tool-${i}`), createVerdict(), 'silent-allow');
      }

      const events = getLiveEvents(db.db, 5);
      expect(events).toHaveLength(5);
      expect(events[0].tool).toBe('tool-9'); // Most recent first
    });

    it('should compute accurate statistics', () => {
      const startTime = Date.now();

      // Create varied events
      createAuditEntry(db.db, createContext('tool-1', 'hyperion'), createVerdict(true, 10), 'silent-allow');
      createAuditEntry(db.db, createContext('tool-2', 'prometheus'), createVerdict(false, 80), 'alert');
      createAuditEntry(db.db, createContext('tool-3', 'osiris'), createVerdict(true, 20), 'silent-allow');

      const endTime = Date.now() + 1000;
      const stats = getStats(db.db, startTime, endTime);

      expect(stats.totalEvents).toBe(3);
      expect(stats.allowed).toBe(2);
      expect(stats.denied).toBe(1);
      expect(stats.asked).toBe(0);
      expect(stats.uniqueTools).toBe(3);
      expect(stats.uniqueHosts).toBe(3);
      expect(stats.avgRiskScore).toBeCloseTo(36.67, 1);
    });

    it('should identify top offenders by agent', () => {
      const startTime = Date.now();

      // Create events with varied agents
      createAuditEntry(db.db, createContext('tool', 'host', 'agent-1'), createVerdict(false), 'alert');
      createAuditEntry(db.db, createContext('tool', 'host', 'agent-1'), createVerdict(false), 'alert');
      createAuditEntry(db.db, createContext('tool', 'host', 'agent-1'), createVerdict(false), 'alert');
      createAuditEntry(db.db, createContext('tool', 'host', 'agent-2'), createVerdict(false), 'alert');
      createAuditEntry(db.db, createContext('tool', 'host', 'agent-3'), createVerdict(true), 'silent-allow');

      const endTime = Date.now() + 1000;
      const top = getTopEntities(db.db, 'agent', startTime, endTime, 2);

      expect(top).toHaveLength(2);
      expect(top[0].entity).toBe('agent-1');
      expect(top[0].denials).toBe(3);
      expect(top[1].entity).toBe('agent-2');
      expect(top[1].denials).toBe(1);
    });

    it('should track host health via circuit breakers', () => {
      recordFailure(db.db, 'hyperion');
      recordFailure(db.db, 'hyperion');
      recordSuccess(db.db, 'prometheus');

      const health = getHostHealth(db.db);

      expect(health).toHaveLength(2);
      const hyperion = health.find((h) => h.host === 'hyperion');
      const prometheus = health.find((h) => h.host === 'prometheus');

      expect(hyperion?.state).toBe('open');
      expect(hyperion?.failureCount).toBe(2);
      expect(prometheus?.state).toBe('closed');
      expect(prometheus?.failureCount).toBe(0);
    });

    it('should measure bandwidth usage over time', () => {
      const startTime = Date.now();

      // Create events spread over time
      for (let i = 0; i < 5; i++) {
        const context = createContext();
        context.timestamp = startTime + i * 30000; // 30s apart
        createAuditEntry(db.db, context, createVerdict(), 'silent-allow');
      }

      const endTime = startTime + 150000;
      const bandwidth = getBandwidthUsage(db.db, startTime, endTime, 60000); // 1-minute buckets

      expect(bandwidth.length).toBeGreaterThan(0);
      expect(bandwidth[0].count).toBeGreaterThan(0);
    });

    it('should retrieve current sentinel mode', () => {
      const mode = getCurrentMode(db.db);
      expect(mode).toBe('silent-allow'); // Default from database init
    });
  });

  describe('Audit Tools', () => {
    it('should query with filters correctly', () => {
      createAuditEntry(db.db, createContext('tool-1', 'hyperion', 'agent-1'), createVerdict(true), 'silent-allow');
      createAuditEntry(db.db, createContext('tool-2', 'prometheus', 'agent-2'), createVerdict(false), 'alert');

      const results = query(db.db, { tool: 'tool-1' });
      expect(results).toHaveLength(1);
      expect(results[0].tool).toBe('tool-1');

      const hostResults = query(db.db, { host: 'prometheus' });
      expect(hostResults).toHaveLength(1);
      expect(hostResults[0].host).toBe('prometheus');
    });

    it('should tail recent entries', () => {
      for (let i = 0; i < 20; i++) {
        createAuditEntry(db.db, createContext(`tool-${i}`), createVerdict(), 'silent-allow');
      }

      const recent = tail(db.db, 5);
      expect(recent).toHaveLength(5);
      expect(recent[0].tool).toBe('tool-19'); // Most recent
    });

    it('should compute comprehensive audit statistics', () => {
      createAuditEntry(db.db, createContext('tool-1'), createVerdict(true, 10), 'silent-allow');
      createAuditEntry(db.db, createContext('tool-2'), createVerdict(false, 50), 'alert');
      createAuditEntry(db.db, createContext('tool-3'), createVerdict(true, 30), 'silent-deny');

      const stats = getAuditStats(db.db);

      expect(stats.totalEntries).toBe(3);
      expect(stats.verdictDistribution.allowed).toBe(2);
      expect(stats.verdictDistribution.denied).toBe(1);
      expect(stats.avgRiskScore).toBeCloseTo(30, 0);
      expect(stats.modeDistribution['silent-allow']).toBe(1);
      expect(stats.modeDistribution['alert']).toBe(1);
      expect(stats.modeDistribution['silent-deny']).toBe(1);
    });

    it('should verify audit chain integrity', () => {
      createAuditEntry(db.db, createContext('tool-1'), createVerdict(), 'silent-allow');
      createAuditEntry(db.db, createContext('tool-2'), createVerdict(), 'silent-allow');
      createAuditEntry(db.db, createContext('tool-3'), createVerdict(), 'silent-allow');

      const result = verify(db.db);

      expect(result.valid).toBe(true);
      expect(result.totalEntries).toBe(3);
      expect(result.brokenChains).toHaveLength(0);
    });

    it('should export audit log as JSON', () => {
      createAuditEntry(db.db, createContext('tool-1'), createVerdict(), 'silent-allow');
      createAuditEntry(db.db, createContext('tool-2'), createVerdict(), 'silent-allow');

      const exported = exportAuditLog(db.db, { limit: 10 });
      const parsed = JSON.parse(exported);

      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(2);
      expect(parsed[0].tool).toBe('tool-2'); // Most recent first
    });

    it('should apply retention policy correctly', () => {
      const now = Date.now();

      // Create old entries by manually updating timestamps in DB
      for (let i = 0; i < 5; i++) {
        createAuditEntry(db.db, createContext(`old-tool-${i}`), createVerdict(), 'silent-allow');
      }

      // Manually update timestamps to be old
      const oldTime = now - 10 * 24 * 60 * 60 * 1000; // 10 days ago
      db.db.prepare('UPDATE audit_log SET timestamp = ? WHERE tool LIKE ?').run(oldTime, 'old-tool-%');

      // Create recent entries
      for (let i = 0; i < 3; i++) {
        createAuditEntry(db.db, createContext(`recent-tool-${i}`), createVerdict(), 'silent-allow');
      }

      // Apply 7-day retention
      const result = applyRetention(db.db, 7 * 24 * 60 * 60 * 1000);

      expect(result.deletedCount).toBe(5);
      expect(result.oldestRemainingTime).toBeGreaterThan(oldTime);

      const remaining = tail(db.db, 100);
      expect(remaining).toHaveLength(3);
    });
  });
});
