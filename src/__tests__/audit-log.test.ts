/**
 * Tests for audit-log.ts
 * TODO: Implement 20 comprehensive tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initializeDatabase } from '../database.js';
import { createAuditEntry, verifyAuditChain, queryAuditLog, updateAuditEntry } from '../audit-log.js';
import type { PolicyContext, PolicyVerdict } from '../types.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { rmSync } from 'node:fs';

describe('Audit Log', () => {
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

  it('should create audit entry with correct sequence number', () => {
    const context: PolicyContext = {
      tool: 'test_tool',
      host: 'hyperion',
      agent: 'user@test',
      arguments: { foo: 'bar' },
      timestamp: Date.now(),
    };

    const verdict: PolicyVerdict = {
      allowed: true,
      action: 'allow',
      reason: 'test',
      riskScore: 0,
      riskFactors: [],
      requiresConfirmation: false,
    };

    const entry = createAuditEntry(db.db, context, verdict, 'silent-allow');
    expect(entry.sequenceNumber).toBe(1);
    expect(entry.hash).toBeTruthy();
    expect(entry.previousHash).toBe('GENESIS');
  });

  it('should chain hashes correctly', () => {
    const context: PolicyContext = {
      tool: 'test_tool',
      host: 'hyperion',
      agent: 'user@test',
      arguments: {},
      timestamp: Date.now(),
    };

    const verdict: PolicyVerdict = {
      allowed: true,
      action: 'allow',
      reason: 'test',
      riskScore: 0,
      riskFactors: [],
      requiresConfirmation: false,
    };

    const entry1 = createAuditEntry(db.db, context, verdict, 'silent-allow');
    const entry2 = createAuditEntry(db.db, context, verdict, 'silent-allow');

    expect(entry2.previousHash).toBe(entry1.hash);
    expect(entry2.sequenceNumber).toBe(2);
  });

  it('should verify audit chain integrity', () => {
    const context: PolicyContext = {
      tool: 'test_tool',
      host: 'hyperion',
      agent: 'user@test',
      arguments: {},
      timestamp: Date.now(),
    };

    const verdict: PolicyVerdict = {
      allowed: true,
      action: 'allow',
      reason: 'test',
      riskScore: 0,
      riskFactors: [],
      requiresConfirmation: false,
    };

    // Create 10 entries
    for (let i = 0; i < 10; i++) {
      createAuditEntry(db.db, context, verdict, 'silent-allow');
    }

    const verification = verifyAuditChain(db.db);
    expect(verification.valid).toBe(true);
    expect(verification.totalEntries).toBe(10);
    expect(verification.brokenChains).toHaveLength(0);
  });

  it('should update audit entry with response status', () => {
    const context: PolicyContext = {
      tool: 'test_tool',
      host: 'hyperion',
      agent: 'user@test',
      arguments: {},
      timestamp: Date.now(),
    };

    const verdict: PolicyVerdict = {
      allowed: true,
      action: 'allow',
      reason: 'test',
      riskScore: 0,
      riskFactors: [],
      requiresConfirmation: false,
    };

    const entry = createAuditEntry(db.db, context, verdict, 'silent-allow');
    updateAuditEntry(db.db, entry.id, { responseStatus: 'success' });

    const entries = queryAuditLog(db.db, { limit: 1 });
    expect(entries[0].responseStatus).toBe('success');
  });

  // TODO: Add 16 more tests covering:
  // - Sensitive field redaction
  // - Query filtering (by tool, host, agent, verdict, time range)
  // - Chain break detection
  // - Pagination
  // - Error handling
});
