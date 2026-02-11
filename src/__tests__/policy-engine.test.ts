/**
 * Tests for policy-engine.ts
 * TODO: Implement 25 comprehensive tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initializeDatabase } from '../database.js';
import { evaluatePolicy } from '../policy-engine.js';
import type { PolicyContext } from '../types.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { rmSync } from 'node:fs';

describe('Policy Engine', () => {
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

  it('should deny operations when in lockdown mode', () => {
    const context: PolicyContext = {
      tool: 'fleet_ssh_exec',
      host: 'hyperion',
      agent: 'user@test',
      arguments: { command: 'ls' },
      timestamp: Date.now(),
    };

    const verdict = evaluatePolicy(db.db, context, 'lockdown');
    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toContain('lockdown');
  });

  it('should allow health checks in lockdown mode with default rules', () => {
    // Insert allow rule for health checks
    db.db
      .prepare(
        `INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run('test-health-rule', 'Allow Health', 0, 'allow', 1, '*health*', Date.now(), Date.now());

    const context: PolicyContext = {
      tool: 'sentinel_health_check',
      host: 'hyperion',
      agent: 'user@test',
      arguments: {},
      timestamp: Date.now(),
    };

    const verdict = evaluatePolicy(db.db, context, 'lockdown');
    expect(verdict.allowed).toBe(true);
  });

  it('should allow all operations in silent-allow mode', () => {
    const context: PolicyContext = {
      tool: 'fleet_ssh_exec',
      host: 'hyperion',
      agent: 'user@test',
      arguments: { command: 'ls' },
      timestamp: Date.now(),
    };

    const verdict = evaluatePolicy(db.db, context, 'silent-allow');
    expect(verdict.allowed).toBe(true);
  });

  // TODO: Add 22 more tests covering:
  // - Circuit breaker enforcement
  // - Quarantine enforcement
  // - Rule matching (glob patterns, priority order)
  // - Schedule validation
  // - Confirmation token handling
  // - Rate limit integration
  // - Risk score calculation
  // - Mode-based defaults (alert, silent-deny)
});
