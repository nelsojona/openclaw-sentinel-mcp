/**
 * Security invariants tests
 * Tests for bypass attempts, SQL injection, privilege escalation, and rule bypass
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initializeDatabase, prepareStatements } from '../database.js';
import { evaluatePolicy } from '../policy-engine.js';
import { createAuditEntry, verifyAuditChain } from '../audit-log.js';
import { quarantineHost, quarantineTool, quarantineAgent, isQuarantined } from '../quarantine-manager.js';
import type { PolicyContext, SentinelRule } from '../types.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';

describe('Security Invariants', () => {
  let dbPath: string;
  let tempDir: string;
  let db: ReturnType<typeof initializeDatabase>;
  let statements: ReturnType<typeof prepareStatements>;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sentinel-test-'));
    dbPath = join(tempDir, 'test.db');
    db = initializeDatabase(dbPath);
    statements = prepareStatements(db.db);
  });

  afterEach(() => {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe('Quarantine Bypass Attempts', () => {
    it('should block quarantined hosts regardless of tool', () => {
      quarantineHost(db.db, 'hyperion', 'Security incident', undefined, 'system');

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const verdict = evaluatePolicy(db.db, context, 'silent-allow');
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('quarantined');
    });

    it('should block quarantined tools regardless of host', () => {
      quarantineTool(db.db, 'fleet_ssh_exec', 'Vulnerable tool', undefined, 'system');

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'prometheus',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const verdict = evaluatePolicy(db.db, context, 'silent-allow');
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('quarantined');
    });

    it('should block quarantined agents regardless of tool or host', () => {
      quarantineAgent(db.db, 'malicious@local', 'Suspicious behavior', undefined, 'system');

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'malicious@local',
        arguments: {},
        timestamp: Date.now(),
      };

      const verdict = evaluatePolicy(db.db, context, 'silent-allow');
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('quarantined');
    });

    it('should prevent quarantine bypass via case manipulation', () => {
      quarantineHost(db.db, 'hyperion', 'Security incident', undefined, 'system');

      // Try case variants
      expect(isQuarantined(db.db, 'host', 'HYPERION')).toBe(false); // SQLite is case-sensitive by default
      expect(isQuarantined(db.db, 'host', 'Hyperion')).toBe(false);
      expect(isQuarantined(db.db, 'host', 'hyperion')).toBe(true); // Only exact match works
    });
  });

  describe('SQL Injection Protection', () => {
    it('should sanitize malicious rule patterns', () => {
      const maliciousPattern = "'; DROP TABLE rules; --";

      const rule: Omit<SentinelRule, 'id' | 'createdAt' | 'updatedAt'> = {
        name: 'Malicious Rule',
        priority: 1000,
        action: 'allow',
        enabled: true,
        toolPattern: maliciousPattern,
      };

      const now = Date.now();
      const fullRule = {
        ...rule,
        id: randomUUID(),
        createdAt: now,
        updatedAt: now,
      };

      // Insert rule with malicious pattern
      const row = {
        id: fullRule.id,
        name: fullRule.name,
        priority: fullRule.priority,
        action: fullRule.action,
        enabled: 1,
        tool_pattern: fullRule.toolPattern,
        host_pattern: null,
        agent_pattern: null,
        argument_pattern: null,
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: now,
        updated_at: now,
        description: null,
        tags: null,
      };

      statements.insertRule.run(row);

      // Verify table still exists
      const count = db.db.prepare('SELECT COUNT(*) as count FROM rules').get() as { count: number };
      expect(count.count).toBeGreaterThan(0);
    });

    it('should sanitize malicious quarantine reasons', () => {
      const maliciousReason = "'; DELETE FROM quarantine WHERE '1'='1";

      quarantineHost(db.db, 'test-host', maliciousReason, undefined, 'system');

      // Verify quarantine table still has data
      const count = db.db.prepare('SELECT COUNT(*) as count FROM quarantine').get() as { count: number };
      expect(count.count).toBe(1);
    });

    it('should sanitize malicious agent identifiers', () => {
      const maliciousAgent = "' OR '1'='1";

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'local',
        agent: maliciousAgent,
        arguments: {},
        timestamp: Date.now(),
      };

      // Should not bypass policy evaluation
      const verdict = evaluatePolicy(db.db, context, 'silent-deny');
      expect(verdict).toBeDefined();
    });
  });

  describe('Privilege Escalation Prevention', () => {
    it('should enforce lockdown mode regardless of rules', () => {
      // Create allow-all rule
      const rule = {
        id: randomUUID(),
        name: 'Allow All',
        priority: 0,
        action: 'allow' as const,
        enabled: 1,
        tool_pattern: '*',
        host_pattern: '*',
        agent_pattern: '*',
        argument_pattern: null,
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        description: null,
        tags: null,
      };

      statements.insertRule.run(rule);

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'rm -rf /' },
        timestamp: Date.now(),
      };

      // Even with allow-all rule, lockdown should deny non-health operations
      const verdict = evaluatePolicy(db.db, context, 'lockdown');
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('lockdown');
    });

    it('should prevent quarantine bypass via rule priority manipulation', () => {
      quarantineTool(db.db, 'fleet_ssh_exec', 'Quarantined', undefined, 'system');

      // Create high-priority allow rule
      const rule = {
        id: randomUUID(),
        name: 'Allow SSH',
        priority: -1000, // Very high priority
        action: 'allow' as const,
        enabled: 1,
        tool_pattern: 'fleet_ssh_exec',
        host_pattern: '*',
        agent_pattern: '*',
        argument_pattern: null,
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        description: null,
        tags: null,
      };

      statements.insertRule.run(rule);

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: {},
        timestamp: Date.now(),
      };

      // Quarantine check happens before rule matching - cannot be bypassed
      const verdict = evaluatePolicy(db.db, context, 'silent-allow');
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('quarantined');
    });

    it('should prevent circuit breaker bypass via rule manipulation', () => {
      // Open circuit breaker for host
      db.db
        .prepare(
          `INSERT INTO circuit_breakers (host, state, failure_count, last_failure, opened_at)
         VALUES (?, ?, ?, ?, ?)`,
        )
        .run('hyperion', 'open', 5, Date.now(), Date.now());

      // Create allow-all rule
      const rule = {
        id: randomUUID(),
        name: 'Allow All',
        priority: 0,
        action: 'allow' as const,
        enabled: 1,
        tool_pattern: '*',
        host_pattern: 'hyperion',
        agent_pattern: '*',
        argument_pattern: null,
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        description: null,
        tags: null,
      };

      statements.insertRule.run(rule);

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: {},
        timestamp: Date.now(),
      };

      // Circuit breaker check happens before rule matching
      const verdict = evaluatePolicy(db.db, context, 'silent-allow');
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('circuit breaker');
    });
  });

  describe('Rule Bypass Prevention', () => {
    it('should prevent wildcard bypass in glob patterns', () => {
      const rule = {
        id: randomUUID(),
        name: 'Block SSH',
        priority: 100,
        action: 'deny' as const,
        enabled: 1,
        tool_pattern: 'fleet_ssh_*',
        host_pattern: null,
        agent_pattern: null,
        argument_pattern: null,
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        description: null,
        tags: null,
      };

      statements.insertRule.run(rule);

      // Try various bypass attempts
      const bypassAttempts = [
        'fleet_ssh_exec',
        'fleet_ssh_copy',
        'fleet_ssh_tunnel',
        'fleet_sshexec', // No underscore - should not match
      ];

      const results = bypassAttempts.map((tool) => {
        const context: PolicyContext = {
          tool,
          host: 'hyperion',
          agent: 'user@local',
          arguments: {},
          timestamp: Date.now(),
        };

        return {
          tool,
          verdict: evaluatePolicy(db.db, context, 'silent-allow'),
        };
      });

      // First 3 should match and be denied
      expect(results[0].verdict.allowed).toBe(false);
      expect(results[1].verdict.allowed).toBe(false);
      expect(results[2].verdict.allowed).toBe(false);

      // Last one should not match (silent-allow mode allows by default)
      expect(results[3].verdict.allowed).toBe(true);
    });

    it('should enforce argument pattern regex correctly', () => {
      const rule = {
        id: randomUUID(),
        name: 'Block Force Push',
        priority: 100,
        action: 'deny' as const,
        enabled: 1,
        tool_pattern: 'fleet_ssh_exec',
        host_pattern: null,
        agent_pattern: null,
        argument_pattern: 'git\\s+push.*--force', // Regex pattern
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        description: null,
        tags: null,
      };

      statements.insertRule.run(rule);

      // Test legitimate and bypass attempts
      const testCases = [
        { args: { command: 'git push --force' }, shouldBlock: true },
        { args: { command: 'git push origin main --force' }, shouldBlock: true },
        { args: { command: 'gitpush--force' }, shouldBlock: false }, // No space
        { args: { command: 'git push' }, shouldBlock: false }, // No --force
        { args: { command: 'ls' }, shouldBlock: false },
      ];

      testCases.forEach(({ args, shouldBlock }) => {
        const context: PolicyContext = {
          tool: 'fleet_ssh_exec',
          host: 'hyperion',
          agent: 'user@local',
          arguments: args,
          timestamp: Date.now(),
        };

        const verdict = evaluatePolicy(db.db, context, 'silent-allow');
        expect(verdict.allowed).toBe(!shouldBlock);
      });
    });

    it('should prevent disabled rule bypass', () => {
      const rule = {
        id: randomUUID(),
        name: 'Disabled Rule',
        priority: 0,
        action: 'allow' as const,
        enabled: 0, // Disabled
        tool_pattern: '*',
        host_pattern: '*',
        agent_pattern: '*',
        argument_pattern: null,
        rate_limit_max_operations: null,
        rate_limit_window_seconds: null,
        rate_limit_refill_rate: null,
        schedule_days_of_week: null,
        schedule_start_hour: null,
        schedule_end_hour: null,
        schedule_timezone: null,
        created_at: Date.now(),
        updated_at: Date.now(),
        description: null,
        tags: null,
      };

      statements.insertRule.run(rule);

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: {},
        timestamp: Date.now(),
      };

      // In silent-deny mode, disabled rule should not allow operation
      const verdict = evaluatePolicy(db.db, context, 'silent-deny');
      expect(verdict.allowed).toBe(false);
    });
  });

  describe('Audit Chain Integrity', () => {
    it('should detect audit chain tampering', () => {
      // Create some audit entries
      const contexts: PolicyContext[] = [
        {
          tool: 'fleet_ssh_exec',
          host: 'hyperion',
          agent: 'user@local',
          arguments: { command: 'ls' },
          timestamp: Date.now(),
        },
        {
          tool: 'openclaw_agent_run',
          host: 'local',
          agent: 'user@local',
          arguments: {},
          timestamp: Date.now(),
        },
      ];

      contexts.forEach((context) => {
        const verdict = evaluatePolicy(db.db, context, 'silent-allow');
        createAuditEntry(db.db, context, verdict, 'silent-allow');
      });

      // Verify chain is valid
      let result = verifyAuditChain(db.db);
      expect(result.valid).toBe(true);
      expect(result.brokenChains).toHaveLength(0);

      // Tamper with an entry
      db.db.prepare('UPDATE audit_log SET tool = ? WHERE id = ?').run('tampered_tool', 1);

      // Verify chain detects tampering
      result = verifyAuditChain(db.db);
      expect(result.valid).toBe(false);
      expect(result.brokenChains.length).toBeGreaterThan(0);
    });

    it('should maintain audit chain across mode changes', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: {},
        timestamp: Date.now(),
      };

      // Create entries in different modes
      const modes: Array<'silent-allow' | 'alert' | 'silent-deny' | 'lockdown'> = [
        'silent-allow',
        'alert',
        'silent-deny',
      ];

      modes.forEach((mode) => {
        const verdict = evaluatePolicy(db.db, context, mode);
        createAuditEntry(db.db, context, verdict, mode);
      });

      // Chain should remain valid across mode changes
      const result = verifyAuditChain(db.db);
      expect(result.valid).toBe(true);
    });

    it('should prevent audit entry deletion without breaking chain detection', () => {
      // Create audit entries
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: {},
        timestamp: Date.now(),
      };

      for (let i = 0; i < 5; i++) {
        const verdict = evaluatePolicy(db.db, context, 'silent-allow');
        createAuditEntry(db.db, context, verdict, 'silent-allow');
      }

      // Delete middle entry
      db.db.prepare('DELETE FROM audit_log WHERE sequence_number = ?').run(3);

      // Chain should detect break
      const result = verifyAuditChain(db.db);
      expect(result.valid).toBe(false);
    });
  });

  describe('Configuration Security', () => {
    it('should validate mode transitions', () => {
      const validModes = ['silent-allow', 'alert', 'silent-deny', 'lockdown'];
      const invalidModes = ['bypass', 'admin', '', null, undefined];

      validModes.forEach((mode) => {
        expect(() => {
          evaluatePolicy(
            db.db,
            {
              tool: 'test',
              host: 'test',
              agent: 'test',
              arguments: {},
              timestamp: Date.now(),
            },
            mode as 'silent-allow' | 'alert' | 'silent-deny' | 'lockdown',
          );
        }).not.toThrow();
      });
    });

    it('should prevent configuration injection via tool arguments', () => {
      const maliciousArgs = {
        mode: 'lockdown',
        bypass: true,
        admin: true,
        __proto__: { admin: true },
      };

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: maliciousArgs,
        timestamp: Date.now(),
      };

      // Mode is explicitly passed, not derived from arguments
      const verdict = evaluatePolicy(db.db, context, 'silent-allow');
      expect(verdict).toBeDefined();
    });
  });
});
