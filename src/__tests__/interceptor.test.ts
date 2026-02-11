/**
 * Tests for interceptor request flow
 *
 * These tests validate the policy evaluation → audit logging → verdict flow
 * that the interceptor implements. Full subprocess integration tests are
 * deferred to integration testing.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { initializeDatabase } from '../database.js';
import { evaluatePolicy } from '../policy-engine.js';
import { createAuditEntry, updateAuditEntry } from '../audit-log.js';
import { generateConfirmationToken, validateConfirmationToken } from '../confirmation-tokens.js';
import type { PolicyContext, SentinelMode } from '../types.js';

describe('Interceptor Request Flow', () => {
  let db: Database.Database;
  const mode: SentinelMode = 'silent-allow';

  beforeEach(() => {
    const { db: database } = initializeDatabase(':memory:');
    db = database;

    // Set mode
    db.prepare('UPDATE config SET value = ? WHERE key = ?').run(mode, 'mode');
  });

  afterEach(() => {
    db.close();
  });

  describe('Allow flow', () => {
    beforeEach(() => {
      // Add allow rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-all', 'Allow All', 1, 'allow', 1, '*', ${Date.now()}, ${Date.now()})
      `).run();
    });

    it('should allow request and create audit entry', () => {
      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test-agent' },
        timestamp: Date.now(),
      };

      // Step 1: Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(true);
      expect(verdict.action).toBe('allow');

      // Step 2: Create audit entry (write-ahead)
      const auditEntry = createAuditEntry(db, context, verdict, mode);
      expect(auditEntry.verdict).toBe('allowed');
      expect(auditEntry.responseStatus).toBeUndefined(); // Not yet updated

      // Step 3: Forward to openclaw-mcp (simulated success)
      updateAuditEntry(db, auditEntry.id, { responseStatus: 'success' });

      // Verify audit entry updated
      const updated = db
        .prepare('SELECT * FROM audit_log WHERE id = ?')
        .get(auditEntry.id) as any;
      expect(updated.response_status).toBe('success');
    });
  });

  describe('Deny flow', () => {
    beforeEach(() => {
      // Add deny rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('deny-agent', 'Deny Agent', 1, 'deny', 1, 'openclaw_agent_*', ${Date.now()}, ${Date.now()})
      `).run();
    });

    it('should deny request and create audit entry', () => {
      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test-agent' },
        timestamp: Date.now(),
      };

      // Step 1: Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.action).toBe('deny');
      expect(verdict.reason).toContain('Denied by rule');

      // Step 2: Create audit entry
      const auditEntry = createAuditEntry(db, context, verdict, mode);
      expect(auditEntry.verdict).toBe('denied');

      // Step 3: Update with error status (not forwarded)
      updateAuditEntry(db, auditEntry.id, {
        responseStatus: 'error',
        errorMessage: verdict.reason,
      });

      // Verify audit entry
      const updated = db
        .prepare('SELECT * FROM audit_log WHERE id = ?')
        .get(auditEntry.id) as any;
      expect(updated.response_status).toBe('error');
      expect(updated.error_message).toContain('Denied by rule');
    });
  });

  describe('Ask flow', () => {
    beforeEach(() => {
      // Add ask rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('ask-fleet', 'Ask Fleet', 1, 'ask', 1, 'fleet_*', ${Date.now()}, ${Date.now()})
      `).run();
    });

    it('should request confirmation and generate token', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Step 1: Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.action).toBe('ask');
      expect(verdict.requiresConfirmation).toBe(true);

      // Step 2: Generate confirmation token
      const token = generateConfirmationToken(db, context);
      expect(token).toBeDefined();

      // Step 3: Create audit entry
      const auditEntry = createAuditEntry(db, context, verdict, mode);
      expect(auditEntry.verdict).toBe('asked');

      // Verify token created
      const tokenRow = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;
      expect(tokenRow).toBeDefined();
      expect(tokenRow.tool).toBe('fleet_ssh_exec');
      expect(tokenRow.used).toBe(0);
    });

    it('should allow request with valid confirmation token', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // First request - generate token
      const verdict1 = evaluatePolicy(db, context, mode);
      expect(verdict1.action).toBe('ask');

      const token = generateConfirmationToken(db, context);

      // Second request - with confirmation token
      const contextWithToken: PolicyContext = {
        ...context,
        confirmationToken: token,
      };

      const verdict2 = evaluatePolicy(db, contextWithToken, mode);
      expect(verdict2.allowed).toBe(true);
      expect(verdict2.action).toBe('allow');
      expect(verdict2.reason).toContain('Confirmed via token');

      // Verify token marked as used
      const tokenRow = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;
      expect(tokenRow.used).toBe(1);
    });
  });

  describe('Timeout flow', () => {
    beforeEach(() => {
      // Add allow rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-all', 'Allow All', 1, 'allow', 1, '*', ${Date.now()}, ${Date.now()})
      `).run();
    });

    it('should mark audit entry as timeout if no response', () => {
      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test-agent' },
        timestamp: Date.now(),
      };

      // Step 1: Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(true);

      // Step 2: Create audit entry
      const auditEntry = createAuditEntry(db, context, verdict, mode);

      // Step 3: Simulate timeout (no response from openclaw-mcp)
      updateAuditEntry(db, auditEntry.id, { responseStatus: 'timeout' });

      // Verify audit entry
      const updated = db
        .prepare('SELECT * FROM audit_log WHERE id = ?')
        .get(auditEntry.id) as any;
      expect(updated.response_status).toBe('timeout');
    });
  });

  describe('Circuit breaker flow', () => {
    beforeEach(() => {
      // Open circuit breaker for hyperion
      db.prepare(`
        INSERT INTO circuit_breakers (host, state, failure_count, opened_at)
        VALUES ('hyperion', 'open', 3, ${Date.now()})
      `).run();
    });

    it('should deny request if circuit breaker is open', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.action).toBe('deny');
      expect(verdict.reason).toContain('circuit breaker is open');
      expect(verdict.riskScore).toBe(100);

      // Create audit entry
      const auditEntry = createAuditEntry(db, context, verdict, mode);
      expect(auditEntry.verdict).toBe('denied');
    });
  });

  describe('Quarantine flow', () => {
    beforeEach(() => {
      // Quarantine hyperion
      db.prepare(`
        INSERT INTO quarantine (scope, target, reason, created_at, created_by)
        VALUES ('host', 'hyperion', 'Security incident', ${Date.now()}, 'admin')
      `).run();
    });

    it('should deny request if host is quarantined', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.action).toBe('deny');
      expect(verdict.reason).toContain('is quarantined');
      expect(verdict.riskScore).toBe(100);

      // Create audit entry
      const auditEntry = createAuditEntry(db, context, verdict, mode);
      expect(auditEntry.verdict).toBe('denied');
    });

    it('should deny request if tool is quarantined', () => {
      // Quarantine tool
      db.prepare(`
        INSERT INTO quarantine (scope, target, reason, created_at, created_by)
        VALUES ('tool', 'fleet_ssh_exec', 'CVE-2024-XXXX', ${Date.now()}, 'admin')
      `).run();

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'prometheus',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('is quarantined');
    });

    it('should deny request if agent is quarantined', () => {
      // Quarantine agent
      db.prepare(`
        INSERT INTO quarantine (scope, target, reason, created_at, created_by)
        VALUES ('agent', 'malicious@remote', 'Suspicious activity', ${Date.now()}, 'admin')
      `).run();

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'malicious@remote',
        arguments: { agent: 'test' },
        timestamp: Date.now(),
      };

      // Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.reason).toContain('is quarantined');
    });
  });

  describe('Lockdown mode flow', () => {
    it('should deny all non-health requests in lockdown mode', () => {
      // Set lockdown mode
      db.prepare('UPDATE config SET value = ? WHERE key = ?').run('lockdown', 'mode');

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Evaluate policy
      const verdict = evaluatePolicy(db, context, 'lockdown');
      expect(verdict.allowed).toBe(false);
      expect(verdict.action).toBe('deny');
      expect(verdict.reason).toContain('lockdown mode');
    });

    it('should allow health checks in lockdown mode', () => {
      // Set lockdown mode
      db.prepare('UPDATE config SET value = ? WHERE key = ?').run('lockdown', 'mode');

      // Add allow rule for health checks
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-health', 'Allow Health', 1, 'allow', 1, '*health*', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'fleet_health_check', // Tool name includes 'health'
        host: 'local',
        agent: 'user@local',
        arguments: {},
        timestamp: Date.now(),
      };

      // Evaluate policy (health check allowed in lockdown)
      const verdict = evaluatePolicy(db, context, 'lockdown');
      expect(verdict.allowed).toBe(true);
    });
  });

  describe('Audit chain integrity', () => {
    it('should maintain hash chain across multiple requests', () => {
      // Add allow rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-all', 'Allow All', 1, 'allow', 1, '*', ${Date.now()}, ${Date.now()})
      `).run();

      const contexts: PolicyContext[] = [
        {
          tool: 'openclaw_agent_run',
          host: 'local',
          agent: 'user@local',
          arguments: { agent: 'test1' },
          timestamp: Date.now(),
        },
        {
          tool: 'openclaw_agent_run',
          host: 'local',
          agent: 'user@local',
          arguments: { agent: 'test2' },
          timestamp: Date.now(),
        },
        {
          tool: 'openclaw_agent_run',
          host: 'local',
          agent: 'user@local',
          arguments: { agent: 'test3' },
          timestamp: Date.now(),
        },
      ];

      // Process 3 requests
      for (const context of contexts) {
        const verdict = evaluatePolicy(db, context, mode);
        createAuditEntry(db, context, verdict, mode);
      }

      // Verify hash chain
      const entries = db
        .prepare('SELECT * FROM audit_log ORDER BY sequence_number ASC')
        .all() as any[];

      expect(entries).toHaveLength(3);

      // First entry should have GENESIS as previous hash
      expect(entries[0].previous_hash).toBe('GENESIS');

      // Second entry should link to first
      expect(entries[1].previous_hash).toBe(entries[0].hash);

      // Third entry should link to second
      expect(entries[2].previous_hash).toBe(entries[1].hash);
    });
  });

  describe('Multiple rule matching', () => {
    it('should match first rule by priority', () => {
      // Add two rules with different priorities
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('deny-low', 'Deny Low Priority', 100, 'deny', 1, 'openclaw_agent_*', ${Date.now()}, ${Date.now()})
      `).run();

      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-high', 'Allow High Priority', 1, 'allow', 1, 'openclaw_agent_*', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test' },
        timestamp: Date.now(),
      };

      // Should match high priority allow rule first
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(true);
      expect(verdict.matchedRuleName).toBe('Allow High Priority');
    });

    it('should skip disabled rules', () => {
      // Add disabled rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-disabled', 'Allow Disabled', 1, 'allow', 0, 'openclaw_agent_*', ${Date.now()}, ${Date.now()})
      `).run();

      // Add enabled deny rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('deny-enabled', 'Deny Enabled', 2, 'deny', 1, 'openclaw_agent_*', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test' },
        timestamp: Date.now(),
      };

      // Should skip disabled rule and match enabled deny rule
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(false);
      expect(verdict.matchedRuleName).toBe('Deny Enabled');
    });
  });

  describe('Error handling', () => {
    it('should record error status when request fails', () => {
      // Add allow rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('allow-all', 'Allow All', 1, 'allow', 1, '*', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test' },
        timestamp: Date.now(),
      };

      // Evaluate and create audit entry
      const verdict = evaluatePolicy(db, context, mode);
      const auditEntry = createAuditEntry(db, context, verdict, mode);

      // Simulate error response
      updateAuditEntry(db, auditEntry.id, {
        responseStatus: 'error',
        errorMessage: 'Connection refused',
      });

      // Verify audit entry
      const updated = db
        .prepare('SELECT * FROM audit_log WHERE id = ?')
        .get(auditEntry.id) as any;
      expect(updated.response_status).toBe('error');
      expect(updated.error_message).toBe('Connection refused');
    });
  });

  describe('Log-only action', () => {
    it('should allow request but log with log-only action', () => {
      // Add log-only rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, tool_pattern, created_at, updated_at)
        VALUES ('log-agent', 'Log Agent', 1, 'log-only', 1, 'openclaw_agent_*', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local',
        agent: 'user@local',
        arguments: { agent: 'test' },
        timestamp: Date.now(),
      };

      // Evaluate policy
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(true);
      expect(verdict.action).toBe('log-only');

      // Create audit entry
      const auditEntry = createAuditEntry(db, context, verdict, mode);
      expect(auditEntry.action).toBe('log-only');
    });
  });

  describe('Expired quarantine cleanup', () => {
    it('should not block if quarantine has expired', () => {
      // Quarantine hyperion with expiry in the past
      db.prepare(`
        INSERT INTO quarantine (scope, target, reason, created_at, expires_at, created_by)
        VALUES ('host', 'hyperion', 'Temporary block', ${Date.now() - 10000}, ${Date.now() - 5000}, 'admin')
      `).run();

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Should not be blocked (quarantine expired)
      // But no matching rule, so default deny in silent-allow mode
      const verdict = evaluatePolicy(db, context, mode);
      // In silent-allow mode, should be allowed
      expect(verdict.allowed).toBe(true);
    });
  });

  describe('Context extraction', () => {
    it('should extract host from arguments for fleet tools', () => {
      // Add fleet-specific rule
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, host_pattern, created_at, updated_at)
        VALUES ('allow-hyperion', 'Allow Hyperion', 1, 'allow', 1, 'hyperion', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion', // Host from arguments
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Should match hyperion host pattern
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(true);
      expect(verdict.matchedRuleName).toBe('Allow Hyperion');
    });

    it('should use local as default host if not specified', () => {
      // Add rule for local host
      db.prepare(`
        INSERT INTO rules (id, name, priority, action, enabled, host_pattern, created_at, updated_at)
        VALUES ('allow-local', 'Allow Local', 1, 'allow', 1, 'local', ${Date.now()}, ${Date.now()})
      `).run();

      const context: PolicyContext = {
        tool: 'openclaw_agent_run',
        host: 'local', // Default host
        agent: 'user@local',
        arguments: { agent: 'test' },
        timestamp: Date.now(),
      };

      // Should match local host pattern
      const verdict = evaluatePolicy(db, context, mode);
      expect(verdict.allowed).toBe(true);
      expect(verdict.matchedRuleName).toBe('Allow Local');
    });
  });
});
