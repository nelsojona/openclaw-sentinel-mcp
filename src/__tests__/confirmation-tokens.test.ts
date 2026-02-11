/**
 * Tests for confirmation token management
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { initializeDatabase } from '../database.js';
import {
  generateConfirmationToken,
  validateConfirmationToken,
  cleanupExpiredTokens,
} from '../confirmation-tokens.js';
import type { PolicyContext } from '../types.js';

describe('Confirmation Tokens', () => {
  let db: Database.Database;

  beforeEach(() => {
    const { db: database } = initializeDatabase(':memory:');
    db = database;
  });

  afterEach(() => {
    db.close();
  });

  describe('generateConfirmationToken', () => {
    it('should generate a valid UUID token', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      // UUID v4 format
      expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    it('should store token in database', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      const row = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;

      expect(row).toBeDefined();
      expect(row.tool).toBe('fleet_ssh_exec');
      expect(row.host).toBe('hyperion');
      expect(row.agent).toBe('user@local');
      expect(row.used).toBe(0);
    });

    it('should set expiry time based on TTL', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const ttlMs = 60000; // 1 minute
      const beforeGen = Date.now();
      const token = generateConfirmationToken(db, context, ttlMs);
      const afterGen = Date.now();

      const row = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;

      expect(row.expires_at).toBeGreaterThanOrEqual(beforeGen + ttlMs);
      expect(row.expires_at).toBeLessThanOrEqual(afterGen + ttlMs);
    });

    it('should redact sensitive arguments', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: {
          command: 'echo',
          password: 'secret123',
        },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      const row = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;

      const args = JSON.parse(row.arguments);
      expect(args.password).toBe('[REDACTED]');
      expect(args.command).toBe('echo');
    });
  });

  describe('validateConfirmationToken', () => {
    it('should validate and consume a valid token', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      // Validate
      const valid = validateConfirmationToken(db, token, context);
      expect(valid).toBe(true);

      // Verify token marked as used
      const row = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;
      expect(row.used).toBe(1);
    });

    it('should reject token if already used', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      // Use once
      validateConfirmationToken(db, token, context);

      // Try to use again
      const valid = validateConfirmationToken(db, token, context);
      expect(valid).toBe(false);
    });

    it('should reject token if expired', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Generate token with 1ms TTL
      const token = generateConfirmationToken(db, context, 1);

      // Wait for expiry
      return new Promise((resolve) => {
        setTimeout(() => {
          const valid = validateConfirmationToken(db, token, context);
          expect(valid).toBe(false);
          resolve(undefined);
        }, 10);
      });
    });

    it('should reject token if context does not match', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      // Try to validate with different context
      const differentContext: PolicyContext = {
        ...context,
        host: 'prometheus', // Different host
      };

      const valid = validateConfirmationToken(db, token, differentContext);
      expect(valid).toBe(false);
    });

    it('should reject token if tool does not match', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      // Try to validate with different tool
      const differentContext: PolicyContext = {
        ...context,
        tool: 'fleet_ssh_exec_long', // Different tool
      };

      const valid = validateConfirmationToken(db, token, differentContext);
      expect(valid).toBe(false);
    });

    it('should reject token if agent does not match', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context);

      // Try to validate with different agent
      const differentContext: PolicyContext = {
        ...context,
        agent: 'attacker@remote', // Different agent
      };

      const valid = validateConfirmationToken(db, token, differentContext);
      expect(valid).toBe(false);
    });

    it('should reject non-existent token', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const valid = validateConfirmationToken(db, 'fake-token-uuid', context);
      expect(valid).toBe(false);
    });
  });

  describe('cleanupExpiredTokens', () => {
    it('should delete expired tokens', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Generate token with 1ms TTL
      const token = generateConfirmationToken(db, context, 1);

      // Wait for expiry
      return new Promise((resolve) => {
        setTimeout(() => {
          const deleted = cleanupExpiredTokens(db);
          expect(deleted).toBe(1);

          // Verify token deleted
          const row = db
            .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
            .get(token) as any;
          expect(row).toBeUndefined();

          resolve(undefined);
        }, 10);
      });
    });

    it('should not delete valid tokens', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const token = generateConfirmationToken(db, context, 300000); // 5 min

      const deleted = cleanupExpiredTokens(db);
      expect(deleted).toBe(0);

      // Verify token still exists
      const row = db
        .prepare('SELECT * FROM confirmation_tokens WHERE token = ?')
        .get(token) as any;
      expect(row).toBeDefined();
    });

    it('should return number of deleted tokens', () => {
      const context: PolicyContext = {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'user@local',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Generate 3 expired tokens
      generateConfirmationToken(db, context, 1);
      generateConfirmationToken(db, context, 1);
      generateConfirmationToken(db, context, 1);

      // Wait for expiry
      return new Promise((resolve) => {
        setTimeout(() => {
          const deleted = cleanupExpiredTokens(db);
          expect(deleted).toBe(3);
          resolve(undefined);
        }, 10);
      });
    });
  });
});
