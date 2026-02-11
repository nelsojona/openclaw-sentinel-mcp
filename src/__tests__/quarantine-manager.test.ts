/**
 * Tests for quarantine-manager.ts
 * Quarantine CRUD operations for hosts, tools, and agents
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initializeDatabase } from '../database.js';
import {
  quarantineHost,
  quarantineTool,
  quarantineAgent,
  liftQuarantine,
  listQuarantines,
  isQuarantined,
} from '../quarantine-manager.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { rmSync } from 'node:fs';

describe('Quarantine Manager', () => {
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

  describe('Quarantine CRUD', () => {
    it('should quarantine a host', () => {
      quarantineHost(db.db, 'hyperion', 'Suspicious activity detected', undefined, 'system');

      const quarantined = isQuarantined(db.db, 'host', 'hyperion');
      expect(quarantined).toBe(true);
    });

    it('should quarantine a tool', () => {
      quarantineTool(db.db, 'fleet_exec', 'Security vulnerability found', undefined, 'system');

      const quarantined = isQuarantined(db.db, 'tool', 'fleet_exec');
      expect(quarantined).toBe(true);
    });

    it('should quarantine an agent', () => {
      quarantineAgent(db.db, 'user@malicious', 'Anomalous behavior', undefined, 'system');

      const quarantined = isQuarantined(db.db, 'agent', 'user@malicious');
      expect(quarantined).toBe(true);
    });

    it('should lift quarantine for a host', () => {
      quarantineHost(db.db, 'hyperion', 'Test', undefined, 'system');

      const lifted = liftQuarantine(db.db, 'host', 'hyperion');
      expect(lifted).toBe(true);

      const quarantined = isQuarantined(db.db, 'host', 'hyperion');
      expect(quarantined).toBe(false);
    });

    it('should lift quarantine for a tool', () => {
      quarantineTool(db.db, 'fleet_exec', 'Test', undefined, 'system');

      const lifted = liftQuarantine(db.db, 'tool', 'fleet_exec');
      expect(lifted).toBe(true);

      const quarantined = isQuarantined(db.db, 'tool', 'fleet_exec');
      expect(quarantined).toBe(false);
    });

    it('should lift quarantine for an agent', () => {
      quarantineAgent(db.db, 'user@test', 'Test', undefined, 'system');

      const lifted = liftQuarantine(db.db, 'agent', 'user@test');
      expect(lifted).toBe(true);

      const quarantined = isQuarantined(db.db, 'agent', 'user@test');
      expect(quarantined).toBe(false);
    });

    it('should return false when lifting non-existent quarantine', () => {
      const lifted = liftQuarantine(db.db, 'host', 'non-existent');
      expect(lifted).toBe(false);
    });

    it('should list all quarantines', () => {
      quarantineHost(db.db, 'hyperion', 'Test 1', undefined, 'system');
      quarantineTool(db.db, 'fleet_exec', 'Test 2', undefined, 'admin');
      quarantineAgent(db.db, 'user@test', 'Test 3', undefined, 'system');

      const quarantines = listQuarantines(db.db);
      expect(quarantines).toHaveLength(3);

      const scopes = quarantines.map((q) => q.scope).sort();
      expect(scopes).toEqual(['agent', 'host', 'tool']);
    });

    it('should return empty list when no quarantines exist', () => {
      const quarantines = listQuarantines(db.db);
      expect(quarantines).toHaveLength(0);
    });
  });

  describe('Quarantine Expiry', () => {
    it('should auto-expire quarantine after expiry time', () => {
      const expiresAt = Date.now() - 1000; // Expired 1 second ago
      quarantineHost(db.db, 'hyperion', 'Test', expiresAt, 'system');

      // isQuarantined should clean up expired entries
      const quarantined = isQuarantined(db.db, 'host', 'hyperion');
      expect(quarantined).toBe(false);
    });

    it('should not expire quarantine before expiry time', () => {
      const expiresAt = Date.now() + 60000; // Expires in 1 minute
      quarantineHost(db.db, 'hyperion', 'Test', expiresAt, 'system');

      const quarantined = isQuarantined(db.db, 'host', 'hyperion');
      expect(quarantined).toBe(true);
    });

    it('should handle permanent quarantine without expiry', () => {
      quarantineHost(db.db, 'hyperion', 'Test', undefined, 'system');

      const quarantined = isQuarantined(db.db, 'host', 'hyperion');
      expect(quarantined).toBe(true);

      // Should still be quarantined even after time passes
      const stillQuarantined = isQuarantined(db.db, 'host', 'hyperion');
      expect(stillQuarantined).toBe(true);
    });

    it('should clean up expired quarantines from list', () => {
      const expiredAt = Date.now() - 1000;
      const futureAt = Date.now() + 60000;

      quarantineHost(db.db, 'expired-host', 'Test', expiredAt, 'system');
      quarantineHost(db.db, 'active-host', 'Test', futureAt, 'system');
      quarantineHost(db.db, 'permanent-host', 'Test', undefined, 'system');

      const quarantines = listQuarantines(db.db);
      expect(quarantines).toHaveLength(2); // Only active and permanent

      const targets = quarantines.map((q) => q.target).sort();
      expect(targets).toEqual(['active-host', 'permanent-host']);
    });
  });

  describe('Scope Isolation', () => {
    it('should isolate host, tool, and agent quarantines', () => {
      quarantineHost(db.db, 'same-name', 'Host reason', undefined, 'system');
      quarantineTool(db.db, 'same-name', 'Tool reason', undefined, 'system');
      quarantineAgent(db.db, 'same-name', 'Agent reason', undefined, 'system');

      const hostQuarantined = isQuarantined(db.db, 'host', 'same-name');
      const toolQuarantined = isQuarantined(db.db, 'tool', 'same-name');
      const agentQuarantined = isQuarantined(db.db, 'agent', 'same-name');

      expect(hostQuarantined).toBe(true);
      expect(toolQuarantined).toBe(true);
      expect(agentQuarantined).toBe(true);
    });

    it('should lift quarantine only for specified scope', () => {
      quarantineHost(db.db, 'same-name', 'Host reason', undefined, 'system');
      quarantineTool(db.db, 'same-name', 'Tool reason', undefined, 'system');

      liftQuarantine(db.db, 'host', 'same-name');

      const hostQuarantined = isQuarantined(db.db, 'host', 'same-name');
      const toolQuarantined = isQuarantined(db.db, 'tool', 'same-name');

      expect(hostQuarantined).toBe(false);
      expect(toolQuarantined).toBe(true);
    });

    it('should update existing quarantine when re-quarantining same target', () => {
      quarantineHost(db.db, 'hyperion', 'Original reason', undefined, 'system');
      quarantineHost(db.db, 'hyperion', 'Updated reason', undefined, 'admin');

      const quarantines = listQuarantines(db.db);
      expect(quarantines).toHaveLength(1);
      expect(quarantines[0].reason).toBe('Updated reason');
      expect(quarantines[0].createdBy).toBe('admin');
    });
  });
});
