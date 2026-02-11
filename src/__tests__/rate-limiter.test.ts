/**
 * Tests for rate-limiter.ts
 * Token bucket algorithm with SQLite persistence
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initializeDatabase } from '../database.js';
import { checkRateLimit, cleanupOldBuckets } from '../rate-limiter.js';
import type { RateLimit, PolicyContext } from '../types.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { rmSync } from 'node:fs';

describe('Rate Limiter', () => {
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
    arguments: {},
    timestamp: Date.now(),
  });

  const createRateLimit = (maxOperations = 10, windowSeconds = 60, refillRate = 1): RateLimit => ({
    maxOperations,
    windowSeconds,
    refillRate,
  });

  describe('Bucket Creation', () => {
    it('should create new bucket with full tokens on first request', () => {
      const context = createContext();
      const rateLimit = createRateLimit(10, 60, 1);

      const result = checkRateLimit(db.db, 'rule-1', context, rateLimit);

      expect(result.allowed).toBe(true);
      expect(result.remainingTokens).toBe(9); // 10 - 1 consumed
    });

    it('should create separate buckets for different rule IDs', () => {
      const context = createContext();
      const rateLimit = createRateLimit(5, 60, 1);

      checkRateLimit(db.db, 'rule-1', context, rateLimit);
      checkRateLimit(db.db, 'rule-1', context, rateLimit);
      checkRateLimit(db.db, 'rule-2', context, rateLimit);

      const result1 = checkRateLimit(db.db, 'rule-1', context, rateLimit);
      const result2 = checkRateLimit(db.db, 'rule-2', context, rateLimit);

      expect(result1.remainingTokens).toBe(2); // 5 - 3 consumed
      expect(result2.remainingTokens).toBe(3); // 5 - 2 consumed
    });

    it('should create separate buckets for different tools', () => {
      const context1 = createContext('tool-1');
      const context2 = createContext('tool-2');
      const rateLimit = createRateLimit(5, 60, 1);

      checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      const result1 = checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      const result2 = checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      expect(result1.remainingTokens).toBe(2); // 5 - 3 consumed
      expect(result2.remainingTokens).toBe(3); // 5 - 2 consumed
    });

    it('should create separate buckets for different hosts', () => {
      const context1 = createContext('tool-1', 'hyperion');
      const context2 = createContext('tool-1', 'prometheus');
      const rateLimit = createRateLimit(5, 60, 1);

      checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      const result1 = checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      const result2 = checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      expect(result1.remainingTokens).toBe(3); // 5 - 2 consumed
      expect(result2.remainingTokens).toBe(3); // 5 - 2 consumed
    });

    it('should create separate buckets for different agents', () => {
      const context1 = createContext('tool-1', 'hyperion', 'agent-1');
      const context2 = createContext('tool-1', 'hyperion', 'agent-2');
      const rateLimit = createRateLimit(5, 60, 1);

      checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      const result1 = checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      const result2 = checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      expect(result1.remainingTokens).toBe(3); // 5 - 2 consumed
      expect(result2.remainingTokens).toBe(3); // 5 - 2 consumed
    });
  });

  describe('Token Refill', () => {
    it('should refill tokens at specified rate', async () => {
      const context = createContext();
      const rateLimit = createRateLimit(10, 60, 2); // 2 tokens per second

      // Consume 5 tokens
      for (let i = 0; i < 5; i++) {
        checkRateLimit(db.db, 'rule-1', context, rateLimit);
      }

      // Wait 1 second - should refill 2 tokens
      await new Promise((resolve) => setTimeout(resolve, 1000));

      const result = checkRateLimit(db.db, 'rule-1', context, rateLimit);
      expect(result.allowed).toBe(true);
      expect(result.remainingTokens).toBeGreaterThanOrEqual(6); // 5 remaining + 2 refilled - 1 consumed
    });

    it('should not exceed max tokens when refilling', async () => {
      const context = createContext();
      const rateLimit = createRateLimit(10, 60, 100); // High refill rate

      // Consume 1 token
      checkRateLimit(db.db, 'rule-1', context, rateLimit);

      // Wait 1 second - should refill to max (10)
      await new Promise((resolve) => setTimeout(resolve, 1000));

      const result = checkRateLimit(db.db, 'rule-1', context, rateLimit);
      expect(result.allowed).toBe(true);
      expect(result.remainingTokens).toBe(9); // Max 10 - 1 consumed
    });

    it('should handle fractional token refill correctly', async () => {
      const context = createContext();
      const rateLimit = createRateLimit(10, 60, 0.5); // 0.5 tokens per second

      // Consume all tokens
      for (let i = 0; i < 10; i++) {
        checkRateLimit(db.db, 'rule-1', context, rateLimit);
      }

      // Wait 500ms - should refill 0.25 tokens (not enough for 1 operation)
      await new Promise((resolve) => setTimeout(resolve, 500));

      const result1 = checkRateLimit(db.db, 'rule-1', context, rateLimit);
      expect(result1.allowed).toBe(false);

      // Wait another 1500ms - total 2s refill = 1 token
      await new Promise((resolve) => setTimeout(resolve, 1500));

      const result2 = checkRateLimit(db.db, 'rule-1', context, rateLimit);
      expect(result2.allowed).toBe(true);
    });
  });

  describe('Throttling', () => {
    it('should throttle when no tokens available', () => {
      const context = createContext();
      const rateLimit = createRateLimit(3, 60, 1);

      // Consume all tokens
      checkRateLimit(db.db, 'rule-1', context, rateLimit);
      checkRateLimit(db.db, 'rule-1', context, rateLimit);
      checkRateLimit(db.db, 'rule-1', context, rateLimit);

      // Should be throttled
      const result = checkRateLimit(db.db, 'rule-1', context, rateLimit);
      expect(result.allowed).toBe(false);
      expect(result.remainingTokens).toBe(0);
    });

    it('should provide correct resetAt timestamp when throttled', () => {
      const context = createContext();
      const rateLimit = createRateLimit(1, 60, 1); // 1 token per second

      // Consume the only token
      checkRateLimit(db.db, 'rule-1', context, rateLimit);

      // Should be throttled
      const now = Date.now();
      const result = checkRateLimit(db.db, 'rule-1', context, rateLimit);

      expect(result.allowed).toBe(false);
      expect(result.resetAt).toBeGreaterThan(now);
      expect(result.resetAt).toBeLessThanOrEqual(now + 2000); // Should reset within ~1 second
    });

    it('should correctly handle burst traffic', () => {
      const context = createContext();
      const rateLimit = createRateLimit(5, 60, 1);

      // Burst of 10 requests - only first 5 should succeed
      const results = [];
      for (let i = 0; i < 10; i++) {
        results.push(checkRateLimit(db.db, 'rule-1', context, rateLimit));
      }

      const allowed = results.filter((r) => r.allowed);
      const throttled = results.filter((r) => !r.allowed);

      expect(allowed.length).toBe(5);
      expect(throttled.length).toBe(5);
    });
  });

  describe('Cleanup', () => {
    it('should delete buckets older than 24 hours', () => {
      const context = createContext();
      const rateLimit = createRateLimit(10, 60, 1);

      // Create a bucket
      checkRateLimit(db.db, 'rule-1', context, rateLimit);

      // Manually update the created_at timestamp to 25 hours ago
      const cutoffTime = Date.now() - 25 * 60 * 60 * 1000;
      db.db.prepare('UPDATE rate_limit_buckets SET created_at = ?').run(cutoffTime);

      // Run cleanup
      const deleted = cleanupOldBuckets(db.db);
      expect(deleted).toBe(1);

      // Verify bucket was deleted
      const buckets = db.db.prepare('SELECT COUNT(*) as count FROM rate_limit_buckets').get() as { count: number };
      expect(buckets.count).toBe(0);
    });

    it('should preserve buckets newer than 24 hours', () => {
      const context = createContext();
      const rateLimit = createRateLimit(10, 60, 1);

      // Create a bucket
      checkRateLimit(db.db, 'rule-1', context, rateLimit);

      // Run cleanup
      const deleted = cleanupOldBuckets(db.db);
      expect(deleted).toBe(0);

      // Verify bucket still exists
      const buckets = db.db.prepare('SELECT COUNT(*) as count FROM rate_limit_buckets').get() as { count: number };
      expect(buckets.count).toBe(1);
    });

    it('should clean up only old buckets in mixed scenario', () => {
      const context1 = createContext('tool-1');
      const context2 = createContext('tool-2');
      const rateLimit = createRateLimit(10, 60, 1);

      // Create two buckets
      checkRateLimit(db.db, 'rule-1', context1, rateLimit);
      checkRateLimit(db.db, 'rule-1', context2, rateLimit);

      // Make one bucket old
      const cutoffTime = Date.now() - 25 * 60 * 60 * 1000;
      db.db.prepare('UPDATE rate_limit_buckets SET created_at = ? WHERE tool = ?').run(cutoffTime, 'tool-1');

      // Run cleanup
      const deleted = cleanupOldBuckets(db.db);
      expect(deleted).toBe(1);

      // Verify only the old bucket was deleted
      const buckets = db.db.prepare('SELECT COUNT(*) as count FROM rate_limit_buckets').get() as { count: number };
      expect(buckets.count).toBe(1);

      const remaining = db.db.prepare('SELECT tool FROM rate_limit_buckets').get() as { tool: string };
      expect(remaining.tool).toBe('tool-2');
    });

    it('should handle no buckets gracefully', () => {
      // Run cleanup on empty database
      const deleted = cleanupOldBuckets(db.db);
      expect(deleted).toBe(0);

      // Verify no buckets exist
      const buckets = db.db.prepare('SELECT COUNT(*) as count FROM rate_limit_buckets').get() as { count: number };
      expect(buckets.count).toBe(0);
    });
  });
});
