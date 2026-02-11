/**
 * Token bucket rate limiter with SQLite persistence.
 *
 * Uses token bucket algorithm: tokens refill at a constant rate.
 * Each operation consumes 1 token. If no tokens available, the operation is throttled.
 *
 * Bucket key: ruleId:tool:host:agent
 */

import type Database from 'better-sqlite3';
import type { RateLimit, RateLimitResult, PolicyContext, RateLimitBucketRow } from './types.js';

/**
 * Check rate limit for a given context.
 * Returns whether the operation is allowed and remaining tokens.
 */
export function checkRateLimit(
  db: Database.Database,
  ruleId: string,
  context: PolicyContext,
  rateLimit: RateLimit,
): RateLimitResult {
  const now = Date.now();
  const { tool, host, agent } = context;

  // Get or create bucket
  const getBucket = db.prepare<{ rule_id: string; tool: string; host: string; agent: string }>(
    'SELECT * FROM rate_limit_buckets WHERE rule_id = @rule_id AND tool = @tool AND host = @host AND agent = @agent',
  );

  let bucket = getBucket.get({
    rule_id: ruleId,
    tool,
    host,
    agent,
  }) as RateLimitBucketRow | undefined;

  if (!bucket) {
    // Create new bucket with full tokens
    const insertBucket = db.prepare<Omit<RateLimitBucketRow, 'id'>>(
      `INSERT INTO rate_limit_buckets (rule_id, tool, host, agent, tokens, last_refill, created_at)
       VALUES (@rule_id, @tool, @host, @agent, @tokens, @last_refill, @created_at)`,
    );

    insertBucket.run({
      rule_id: ruleId,
      tool,
      host,
      agent,
      tokens: rateLimit.maxOperations,
      last_refill: now,
      created_at: now,
    });

    bucket = getBucket.get({
      rule_id: ruleId,
      tool,
      host,
      agent,
    }) as RateLimitBucketRow;
  }

  // Calculate token refill
  const elapsedSeconds = (now - bucket.last_refill) / 1000;
  const refillTokens = elapsedSeconds * rateLimit.refillRate;
  const currentTokens = Math.min(bucket.tokens + refillTokens, rateLimit.maxOperations);

  // Check if we have enough tokens
  if (currentTokens >= 1) {
    // Consume 1 token
    const newTokens = currentTokens - 1;

    const updateBucket = db.prepare<{ tokens: number; last_refill: number; rule_id: string; tool: string; host: string; agent: string }>(
      `UPDATE rate_limit_buckets SET tokens = @tokens, last_refill = @last_refill
       WHERE rule_id = @rule_id AND tool = @tool AND host = @host AND agent = @agent`,
    );

    updateBucket.run({
      tokens: newTokens,
      last_refill: now,
      rule_id: ruleId,
      tool,
      host,
      agent,
    });

    return {
      allowed: true,
      remainingTokens: Math.floor(newTokens),
      resetAt: now + Math.ceil((rateLimit.maxOperations - newTokens) / rateLimit.refillRate) * 1000,
    };
  }

  // Not enough tokens - throttled
  const tokensNeeded = 1 - currentTokens;
  const resetDelaySeconds = Math.ceil(tokensNeeded / rateLimit.refillRate);

  return {
    allowed: false,
    remainingTokens: 0,
    resetAt: now + resetDelaySeconds * 1000,
  };
}

/**
 * Clean up old rate limit buckets (idle for more than 24 hours).
 * This prevents unbounded growth of the buckets table.
 */
export function cleanupOldBuckets(db: Database.Database): number {
  const cutoffTime = Date.now() - 24 * 60 * 60 * 1000; // 24 hours ago

  const cleanup = db.prepare<{ cutoff: number }>(
    'DELETE FROM rate_limit_buckets WHERE created_at < @cutoff',
  );

  const result = cleanup.run({ cutoff: cutoffTime });
  return result.changes;
}
