/**
 * Confirmation token management for ask mode
 *
 * Single-use tokens with 5-minute TTL for confirming risky operations
 */

import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';
import type { PolicyContext } from './types.js';
import { redactAndSerialize } from './redaction.js';

const DEFAULT_TTL_MS = 300000; // 5 minutes

/**
 * Generate a confirmation token
 *
 * @param db - Database connection
 * @param context - Policy context
 * @param ttlMs - Token TTL in milliseconds (default 5 min)
 * @returns Confirmation token (UUID)
 */
export function generateConfirmationToken(
  db: Database.Database,
  context: PolicyContext,
  ttlMs: number = DEFAULT_TTL_MS,
): string {
  const token = randomUUID();
  const now = Date.now();
  const expiresAt = now + ttlMs;

  const argumentsJson = redactAndSerialize(context.arguments);

  db.prepare(`
    INSERT INTO confirmation_tokens (token, tool, host, agent, arguments, created_at, expires_at, used)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0)
  `).run(token, context.tool, context.host, context.agent, argumentsJson, now, expiresAt);

  return token;
}

/**
 * Validate and consume a confirmation token
 *
 * Checks that:
 * - Token exists
 * - Token not expired
 * - Token not already used
 * - Token matches context (tool, host, agent)
 *
 * If valid, marks token as used.
 *
 * @param db - Database connection
 * @param token - Confirmation token
 * @param context - Policy context to validate against
 * @returns True if valid and consumed
 */
export function validateConfirmationToken(
  db: Database.Database,
  token: string,
  context: PolicyContext,
): boolean {
  const now = Date.now();

  // Clean up expired tokens first
  db.prepare('DELETE FROM confirmation_tokens WHERE expires_at < ?').run(now);

  // Fetch token
  const row = db.prepare(`
    SELECT id, tool, host, agent, expires_at, used
    FROM confirmation_tokens
    WHERE token = ?
  `).get(token) as
    | { id: number; tool: string; host: string; agent: string; expires_at: number; used: number }
    | undefined;

  if (!row) {
    return false; // Token not found
  }

  if (row.used === 1) {
    return false; // Already used
  }

  if (row.expires_at < now) {
    return false; // Expired
  }

  // Validate context match
  if (row.tool !== context.tool || row.host !== context.host || row.agent !== context.agent) {
    return false; // Context mismatch
  }

  // Mark token as used
  db.prepare('UPDATE confirmation_tokens SET used = 1 WHERE token = ?').run(token);

  return true;
}

/**
 * Cleanup expired tokens
 *
 * Should be called periodically to prune old tokens.
 *
 * @param db - Database connection
 * @returns Number of tokens deleted
 */
export function cleanupExpiredTokens(db: Database.Database): number {
  const now = Date.now();
  const result = db.prepare('DELETE FROM confirmation_tokens WHERE expires_at < ?').run(now);
  return result.changes;
}
