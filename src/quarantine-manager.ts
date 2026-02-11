/**
 * Quarantine management for hosts, tools, and agents.
 *
 * Quarantine blocks operations across all scopes. Supports automatic expiry.
 */

import type Database from 'better-sqlite3';
import type { QuarantineScope, Quarantine, QuarantineRow } from './types.js';

/**
 * Quarantine a host.
 * Blocks all operations targeting this host.
 */
export function quarantineHost(
  db: Database.Database,
  target: string,
  reason: string,
  expiresAt: number | undefined,
  createdBy: string,
): void {
  quarantine(db, 'host', target, reason, expiresAt, createdBy);
}

/**
 * Quarantine a tool.
 * Blocks all operations using this tool.
 */
export function quarantineTool(
  db: Database.Database,
  target: string,
  reason: string,
  expiresAt: number | undefined,
  createdBy: string,
): void {
  quarantine(db, 'tool', target, reason, expiresAt, createdBy);
}

/**
 * Quarantine an agent.
 * Blocks all operations by this agent.
 */
export function quarantineAgent(
  db: Database.Database,
  target: string,
  reason: string,
  expiresAt: number | undefined,
  createdBy: string,
): void {
  quarantine(db, 'agent', target, reason, expiresAt, createdBy);
}

/**
 * Generic quarantine function.
 */
function quarantine(
  db: Database.Database,
  scope: QuarantineScope,
  target: string,
  reason: string,
  expiresAt: number | undefined,
  createdBy: string,
): void {
  const now = Date.now();

  const insert = db.prepare<Omit<QuarantineRow, 'id'>>(
    `INSERT INTO quarantine (scope, target, reason, created_at, expires_at, created_by)
     VALUES (@scope, @target, @reason, @created_at, @expires_at, @created_by)
     ON CONFLICT(scope, target) DO UPDATE SET
       reason = @reason,
       expires_at = @expires_at,
       created_by = @created_by`,
  );

  insert.run({
    scope,
    target,
    reason,
    created_at: now,
    expires_at: expiresAt ?? null,
    created_by: createdBy,
  });
}

/**
 * Lift quarantine for a specific scope and target.
 */
export function liftQuarantine(db: Database.Database, scope: QuarantineScope, target: string): boolean {
  const del = db.prepare<{ scope: string; target: string }>(
    'DELETE FROM quarantine WHERE scope = @scope AND target = @target',
  );

  const result = del.run({ scope, target });
  return result.changes > 0;
}

/**
 * List all active quarantines.
 * Automatically cleans up expired quarantines before returning.
 */
export function listQuarantines(db: Database.Database): Quarantine[] {
  cleanupExpiredQuarantines(db);

  const list = db.prepare('SELECT * FROM quarantine ORDER BY created_at DESC');
  const rows = list.all() as QuarantineRow[];

  return rows.map(rowToQuarantine);
}

/**
 * Check if a target is quarantined in a specific scope.
 * Automatically cleans up expired quarantines.
 */
export function isQuarantined(db: Database.Database, scope: QuarantineScope, target: string): boolean {
  cleanupExpiredQuarantines(db);

  const get = db.prepare<{ scope: string; target: string }>(
    'SELECT * FROM quarantine WHERE scope = @scope AND target = @target',
  );

  const row = get.get({ scope, target }) as QuarantineRow | undefined;
  return row !== undefined;
}

/**
 * Clean up expired quarantines.
 */
function cleanupExpiredQuarantines(db: Database.Database): void {
  const now = Date.now();

  const cleanup = db.prepare<{ now: number }>(
    'DELETE FROM quarantine WHERE expires_at IS NOT NULL AND expires_at < @now',
  );

  cleanup.run({ now });
}

/**
 * Convert database row to Quarantine object.
 */
function rowToQuarantine(row: QuarantineRow): Quarantine {
  return {
    id: row.id,
    scope: row.scope as QuarantineScope,
    target: row.target,
    reason: row.reason,
    createdAt: row.created_at,
    expiresAt: row.expires_at ?? undefined,
    createdBy: row.created_by,
  };
}
