/**
 * Circuit breaker state machine for host health tracking.
 *
 * Adapted from openclaw-fleet/addons/openclaw-mcp/src/mcp/fleet-health.ts
 *
 * States:
 * - closed: Normal operation (< failure threshold)
 * - open: Too many failures, reject operations
 * - half-open: Cooldown elapsed, allow one retry
 *
 * Default: 2 failures threshold, 120s cooldown
 */

import type Database from 'better-sqlite3';
import type { CircuitState, CircuitBreakerRow } from './types.js';

const FAILURE_THRESHOLD = 2;
const DEFAULT_COOLDOWN_MS = 120_000; // 120 seconds

/**
 * Record a successful operation for a host.
 * Resets the failure counter and closes the circuit.
 */
export function recordSuccess(db: Database.Database, host: string): void {
  const now = Date.now();

  const upsert = db.prepare<Omit<CircuitBreakerRow, 'id'>>(
    `INSERT INTO circuit_breakers (host, state, failure_count, last_failure, last_success, opened_at, half_open_at)
     VALUES (@host, @state, @failure_count, @last_failure, @last_success, @opened_at, @half_open_at)
     ON CONFLICT(host) DO UPDATE SET
       state = @state,
       failure_count = @failure_count,
       last_success = @last_success,
       opened_at = NULL,
       half_open_at = NULL`,
  );

  upsert.run({
    host,
    state: 'closed',
    failure_count: 0,
    last_failure: null,
    last_success: now,
    opened_at: null,
    half_open_at: null,
  });
}

/**
 * Record a failed operation for a host.
 * Increments failure count and opens circuit after threshold.
 */
export function recordFailure(db: Database.Database, host: string): void {
  const now = Date.now();

  const getBreaker = db.prepare<{ host: string }>(
    'SELECT * FROM circuit_breakers WHERE host = @host',
  );

  const existing = getBreaker.get({ host }) as CircuitBreakerRow | undefined;

  const newFailureCount = (existing?.failure_count ?? 0) + 1;
  const newState: CircuitState = newFailureCount >= FAILURE_THRESHOLD ? 'open' : 'closed';

  const upsert = db.prepare<Omit<CircuitBreakerRow, 'id'>>(
    `INSERT INTO circuit_breakers (host, state, failure_count, last_failure, last_success, opened_at, half_open_at)
     VALUES (@host, @state, @failure_count, @last_failure, @last_success, @opened_at, @half_open_at)
     ON CONFLICT(host) DO UPDATE SET
       state = @state,
       failure_count = @failure_count,
       last_failure = @last_failure,
       opened_at = @opened_at`,
  );

  upsert.run({
    host,
    state: newState,
    failure_count: newFailureCount,
    last_failure: now,
    last_success: existing?.last_success ?? null,
    opened_at: newState === 'open' ? now : existing?.opened_at ?? null,
    half_open_at: null,
  });
}

/**
 * Get the circuit state for a host.
 * Returns 'closed', 'open', or 'half-open' based on failure count and cooldown.
 */
export function getState(db: Database.Database, host: string, cooldownMs: number = DEFAULT_COOLDOWN_MS): CircuitState {
  const now = Date.now();

  const getBreaker = db.prepare<{ host: string }>(
    'SELECT * FROM circuit_breakers WHERE host = @host',
  );

  const breaker = getBreaker.get({ host }) as CircuitBreakerRow | undefined;

  if (!breaker) {
    return 'closed';
  }

  if (breaker.failure_count < FAILURE_THRESHOLD) {
    return 'closed';
  }

  // Circuit is open - check if cooldown has elapsed
  if (breaker.opened_at) {
    const elapsed = now - breaker.opened_at;
    if (elapsed >= cooldownMs) {
      // Transition to half-open
      const updateState = db.prepare<{ state: string; half_open_at: number; host: string }>(
        'UPDATE circuit_breakers SET state = @state, half_open_at = @half_open_at WHERE host = @host',
      );

      updateState.run({
        state: 'half-open',
        half_open_at: now,
        host,
      });

      return 'half-open';
    }
  }

  return breaker.state as CircuitState;
}

/**
 * Check if a host is healthy (circuit closed or half-open).
 * Returns false if circuit is open.
 */
export function isHealthy(db: Database.Database, host: string, cooldownMs: number = DEFAULT_COOLDOWN_MS): boolean {
  const state = getState(db, host, cooldownMs);
  return state !== 'open';
}

/**
 * Get the number of seconds until the circuit may half-open.
 * Returns 0 if already healthy or half-open.
 */
export function retryAfterSeconds(db: Database.Database, host: string, cooldownMs: number = DEFAULT_COOLDOWN_MS): number {
  const now = Date.now();

  const getBreaker = db.prepare<{ host: string }>(
    'SELECT * FROM circuit_breakers WHERE host = @host',
  );

  const breaker = getBreaker.get({ host }) as CircuitBreakerRow | undefined;

  if (!breaker || breaker.failure_count < FAILURE_THRESHOLD) {
    return 0;
  }

  if (!breaker.opened_at) {
    return 0;
  }

  const elapsed = now - breaker.opened_at;
  const remaining = cooldownMs - elapsed;

  return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
}
