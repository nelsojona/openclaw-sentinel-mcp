/**
 * Policy evaluation engine for OpenClaw Sentinel
 *
 * Evaluation order (7 steps):
 * 1. Circuit breaker check (host unavailable?)
 * 2. Quarantine check (host/tool/agent quarantined?)
 * 3. Mode enforcement (lockdown = deny all except health)
 * 4. Rule matching (priority-ordered, first match wins)
 * 5. Rate limiting (per matching rule's bucket)
 * 6. Anomaly detection (score + risk factors)
 * 7. Final verdict (allow/deny/ask/log-only)
 */

import type Database from 'better-sqlite3';
import type {
  PolicyContext,
  PolicyVerdict,
  SentinelMode,
  SentinelRule,
  RuleRow,
  RiskFactor,
  Schedule,
  RateLimit,
} from './types.js';

/**
 * Convert glob pattern to regex
 *
 * Supports:
 * - * (matches any characters except /)
 * - ** (matches any characters including /)
 * - ? (matches single character)
 *
 * @param pattern - Glob pattern
 * @returns RegExp
 */
function globToRegex(pattern: string): RegExp {
  // Escape special regex characters except glob wildcards
  let regex = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '__DOUBLESTAR__')
    .replace(/\*/g, '[^/]*')
    .replace(/__DOUBLESTAR__/g, '.*')
    .replace(/\?/g, '.');

  return new RegExp(`^${regex}$`, 'i');
}

/**
 * Check if a value matches a glob pattern
 *
 * @param value - Value to test
 * @param pattern - Glob pattern
 * @returns True if matches
 */
function matchesPattern(value: string, pattern: string): boolean {
  const regex = globToRegex(pattern);
  return regex.test(value);
}

/**
 * Check if current time is within schedule
 *
 * @param schedule - Schedule configuration
 * @returns True if within schedule
 */
function withinSchedule(schedule: Schedule): boolean {
  const now = new Date();

  // Check day of week
  if (schedule.daysOfWeek && schedule.daysOfWeek.length > 0) {
    const dayOfWeek = now.getDay(); // 0-6
    if (!schedule.daysOfWeek.includes(dayOfWeek)) {
      return false;
    }
  }

  // Check time of day
  if (schedule.startHour !== undefined || schedule.endHour !== undefined) {
    const hour = now.getHours(); // 0-23
    const startHour = schedule.startHour ?? 0;
    const endHour = schedule.endHour ?? 23;

    if (hour < startHour || hour > endHour) {
      return false;
    }
  }

  return true;
}

/**
 * Convert database row to SentinelRule
 *
 * @param row - Database row
 * @returns SentinelRule
 */
function rowToRule(row: RuleRow): SentinelRule {
  const rule: SentinelRule = {
    id: row.id,
    name: row.name,
    priority: row.priority,
    action: row.action as 'allow' | 'deny' | 'ask' | 'log-only',
    enabled: row.enabled === 1,
    toolPattern: row.tool_pattern ?? undefined,
    hostPattern: row.host_pattern ?? undefined,
    agentPattern: row.agent_pattern ?? undefined,
    argumentPattern: row.argument_pattern ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    description: row.description ?? undefined,
    tags: row.tags ? JSON.parse(row.tags) : undefined,
  };

  // Rate limit
  if (
    row.rate_limit_max_operations !== null &&
    row.rate_limit_max_operations !== undefined &&
    row.rate_limit_window_seconds !== null &&
    row.rate_limit_window_seconds !== undefined &&
    row.rate_limit_refill_rate !== null &&
    row.rate_limit_refill_rate !== undefined
  ) {
    rule.rateLimit = {
      maxOperations: row.rate_limit_max_operations,
      windowSeconds: row.rate_limit_window_seconds,
      refillRate: row.rate_limit_refill_rate,
    };
  }

  // Schedule
  if (
    row.schedule_days_of_week ||
    row.schedule_start_hour !== null ||
    row.schedule_end_hour !== null ||
    row.schedule_timezone
  ) {
    rule.schedule = {
      daysOfWeek: row.schedule_days_of_week ? JSON.parse(row.schedule_days_of_week) : undefined,
      startHour: row.schedule_start_hour ?? undefined,
      endHour: row.schedule_end_hour ?? undefined,
      timezone: row.schedule_timezone ?? undefined,
    };
  }

  return rule;
}

/**
 * Check if a rule matches the context
 *
 * @param rule - Rule to check
 * @param context - Policy context
 * @returns True if rule matches
 */
function ruleMatches(rule: SentinelRule, context: PolicyContext): boolean {
  // Tool pattern
  if (rule.toolPattern && !matchesPattern(context.tool, rule.toolPattern)) {
    return false;
  }

  // Host pattern
  if (rule.hostPattern && !matchesPattern(context.host, rule.hostPattern)) {
    return false;
  }

  // Agent pattern
  if (rule.agentPattern && !matchesPattern(context.agent, rule.agentPattern)) {
    return false;
  }

  // Argument pattern (regex on JSON serialized arguments)
  if (rule.argumentPattern) {
    const argsStr = JSON.stringify(context.arguments);
    const regex = new RegExp(rule.argumentPattern, 'i');
    if (!regex.test(argsStr)) {
      return false;
    }
  }

  // Schedule
  if (rule.schedule && !withinSchedule(rule.schedule)) {
    return false;
  }

  return true;
}

/**
 * Calculate composite risk score from individual risk factors
 *
 * @param riskFactors - Array of risk factors
 * @param anomalyScore - Anomaly detection composite score
 * @returns Composite risk score (0-100)
 */
function calculateCompositeRisk(riskFactors: RiskFactor[], anomalyScore: number): number {
  if (riskFactors.length === 0) {
    return anomalyScore;
  }

  // Weight: 60% anomaly score, 40% average of other risk factors
  const otherFactorsAvg =
    riskFactors.reduce((sum, factor) => sum + factor.score, 0) / riskFactors.length;

  return Math.min(100, anomalyScore * 0.6 + otherFactorsAvg * 0.4);
}

/**
 * Check if host circuit breaker is open
 *
 * @param db - Database connection
 * @param host - Host identifier
 * @returns True if circuit is open (host unavailable)
 */
function isCircuitOpen(db: Database.Database, host: string): boolean {
  const row = db
    .prepare('SELECT state, opened_at FROM circuit_breakers WHERE host = ?')
    .get(host) as { state: string; opened_at: number } | undefined;

  if (!row) {
    return false; // No circuit breaker = closed
  }

  if (row.state === 'open') {
    // Check if cooldown period has elapsed (default 120s)
    const cooldownMs = 120000;
    const now = Date.now();
    if (now - row.opened_at < cooldownMs) {
      return true; // Still in cooldown
    }

    // Move to half-open state
    db.prepare('UPDATE circuit_breakers SET state = ?, half_open_at = ? WHERE host = ?').run(
      'half-open',
      now,
      host,
    );
    return false;
  }

  return false;
}

/**
 * Check if target is quarantined
 *
 * @param db - Database connection
 * @param scope - Quarantine scope (host/tool/agent)
 * @param target - Target identifier
 * @returns True if quarantined
 */
function isQuarantined(
  db: Database.Database,
  scope: 'host' | 'tool' | 'agent',
  target: string,
): boolean {
  // Clean up expired quarantines first
  db.prepare('DELETE FROM quarantine WHERE expires_at IS NOT NULL AND expires_at < ?').run(Date.now());

  const row = db
    .prepare('SELECT id FROM quarantine WHERE scope = ? AND target = ?')
    .get(scope, target) as { id: number } | undefined;

  return row !== undefined;
}

/**
 * Evaluate policy for a given context
 *
 * Implements the 7-step evaluation order:
 * 1. Circuit breaker check
 * 2. Quarantine check
 * 3. Mode enforcement
 * 4. Rule matching
 * 5. Rate limiting (handled by caller)
 * 6. Anomaly detection (handled by caller)
 * 7. Final verdict
 *
 * @param db - Database connection
 * @param context - Policy context
 * @param mode - Current sentinel mode
 * @param anomalyScore - Anomaly score (0-100)
 * @param additionalRiskFactors - Additional risk factors from external analysis
 * @returns Policy verdict
 */
export function evaluatePolicy(
  db: Database.Database,
  context: PolicyContext,
  mode: SentinelMode,
  anomalyScore: number = 0,
  additionalRiskFactors: RiskFactor[] = [],
): PolicyVerdict {
  const riskFactors: RiskFactor[] = [...additionalRiskFactors];

  // Step 1: Circuit breaker check
  if (isCircuitOpen(db, context.host)) {
    riskFactors.push({
      factor: 'circuit_breaker',
      score: 100,
      details: `Circuit breaker open for host ${context.host}`,
    });

    return {
      allowed: false,
      action: 'deny',
      reason: `Host ${context.host} circuit breaker is open (unavailable)`,
      riskScore: 100,
      riskFactors,
      requiresConfirmation: false,
    };
  }

  // Step 2: Quarantine check
  if (isQuarantined(db, 'host', context.host)) {
    riskFactors.push({
      factor: 'quarantine',
      score: 100,
      details: `Host ${context.host} is quarantined`,
    });

    return {
      allowed: false,
      action: 'deny',
      reason: `Host ${context.host} is quarantined`,
      riskScore: 100,
      riskFactors,
      requiresConfirmation: false,
    };
  }

  if (isQuarantined(db, 'tool', context.tool)) {
    riskFactors.push({
      factor: 'quarantine',
      score: 100,
      details: `Tool ${context.tool} is quarantined`,
    });

    return {
      allowed: false,
      action: 'deny',
      reason: `Tool ${context.tool} is quarantined`,
      riskScore: 100,
      riskFactors,
      requiresConfirmation: false,
    };
  }

  if (isQuarantined(db, 'agent', context.agent)) {
    riskFactors.push({
      factor: 'quarantine',
      score: 100,
      details: `Agent ${context.agent} is quarantined`,
    });

    return {
      allowed: false,
      action: 'deny',
      reason: `Agent ${context.agent} is quarantined`,
      riskScore: 100,
      riskFactors,
      requiresConfirmation: false,
    };
  }

  // Step 3: Mode enforcement
  if (mode === 'lockdown') {
    // In lockdown, only allow health checks
    const isHealthCheck = context.tool.includes('health') || context.tool.includes('status');
    if (!isHealthCheck) {
      riskFactors.push({
        factor: 'lockdown_mode',
        score: 100,
        details: 'System in lockdown mode, only health checks allowed',
      });

      return {
        allowed: false,
        action: 'deny',
        reason: 'System in lockdown mode',
        riskScore: 100,
        riskFactors,
        requiresConfirmation: false,
      };
    } else {
      // Health check in lockdown - allow it
      return {
        allowed: true,
        action: 'allow',
        reason: 'Health check allowed in lockdown mode',
        riskScore: 0,
        riskFactors,
        requiresConfirmation: false,
      };
    }
  }

  // Step 4: Rule matching (priority-ordered, first match wins)
  const rules = db
    .prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY priority ASC, created_at ASC')
    .all() as RuleRow[];

  for (const ruleRow of rules) {
    const rule = rowToRule(ruleRow);

    if (ruleMatches(rule, context)) {
      // Matched rule - calculate composite risk
      const compositeRisk = calculateCompositeRisk(riskFactors, anomalyScore);

      // Check for confirmation token (ask mode retry)
      if (rule.action === 'ask' && context.confirmationToken) {
        // Verify token
        const tokenRow = db
          .prepare('SELECT used FROM confirmation_tokens WHERE token = ? AND used = 0')
          .get(context.confirmationToken) as { used: number } | undefined;

        if (tokenRow) {
          // Valid token - mark used and allow
          db.prepare('UPDATE confirmation_tokens SET used = 1 WHERE token = ?').run(
            context.confirmationToken,
          );

          return {
            allowed: true,
            action: 'allow',
            reason: `Confirmed via token (rule: ${rule.name})`,
            matchedRuleId: rule.id,
            matchedRuleName: rule.name,
            riskScore: compositeRisk,
            riskFactors,
            requiresConfirmation: false,
          };
        }
      }

      // Apply rule action
      if (rule.action === 'allow') {
        return {
          allowed: true,
          action: 'allow',
          reason: `Allowed by rule: ${rule.name}`,
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
          riskScore: compositeRisk,
          riskFactors,
          requiresConfirmation: false,
        };
      }

      if (rule.action === 'deny') {
        return {
          allowed: false,
          action: 'deny',
          reason: `Denied by rule: ${rule.name}`,
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
          riskScore: compositeRisk,
          riskFactors,
          requiresConfirmation: false,
        };
      }

      if (rule.action === 'ask') {
        return {
          allowed: false,
          action: 'ask',
          reason: `Confirmation required (rule: ${rule.name})`,
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
          riskScore: compositeRisk,
          riskFactors,
          requiresConfirmation: true,
        };
      }

      if (rule.action === 'log-only') {
        // Log but allow
        return {
          allowed: true,
          action: 'log-only',
          reason: `Logged by rule: ${rule.name}`,
          matchedRuleId: rule.id,
          matchedRuleName: rule.name,
          riskScore: compositeRisk,
          riskFactors,
          requiresConfirmation: false,
        };
      }
    }
  }

  // Step 7: No rule matched - apply mode-based default
  const compositeRisk = calculateCompositeRisk(riskFactors, anomalyScore);

  if (mode === 'silent-allow') {
    return {
      allowed: true,
      action: 'allow',
      reason: 'No matching rule, silent-allow mode',
      riskScore: compositeRisk,
      riskFactors,
      requiresConfirmation: false,
    };
  }

  if (mode === 'alert') {
    // Ask for confirmation in alert mode
    return {
      allowed: false,
      action: 'ask',
      reason: 'No matching rule, confirmation required in alert mode',
      riskScore: compositeRisk,
      riskFactors,
      requiresConfirmation: true,
    };
  }

  if (mode === 'silent-deny') {
    return {
      allowed: false,
      action: 'deny',
      reason: 'No matching rule, deny-by-default in silent-deny mode',
      riskScore: compositeRisk,
      riskFactors,
      requiresConfirmation: false,
    };
  }

  // Default: deny
  return {
    allowed: false,
    action: 'deny',
    reason: 'No matching rule, default deny',
    riskScore: compositeRisk,
    riskFactors,
    requiresConfirmation: false,
  };
}
