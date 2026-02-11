/**
 * Core type definitions for OpenClaw Sentinel MCP
 */

/**
 * Operation modes for the sentinel
 */
export type SentinelMode = 'silent-allow' | 'alert' | 'silent-deny' | 'lockdown';

/**
 * Rule actions
 */
export type RuleAction = 'allow' | 'deny' | 'ask' | 'log-only';

/**
 * Rule priority (lower number = higher priority)
 */
export type RulePriority = number;

/**
 * Time-of-day schedule for rules
 */
export interface Schedule {
  daysOfWeek?: number[]; // 0-6 (Sunday-Saturday)
  startHour?: number; // 0-23
  endHour?: number; // 0-23
  timezone?: string; // IANA timezone (default: system timezone)
}

/**
 * Rate limit configuration
 */
export interface RateLimit {
  maxOperations: number;
  windowSeconds: number;
  refillRate: number; // tokens per second
}

/**
 * Firewall rule definition
 */
export interface SentinelRule {
  id: string;
  name: string;
  priority: RulePriority;
  action: RuleAction;
  enabled: boolean;

  // Match criteria (glob patterns)
  toolPattern?: string; // e.g., "fleet_*", "openclaw_agent_*"
  hostPattern?: string; // e.g., "hyperion", "*"
  agentPattern?: string; // e.g., "user@*", "*"
  argumentPattern?: string; // Regex pattern for argument matching

  // Rate limiting
  rateLimit?: RateLimit;

  // Schedule
  schedule?: Schedule;

  // Metadata
  createdAt: number;
  updatedAt: number;
  description?: string;
  tags?: string[];
}

/**
 * Policy evaluation context
 */
export interface PolicyContext {
  tool: string;
  host: string;
  agent: string;
  arguments: Record<string, unknown>;
  timestamp: number;
  sessionId?: string;
  confirmationToken?: string; // For ask mode retries
}

/**
 * Risk factor for anomaly detection
 */
export interface RiskFactor {
  factor: string;
  score: number; // 0-100
  details: string;
}

/**
 * Policy verdict
 */
export interface PolicyVerdict {
  allowed: boolean;
  action: RuleAction;
  reason: string;
  matchedRuleId?: string;
  matchedRuleName?: string;
  riskScore: number; // 0-100 composite score
  riskFactors: RiskFactor[];
  requiresConfirmation: boolean;
  confirmationToken?: string;
}

/**
 * Audit log entry
 */
export interface AuditEntry {
  id: number;
  sequenceNumber: number;
  timestamp: number;
  tool: string;
  host: string;
  agent: string;
  arguments: string; // JSON (redacted)
  verdict: 'allowed' | 'denied' | 'asked';
  action: RuleAction;
  matchedRuleId?: string;
  riskScore: number;
  riskFactors: string; // JSON
  mode: SentinelMode;
  responseStatus?: 'success' | 'error' | 'timeout';
  errorMessage?: string;
  hash: string;
  previousHash: string;
}

/**
 * Audit chain verification result
 */
export interface AuditVerificationResult {
  valid: boolean;
  totalEntries: number;
  brokenChains: Array<{
    sequenceNumber: number;
    expectedHash: string;
    actualHash: string;
  }>;
}

/**
 * Anomaly baseline (EWMA)
 */
export interface AnomalyBaseline {
  id: number;
  tool: string;
  host: string;

  // Frequency baseline
  frequencyMean: number; // ops/hour
  frequencyStdDev: number;

  // Temporal baseline
  hourlyDistribution: string; // JSON array of 24 hourly probabilities

  // Argument baseline
  argumentFingerprints: string; // JSON set of seen argument hashes

  // Sequence baseline
  toolBigrams: string; // JSON map of tool call pairs → probability

  // Error rate baseline
  errorRateMean: number; // 0-1
  errorRateStdDev: number;

  // Metadata
  lastUpdated: number;
  sampleCount: number;
}

/**
 * Anomaly score breakdown
 */
export interface AnomalyScore {
  composite: number; // 0-100 weighted average
  frequency: number; // 0-100
  temporal: number; // 0-100
  argumentNovelty: number; // 0-100
  sequence: number; // 0-100
  errorRate: number; // 0-100
}

/**
 * Rate limit bucket
 */
export interface RateLimitBucket {
  id: number;
  ruleId: string;
  tool: string;
  host: string;
  agent: string;
  tokens: number;
  lastRefill: number;
  createdAt: number;
}

/**
 * Rate limit check result
 */
export interface RateLimitResult {
  allowed: boolean;
  remainingTokens: number;
  resetAt: number; // Unix timestamp
}

/**
 * Circuit breaker state
 */
export type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Circuit breaker record
 */
export interface CircuitBreaker {
  id: number;
  host: string;
  state: CircuitState;
  failureCount: number;
  lastFailure?: number;
  lastSuccess?: number;
  openedAt?: number;
  halfOpenAt?: number;
}

/**
 * Quarantine scope
 */
export type QuarantineScope = 'host' | 'tool' | 'agent';

/**
 * Quarantine record
 */
export interface Quarantine {
  id: number;
  scope: QuarantineScope;
  target: string; // host/tool/agent identifier
  reason: string;
  createdAt: number;
  expiresAt?: number;
  createdBy: string; // agent who created the quarantine
}

/**
 * Alert severity
 */
export type AlertSeverity = 'info' | 'warning' | 'critical';

/**
 * Alert status
 */
export type AlertStatus = 'active' | 'acknowledged' | 'resolved';

/**
 * Alert record
 */
export interface Alert {
  id: number;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  message: string;
  riskScore: number;
  tool: string;
  host: string;
  agent: string;
  createdAt: number;
  acknowledgedAt?: number;
  acknowledgedBy?: string;
  resolvedAt?: number;
  resolvedBy?: string;
}

/**
 * Confirmation token for ask mode
 */
export interface ConfirmationToken {
  id: number;
  token: string;
  tool: string;
  host: string;
  agent: string;
  arguments: string; // JSON
  createdAt: number;
  expiresAt: number;
  used: boolean;
}

/**
 * Sentinel configuration
 */
export interface SentinelConfig {
  mode: SentinelMode;
  databasePath: string;

  // openclaw-mcp subprocess config
  openclawMcpCommand: string;
  openclawMcpArgs: string[];

  // Anomaly detection thresholds
  anomalyThresholds: {
    suspicious: number; // Default: 30
    anomalous: number; // Default: 60
    critical: number; // Default: 80
    autoLockdown: number; // Default: 90
  };

  // Circuit breaker config
  circuitBreaker: {
    failureThreshold: number; // Default: 2
    cooldownMs: number; // Default: 120000 (2 min)
  };

  // Rate limit defaults
  defaultRateLimit?: RateLimit;

  // Alert webhooks
  alertWebhooks?: string[];

  // Confirmation token TTL
  confirmationTokenTtlMs: number; // Default: 300000 (5 min)
}

/**
 * Database row types (snake_case from SQLite)
 */
export interface RuleRow {
  id: string;
  name: string;
  priority: number;
  action: string;
  enabled: number;
  tool_pattern?: string;
  host_pattern?: string;
  agent_pattern?: string;
  argument_pattern?: string;
  rate_limit_max_operations?: number;
  rate_limit_window_seconds?: number;
  rate_limit_refill_rate?: number;
  schedule_days_of_week?: string;
  schedule_start_hour?: number;
  schedule_end_hour?: number;
  schedule_timezone?: string;
  created_at: number;
  updated_at: number;
  description?: string;
  tags?: string;
}

export interface AuditRow {
  id: number;
  sequence_number: number;
  timestamp: number;
  tool: string;
  host: string;
  agent: string;
  arguments: string;
  verdict: string;
  action: string;
  matched_rule_id?: string;
  risk_score: number;
  risk_factors: string;
  mode: string;
  response_status?: string;
  error_message?: string;
  hash: string;
  previous_hash: string;
}

export interface AnomalyBaselineRow {
  id: number;
  tool: string;
  host: string;
  frequency_mean: number;
  frequency_std_dev: number;
  hourly_distribution: string;
  argument_fingerprints: string;
  tool_bigrams: string;
  error_rate_mean: number;
  error_rate_std_dev: number;
  last_updated: number;
  sample_count: number;
}

export interface RateLimitBucketRow {
  id: number;
  rule_id: string;
  tool: string;
  host: string;
  agent: string;
  tokens: number;
  last_refill: number;
  created_at: number;
}

export interface CircuitBreakerRow {
  id: number;
  host: string;
  state: string;
  failure_count: number;
  last_failure?: number;
  last_success?: number;
  opened_at?: number;
  half_open_at?: number;
}

export interface QuarantineRow {
  id: number;
  scope: string;
  target: string;
  reason: string;
  created_at: number;
  expires_at?: number;
  created_by: string;
}

export interface AlertRow {
  id: number;
  severity: string;
  status: string;
  title: string;
  message: string;
  risk_score: number;
  tool: string;
  host: string;
  agent: string;
  created_at: number;
  acknowledged_at?: number;
  acknowledged_by?: string;
  resolved_at?: number;
  resolved_by?: string;
}

export interface ConfirmationTokenRow {
  id: number;
  token: string;
  tool: string;
  host: string;
  agent: string;
  arguments: string;
  created_at: number;
  expires_at: number;
  used: number;
}

export interface ConfigRow {
  key: string;
  value: string;
}
