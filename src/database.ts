/**
 * SQLite database initialization and schema for OpenClaw Sentinel
 */

import Database from 'better-sqlite3';
import type {
  RuleRow,
  AuditRow,
  AnomalyBaselineRow,
  RateLimitBucketRow,
  CircuitBreakerRow,
  QuarantineRow,
  AlertRow,
  ConfirmationTokenRow,
  ConfigRow,
} from './types.js';

export interface SentinelDatabase {
  db: Database.Database;
  close: () => void;
}

/**
 * Initialize the Sentinel database with schema
 */
export function initializeDatabase(dbPath: string): SentinelDatabase {
  const db = new Database(dbPath);

  // Enable WAL mode for better concurrency
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Create schema
  createSchema(db);

  return {
    db,
    close: () => db.close(),
  };
}

/**
 * Create all database tables
 */
function createSchema(db: Database.Database): void {
  // Table 1: Rules
  db.exec(`
    CREATE TABLE IF NOT EXISTS rules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      priority INTEGER NOT NULL DEFAULT 1000,
      action TEXT NOT NULL CHECK(action IN ('allow', 'deny', 'ask', 'log-only')),
      enabled INTEGER NOT NULL DEFAULT 1,

      -- Match criteria
      tool_pattern TEXT,
      host_pattern TEXT,
      agent_pattern TEXT,
      argument_pattern TEXT,

      -- Rate limiting
      rate_limit_max_operations INTEGER,
      rate_limit_window_seconds INTEGER,
      rate_limit_refill_rate REAL,

      -- Schedule
      schedule_days_of_week TEXT, -- JSON array
      schedule_start_hour INTEGER,
      schedule_end_hour INTEGER,
      schedule_timezone TEXT,

      -- Metadata
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      description TEXT,
      tags TEXT -- JSON array
    );

    CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);
    CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
  `);

  // Table 2: Audit Log
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sequence_number INTEGER NOT NULL UNIQUE,
      timestamp INTEGER NOT NULL,
      tool TEXT NOT NULL,
      host TEXT NOT NULL,
      agent TEXT NOT NULL,
      arguments TEXT NOT NULL, -- JSON (redacted)
      verdict TEXT NOT NULL CHECK(verdict IN ('allowed', 'denied', 'asked')),
      action TEXT NOT NULL,
      matched_rule_id TEXT,
      risk_score REAL NOT NULL,
      risk_factors TEXT NOT NULL, -- JSON
      mode TEXT NOT NULL,
      response_status TEXT CHECK(response_status IN ('success', 'error', 'timeout')),
      error_message TEXT,
      hash TEXT NOT NULL UNIQUE,
      previous_hash TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
    CREATE INDEX IF NOT EXISTS idx_audit_host ON audit_log(host);
    CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number);
  `);

  // Table 3: Anomaly Baselines
  db.exec(`
    CREATE TABLE IF NOT EXISTS anomaly_baselines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tool TEXT NOT NULL,
      host TEXT NOT NULL,
      frequency_mean REAL NOT NULL DEFAULT 0,
      frequency_std_dev REAL NOT NULL DEFAULT 0,
      hourly_distribution TEXT NOT NULL DEFAULT '[]', -- JSON
      argument_fingerprints TEXT NOT NULL DEFAULT '[]', -- JSON
      tool_bigrams TEXT NOT NULL DEFAULT '{}', -- JSON
      error_rate_mean REAL NOT NULL DEFAULT 0,
      error_rate_std_dev REAL NOT NULL DEFAULT 0,
      last_updated INTEGER NOT NULL,
      sample_count INTEGER NOT NULL DEFAULT 0,

      UNIQUE(tool, host)
    );

    CREATE INDEX IF NOT EXISTS idx_baselines_tool_host ON anomaly_baselines(tool, host);
  `);

  // Table 4: Rate Limit Buckets
  db.exec(`
    CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rule_id TEXT NOT NULL,
      tool TEXT NOT NULL,
      host TEXT NOT NULL,
      agent TEXT NOT NULL,
      tokens REAL NOT NULL,
      last_refill INTEGER NOT NULL,
      created_at INTEGER NOT NULL,

      UNIQUE(rule_id, tool, host, agent)
    );

    CREATE INDEX IF NOT EXISTS idx_buckets_key ON rate_limit_buckets(rule_id, tool, host, agent);
    CREATE INDEX IF NOT EXISTS idx_buckets_created ON rate_limit_buckets(created_at);
  `);

  // Table 5: Circuit Breakers
  db.exec(`
    CREATE TABLE IF NOT EXISTS circuit_breakers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL CHECK(state IN ('closed', 'open', 'half-open')),
      failure_count INTEGER NOT NULL DEFAULT 0,
      last_failure INTEGER,
      last_success INTEGER,
      opened_at INTEGER,
      half_open_at INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_circuit_host ON circuit_breakers(host);
  `);

  // Table 6: Quarantine
  db.exec(`
    CREATE TABLE IF NOT EXISTS quarantine (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scope TEXT NOT NULL CHECK(scope IN ('host', 'tool', 'agent')),
      target TEXT NOT NULL,
      reason TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER,
      created_by TEXT NOT NULL,

      UNIQUE(scope, target)
    );

    CREATE INDEX IF NOT EXISTS idx_quarantine_scope_target ON quarantine(scope, target);
    CREATE INDEX IF NOT EXISTS idx_quarantine_expires ON quarantine(expires_at);
  `);

  // Table 7: Alerts
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'critical')),
      status TEXT NOT NULL CHECK(status IN ('active', 'acknowledged', 'resolved')),
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      risk_score REAL NOT NULL,
      tool TEXT NOT NULL,
      host TEXT NOT NULL,
      agent TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      acknowledged_at INTEGER,
      acknowledged_by TEXT,
      resolved_at INTEGER,
      resolved_by TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
  `);

  // Table 8: Confirmation Tokens
  db.exec(`
    CREATE TABLE IF NOT EXISTS confirmation_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      tool TEXT NOT NULL,
      host TEXT NOT NULL,
      agent TEXT NOT NULL,
      arguments TEXT NOT NULL, -- JSON
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_tokens_token ON confirmation_tokens(token);
    CREATE INDEX IF NOT EXISTS idx_tokens_expires ON confirmation_tokens(expires_at);
  `);

  // Table 9: Config
  db.exec(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  // Initialize default config if empty
  const configCount = db.prepare('SELECT COUNT(*) as count FROM config').get() as { count: number };
  if (configCount.count === 0) {
    const insertConfig = db.prepare('INSERT INTO config (key, value) VALUES (?, ?)');
    insertConfig.run('mode', 'silent-allow');
    insertConfig.run('anomaly_threshold_suspicious', '30');
    insertConfig.run('anomaly_threshold_anomalous', '60');
    insertConfig.run('anomaly_threshold_critical', '80');
    insertConfig.run('anomaly_threshold_auto_lockdown', '90');
  }
}

/**
 * Prepared statement helpers
 */

export interface PreparedStatements {
  // Rules
  insertRule: Database.Statement<RuleRow>;
  updateRule: Database.Statement<Partial<RuleRow> & { id: string }>;
  deleteRule: Database.Statement<{ id: string }>;
  getRuleById: Database.Statement<{ id: string }>;
  listRules: Database.Statement<unknown[]>;
  listEnabledRules: Database.Statement<unknown[]>;

  // Audit Log
  insertAuditEntry: Database.Statement<Omit<AuditRow, 'id'>>;
  updateAuditEntry: Database.Statement<{ id: number; response_status?: string; error_message?: string }>;
  getLastAuditSequence: Database.Statement<unknown[]>;
  getLastAuditHash: Database.Statement<unknown[]>;
  queryAuditLog: Database.Statement<{ limit: number; offset: number }>;

  // Anomaly Baselines
  upsertBaseline: Database.Statement<Omit<AnomalyBaselineRow, 'id'>>;
  getBaseline: Database.Statement<{ tool: string; host: string }>;

  // Rate Limit Buckets
  upsertBucket: Database.Statement<Omit<RateLimitBucketRow, 'id'>>;
  getBucket: Database.Statement<{ rule_id: string; tool: string; host: string; agent: string }>;
  cleanupOldBuckets: Database.Statement<{ cutoff: number }>;

  // Circuit Breakers
  upsertCircuitBreaker: Database.Statement<Omit<CircuitBreakerRow, 'id'>>;
  getCircuitBreaker: Database.Statement<{ host: string }>;

  // Quarantine
  insertQuarantine: Database.Statement<Omit<QuarantineRow, 'id'>>;
  deleteQuarantine: Database.Statement<{ scope: string; target: string }>;
  getQuarantine: Database.Statement<{ scope: string; target: string }>;
  listQuarantines: Database.Statement<unknown[]>;
  cleanupExpiredQuarantines: Database.Statement<{ now: number }>;

  // Alerts
  insertAlert: Database.Statement<Omit<AlertRow, 'id'>>;
  updateAlert: Database.Statement<Partial<AlertRow> & { id: number }>;
  listAlerts: Database.Statement<{ status?: string }>;

  // Confirmation Tokens
  insertToken: Database.Statement<Omit<ConfirmationTokenRow, 'id'>>;
  getToken: Database.Statement<{ token: string }>;
  markTokenUsed: Database.Statement<{ token: string }>;
  cleanupExpiredTokens: Database.Statement<{ now: number }>;

  // Config
  getConfig: Database.Statement<{ key: string }>;
  setConfig: Database.Statement<{ key: string; value: string }>;
}

export function prepareStatements(db: Database.Database): PreparedStatements {
  return {
    // Rules
    insertRule: db.prepare(`
      INSERT INTO rules (
        id, name, priority, action, enabled, tool_pattern, host_pattern, agent_pattern,
        argument_pattern, rate_limit_max_operations, rate_limit_window_seconds,
        rate_limit_refill_rate, schedule_days_of_week, schedule_start_hour,
        schedule_end_hour, schedule_timezone, created_at, updated_at, description, tags
      ) VALUES (
        @id, @name, @priority, @action, @enabled, @tool_pattern, @host_pattern, @agent_pattern,
        @argument_pattern, @rate_limit_max_operations, @rate_limit_window_seconds,
        @rate_limit_refill_rate, @schedule_days_of_week, @schedule_start_hour,
        @schedule_end_hour, @schedule_timezone, @created_at, @updated_at, @description, @tags
      )
    `),
    updateRule: db.prepare(`
      UPDATE rules SET
        name = COALESCE(@name, name),
        priority = COALESCE(@priority, priority),
        action = COALESCE(@action, action),
        enabled = COALESCE(@enabled, enabled),
        tool_pattern = COALESCE(@tool_pattern, tool_pattern),
        host_pattern = COALESCE(@host_pattern, host_pattern),
        agent_pattern = COALESCE(@agent_pattern, agent_pattern),
        argument_pattern = COALESCE(@argument_pattern, argument_pattern),
        rate_limit_max_operations = COALESCE(@rate_limit_max_operations, rate_limit_max_operations),
        rate_limit_window_seconds = COALESCE(@rate_limit_window_seconds, rate_limit_window_seconds),
        rate_limit_refill_rate = COALESCE(@rate_limit_refill_rate, rate_limit_refill_rate),
        schedule_days_of_week = COALESCE(@schedule_days_of_week, schedule_days_of_week),
        schedule_start_hour = COALESCE(@schedule_start_hour, schedule_start_hour),
        schedule_end_hour = COALESCE(@schedule_end_hour, schedule_end_hour),
        schedule_timezone = COALESCE(@schedule_timezone, schedule_timezone),
        updated_at = @updated_at,
        description = COALESCE(@description, description),
        tags = COALESCE(@tags, tags)
      WHERE id = @id
    `),
    deleteRule: db.prepare('DELETE FROM rules WHERE id = @id'),
    getRuleById: db.prepare('SELECT * FROM rules WHERE id = @id'),
    listRules: db.prepare('SELECT * FROM rules ORDER BY priority ASC, created_at ASC'),
    listEnabledRules: db.prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY priority ASC, created_at ASC'),

    // Audit Log
    insertAuditEntry: db.prepare(`
      INSERT INTO audit_log (
        sequence_number, timestamp, tool, host, agent, arguments, verdict, action,
        matched_rule_id, risk_score, risk_factors, mode, response_status, error_message,
        hash, previous_hash
      ) VALUES (
        @sequence_number, @timestamp, @tool, @host, @agent, @arguments, @verdict, @action,
        @matched_rule_id, @risk_score, @risk_factors, @mode, @response_status, @error_message,
        @hash, @previous_hash
      )
    `),
    updateAuditEntry: db.prepare(`
      UPDATE audit_log SET
        response_status = COALESCE(@response_status, response_status),
        error_message = COALESCE(@error_message, error_message)
      WHERE id = @id
    `),
    getLastAuditSequence: db.prepare('SELECT MAX(sequence_number) as seq FROM audit_log'),
    getLastAuditHash: db.prepare('SELECT hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1'),
    queryAuditLog: db.prepare('SELECT * FROM audit_log ORDER BY sequence_number DESC LIMIT @limit OFFSET @offset'),

    // Anomaly Baselines
    upsertBaseline: db.prepare(`
      INSERT INTO anomaly_baselines (
        tool, host, frequency_mean, frequency_std_dev, hourly_distribution,
        argument_fingerprints, tool_bigrams, error_rate_mean, error_rate_std_dev,
        last_updated, sample_count
      ) VALUES (
        @tool, @host, @frequency_mean, @frequency_std_dev, @hourly_distribution,
        @argument_fingerprints, @tool_bigrams, @error_rate_mean, @error_rate_std_dev,
        @last_updated, @sample_count
      )
      ON CONFLICT(tool, host) DO UPDATE SET
        frequency_mean = @frequency_mean,
        frequency_std_dev = @frequency_std_dev,
        hourly_distribution = @hourly_distribution,
        argument_fingerprints = @argument_fingerprints,
        tool_bigrams = @tool_bigrams,
        error_rate_mean = @error_rate_mean,
        error_rate_std_dev = @error_rate_std_dev,
        last_updated = @last_updated,
        sample_count = @sample_count
    `),
    getBaseline: db.prepare('SELECT * FROM anomaly_baselines WHERE tool = @tool AND host = @host'),

    // Rate Limit Buckets
    upsertBucket: db.prepare(`
      INSERT INTO rate_limit_buckets (
        rule_id, tool, host, agent, tokens, last_refill, created_at
      ) VALUES (
        @rule_id, @tool, @host, @agent, @tokens, @last_refill, @created_at
      )
      ON CONFLICT(rule_id, tool, host, agent) DO UPDATE SET
        tokens = @tokens,
        last_refill = @last_refill
    `),
    getBucket: db.prepare('SELECT * FROM rate_limit_buckets WHERE rule_id = @rule_id AND tool = @tool AND host = @host AND agent = @agent'),
    cleanupOldBuckets: db.prepare('DELETE FROM rate_limit_buckets WHERE created_at < @cutoff'),

    // Circuit Breakers
    upsertCircuitBreaker: db.prepare(`
      INSERT INTO circuit_breakers (
        host, state, failure_count, last_failure, last_success, opened_at, half_open_at
      ) VALUES (
        @host, @state, @failure_count, @last_failure, @last_success, @opened_at, @half_open_at
      )
      ON CONFLICT(host) DO UPDATE SET
        state = @state,
        failure_count = @failure_count,
        last_failure = @last_failure,
        last_success = @last_success,
        opened_at = @opened_at,
        half_open_at = @half_open_at
    `),
    getCircuitBreaker: db.prepare('SELECT * FROM circuit_breakers WHERE host = @host'),

    // Quarantine
    insertQuarantine: db.prepare(`
      INSERT INTO quarantine (scope, target, reason, created_at, expires_at, created_by)
      VALUES (@scope, @target, @reason, @created_at, @expires_at, @created_by)
    `),
    deleteQuarantine: db.prepare('DELETE FROM quarantine WHERE scope = @scope AND target = @target'),
    getQuarantine: db.prepare('SELECT * FROM quarantine WHERE scope = @scope AND target = @target'),
    listQuarantines: db.prepare('SELECT * FROM quarantine ORDER BY created_at DESC'),
    cleanupExpiredQuarantines: db.prepare('DELETE FROM quarantine WHERE expires_at IS NOT NULL AND expires_at < @now'),

    // Alerts
    insertAlert: db.prepare(`
      INSERT INTO alerts (
        severity, status, title, message, risk_score, tool, host, agent, created_at,
        acknowledged_at, acknowledged_by, resolved_at, resolved_by
      ) VALUES (
        @severity, @status, @title, @message, @risk_score, @tool, @host, @agent, @created_at,
        @acknowledged_at, @acknowledged_by, @resolved_at, @resolved_by
      )
    `),
    updateAlert: db.prepare(`
      UPDATE alerts SET
        status = COALESCE(@status, status),
        acknowledged_at = COALESCE(@acknowledged_at, acknowledged_at),
        acknowledged_by = COALESCE(@acknowledged_by, acknowledged_by),
        resolved_at = COALESCE(@resolved_at, resolved_at),
        resolved_by = COALESCE(@resolved_by, resolved_by)
      WHERE id = @id
    `),
    listAlerts: db.prepare('SELECT * FROM alerts WHERE (@status IS NULL OR status = @status) ORDER BY created_at DESC'),

    // Confirmation Tokens
    insertToken: db.prepare(`
      INSERT INTO confirmation_tokens (token, tool, host, agent, arguments, created_at, expires_at, used)
      VALUES (@token, @tool, @host, @agent, @arguments, @created_at, @expires_at, @used)
    `),
    getToken: db.prepare('SELECT * FROM confirmation_tokens WHERE token = @token'),
    markTokenUsed: db.prepare('UPDATE confirmation_tokens SET used = 1 WHERE token = @token'),
    cleanupExpiredTokens: db.prepare('DELETE FROM confirmation_tokens WHERE expires_at < @now'),

    // Config
    getConfig: db.prepare('SELECT value FROM config WHERE key = @key'),
    setConfig: db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (@key, @value)'),
  };
}
