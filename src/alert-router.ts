/**
 * Alert dispatch and routing
 */

import type Database from 'better-sqlite3';
import type { Alert, AlertRow, AlertSeverity, SentinelConfig } from './types.js';

/**
 * Determine alert severity from risk score
 *
 * @param riskScore - Risk score (0-100)
 * @returns Alert severity
 */
export function severityFromRiskScore(riskScore: number): AlertSeverity {
  if (riskScore >= 80) {
    return 'critical';
  }
  if (riskScore >= 60) {
    return 'warning';
  }
  return 'info';
}

/**
 * Fire an alert (write to database + dispatch)
 *
 * @param db - Database connection
 * @param alert - Alert to fire
 * @param config - Sentinel configuration (for webhook dispatch)
 */
export function fireAlert(
  db: Database.Database,
  alert: Omit<Alert, 'id'>,
  config?: SentinelConfig,
): void {
  const now = Date.now();

  const row: Omit<AlertRow, 'id'> = {
    severity: alert.severity,
    status: alert.status,
    title: alert.title,
    message: alert.message,
    risk_score: alert.riskScore,
    tool: alert.tool,
    host: alert.host,
    agent: alert.agent,
    created_at: now,
    acknowledged_at: undefined,
    acknowledged_by: undefined,
    resolved_at: undefined,
    resolved_by: undefined,
  };

  // Write to database
  db.prepare(
    `INSERT INTO alerts (
      severity, status, title, message, risk_score, tool, host, agent, created_at,
      acknowledged_at, acknowledged_by, resolved_at, resolved_by
    ) VALUES (
      @severity, @status, @title, @message, @risk_score, @tool, @host, @agent, @created_at,
      @acknowledged_at, @acknowledged_by, @resolved_at, @resolved_by
    )`,
  ).run(row);

  // Console output
  const severityIcon = {
    info: 'ℹ️',
    warning: '⚠️',
    critical: '🚨',
  };

  console.error(`${severityIcon[alert.severity]} SENTINEL ALERT [${alert.severity.toUpperCase()}]`);
  console.error(`Title: ${alert.title}`);
  console.error(`Message: ${alert.message}`);
  console.error(`Risk Score: ${alert.riskScore.toFixed(1)}`);
  console.error(`Tool: ${alert.tool} | Host: ${alert.host} | Agent: ${alert.agent}`);
  console.error('---');

  // Optional webhook dispatch
  if (config?.alertWebhooks && config.alertWebhooks.length > 0) {
    dispatchWebhooks(alert, config.alertWebhooks);
  }
}

/**
 * Dispatch alert to webhooks (fire-and-forget)
 *
 * @param alert - Alert to dispatch
 * @param webhooks - Webhook URLs
 */
function dispatchWebhooks(alert: Omit<Alert, 'id'>, webhooks: string[]): void {
  const payload = {
    severity: alert.severity,
    title: alert.title,
    message: alert.message,
    riskScore: alert.riskScore,
    tool: alert.tool,
    host: alert.host,
    agent: alert.agent,
    timestamp: Date.now(),
  };

  for (const url of webhooks) {
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    }).catch((err) => {
      console.error(`Failed to dispatch alert to webhook ${url}:`, err);
    });
  }
}
