/**
 * Alert management tools for OpenClaw Sentinel MCP
 */

import { z } from 'zod';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { SentinelDatabase } from '../database.js';
import type { SentinelConfig, AlertRow } from '../types.js';
import { fireAlert, severityFromRiskScore } from '../alert-router.js';

/**
 * Register alert tools
 *
 * @param server - MCP server instance
 * @param sentinelDb - Sentinel database
 * @param config - Sentinel configuration
 */
export function registerAlertTools(
  server: Server,
  sentinelDb: SentinelDatabase,
  config: SentinelConfig,
): void {
  const { db } = sentinelDb;

  // Tool 1: List alerts
  server.tool(
    'sentinel_alert_list',
    'List sentinel alerts with optional status filter',
    {
      status: z
        .enum(['active', 'acknowledged', 'resolved'])
        .optional()
        .describe('Filter by alert status (default: all)'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum number of alerts to return'),
    },
    async (args) => {
      const status = args.status as 'active' | 'acknowledged' | 'resolved' | undefined;
      const limit = args.limit as number;

      const alerts = db
        .prepare(
          `SELECT * FROM alerts
           WHERE (@status IS NULL OR status = @status)
           ORDER BY created_at DESC
           LIMIT @limit`,
        )
        .all({ status: status ?? null, limit }) as AlertRow[];

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                count: alerts.length,
                alerts: alerts.map((row) => ({
                  id: row.id,
                  severity: row.severity,
                  status: row.status,
                  title: row.title,
                  message: row.message,
                  riskScore: row.risk_score,
                  tool: row.tool,
                  host: row.host,
                  agent: row.agent,
                  createdAt: new Date(row.created_at).toISOString(),
                  acknowledgedAt: row.acknowledged_at
                    ? new Date(row.acknowledged_at).toISOString()
                    : undefined,
                  acknowledgedBy: row.acknowledged_by ?? undefined,
                  resolvedAt: row.resolved_at ? new Date(row.resolved_at).toISOString() : undefined,
                  resolvedBy: row.resolved_by ?? undefined,
                })),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 2: Acknowledge alert
  server.tool(
    'sentinel_alert_acknowledge',
    'Acknowledge a sentinel alert',
    {
      alertId: z.number().describe('Alert ID to acknowledge'),
      acknowledgedBy: z.string().describe('Agent/user acknowledging the alert'),
    },
    async (args) => {
      const alertId = args.alertId as number;
      const acknowledgedBy = args.acknowledgedBy as string;

      const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(alertId) as AlertRow | undefined;

      if (!alert) {
        throw new Error(`Alert ${alertId} not found`);
      }

      if (alert.status !== 'active') {
        throw new Error(`Alert ${alertId} is not active (current status: ${alert.status})`);
      }

      const now = Date.now();
      db.prepare(
        'UPDATE alerts SET status = ?, acknowledged_at = ?, acknowledged_by = ? WHERE id = ?',
      ).run('acknowledged', now, acknowledgedBy, alertId);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                alertId,
                status: 'acknowledged',
                acknowledgedBy,
                acknowledgedAt: new Date(now).toISOString(),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 3: Configure alert webhooks
  server.tool(
    'sentinel_alert_configure',
    'Configure alert webhook URLs',
    {
      webhooks: z.array(z.string().url()).describe('Array of webhook URLs to receive alerts'),
    },
    async (args) => {
      const webhooks = args.webhooks as string[];

      // Update config in database
      db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(
        'alert_webhooks',
        JSON.stringify(webhooks),
      );

      // Update in-memory config
      config.alertWebhooks = webhooks;

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                webhooks,
                message: `Configured ${webhooks.length} alert webhook(s)`,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 4: Test alert dispatch
  server.tool(
    'sentinel_alert_test',
    'Test alert dispatch (sends test alert)',
    {
      severity: z.enum(['info', 'warning', 'critical']).default('info').describe('Test alert severity'),
    },
    async (args) => {
      const severity = args.severity as 'info' | 'warning' | 'critical';

      const testAlert = {
        severity,
        status: 'active' as const,
        title: 'Test Alert',
        message: 'This is a test alert from OpenClaw Sentinel',
        riskScore: severity === 'critical' ? 85 : severity === 'warning' ? 65 : 45,
        tool: 'sentinel_alert_test',
        host: 'test',
        agent: 'test-agent',
      };

      fireAlert(db, testAlert, config);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                message: 'Test alert fired',
                severity,
                webhooksConfigured: config.alertWebhooks?.length ?? 0,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 5: Alert history query
  server.tool(
    'sentinel_alert_history',
    'Query alert history with advanced filters',
    {
      tool: z.string().optional().describe('Filter by tool name'),
      host: z.string().optional().describe('Filter by host'),
      agent: z.string().optional().describe('Filter by agent'),
      severity: z.enum(['info', 'warning', 'critical']).optional().describe('Filter by severity'),
      minRiskScore: z.number().min(0).max(100).optional().describe('Minimum risk score'),
      startTime: z.number().optional().describe('Start timestamp (Unix ms)'),
      endTime: z.number().optional().describe('End timestamp (Unix ms)'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum results'),
    },
    async (args) => {
      const tool = args.tool as string | undefined;
      const host = args.host as string | undefined;
      const agent = args.agent as string | undefined;
      const severity = args.severity as 'info' | 'warning' | 'critical' | undefined;
      const minRiskScore = args.minRiskScore as number | undefined;
      const startTime = args.startTime as number | undefined;
      const endTime = args.endTime as number | undefined;
      const limit = args.limit as number;

      const conditions: string[] = [];
      const params: Record<string, string | number | null> = {};

      if (tool) {
        conditions.push('tool = @tool');
        params.tool = tool;
      }

      if (host) {
        conditions.push('host = @host');
        params.host = host;
      }

      if (agent) {
        conditions.push('agent = @agent');
        params.agent = agent;
      }

      if (severity) {
        conditions.push('severity = @severity');
        params.severity = severity;
      }

      if (minRiskScore !== undefined) {
        conditions.push('risk_score >= @minRiskScore');
        params.minRiskScore = minRiskScore;
      }

      if (startTime !== undefined) {
        conditions.push('created_at >= @startTime');
        params.startTime = startTime;
      }

      if (endTime !== undefined) {
        conditions.push('created_at <= @endTime');
        params.endTime = endTime;
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
      const query = `SELECT * FROM alerts ${whereClause} ORDER BY created_at DESC LIMIT @limit`;
      params.limit = limit;

      const alerts = db.prepare(query).all(params) as AlertRow[];

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                count: alerts.length,
                filters: {
                  tool,
                  host,
                  agent,
                  severity,
                  minRiskScore,
                  startTime: startTime ? new Date(startTime).toISOString() : undefined,
                  endTime: endTime ? new Date(endTime).toISOString() : undefined,
                },
                alerts: alerts.map((row) => ({
                  id: row.id,
                  severity: row.severity,
                  status: row.status,
                  title: row.title,
                  message: row.message,
                  riskScore: row.risk_score,
                  tool: row.tool,
                  host: row.host,
                  agent: row.agent,
                  createdAt: new Date(row.created_at).toISOString(),
                })),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );
}
