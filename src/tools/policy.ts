/**
 * Policy management tools for OpenClaw Sentinel MCP
 */

import { z } from 'zod';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { SentinelDatabase } from '../database.js';
import type { SentinelConfig, AnomalyBaselineRow, RuleRow } from '../types.js';

/**
 * Register policy tools
 *
 * @param server - MCP server instance
 * @param sentinelDb - Sentinel database
 * @param config - Sentinel configuration
 */
export function registerPolicyTools(
  server: Server,
  sentinelDb: SentinelDatabase,
  config: SentinelConfig,
): void {
  const { db } = sentinelDb;

  // Tool 1: Policy status
  server.tool(
    'sentinel_policy_status',
    'Show current sentinel mode and anomaly thresholds',
    {},
    async () => {
      const mode = (db.prepare('SELECT value FROM config WHERE key = ?').get('mode') as { value: string })
        .value;

      const thresholds = {
        suspicious: Number(
          (db.prepare('SELECT value FROM config WHERE key = ?').get('anomaly_threshold_suspicious') as {
            value: string;
          }).value,
        ),
        anomalous: Number(
          (db.prepare('SELECT value FROM config WHERE key = ?').get('anomaly_threshold_anomalous') as {
            value: string;
          }).value,
        ),
        critical: Number(
          (db.prepare('SELECT value FROM config WHERE key = ?').get('anomaly_threshold_critical') as {
            value: string;
          }).value,
        ),
        autoLockdown: Number(
          (db.prepare('SELECT value FROM config WHERE key = ?').get('anomaly_threshold_auto_lockdown') as {
            value: string;
          }).value,
        ),
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                mode,
                anomalyThresholds: thresholds,
                description: {
                  'silent-allow': 'Allow all operations by default, log only',
                  alert: 'Prompt for confirmation when no rule matches',
                  'silent-deny': 'Deny all operations by default',
                  lockdown: 'Deny all operations except health checks',
                },
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 2: View anomaly baselines
  server.tool(
    'sentinel_policy_baseline',
    'View anomaly detection baselines for tool/host pairs',
    {
      tool: z.string().optional().describe('Filter by tool name'),
      host: z.string().optional().describe('Filter by host'),
      limit: z.number().min(1).max(100).default(20).describe('Maximum baselines to return'),
    },
    async (args) => {
      const tool = args.tool as string | undefined;
      const host = args.host as string | undefined;
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

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
      const query = `SELECT * FROM anomaly_baselines ${whereClause} ORDER BY last_updated DESC LIMIT @limit`;
      params.limit = limit;

      const baselines = db.prepare(query).all(params) as AnomalyBaselineRow[];

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                count: baselines.length,
                baselines: baselines.map((row) => ({
                  tool: row.tool,
                  host: row.host,
                  frequency: {
                    mean: row.frequency_mean.toFixed(2),
                    stdDev: row.frequency_std_dev.toFixed(2),
                  },
                  errorRate: {
                    mean: (row.error_rate_mean * 100).toFixed(2) + '%',
                    stdDev: (row.error_rate_std_dev * 100).toFixed(2) + '%',
                  },
                  sampleCount: row.sample_count,
                  lastUpdated: new Date(row.last_updated).toISOString(),
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

  // Tool 3: Update anomaly thresholds
  server.tool(
    'sentinel_policy_threshold',
    'Update anomaly detection thresholds',
    {
      suspicious: z.number().min(0).max(100).optional().describe('Suspicious threshold (default: 30)'),
      anomalous: z.number().min(0).max(100).optional().describe('Anomalous threshold (default: 60)'),
      critical: z.number().min(0).max(100).optional().describe('Critical threshold (default: 80)'),
      autoLockdown: z.number().min(0).max(100).optional().describe('Auto-lockdown threshold (default: 90)'),
    },
    async (args) => {
      const suspicious = args.suspicious as number | undefined;
      const anomalous = args.anomalous as number | undefined;
      const critical = args.critical as number | undefined;
      const autoLockdown = args.autoLockdown as number | undefined;

      const updates: Record<string, number> = {};

      if (suspicious !== undefined) {
        db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(
          'anomaly_threshold_suspicious',
          suspicious.toString(),
        );
        config.anomalyThresholds.suspicious = suspicious;
        updates.suspicious = suspicious;
      }

      if (anomalous !== undefined) {
        db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(
          'anomaly_threshold_anomalous',
          anomalous.toString(),
        );
        config.anomalyThresholds.anomalous = anomalous;
        updates.anomalous = anomalous;
      }

      if (critical !== undefined) {
        db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(
          'anomaly_threshold_critical',
          critical.toString(),
        );
        config.anomalyThresholds.critical = critical;
        updates.critical = critical;
      }

      if (autoLockdown !== undefined) {
        db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(
          'anomaly_threshold_auto_lockdown',
          autoLockdown.toString(),
        );
        config.anomalyThresholds.autoLockdown = autoLockdown;
        updates.autoLockdown = autoLockdown;
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                updates,
                currentThresholds: config.anomalyThresholds,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 4: View/update rule schedules
  server.tool(
    'sentinel_policy_schedule',
    'View or update rule schedules',
    {
      ruleId: z.string().describe('Rule ID to view/update'),
      daysOfWeek: z
        .array(z.number().min(0).max(6))
        .optional()
        .describe('Days of week (0=Sunday, 6=Saturday)'),
      startHour: z.number().min(0).max(23).optional().describe('Start hour (0-23)'),
      endHour: z.number().min(0).max(23).optional().describe('End hour (0-23)'),
      timezone: z.string().optional().describe('IANA timezone (e.g., America/New_York)'),
    },
    async (args) => {
      const ruleId = args.ruleId as string;
      const daysOfWeek = args.daysOfWeek as number[] | undefined;
      const startHour = args.startHour as number | undefined;
      const endHour = args.endHour as number | undefined;
      const timezone = args.timezone as string | undefined;

      const rule = db.prepare('SELECT * FROM rules WHERE id = ?').get(ruleId) as RuleRow | undefined;

      if (!rule) {
        throw new Error(`Rule ${ruleId} not found`);
      }

      // If no updates, just return current schedule
      if (
        daysOfWeek === undefined &&
        startHour === undefined &&
        endHour === undefined &&
        timezone === undefined
      ) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ruleId: rule.id,
                  ruleName: rule.name,
                  schedule: {
                    daysOfWeek: rule.schedule_days_of_week ? JSON.parse(rule.schedule_days_of_week) : null,
                    startHour: rule.schedule_start_hour,
                    endHour: rule.schedule_end_hour,
                    timezone: rule.schedule_timezone,
                  },
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      // Update schedule
      const updates: Partial<RuleRow> = {
        id: ruleId,
        updated_at: Date.now(),
      };

      if (daysOfWeek !== undefined) {
        updates.schedule_days_of_week = JSON.stringify(daysOfWeek);
      }

      if (startHour !== undefined) {
        updates.schedule_start_hour = startHour;
      }

      if (endHour !== undefined) {
        updates.schedule_end_hour = endHour;
      }

      if (timezone !== undefined) {
        updates.schedule_timezone = timezone;
      }

      db.prepare(
        `UPDATE rules SET
          schedule_days_of_week = COALESCE(@schedule_days_of_week, schedule_days_of_week),
          schedule_start_hour = COALESCE(@schedule_start_hour, schedule_start_hour),
          schedule_end_hour = COALESCE(@schedule_end_hour, schedule_end_hour),
          schedule_timezone = COALESCE(@schedule_timezone, schedule_timezone),
          updated_at = @updated_at
         WHERE id = @id`,
      ).run(updates);

      const updatedRule = db.prepare('SELECT * FROM rules WHERE id = ?').get(ruleId) as RuleRow;

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                ruleId: updatedRule.id,
                ruleName: updatedRule.name,
                schedule: {
                  daysOfWeek: updatedRule.schedule_days_of_week
                    ? JSON.parse(updatedRule.schedule_days_of_week)
                    : null,
                  startHour: updatedRule.schedule_start_hour,
                  endHour: updatedRule.schedule_end_hour,
                  timezone: updatedRule.schedule_timezone,
                },
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Tool 5: Configure trusted agents (allow-list)
  server.tool(
    'sentinel_policy_agent_trust',
    'Configure trusted agent patterns (creates high-priority allow rules)',
    {
      agentPattern: z.string().describe('Agent glob pattern (e.g., "admin@*", "user@hyperion")'),
      action: z.enum(['trust', 'untrust']).describe('Trust or untrust the agent pattern'),
    },
    async (args) => {
      const agentPattern = args.agentPattern as string;
      const action = args.action as 'trust' | 'untrust';

      const ruleId = `trusted-agent-${agentPattern.replace(/[^a-zA-Z0-9]/g, '-')}`;

      if (action === 'trust') {
        // Create high-priority allow rule
        const now = Date.now();
        const rule: RuleRow = {
          id: ruleId,
          name: `Trusted Agent: ${agentPattern}`,
          priority: 100, // High priority
          action: 'allow',
          enabled: 1,
          tool_pattern: undefined,
          host_pattern: undefined,
          agent_pattern: agentPattern,
          argument_pattern: undefined,
          rate_limit_max_operations: undefined,
          rate_limit_window_seconds: undefined,
          rate_limit_refill_rate: undefined,
          schedule_days_of_week: undefined,
          schedule_start_hour: undefined,
          schedule_end_hour: undefined,
          schedule_timezone: undefined,
          created_at: now,
          updated_at: now,
          description: `Trusted agent pattern: ${agentPattern}`,
          tags: JSON.stringify(['trusted-agent']),
        };

        db.prepare(
          `INSERT OR REPLACE INTO rules (
            id, name, priority, action, enabled, tool_pattern, host_pattern, agent_pattern,
            argument_pattern, rate_limit_max_operations, rate_limit_window_seconds,
            rate_limit_refill_rate, schedule_days_of_week, schedule_start_hour,
            schedule_end_hour, schedule_timezone, created_at, updated_at, description, tags
          ) VALUES (
            @id, @name, @priority, @action, @enabled, @tool_pattern, @host_pattern, @agent_pattern,
            @argument_pattern, @rate_limit_max_operations, @rate_limit_window_seconds,
            @rate_limit_refill_rate, @schedule_days_of_week, @schedule_start_hour,
            @schedule_end_hour, @schedule_timezone, @created_at, @updated_at, @description, @tags
          )`,
        ).run(rule);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  action: 'trusted',
                  agentPattern,
                  ruleId,
                  message: `Agent pattern "${agentPattern}" is now trusted (high-priority allow rule created)`,
                },
                null,
                2,
              ),
            },
          ],
        };
      } else {
        // Remove trust rule
        db.prepare('DELETE FROM rules WHERE id = ?').run(ruleId);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  action: 'untrusted',
                  agentPattern,
                  ruleId,
                  message: `Agent pattern "${agentPattern}" trust removed`,
                },
                null,
                2,
              ),
            },
          ],
        };
      }
    },
  );

  // Tool 6: Generate policy report
  server.tool(
    'sentinel_policy_report',
    'Generate comprehensive policy report',
    {
      includeSamples: z.boolean().default(false).describe('Include sample audit entries'),
    },
    async (args) => {
      const includeSamples = args.includeSamples as boolean;

      const mode = (db.prepare('SELECT value FROM config WHERE key = ?').get('mode') as { value: string })
        .value;

      const rules = db.prepare('SELECT * FROM rules ORDER BY priority ASC').all() as RuleRow[];

      const activeAlerts = db
        .prepare('SELECT COUNT(*) as count FROM alerts WHERE status = ?')
        .get('active') as { count: number };

      const quarantines = db.prepare('SELECT COUNT(*) as count FROM quarantine').get() as {
        count: number;
      };

      const baselines = db.prepare('SELECT COUNT(*) as count FROM anomaly_baselines').get() as {
        count: number;
      };

      const auditCount = db.prepare('SELECT COUNT(*) as count FROM audit_log').get() as {
        count: number;
      };

      const report: Record<string, unknown> = {
        generatedAt: new Date().toISOString(),
        mode,
        summary: {
          totalRules: rules.length,
          enabledRules: rules.filter((r) => r.enabled === 1).length,
          activeAlerts: activeAlerts.count,
          quarantines: quarantines.count,
          anomalyBaselines: baselines.count,
          totalAuditEntries: auditCount.count,
        },
        rules: rules.map((r) => ({
          id: r.id,
          name: r.name,
          priority: r.priority,
          action: r.action,
          enabled: r.enabled === 1,
          patterns: {
            tool: r.tool_pattern,
            host: r.host_pattern,
            agent: r.agent_pattern,
          },
        })),
      };

      if (includeSamples) {
        const recentAudit = db
          .prepare('SELECT * FROM audit_log ORDER BY sequence_number DESC LIMIT 10')
          .all();
        report.recentAuditSamples = recentAudit;
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    },
  );
}
