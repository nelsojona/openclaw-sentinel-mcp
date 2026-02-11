/**
 * Firewall rule management tools for OpenClaw Sentinel MCP
 */

import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SentinelDatabase, PreparedStatements } from '../database.js';
import type { SentinelRule, RuleRow, PolicyContext } from '../types.js';
import { textContent, errorContent } from '../mcp/server.js';
import { evaluatePolicy } from '../policy-engine.js';

/**
 * Convert database row to SentinelRule
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
 * Convert SentinelRule to database row
 */
function ruleToRow(rule: SentinelRule): RuleRow {
  return {
    id: rule.id,
    name: rule.name,
    priority: rule.priority,
    action: rule.action,
    enabled: rule.enabled ? 1 : 0,
    tool_pattern: rule.toolPattern ?? null,
    host_pattern: rule.hostPattern ?? null,
    agent_pattern: rule.agentPattern ?? null,
    argument_pattern: rule.argumentPattern ?? null,
    rate_limit_max_operations: rule.rateLimit?.maxOperations ?? null,
    rate_limit_window_seconds: rule.rateLimit?.windowSeconds ?? null,
    rate_limit_refill_rate: rule.rateLimit?.refillRate ?? null,
    schedule_days_of_week: rule.schedule?.daysOfWeek ? JSON.stringify(rule.schedule.daysOfWeek) : null,
    schedule_start_hour: rule.schedule?.startHour ?? null,
    schedule_end_hour: rule.schedule?.endHour ?? null,
    schedule_timezone: rule.schedule?.timezone ?? null,
    created_at: rule.createdAt,
    updated_at: rule.updatedAt,
    description: rule.description ?? null,
    tags: rule.tags ? JSON.stringify(rule.tags) : null,
  };
}

/**
 * Register all firewall rule tools
 */
export function registerFirewallTools(
  server: McpServer,
  database: SentinelDatabase,
  statements: PreparedStatements,
): void {
  const { db } = database;

  // Tool 1: sentinel_rule_create
  server.tool(
    'sentinel_rule_create',
    'Create a new firewall rule with optional rate limiting and scheduling',
    {
      name: z.string().describe('Rule name (human-readable identifier)'),
      priority: z.number().optional().describe('Rule priority (lower = higher priority, default: 1000)'),
      action: z.enum(['allow', 'deny', 'ask', 'log-only']).describe('Action to take when rule matches'),
      enabled: z.boolean().optional().describe('Whether rule is enabled (default: true)'),
      toolPattern: z.string().optional().describe('Glob pattern for tool names (e.g., "fleet_*")'),
      hostPattern: z.string().optional().describe('Glob pattern for hosts (e.g., "hyperion")'),
      agentPattern: z.string().optional().describe('Glob pattern for agents (e.g., "user@*")'),
      argumentPattern: z.string().optional().describe('Regex pattern for argument matching'),
      rateLimit: z
        .object({
          maxOperations: z.number().describe('Maximum operations allowed'),
          windowSeconds: z.number().describe('Time window in seconds'),
          refillRate: z.number().describe('Token refill rate per second'),
        })
        .optional()
        .describe('Rate limit configuration'),
      schedule: z
        .object({
          daysOfWeek: z.array(z.number().min(0).max(6)).optional().describe('Days of week (0=Sunday, 6=Saturday)'),
          startHour: z.number().min(0).max(23).optional().describe('Start hour (0-23)'),
          endHour: z.number().min(0).max(23).optional().describe('End hour (0-23)'),
          timezone: z.string().optional().describe('IANA timezone (default: system timezone)'),
        })
        .optional()
        .describe('Time-of-day schedule'),
      description: z.string().optional().describe('Rule description'),
      tags: z.array(z.string()).optional().describe('Tags for categorization'),
    },
    async (args) => {
      try {
        const now = Date.now();
        const rule: SentinelRule = {
          id: randomUUID(),
          name: args.name,
          priority: args.priority ?? 1000,
          action: args.action,
          enabled: args.enabled ?? true,
          toolPattern: args.toolPattern,
          hostPattern: args.hostPattern,
          agentPattern: args.agentPattern,
          argumentPattern: args.argumentPattern,
          rateLimit: args.rateLimit,
          schedule: args.schedule,
          createdAt: now,
          updatedAt: now,
          description: args.description,
          tags: args.tags,
        };

        const row = ruleToRow(rule);
        statements.insertRule.run(row);

        return textContent(JSON.stringify(rule, null, 2));
      } catch (error) {
        return errorContent(`Failed to create rule: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 2: sentinel_rule_update
  server.tool(
    'sentinel_rule_update',
    'Update an existing firewall rule',
    {
      id: z.string().describe('Rule ID to update'),
      name: z.string().optional().describe('New rule name'),
      priority: z.number().optional().describe('New priority'),
      action: z.enum(['allow', 'deny', 'ask', 'log-only']).optional().describe('New action'),
      enabled: z.boolean().optional().describe('Enable/disable rule'),
      toolPattern: z.string().optional().describe('New tool pattern'),
      hostPattern: z.string().optional().describe('New host pattern'),
      agentPattern: z.string().optional().describe('New agent pattern'),
      argumentPattern: z.string().optional().describe('New argument pattern'),
      description: z.string().optional().describe('New description'),
      tags: z.array(z.string()).optional().describe('New tags'),
    },
    async (args) => {
      try {
        // Check if rule exists
        const existing = statements.getRuleById.get({ id: args.id }) as RuleRow | undefined;
        if (!existing) {
          return errorContent(`Rule not found: ${args.id}`);
        }

        // Build update object
        const update: Partial<RuleRow> & { id: string } = {
          id: args.id,
          updated_at: Date.now(),
        };

        if (args.name !== undefined) {
          update.name = args.name;
        }
        if (args.priority !== undefined) {
          update.priority = args.priority;
        }
        if (args.action !== undefined) {
          update.action = args.action;
        }
        if (args.enabled !== undefined) {
          update.enabled = args.enabled ? 1 : 0;
        }
        if (args.toolPattern !== undefined) {
          update.tool_pattern = args.toolPattern;
        }
        if (args.hostPattern !== undefined) {
          update.host_pattern = args.hostPattern;
        }
        if (args.agentPattern !== undefined) {
          update.agent_pattern = args.agentPattern;
        }
        if (args.argumentPattern !== undefined) {
          update.argument_pattern = args.argumentPattern;
        }
        if (args.description !== undefined) {
          update.description = args.description;
        }
        if (args.tags !== undefined) {
          update.tags = JSON.stringify(args.tags);
        }

        statements.updateRule.run(update);

        // Fetch updated rule
        const updated = statements.getRuleById.get({ id: args.id }) as RuleRow;
        const rule = rowToRule(updated);

        return textContent(JSON.stringify(rule, null, 2));
      } catch (error) {
        return errorContent(`Failed to update rule: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 3: sentinel_rule_delete
  server.tool(
    'sentinel_rule_delete',
    'Delete a firewall rule by ID',
    {
      id: z.string().describe('Rule ID to delete'),
    },
    async (args) => {
      try {
        // Check if rule exists
        const existing = statements.getRuleById.get({ id: args.id }) as RuleRow | undefined;
        if (!existing) {
          return errorContent(`Rule not found: ${args.id}`);
        }

        statements.deleteRule.run({ id: args.id });

        return textContent(JSON.stringify({ deleted: true, id: args.id }, null, 2));
      } catch (error) {
        return errorContent(`Failed to delete rule: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 4: sentinel_rule_list
  server.tool(
    'sentinel_rule_list',
    'List all firewall rules, optionally filtered by enabled status',
    {
      enabledOnly: z.boolean().optional().describe('Only return enabled rules (default: false)'),
    },
    async (args) => {
      try {
        const rows = args.enabledOnly
          ? (statements.listEnabledRules.all() as RuleRow[])
          : (statements.listRules.all() as RuleRow[]);

        const rules = rows.map(rowToRule);

        return textContent(JSON.stringify(rules, null, 2));
      } catch (error) {
        return errorContent(`Failed to list rules: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 5: sentinel_rule_test
  server.tool(
    'sentinel_rule_test',
    'Test if a policy context would match a rule (for debugging)',
    {
      tool: z.string().describe('Tool name to test'),
      host: z.string().describe('Host identifier to test'),
      agent: z.string().describe('Agent identifier to test'),
      arguments: z.record(z.unknown()).optional().describe('Arguments to test'),
    },
    async (args) => {
      try {
        const context: PolicyContext = {
          tool: args.tool,
          host: args.host,
          agent: args.agent,
          arguments: args.arguments ?? {},
          timestamp: Date.now(),
        };

        // Get current mode
        const modeRow = statements.getConfig.get({ key: 'mode' }) as { value: string } | undefined;
        const mode = (modeRow?.value ?? 'silent-allow') as 'silent-allow' | 'alert' | 'silent-deny' | 'lockdown';

        // Evaluate policy
        const verdict = evaluatePolicy(db, context, mode);

        return textContent(JSON.stringify(verdict, null, 2));
      } catch (error) {
        return errorContent(`Failed to test rule: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 6: sentinel_rule_import
  server.tool(
    'sentinel_rule_import',
    'Import rules from JSON (bulk create)',
    {
      rules: z.array(
        z.object({
          name: z.string(),
          priority: z.number().optional(),
          action: z.enum(['allow', 'deny', 'ask', 'log-only']),
          enabled: z.boolean().optional(),
          toolPattern: z.string().optional(),
          hostPattern: z.string().optional(),
          agentPattern: z.string().optional(),
          argumentPattern: z.string().optional(),
          description: z.string().optional(),
          tags: z.array(z.string()).optional(),
        }),
      ).describe('Array of rules to import'),
    },
    async (args) => {
      try {
        const imported: SentinelRule[] = [];
        const now = Date.now();

        for (const ruleInput of args.rules) {
          const rule: SentinelRule = {
            id: randomUUID(),
            name: ruleInput.name,
            priority: ruleInput.priority ?? 1000,
            action: ruleInput.action,
            enabled: ruleInput.enabled ?? true,
            toolPattern: ruleInput.toolPattern,
            hostPattern: ruleInput.hostPattern,
            agentPattern: ruleInput.agentPattern,
            argumentPattern: ruleInput.argumentPattern,
            createdAt: now,
            updatedAt: now,
            description: ruleInput.description,
            tags: ruleInput.tags,
          };

          const row = ruleToRow(rule);
          statements.insertRule.run(row);
          imported.push(rule);
        }

        return textContent(JSON.stringify({ imported: imported.length, rules: imported }, null, 2));
      } catch (error) {
        return errorContent(`Failed to import rules: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 7: sentinel_rule_export
  server.tool(
    'sentinel_rule_export',
    'Export all rules to JSON format',
    {},
    async () => {
      try {
        const rows = statements.listRules.all() as RuleRow[];
        const rules = rows.map(rowToRule);

        return textContent(JSON.stringify(rules, null, 2));
      } catch (error) {
        return errorContent(`Failed to export rules: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );
}
