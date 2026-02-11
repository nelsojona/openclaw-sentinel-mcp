/**
 * Default firewall rules shipped with OpenClaw Sentinel
 *
 * These rules provide essential security guardrails and are loaded automatically
 * on first initialization.
 */

import type { SentinelRule } from './types.js';
import { randomUUID } from 'node:crypto';

/**
 * Generate default rules for initial database setup
 *
 * @returns Array of default rules
 */
export function getDefaultRules(): SentinelRule[] {
  const now = Date.now();

  return [
    // Rule 1: Always allow health checks (priority 0 - highest)
    {
      id: randomUUID(),
      name: 'Allow Health Checks',
      priority: 0,
      action: 'allow',
      enabled: true,
      toolPattern: '*health*',
      description: 'Always allow health check operations',
      tags: ['system', 'health'],
      createdAt: now,
      updatedAt: now,
    },

    // Rule 2: Always allow status queries (priority 1)
    {
      id: randomUUID(),
      name: 'Allow Status Queries',
      priority: 1,
      action: 'allow',
      enabled: true,
      toolPattern: '*status*',
      description: 'Always allow status query operations',
      tags: ['system', 'status'],
      createdAt: now,
      updatedAt: now,
    },

    // Rule 3: Block force push to main (priority 5)
    {
      id: randomUUID(),
      name: 'Block Force Push to Main',
      priority: 5,
      action: 'deny',
      enabled: true,
      toolPattern: 'fleet_ssh_exec',
      argumentPattern: 'git\\s+push.*--force.*(main|master)',
      description: 'Prevent destructive force push to main/master branches',
      tags: ['security', 'git', 'destructive'],
      createdAt: now,
      updatedAt: now,
    },

    // Rule 4: Ask before rm -rf (priority 5)
    {
      id: randomUUID(),
      name: 'Confirm Recursive Delete',
      priority: 5,
      action: 'ask',
      enabled: true,
      toolPattern: 'fleet_ssh_exec',
      argumentPattern: 'rm\\s+-[rf]{1,2}',
      description: 'Require confirmation before recursive delete operations',
      tags: ['security', 'destructive'],
      createdAt: now,
      updatedAt: now,
    },

    // Rule 5: Rate limit agent runs (priority 10)
    {
      id: randomUUID(),
      name: 'Rate Limit Agent Runs',
      priority: 10,
      action: 'allow',
      enabled: true,
      toolPattern: 'openclaw_agent_run',
      rateLimit: {
        maxOperations: 10,
        windowSeconds: 60,
        refillRate: 10 / 60, // 10 per minute
      },
      description: 'Limit agent runs to 10 per minute to prevent runaway execution',
      tags: ['rate-limit', 'agent'],
      createdAt: now,
      updatedAt: now,
    },

    // Rule 6: Log all fleet operations (priority 1000 - low priority catchall)
    {
      id: randomUUID(),
      name: 'Log Fleet Operations',
      priority: 1000,
      action: 'log-only',
      enabled: true,
      toolPattern: 'fleet_*',
      description: 'Log all fleet SSH operations for audit trail',
      tags: ['audit', 'fleet'],
      createdAt: now,
      updatedAt: now,
    },
  ];
}

/**
 * Serialize default rules to JSON for config/default-rules.json
 *
 * @returns JSON string
 */
export function serializeDefaultRules(): string {
  const rules = getDefaultRules();
  return JSON.stringify(rules, null, 2);
}
