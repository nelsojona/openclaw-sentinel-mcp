/**
 * Quarantine management tools for OpenClaw Sentinel MCP
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { SentinelDatabase, PreparedStatements } from '../database.js';
import { textContent, errorContent } from '../mcp/server.js';
import {
  quarantineHost,
  quarantineTool,
  quarantineAgent,
  liftQuarantine,
  listQuarantines,
} from '../quarantine-manager.js';

/**
 * Register all quarantine management tools
 */
export function registerQuarantineTools(
  server: McpServer,
  database: SentinelDatabase,
  statements: PreparedStatements,
): void {
  const { db } = database;

  // Tool 1: sentinel_quarantine_host
  server.tool(
    'sentinel_quarantine_host',
    'Quarantine a host to block all operations targeting it',
    {
      host: z.string().describe('Host identifier to quarantine'),
      reason: z.string().describe('Reason for quarantine'),
      expiresIn: z.number().optional().describe('Auto-expire after N milliseconds (default: never)'),
      createdBy: z.string().default('system').describe('Who created the quarantine (default: system)'),
    },
    async (args) => {
      try {
        const expiresAt = args.expiresIn ? Date.now() + args.expiresIn : undefined;

        quarantineHost(db, args.host, args.reason, expiresAt, args.createdBy);

        return textContent(
          JSON.stringify(
            {
              quarantined: true,
              scope: 'host',
              target: args.host,
              reason: args.reason,
              expiresAt,
              createdBy: args.createdBy,
            },
            null,
            2,
          ),
        );
      } catch (error) {
        return errorContent(`Failed to quarantine host: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 2: sentinel_quarantine_tool
  server.tool(
    'sentinel_quarantine_tool',
    'Quarantine a tool to block all operations using it',
    {
      tool: z.string().describe('Tool name to quarantine'),
      reason: z.string().describe('Reason for quarantine'),
      expiresIn: z.number().optional().describe('Auto-expire after N milliseconds (default: never)'),
      createdBy: z.string().default('system').describe('Who created the quarantine (default: system)'),
    },
    async (args) => {
      try {
        const expiresAt = args.expiresIn ? Date.now() + args.expiresIn : undefined;

        quarantineTool(db, args.tool, args.reason, expiresAt, args.createdBy);

        return textContent(
          JSON.stringify(
            {
              quarantined: true,
              scope: 'tool',
              target: args.tool,
              reason: args.reason,
              expiresAt,
              createdBy: args.createdBy,
            },
            null,
            2,
          ),
        );
      } catch (error) {
        return errorContent(`Failed to quarantine tool: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 3: sentinel_quarantine_agent
  server.tool(
    'sentinel_quarantine_agent',
    'Quarantine an agent to block all operations by it',
    {
      agent: z.string().describe('Agent identifier to quarantine'),
      reason: z.string().describe('Reason for quarantine'),
      expiresIn: z.number().optional().describe('Auto-expire after N milliseconds (default: never)'),
      createdBy: z.string().default('system').describe('Who created the quarantine (default: system)'),
    },
    async (args) => {
      try {
        const expiresAt = args.expiresIn ? Date.now() + args.expiresIn : undefined;

        quarantineAgent(db, args.agent, args.reason, expiresAt, args.createdBy);

        return textContent(
          JSON.stringify(
            {
              quarantined: true,
              scope: 'agent',
              target: args.agent,
              reason: args.reason,
              expiresAt,
              createdBy: args.createdBy,
            },
            null,
            2,
          ),
        );
      } catch (error) {
        return errorContent(`Failed to quarantine agent: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 4: sentinel_quarantine_list
  server.tool(
    'sentinel_quarantine_list',
    'List all active quarantines',
    {},
    async () => {
      try {
        const quarantines = listQuarantines(db);

        return textContent(JSON.stringify(quarantines, null, 2));
      } catch (error) {
        return errorContent(`Failed to list quarantines: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );

  // Tool 5: sentinel_quarantine_lift
  server.tool(
    'sentinel_quarantine_lift',
    'Lift quarantine for a specific scope and target',
    {
      scope: z.enum(['host', 'tool', 'agent']).describe('Quarantine scope'),
      target: z.string().describe('Target identifier to un-quarantine'),
    },
    async (args) => {
      try {
        const lifted = liftQuarantine(db, args.scope, args.target);

        if (!lifted) {
          return errorContent(`Quarantine not found for ${args.scope}: ${args.target}`);
        }

        return textContent(
          JSON.stringify(
            {
              lifted: true,
              scope: args.scope,
              target: args.target,
            },
            null,
            2,
          ),
        );
      } catch (error) {
        return errorContent(`Failed to lift quarantine: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
  );
}
