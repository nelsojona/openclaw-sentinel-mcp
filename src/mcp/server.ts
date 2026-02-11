/**
 * MCP server for OpenClaw Sentinel
 * Provides policy enforcement, firewall rules, and audit tools via MCP protocol
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { initializeDatabase, prepareStatements, type SentinelDatabase } from '../database.js';
import { registerFirewallTools } from '../tools/firewall-rules.js';
import { registerQuarantineTools } from '../tools/quarantine.js';
import { registerAlertTools } from '../tools/alerts.js';
import { registerPolicyTools } from '../tools/policy.js';

export interface SentinelMcpOptions {
  databasePath: string;
  verbose?: boolean;
}

/**
 * Helper function to create text content response
 */
export function textContent(text: string) {
  return { content: [{ type: 'text' as const, text }] };
}

/**
 * Helper function to create error content response
 */
export function errorContent(text: string) {
  return { content: [{ type: 'text' as const, text }], isError: true };
}

/**
 * Start the Sentinel MCP server
 */
export async function serveMcp(options: SentinelMcpOptions): Promise<void> {
  const log = options.verbose
    ? (...args: unknown[]) => process.stderr.write(`[sentinel-mcp] ${args.join(' ')}\n`)
    : () => {};

  log('Starting OpenClaw Sentinel MCP server...');

  // Initialize database
  const database = initializeDatabase(options.databasePath);
  const statements = prepareStatements(database.db);

  log(`Database initialized at ${options.databasePath}`);

  // Create MCP server
  const server = new McpServer(
    { name: 'openclaw-sentinel', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // Register tool modules
  registerFirewallTools(server, database, statements);
  registerQuarantineTools(server, database, statements);
  registerAlertTools(server, database, statements);
  registerPolicyTools(server, database, statements);

  log('Tools registered (7 firewall + 5 quarantine + 5 alert + 6 policy = 23 tools)');

  // Connect stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  log('MCP server running on stdio');

  // Cleanup on process exit
  process.on('SIGINT', () => {
    log('Shutting down...');
    database.close();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    log('Shutting down...');
    database.close();
    process.exit(0);
  });
}
