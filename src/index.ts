/**
 * OpenClaw Sentinel MCP Server
 * Main entry point for the MCP server
 */

import { serveMcp } from './mcp/server.js';

// Re-export core modules
export { initializeDatabase, prepareStatements } from './database.js';
export { evaluatePolicy } from './policy-engine.js';
export { createAuditEntry, updateAuditEntry, verifyAuditChain, queryAuditLog } from './audit-log.js';
export * from './types.js';

// Start server if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const databasePath = process.env.SENTINEL_DB_PATH ?? './sentinel.db';
  const verbose = process.env.VERBOSE === 'true' || process.argv.includes('--verbose');

  serveMcp({ databasePath, verbose }).catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
