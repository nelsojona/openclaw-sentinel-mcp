#!/usr/bin/env node
/**
 * Audit chain verification script
 * Verifies the integrity of the hash-chained audit log
 */

import { initializeDatabase } from '../database.js';
import { verifyAuditChain, queryAuditLog } from '../audit-log.js';

function main() {
  const dbPath = process.argv[2] || './sentinel.db';

  console.log(`Verifying audit chain in ${dbPath}...`);

  // Open database
  const database = initializeDatabase(dbPath);

  // Verify chain
  const result = verifyAuditChain(database.db);

  console.log(`\nAudit Chain Verification`);
  console.log(`${'='.repeat(50)}`);
  console.log(`Total entries: ${result.totalEntries}`);
  console.log(`Status: ${result.valid ? '✓ VALID' : '✗ INVALID'}`);

  if (!result.valid) {
    console.log(`\n${result.brokenChains.length} broken chain(s) detected:\n`);

    result.brokenChains.forEach((broken) => {
      console.log(`  Sequence #${broken.sequenceNumber}:`);
      console.log(`    Expected hash: ${broken.expectedHash.substring(0, 16)}...`);
      console.log(`    Actual hash:   ${broken.actualHash.substring(0, 16)}...`);
      console.log();
    });

    console.log('⚠️  WARNING: Audit log has been tampered with or corrupted!');
    database.close();
    process.exit(1);
  }

  // Display recent entries
  console.log('\nRecent Audit Entries (last 10):');
  console.log(`${'-'.repeat(50)}`);

  const recentEntries = queryAuditLog(database.db, { limit: 10 });

  recentEntries.forEach((entry) => {
    const timestamp = new Date(entry.timestamp).toISOString();
    const verdict = entry.verdict.toUpperCase().padEnd(7);
    const action = entry.action.toUpperCase().padEnd(8);
    const riskScore = entry.riskScore.toFixed(1).padStart(5);

    console.log(`  #${entry.sequenceNumber.toString().padStart(4)} | ${timestamp} | ${verdict} | ${action} | Risk: ${riskScore}`);
    console.log(`      Tool: ${entry.tool}`);
    console.log(`      Host: ${entry.host}`);
    console.log(`      Agent: ${entry.agent}`);

    if (entry.matchedRuleId) {
      console.log(`      Rule: ${entry.matchedRuleId}`);
    }

    if (entry.responseStatus) {
      console.log(`      Response: ${entry.responseStatus}`);
    }

    console.log();
  });

  database.close();
  console.log('✓ Verification complete');
}

main();
