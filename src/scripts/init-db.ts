#!/usr/bin/env node
/**
 * Database initialization script
 * Creates a new Sentinel database with default rules
 */

import { initializeDatabase, prepareStatements } from '../database.js';
import { getDefaultRules } from '../default-rules.js';

function main() {
  const dbPath = process.argv[2] || './sentinel.db';

  console.log(`Initializing Sentinel database at ${dbPath}...`);

  // Initialize database (creates schema)
  const database = initializeDatabase(dbPath);
  const statements = prepareStatements(database.db);

  console.log('✓ Database schema created');

  // Check if rules already exist
  const existingRules = statements.listRules.all();
  if (existingRules.length > 0) {
    console.log(`Database already has ${existingRules.length} rules. Skipping default rules.`);
    database.close();
    return;
  }

  // Insert default rules
  const defaultRules = getDefaultRules();
  let inserted = 0;

  for (const rule of defaultRules) {
    const row = {
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

    statements.insertRule.run(row);
    inserted++;
  }

  console.log(`✓ Inserted ${inserted} default rules`);

  // Display summary
  console.log('\nDefault Rules:');
  defaultRules.forEach((rule) => {
    console.log(`  - [${rule.action.toUpperCase()}] ${rule.name} (priority ${rule.priority})`);
  });

  database.close();
  console.log('\n✓ Database initialized successfully');
}

main();
