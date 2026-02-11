/**
 * Integration tests for MCP server
 * Tests the full MCP protocol via stdio transport
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unlinkSync } from 'node:fs';

describe('MCP Server Integration', () => {
  let serverProcess: ChildProcess;
  let dbPath: string;
  let requestId = 1;

  beforeAll(async () => {
    // Create temporary database
    dbPath = join(tmpdir(), `sentinel-test-${Date.now()}.db`);

    // Spawn MCP server
    serverProcess = spawn('node', ['dist/index.js'], {
      env: {
        ...process.env,
        SENTINEL_DB_PATH: dbPath,
        VERBOSE: 'false',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    // Wait for server to initialize
    await new Promise((resolve) => setTimeout(resolve, 1000));
  });

  afterAll(() => {
    if (serverProcess) {
      serverProcess.kill();
    }
    try {
      unlinkSync(dbPath);
    } catch {
      // Ignore
    }
  });

  function sendRequest(method: string, params: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = requestId++;
      const request = {
        jsonrpc: '2.0',
        id,
        method,
        params,
      };

      let responseData = '';

      const onData = (data: Buffer) => {
        responseData += data.toString();

        // Try to parse complete JSON-RPC response
        try {
          const lines = responseData.split('\n').filter((line) => line.trim());
          for (const line of lines) {
            const response = JSON.parse(line);
            if (response.id === id) {
              serverProcess.stdout?.removeListener('data', onData);
              if (response.error) {
                reject(new Error(response.error.message));
              } else {
                resolve(response.result);
              }
              return;
            }
          }
        } catch {
          // Not a complete response yet
        }
      };

      serverProcess.stdout?.on('data', onData);

      // Send request
      serverProcess.stdin?.write(JSON.stringify(request) + '\n');

      // Timeout after 5 seconds
      setTimeout(() => {
        serverProcess.stdout?.removeListener('data', onData);
        reject(new Error('Request timeout'));
      }, 5000);
    });
  }

  it('should initialize MCP server', async () => {
    const response = await sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: {
        name: 'test-client',
        version: '1.0.0',
      },
    });

    expect(response).toHaveProperty('protocolVersion');
    expect(response).toHaveProperty('capabilities');
    expect(response).toHaveProperty('serverInfo');
  });

  it('should list tools', async () => {
    const response = (await sendRequest('tools/list', {})) as { tools: Array<{ name: string }> };

    expect(response.tools).toBeInstanceOf(Array);
    expect(response.tools.length).toBeGreaterThanOrEqual(7);

    const toolNames = response.tools.map((t) => t.name);
    expect(toolNames).toContain('sentinel_rule_create');
    expect(toolNames).toContain('sentinel_rule_update');
    expect(toolNames).toContain('sentinel_rule_delete');
    expect(toolNames).toContain('sentinel_rule_list');
    expect(toolNames).toContain('sentinel_rule_test');
    expect(toolNames).toContain('sentinel_rule_import');
    expect(toolNames).toContain('sentinel_rule_export');
  });

  it('should create a firewall rule', async () => {
    const response = (await sendRequest('tools/call', {
      name: 'sentinel_rule_create',
      arguments: {
        name: 'Test Rule',
        action: 'allow',
        toolPattern: 'fleet_*',
        hostPattern: 'hyperion',
        priority: 100,
        description: 'Test rule for integration tests',
      },
    })) as { content: Array<{ type: string; text: string }> };

    expect(response.content).toBeInstanceOf(Array);
    expect(response.content[0].type).toBe('text');

    const rule = JSON.parse(response.content[0].text);
    expect(rule.name).toBe('Test Rule');
    expect(rule.action).toBe('allow');
    expect(rule.toolPattern).toBe('fleet_*');
    expect(rule.hostPattern).toBe('hyperion');
    expect(rule.priority).toBe(100);
  });

  it('should list firewall rules', async () => {
    const response = (await sendRequest('tools/call', {
      name: 'sentinel_rule_list',
      arguments: {},
    })) as { content: Array<{ type: string; text: string }> };

    expect(response.content).toBeInstanceOf(Array);
    const rules = JSON.parse(response.content[0].text);
    expect(rules).toBeInstanceOf(Array);
    expect(rules.length).toBeGreaterThanOrEqual(1);
  });

  it('should update a firewall rule', async () => {
    // First, create a rule
    const createResponse = (await sendRequest('tools/call', {
      name: 'sentinel_rule_create',
      arguments: {
        name: 'Update Test',
        action: 'deny',
        priority: 200,
      },
    })) as { content: Array<{ type: string; text: string }> };

    const createdRule = JSON.parse(createResponse.content[0].text);
    const ruleId = createdRule.id;

    // Update the rule
    const updateResponse = (await sendRequest('tools/call', {
      name: 'sentinel_rule_update',
      arguments: {
        id: ruleId,
        name: 'Updated Name',
        action: 'allow',
      },
    })) as { content: Array<{ type: string; text: string }>; isError?: boolean };

    // Check for error response
    if (updateResponse.isError) {
      throw new Error(`Update failed: ${updateResponse.content[0].text}`);
    }

    const updatedRule = JSON.parse(updateResponse.content[0].text);
    expect(updatedRule.id).toBe(ruleId);
    expect(updatedRule.name).toBe('Updated Name');
    expect(updatedRule.action).toBe('allow');
  });

  it('should delete a firewall rule', async () => {
    // Create a rule to delete
    const createResponse = (await sendRequest('tools/call', {
      name: 'sentinel_rule_create',
      arguments: {
        name: 'Delete Test',
        action: 'deny',
      },
    })) as { content: Array<{ type: string; text: string }> };

    const createdRule = JSON.parse(createResponse.content[0].text);
    const ruleId = createdRule.id;

    // Delete the rule
    const deleteResponse = (await sendRequest('tools/call', {
      name: 'sentinel_rule_delete',
      arguments: {
        id: ruleId,
      },
    })) as { content: Array<{ type: string; text: string }> };

    const result = JSON.parse(deleteResponse.content[0].text);
    expect(result.deleted).toBe(true);
    expect(result.id).toBe(ruleId);
  });

  it('should test policy evaluation', async () => {
    const response = (await sendRequest('tools/call', {
      name: 'sentinel_rule_test',
      arguments: {
        tool: 'fleet_ssh_exec',
        host: 'hyperion',
        agent: 'test-agent',
        arguments: { command: 'ls' },
      },
    })) as { content: Array<{ type: string; text: string }> };

    expect(response.content).toBeInstanceOf(Array);
    const verdict = JSON.parse(response.content[0].text);

    expect(verdict).toHaveProperty('allowed');
    expect(verdict).toHaveProperty('action');
    expect(verdict).toHaveProperty('reason');
    expect(verdict).toHaveProperty('riskScore');
    expect(verdict).toHaveProperty('riskFactors');
  });

  it('should import rules', async () => {
    const response = (await sendRequest('tools/call', {
      name: 'sentinel_rule_import',
      arguments: {
        rules: [
          {
            name: 'Import Test 1',
            action: 'allow',
            toolPattern: 'openclaw_*',
          },
          {
            name: 'Import Test 2',
            action: 'deny',
            hostPattern: 'prometheus',
          },
        ],
      },
    })) as { content: Array<{ type: string; text: string }> };

    expect(response.content).toBeInstanceOf(Array);
    const result = JSON.parse(response.content[0].text);

    expect(result.imported).toBe(2);
    expect(result.rules).toBeInstanceOf(Array);
    expect(result.rules.length).toBe(2);
  });

  it('should export rules', async () => {
    const response = (await sendRequest('tools/call', {
      name: 'sentinel_rule_export',
      arguments: {},
    })) as { content: Array<{ type: string; text: string }> };

    expect(response.content).toBeInstanceOf(Array);
    const rules = JSON.parse(response.content[0].text);

    expect(rules).toBeInstanceOf(Array);
    expect(rules.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle rate-limited rules', async () => {
    const response = (await sendRequest('tools/call', {
      name: 'sentinel_rule_create',
      arguments: {
        name: 'Rate Limited Rule',
        action: 'allow',
        toolPattern: 'fleet_*',
        rateLimit: {
          maxOperations: 10,
          windowSeconds: 60,
          refillRate: 0.5,
        },
      },
    })) as { content: Array<{ type: string; text: string }> };

    const rule = JSON.parse(response.content[0].text);
    expect(rule.rateLimit).toBeDefined();
    expect(rule.rateLimit.maxOperations).toBe(10);
    expect(rule.rateLimit.windowSeconds).toBe(60);
    expect(rule.rateLimit.refillRate).toBe(0.5);
  });
});
