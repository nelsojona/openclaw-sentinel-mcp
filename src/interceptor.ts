/**
 * Proxy interceptor for openclaw-mcp
 *
 * Sits between agents and openclaw-mcp, enforcing sentinel policies
 *
 * Request flow:
 * 1. stdin → parse JSON-RPC
 * 2. evaluatePolicy()
 * 3. createAuditEntry() (write-ahead logging)
 * 4. Forward/deny/ask based on verdict
 * 5. updateAuditEntry() with response status
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type Database from 'better-sqlite3';
import type { PolicyContext, SentinelMode, SentinelConfig } from './types.js';
import { evaluatePolicy } from './policy-engine.js';
import { createAuditEntry, updateAuditEntry } from './audit-log.js';
import { generateConfirmationToken } from './confirmation-tokens.js';

const FORWARD_TIMEOUT_MS = 15000; // 15s timeout for forwarding

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id?: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/**
 * Sentinel interceptor
 *
 * Spawns openclaw-mcp subprocess and intercepts all tool calls
 */
export class SentinelInterceptor {
  private db: Database.Database;
  private config: SentinelConfig;
  private openclawProcess: ChildProcess | null = null;
  private responseCallbacks: Map<
    string | number,
    { resolve: (response: JsonRpcResponse) => void; timer: NodeJS.Timeout }
  > = new Map();

  constructor(db: Database.Database, config: SentinelConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Start the interceptor
   *
   * Spawns openclaw-mcp subprocess and sets up stdio pipes
   */
  start(): void {
    // Spawn openclaw-mcp subprocess
    this.openclawProcess = spawn(this.config.openclawMcpCommand, this.config.openclawMcpArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    if (!this.openclawProcess.stdin || !this.openclawProcess.stdout || !this.openclawProcess.stderr) {
      throw new Error('Failed to create stdio pipes for openclaw-mcp subprocess');
    }

    // Listen for responses from openclaw-mcp stdout
    const rl = createInterface({
      input: this.openclawProcess.stdout,
      crlfDelay: Number.POSITIVE_INFINITY,
    });

    rl.on('line', (line) => {
      try {
        const response = JSON.parse(line) as JsonRpcResponse;
        this.handleOpenclawResponse(response);
      } catch (error) {
        console.error('Failed to parse openclaw-mcp response:', error);
      }
    });

    // Forward stderr to our stderr
    this.openclawProcess.stderr.on('data', (data) => {
      process.stderr.write(data);
    });

    // Listen for stdin from agent
    const stdinRl = createInterface({
      input: process.stdin,
      crlfDelay: Number.POSITIVE_INFINITY,
    });

    stdinRl.on('line', (line) => {
      this.handleAgentRequest(line);
    });

    // Handle process exit
    this.openclawProcess.on('exit', (code) => {
      console.error(`openclaw-mcp process exited with code ${code}`);
      process.exit(code ?? 1);
    });
  }

  /**
   * Handle JSON-RPC request from agent
   */
  private handleAgentRequest(line: string): void {
    try {
      const request = JSON.parse(line) as JsonRpcRequest;

      // Extract context from request
      const context = this.extractContext(request);

      if (!context) {
        // Not a tool call, forward directly (e.g., initialize, ping)
        this.forwardToOpenclaw(request);
        return;
      }

      // Get current mode
      const modeRow = this.db.prepare('SELECT value FROM config WHERE key = ?').get('mode') as
        | { value: string }
        | undefined;
      const mode = (modeRow?.value ?? 'silent-allow') as SentinelMode;

      // Evaluate policy
      const verdict = evaluatePolicy(this.db, context, mode);

      // Create audit entry (write-ahead logging)
      const auditEntry = createAuditEntry(this.db, context, verdict, mode);

      // Handle verdict
      if (verdict.action === 'deny') {
        // Denied - send synthetic error response
        updateAuditEntry(this.db, auditEntry.id, { responseStatus: 'error', errorMessage: verdict.reason });

        const errorResponse: JsonRpcResponse = {
          jsonrpc: '2.0',
          id: request.id,
          error: {
            code: -32000,
            message: 'Policy violation',
            data: {
              reason: verdict.reason,
              riskScore: verdict.riskScore,
              riskFactors: verdict.riskFactors,
            },
          },
        };

        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      }

      if (verdict.action === 'ask') {
        // Ask for confirmation - generate token and return
        const token = generateConfirmationToken(this.db, context, this.config.confirmationTokenTtlMs);

        updateAuditEntry(this.db, auditEntry.id, {
          responseStatus: 'error',
          errorMessage: `Confirmation required: ${verdict.reason}`,
        });

        const errorResponse: JsonRpcResponse = {
          jsonrpc: '2.0',
          id: request.id,
          error: {
            code: -32001,
            message: 'Confirmation required',
            data: {
              reason: verdict.reason,
              confirmationToken: token,
              riskScore: verdict.riskScore,
              riskFactors: verdict.riskFactors,
            },
          },
        };

        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      }

      // Allowed - forward to openclaw-mcp
      this.forwardToOpenclawWithTimeout(request, auditEntry.id);
    } catch (error) {
      console.error('Failed to handle agent request:', error);
    }
  }

  /**
   * Extract policy context from JSON-RPC request
   *
   * Returns null if not a tool call
   */
  private extractContext(request: JsonRpcRequest): PolicyContext | null {
    // Tool calls use the "tools/call" method
    if (request.method !== 'tools/call') {
      return null;
    }

    const params = request.params ?? {};
    const tool = params.name as string | undefined;
    const args = (params.arguments ?? {}) as Record<string, unknown>;

    if (!tool) {
      return null;
    }

    // Extract host from arguments (fleet tools) or default to 'local'
    const host = (args.host as string | undefined) ?? 'local';

    // Extract agent from session or default to 'unknown'
    const agent = (params.agent as string | undefined) ?? 'unknown';

    return {
      tool,
      host,
      agent,
      arguments: args,
      timestamp: Date.now(),
    };
  }

  /**
   * Forward request to openclaw-mcp with timeout
   */
  private forwardToOpenclawWithTimeout(request: JsonRpcRequest, auditEntryId: number): void {
    if (!this.openclawProcess?.stdin) {
      console.error('openclaw-mcp process not running');
      return;
    }

    // Set up timeout and callback
    const timer = setTimeout(() => {
      this.responseCallbacks.delete(request.id!);
      updateAuditEntry(this.db, auditEntryId, { responseStatus: 'timeout' });

      const timeoutResponse: JsonRpcResponse = {
        jsonrpc: '2.0',
        id: request.id,
        error: {
          code: -32002,
          message: 'Request timeout',
        },
      };

      process.stdout.write(JSON.stringify(timeoutResponse) + '\n');
    }, FORWARD_TIMEOUT_MS);

    this.responseCallbacks.set(request.id!, {
      resolve: (response) => {
        clearTimeout(timer);
        const hasError = response.error !== undefined;
        updateAuditEntry(this.db, auditEntryId, {
          responseStatus: hasError ? 'error' : 'success',
          errorMessage: hasError ? response.error?.message : undefined,
        });
        process.stdout.write(JSON.stringify(response) + '\n');
      },
      timer,
    });

    // Forward request
    this.forwardToOpenclaw(request);
  }

  /**
   * Forward request directly to openclaw-mcp (no interception)
   */
  private forwardToOpenclaw(request: JsonRpcRequest): void {
    if (!this.openclawProcess?.stdin) {
      console.error('openclaw-mcp process not running');
      return;
    }

    this.openclawProcess.stdin.write(JSON.stringify(request) + '\n');
  }

  /**
   * Handle response from openclaw-mcp
   */
  private handleOpenclawResponse(response: JsonRpcResponse): void {
    const callback = this.responseCallbacks.get(response.id!);

    if (callback) {
      this.responseCallbacks.delete(response.id!);
      callback.resolve(response);
    } else {
      // No callback registered (e.g., initialize response), forward directly
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  }

  /**
   * Stop the interceptor
   */
  stop(): void {
    if (this.openclawProcess) {
      this.openclawProcess.kill();
      this.openclawProcess = null;
    }

    // Clear all pending callbacks
    this.responseCallbacks.forEach((callback, id) => {
      clearTimeout(callback.timer);
      this.responseCallbacks.delete(id);
    });
  }
}
