# OpenClaw Sentinel MCP — Repository Guidelines

Network security sentinel for OpenClaw fleet. Provides policy enforcement, anomaly detection, and tamper-evident audit logging.

## Git Push Access (CRITICAL)

We have push access ONLY to these four GitHub repos:

- **https://github.com/nelsojona/mcp-menubar** - MCP menubar app (Swift)
- **https://github.com/nelsojona/openclaw-fleet** - Fleet monorepo (submodules + workspace packages)
- **https://github.com/nelsojona/openclaw-mcp** - MCP server source snapshot
- **https://github.com/nelsojona/openclaw-sentinel-mcp** - This repo (security sentinel)

We do **NOT** have push access to `openclaw/openclaw` or any other `openclaw/*` org repos. NEVER attempt to `git push` to repos outside this list.

## Ecosystem Position

```
TOP:    openclaw/openclaw (upstream)
SECOND: openclaw-sentinel-mcp (this repo) wraps openclaw-mcp
        openclaw-mcp · openclaw-fleet · mcp-menubar
THIRD:  mastra-swift (consumes these tools)
```

Sentinel sits between AI agents and openclaw-mcp as a transparent security proxy.

## Build & Test

```bash
npm install
npm run build       # Compile TypeScript
npm run test        # 135 tests (all components)
npm run typecheck   # Type-check without build
npm run lint        # Oxlint
npm run format      # Oxfmt
```

### Test Coverage (124 tests)

- Policy engine: 3 tests
- Audit log: 4 tests
- Rate limiter: 15 tests
- Quarantine: 16 tests
- Anomaly detector: 13 tests
- Interceptor: 19 tests
- Confirmation tokens: 14 tests
- Integration: 10 tests
- Integration monitoring: 12 tests
- Security invariants: 18 tests

## MCP Server Registration (CRITICAL)

**Adding this repo as a git submodule does NOT automatically register the MCP server with Claude Desktop.**

MCP server discovery happens at the Claude Desktop configuration level, not at the git submodule level.

### Registration Steps (Required)

1. **Build the server:**
   ```bash
   npm install && npm run build
   ```

2. **Initialize the database:**
   ```bash
   mkdir -p ~/.openclaw-sentinel
   node dist/scripts/init-db.js ~/.openclaw-sentinel/sentinel.db
   ```

3. **Add to Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "openclaw-sentinel": {
         "command": "/opt/homebrew/bin/node",
         "args": ["/absolute/path/to/openclaw-sentinel-mcp/dist/index.js"],
         "env": {
           "SENTINEL_DB_PATH": "/Users/YOUR_USERNAME/.openclaw-sentinel/sentinel.db"
         }
       }
     }
   }
   ```

4. **Restart Claude Desktop** (or mcp-menubar app if using that).

### Important Notes

- **Use absolute paths** - No `~` or relative paths in config
- **SENTINEL_DB_PATH required** - Server won't start without it
- **mcp-menubar reads Claude Desktop config** - The menubar app discovers MCP servers by reading Claude Desktop's configuration
- **Registration is manual** - No auto-discovery of git submodules

### Verification

After registration, verify the server is discovered:
```bash
# Check if server starts
SENTINEL_DB_PATH=~/.openclaw-sentinel/sentinel.db node dist/index.js
# Send: {"jsonrpc":"2.0","id":1,"method":"tools/list"}
# Expect: 23 tools in response
```

## Project Structure

```
src/
  index.ts                    # Public exports
  server.ts                   # MCP server setup (stdio transport)
  types.ts                    # Core type definitions
  database.ts                 # SQLite schema (10 tables)
  interceptor.ts              # Proxy for openclaw-mcp
  policy-engine.ts            # Rule evaluation (7-step order)
  audit-log.ts                # Hash-chained logging
  rate-limiter.ts             # Token-bucket algorithm
  circuit-breaker.ts          # Per-host circuit breaker
  anomaly-detector.ts         # EWMA anomaly detection
  quarantine-manager.ts       # Quarantine state management
  alert-router.ts             # Alert webhook dispatch
  confirmation-tokens.ts      # Single-use tokens for ask mode
  redaction.ts                # Sensitive field redaction
  default-rules.ts            # Essential hardcoded rules
  tools/
    firewall-rules.ts         # 7 rule management tools
    monitor.ts                # 6 monitoring tools
    audit.ts                  # 6 audit query tools
    policy.ts                 # 6 policy management tools
    alerts.ts                 # 5 alert management tools
    quarantine.ts             # 5 quarantine tools
  __tests__/                  # All test files
config/
  default-rules.json          # Shipped default ruleset
  schema.json                 # Rule validation schema
scripts/
  init-db.ts                  # Database setup script
  verify-audit-chain.ts       # Standalone verification
```

35 tools total across firewall rules, monitoring, audit, policy, alerts, and quarantine.

## Coding Conventions

### TypeScript
- Language: TypeScript (ESM), strict typing, avoid `any`
- Formatting/linting: Oxlint + Oxfmt
- All `if` statements require braces
- Tool naming: `sentinel_` prefix for all tools
- Tool pattern: `server.tool(name, description, zodSchema, handler)`
- Response pattern: `{ content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }`

### Database
- SQLite with better-sqlite3
- Prepared statements only (no SQL injection)
- WAL mode for concurrency
- 10 tables: rules, audit_log, anomaly_baselines, rate_limit_buckets, circuit_breakers, quarantine, alerts, confirmation_tokens, config

### Security Patterns
- Hash-chained audit log (SHA-256)
- Sensitive field redaction (password, secret, token, api_key → `[REDACTED]`)
- Circuit breaker per host (2 failures threshold, 120s cooldown)
- Token bucket rate limiting
- EWMA anomaly detection (α = 0.1)
- Deny-by-default policy enforcement

## Key Patterns

### Policy Evaluation Order (7 steps)

1. Circuit breaker check (host unavailable?)
2. Quarantine check (host/tool/agent quarantined?)
3. Mode enforcement (lockdown = deny all except health)
4. Rule matching (priority-ordered, first match wins)
5. Rate limiting (per matching rule's bucket)
6. Anomaly detection (score + risk factors)
7. Final verdict (allow/deny/ask/log-only)

### Audit Chain Integrity

```
hash = SHA-256(sequenceNumber + timestamp + tool + host + agent + verdict + previousHash)
```

First entry: `previousHash = "GENESIS"`
Verification walks chain, detects breaks.

### Anomaly Detection (EWMA)

```
frequencyMean = α × currentRate + (1 - α) × frequencyMean
```

**Components** (weighted):
- Frequency (25%): Z-score vs baseline
- Temporal (15%): Time-of-day probability
- Argument novelty (30%): Never-seen patterns
- Sequence (15%): Unusual bigrams
- Error rate (15%): Spike detection

**Thresholds**: 30 (suspicious), 60 (anomalous), 80 (critical), 90 (auto-lockdown)

### Response Helpers

```typescript
function textContent(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function errorContent(text: string) {
  return { content: [{ type: "text" as const, text }], isError: true };
}
```

## Reference Patterns

Adapted from:
- **MCP server setup**: `/Users/jonathannelson/Development/Personal/openclaw-fleet/addons/openclaw-mcp/src/mcp/server.ts`
- **Tool registration**: `/Users/jonathannelson/Development/Personal/openclaw-fleet/addons/openclaw-mcp/src/mcp/tools-gateway.ts`
- **Circuit breaker**: `/Users/jonathannelson/Development/Personal/openclaw-fleet/addons/openclaw-mcp/src/mcp/fleet-health.ts`
- **Security patterns**: `/Users/jonathannelson/Development/Personal/openclaw-fleet/addons/openclaw-mcp/src/mcp/fleet-config.ts`

## Git & Push Rules

- Remote: `git@github.com:nelsojona/openclaw-sentinel-mcp.git`
- Always use noreply email: `688996+nelsojona@users.noreply.github.com`
- Commit pattern: Concise, action-oriented messages
- Push after successful edits (per CLAUDE.md policy)

```bash
git config user.email "688996+nelsojona@users.noreply.github.com"
git config user.name "Jonathan Nelson"
```

## Four Operation Modes

1. **silent-allow** - Learning phase, allow all, build baselines
2. **alert** - Interactive, fire alerts, request confirmations
3. **silent-deny** - Production, enforce policy, deny by default
4. **lockdown** - Emergency, deny all except health checks

## Critical Implementation Details

### Interceptor Pattern

Spawn openclaw-mcp subprocess with stdio pipes:
```typescript
openclawProcess = spawn(config.openclawMcpCommand, config.openclawMcpArgs, {
  stdio: ['pipe', 'pipe', 'pipe']
});
```

Request flow:
1. Listen for MCP requests on sentinel's stdin
2. Extract tool name, arguments, agent from JSON-RPC
3. Call `evaluatePolicy()` → verdict
4. Call `createAuditEntry()` (write-ahead)
5. If allowed: write to openclaw-mcp stdin, relay response
6. If denied: send synthetic error with verdict details
7. Update audit entry with responseStatus

### Rate Limiting

Token bucket algorithm:
- Bucket key: `ruleId:tool:host:agent`
- Refill: `tokens += elapsedSeconds × refillRate`
- Consumption: 1 token per operation
- Persistence: SQLite after each check
- Cleanup: Prune buckets idle >24hrs

### Default Rules (6 essential)

1. Always allow health checks (`*health*`)
2. Always allow status queries (`*status*`)
3. Rate limit agent runs (10/min max)
4. Block force push to main
5. Ask before `rm -rf`
6. Log all fleet operations

## Verification Steps

```bash
# 1. Build & test
npm test              # All 135 tests pass

# 2. Integration test
SENTINEL_MODE=alert \
SENTINEL_DB_PATH=~/.openclaw-sentinel/test.db \
node dist/index.js

# 3. Verify audit chain
npm run verify-audit

# 4. Test policy enforcement
# (Create deny rule, verify blocked)

# 5. Test anomaly detection
# (Generate burst, verify scoring)
```

## Performance Requirements

- Policy evaluation: <5ms p99 latency
- Audit chain verification: <100ms for 10k entries
- Anomaly detection: <10ms per request
- Rate limit check: <2ms per request

## Security Considerations

- No SQL injection (prepared statements only)
- Sensitive field redaction in audit log
- Hash chain tamper detection
- Circuit breaker prevents cascading failures
- Token bucket prevents DoS
- EWMA detects statistical anomalies
- Deny-by-default policy enforcement
