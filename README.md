# OpenClaw Sentinel MCP

Network security sentinel for the OpenClaw fleet and gateway infrastructure. Provides policy enforcement, anomaly detection, and tamper-evident audit logging for AI agent operations.

## Architecture

Think "Little Snitch + FireWally for AI agents" - a security layer that sits between AI agents and openclaw-mcp:

- **Policy Decision Point** - Centralized rule evaluation with deny-by-default
- **Real-time Monitoring** - Per-tool/per-host telemetry with risk scoring
- **Anomaly Detection** - EWMA-based statistical analysis with auto-lockdown
- **Tamper-evident Audit** - SHA-256 hash-chained audit log

## Features

### Four Operation Modes

1. **silent-allow** (Learning) - Allow all, learn baselines, no alerts
2. **alert** (Interactive) - Allow all, fire alerts, request confirmations for unknown operations
3. **silent-deny** (Production) - Deny by default, enforce policy, log denials
4. **lockdown** (Emergency) - Deny all except health checks

### 35 MCP Tools

- **7 Firewall Rules** - Create, update, delete, list, test, import, export
- **6 Monitoring** - Live feed, stats, top tools, host breakdown, bandwidth, mode control
- **6 Audit** - Query, tail, stats, verify chain, export, retention
- **6 Policy** - Status, baseline, thresholds, schedules, agent trust, report
- **5 Alerts** - List, acknowledge, configure webhooks, test, history
- **5 Quarantine** - Quarantine/lift host/tool/agent, list active

### Security Layers

**Layer 1: Policy Engine** - Little Snitch-inspired rule evaluation
- Priority-ordered rules with glob patterns
- Allow/deny/ask/log-only actions
- Rate limiting per rule
- Time-of-day and day-of-week schedules

**Layer 2: Connection Monitor** - FireWally-inspired telemetry
- Per-tool/per-host request tracking
- Real-time risk scoring
- Circuit breaker protection
- Quarantine management

**Layer 3: Anomaly Detection** - EWMA statistical analysis
- Frequency anomalies (ops/hour vs baseline)
- Temporal anomalies (unusual time-of-day)
- Argument novelty (never-seen patterns)
- Sequence anomalies (unusual tool call chains)
- Error rate spikes

## Quick Start

### Installation

```bash
npm install
npm run build
npm run init-db  # Initialize SQLite database
```

### Configuration

Create `~/.openclaw-sentinel/config.json`:

```json
{
  "mode": "silent-allow",
  "database": "~/.openclaw-sentinel/sentinel.db",
  "openclawMcp": {
    "command": "node",
    "args": ["/path/to/openclaw-mcp/dist/index.js"]
  },
  "anomalyThresholds": {
    "suspicious": 30,
    "anomalous": 60,
    "critical": 80,
    "autoLockdown": 90
  }
}
```

### MCP Server Setup

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openclaw-sentinel": {
      "command": "node",
      "args": ["/path/to/openclaw-sentinel-mcp/dist/index.js"]
    }
  }
}
```

### Usage

The sentinel operates as a transparent proxy:

1. **Learning Phase** (silent-allow) - Run normal workload for baseline training
2. **Interactive Phase** (alert) - Review anomalies, create rules from confirmations
3. **Production Phase** (silent-deny) - Enforce policy, deny unknown operations
4. **Emergency** (lockdown) - Block everything except health checks

## Workflow Example

```bash
# 1. Start in learning mode (silent-allow)
sentinel_monitor_mode --mode silent-allow

# Run normal workload for 1 hour to establish baselines

# 2. Review learned baseline
sentinel_policy_baseline --show

# 3. Switch to alert mode
sentinel_monitor_mode --mode alert

# Unknown operation triggers ask mode:
# - Receive confirmation token
# - Retry with token
# - Rule created automatically

# 4. Switch to production (silent-deny)
sentinel_monitor_mode --mode silent-deny

# Only whitelisted operations allowed

# 5. Monitor live activity
sentinel_monitor_live

# 6. Verify audit chain integrity
sentinel_audit_verify
```

## Default Rules

Ships with 6 essential rules:

1. Always allow health checks (`*health*`)
2. Always allow status queries (`*status*`)
3. Rate limit agent runs (10/min max)
4. Block force push to main
5. Ask before `rm -rf`
6. Log all fleet operations

## Development

```bash
npm test              # Run 135 tests
npm run typecheck     # Type check
npm run lint          # Lint with oxlint
npm run format        # Format with oxfmt
```

### Test Coverage

- Policy engine: 25 tests
- Audit log: 20 tests
- Rate limiter: 15 tests
- Quarantine: 12 tests
- Anomaly detector: 20 tests
- Interceptor: 18 tests
- Integration: 10 tests
- Security invariants: 15 tests

**Total: 135 tests**

## Architecture Details

### Proxy Interceptor Pattern

Sentinel spawns openclaw-mcp as a subprocess and intercepts MCP JSON-RPC messages:

1. Agent sends MCP request → Sentinel
2. Sentinel evaluates policy (7-step evaluation order)
3. If allowed: forward to openclaw-mcp, relay response
4. If denied: return synthetic error with reason + risk factors
5. If ask: return confirmation token, require token in retry

### Policy Evaluation Order

1. Circuit breaker check (host unavailable?)
2. Quarantine check (host/tool/agent quarantined?)
3. Mode enforcement (lockdown = deny all except health)
4. Rule matching (priority-ordered, first match wins)
5. Rate limiting (per matching rule's bucket)
6. Anomaly detection (score + risk factors)
7. Final verdict (allow/deny/ask/log-only)

### Audit Chain Integrity

Hash chain formula:
```
hash = SHA-256(sequenceNumber + timestamp + tool + host + agent + verdict + previousHash)
```

First entry: `previousHash = "GENESIS"`
Each subsequent entry chains to previous.

Verification walks the chain and detects breaks.

### Anomaly Detection

EWMA with α = 0.1 decay factor:
```
frequencyMean = α × currentRate + (1 - α) × frequencyMean
```

**Five components** (weighted):
- Frequency (25%): Z-score of ops/hour vs baseline
- Temporal (15%): Probability of this hour vs distribution
- Argument novelty (30%): Never-seen argument fingerprint
- Sequence (15%): Unusual tool call bigram
- Error rate (15%): Error rate spike vs baseline

**Thresholds**:
- Suspicious: 30
- Anomalous: 60
- Critical: 80
- Auto-lockdown: 90

## License

MIT

## Repository

https://github.com/nelsojona/openclaw-sentinel-mcp
