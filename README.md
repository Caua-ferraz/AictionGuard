<p align="center">
  <img src="docs/assets/banner.svg" alt="AgentGuard" width="720" />
</p>

<p align="center">
  <strong>The firewall for AI agents.</strong><br/>
  Policy enforcement, real-time oversight, and full audit logging for autonomous AI systems.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#why-agentguard">Why AgentGuard</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#policy-engine">Policy Engine</a> •
  <a href="#dashboard">Dashboard</a> •
  <a href="#adapters">Adapters</a> •
  <a href="docs/SETUP.md">Setup Guide</a> •
  <a href="docs/CONTRIBUTING.md">Contributing</a>
</p>

---
## ⚠️ Attention

Some features of this project are not yet fully implemented and are currently under active development.


## The Problem

Every trending AI project is giving agents more autonomy — running shell commands, browsing the web, calling APIs, moving money, even performing penetration tests. But **nobody is building the guardrails.**

Right now, most teams deploying AI agents are just... hoping they behave.

**AgentGuard** fixes that.

## Why AgentGuard

| Without AgentGuard | With AgentGuard |
|---|---|
| Agent runs `rm -rf /` — you find out later | Policy blocks destructive commands before execution |
| Agent calls production API with no oversight | Action paused, you get a Slack/webhook notification to approve |
| No record of what the agent did or why | Full audit trail with timestamps, reasoning, and decisions |
| "It worked on my machine" debugging | Query any agent session from the audit log |
| One policy for all agents | Per-agent, per-environment, per-tool permission scoping |

## Quickstart

### Prerequisites

- **Go 1.22+** — `go version`
- **Git** — `git --version`
- **Python 3.8+** (optional, for SDK) — `python --version`

### Install

```bash
# From source
git clone https://github.com/Caua-ferraz/AictionGuard.git
cd AictionGuard
go build -o AictionGuard ./cmd/AictionGuard

# Or via Go install
go install github.com/Caua-ferraz/AictionGuard/cmd/AictionGuard@latest

# Or Docker
docker run -d -p 8080:8080 -v ./configs:/etc/AictionGuard AictionGuard:latest
```

### Define a Policy

Create `policies/default.yaml`:

```yaml
# AictionGuard Policy File
version: "1"
name: "development-sandbox"
description: "Safe defaults for development agents"

rules:
  # File system access
  - scope: filesystem
    allow:
      - action: read
        paths: ["./workspace/**", "/tmp/**"]
      - action: write
        paths: ["./workspace/**"]
    deny:
      - action: delete
        paths: ["**"]
        message: "File deletion is not permitted"
      - action: write
        paths: ["/etc/**", "/usr/**", "~/.ssh/**"]

  # Shell commands
  - scope: shell
    require_approval:
      - pattern: "sudo *"
      - pattern: "curl * | bash"
      - pattern: "rm -rf *"
    deny:
      - pattern: ":(){ :|:& };:"
        message: "Fork bomb detected"
    allow:
      - pattern: "ls *"
      - pattern: "cat *"
      - pattern: "grep *"
      - pattern: "python *"

  # API / Network calls
  - scope: network
    allow:
      - domain: "api.openai.com"
      - domain: "api.anthropic.com"
      - domain: "*.slack.com"
    deny:
      - domain: "*.production.internal"
        message: "Production access requires elevated policy"
    rate_limit:
      max_requests: 100
      window: "1m"

  # Cost guardrails
  - scope: cost
    limits:
      max_per_action: "$0.50"
      max_per_session: "$10.00"
      alert_threshold: "$5.00"

# Per-agent overrides
agents:
  research-bot:
    extends: "default"
    override:
      - scope: network
        allow:
          - domain: "scholar.google.com"
          - domain: "arxiv.org"

notifications:
  approval_required:
    - type: slack
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    - type: console
  on_deny:
    - type: log
      level: warn
```

### Start the Server

```bash
# Start AgentGuard with the default policy
AictionGuard serve --policy configs/default.yaml --port 8080

# With the dashboard enabled
AictionGuard serve --policy configs/default.yaml --port 8080 --dashboard

# Watch mode (live policy reloading)
AictionGuard serve --policy configs/default.yaml --watch --dashboard
```

### Connect Your Agent

```python
# Python — wrap any agent framework
from AictionGuard import Guard

guard = Guard("http://localhost:8080")

# Before executing any action, check it
result = guard.check("shell", command="rm -rf ./old_data")
# result.decision = "REQUIRE_APPROVAL"
# result.reason = "Matches pattern: rm -rf *"
# result.approval_url = "http://localhost:8080/approve/abc123"

if result.allowed:
    execute(command)
```

```typescript
// TypeScript / Node.js
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard('http://localhost:8080');

const result = await guard.check('network', {
  method: 'POST',
  url: 'https://api.production.internal/deploy',
});
// result.decision = "DENIED"
// result.reason = "Production access requires elevated policy"
```

## Architecture

```
┌─────────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│   AI Agent      │────▶│   AgentGuard Proxy        │────▶│  Target     │
│  (any framework)│◀────│                            │◀────│  (tools,    │
│                 │     │  ┌──────────────────────┐  │     │   APIs,     │
│  • LangChain    │     │  │  Policy Engine       │  │     │   shell)    │
│  • CrewAI       │     │  ├──────────────────────┤  │     └─────────────┘
│  • browser-use  │     │  │  Rate Limiter        │  │
│  • Claude (MCP) │     │  ├──────────────────────┤  │     ┌─────────────┐
│  • Custom       │     │  │  Approval Queue      │  │────▶│  Dashboard  │
│                 │     │  ├──────────────────────┤  │     │  (web UI)   │
│                 │     │  │  Notifier (Slack/WH) │  │     └─────────────┘
│                 │     │  ├──────────────────────┤  │
│                 │     │  │  Audit Logger         │  │     ┌─────────────┐
│                 │     │  └──────────────────────┘  │────▶│  Audit Log  │
└─────────────────┘     └──────────────────────────┘     │  (JSON)     │
                                                          └─────────────┘
```

### Core Components

**Policy Engine** — Evaluates every agent action against your YAML policy rules. Supports glob patterns, regex matching, per-agent overrides, and cost evaluation. Rule precedence: deny → require_approval → allow → default deny.

**Rate Limiter** — Token-bucket rate limiting per scope, per agent. Prevents runaway agents from burning through API quotas.

**Audit Logger** — Records every action attempt with full context: what was requested, which rule matched, what decision was made, and wall-clock timestamps. Outputs to JSON lines.

**Approval Queue** — When an action hits a `require_approval` rule, it's held in a queue. You get notified via webhook/Slack/console, and can approve or deny from the dashboard or CLI.

**Notifier** — Sends alerts to Slack webhooks, generic webhooks, console, or the log when actions are denied or require approval.

## Policy Engine

Policies are declarative YAML files with a simple mental model:

```
For each action → check deny rules → check require_approval → check allow rules → default deny
```

### Rule Scopes

| Scope | Controls | Example |
|---|---|---|
| `filesystem` | File read/write/delete | Block writes to system dirs |
| `shell` | Command execution | Require approval for `sudo` |
| `network` | HTTP/API calls | Whitelist specific domains |
| `browser` | Web automation | Block navigation to banking sites |
| `cost` | Spend limits | Cap per-action API costs |
| `data` | Data exfiltration | Block sending PII to external APIs |

### Per-Agent Overrides

```yaml
agents:
  research-bot:
    extends: "default"
    override:
      - scope: network
        allow:
          - domain: "scholar.google.com"
          - domain: "arxiv.org"

  deploy-bot:
    extends: "default"
    override:
      - scope: shell
        require_approval:
          - pattern: "*"  # Everything needs approval
```

### Rate Limiting

```yaml
rules:
  - scope: network
    rate_limit:
      max_requests: 60
      window: "1m"
```

### Cost Guardrails

Send `est_cost` in the check request to trigger cost evaluation:

```yaml
rules:
  - scope: cost
    limits:
      max_per_action: "$0.50"      # Deny if exceeded
      max_per_session: "$10.00"
      alert_threshold: "$5.00"     # Require approval if exceeded
```

### Notifications

```yaml
notifications:
  approval_required:
    - type: slack
      url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    - type: webhook
      url: "https://your-server.com/agentguard-events"
    - type: console
  on_deny:
    - type: log
      level: warn
```

## Dashboard

The web dashboard gives you real-time visibility into what your agents are doing.

```bash
agentguard serve --dashboard
# → http://localhost:8080/dashboard
```

**Features:**
- **Live feed** — Watch agent actions stream in real time via SSE
- **Approval queue** — Approve or deny pending actions with one click
- **Statistics** — Total checks, allowed/denied/pending counts
- **Connection status** — Live/disconnected indicator

## Adapters

AgentGuard works with any agent framework through adapters:

| Framework | Status | Install |
|---|---|---|
| LangChain | Ready | `pip install agentguard[langchain]` |
| CrewAI | Ready | `pip install agentguard[crewai]` |
| browser-use | Ready | `pip install agentguard[browser-use]` |
| Anthropic MCP | Ready | `pip install agentguard[mcp]` |
| TypeScript/Node.js | Ready | `npm install @agentguard/sdk` |
| Custom / HTTP | Ready | Any HTTP client |
| AutoGPT | Planned | — |
| OpenAI Agents SDK | Planned | — |

### LangChain Example

```python
from langchain.agents import create_react_agent
from agentguard.adapters.langchain import GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="research-bot"
)

agent = create_react_agent(llm, toolkit.tools, prompt)
# All tool calls now flow through AgentGuard automatically
```

### CrewAI Example

```python
from agentguard.adapters.crewai import guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)
```

### MCP Integration

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "python",
      "args": ["-m", "agentguard.adapters.mcp", "--guard-url", "http://localhost:8080"]
    }
  }
}
```

## CLI Reference

```bash
agentguard serve      # Start the proxy server
agentguard validate   # Validate policy files
agentguard approve    # Approve a pending action from CLI
agentguard deny       # Deny a pending action from CLI
agentguard status     # Show server health and pending approvals
agentguard audit      # Query the audit log
agentguard version    # Print version
```

## Roadmap

- [x] Core policy engine with YAML rules
- [x] Audit logging (JSON lines)
- [x] Shell, filesystem, network, browser, cost scopes
- [x] Approval queue with webhook/Slack notifications
- [x] Web dashboard (live feed + interactive approval)
- [x] Rate limiting enforcement
- [x] Per-agent policy overrides
- [x] Cost guardrails with threshold alerts
- [x] LangChain, CrewAI, browser-use, MCP adapters
- [x] Full CLI (approve, deny, status, audit)
- [ ] SQLite/PostgreSQL audit backend
- [ ] Data exfiltration detection (PII scanning)
- [ ] Policy-as-code (test policies in CI/CD)
- [ ] Multi-agent session correlation
- [ ] Session replay in dashboard
- [ ] Policy editor in dashboard
- [ ] SOC 2 / compliance report generation
- [ ] VS Code extension for policy authoring

## Contributing

We'd love your help. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

Priority areas:
- **Adapters** — Add support for more agent frameworks
- **Policy rules** — New scope types and matching strategies
- **Dashboard** — UI improvements and new visualizations
- **Documentation** — Guides, examples, and tutorials

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Stop hoping your agents behave. Start knowing.</strong>
</p>
