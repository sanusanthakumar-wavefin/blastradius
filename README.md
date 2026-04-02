# BlastRadius — Automated PR Impact Analysis

> Before you merge, know what you'll break.

BlastRadius analyzes every PR to find cross-repo downstream dependencies, runtime service impacts, and incident history — then posts a risk report as a PR comment.

## What it does

1. **Reads the PR diff** and extracts changed symbols (classes, functions, imports, protobuf messages, gRPC methods)
2. **Searches all org repos** for references to those symbols
3. **Queries Datadog APM** for runtime service dependencies
4. **Checks incident history** for affected services
5. **AI classifies risk** and generates deployment order
6. **Posts a report** as a PR comment with a Mermaid deploy DAG

## Quick Start

### As an MCP Server (VS Code Copilot)

```json
// .vscode/settings.json
{
  "mcp": {
    "servers": {
      "blastradius": {
        "command": "python",
        "args": ["-m", "blastradius.mcp_server"],
        "env": {
          "GITHUB_TOKEN": "${env:GITHUB_TOKEN}",
          "OPENAI_API_KEY": "${env:OPENAI_API_KEY}",
          "DD_API_KEY": "${env:DD_API_KEY}",
          "DD_APP_KEY": "${env:DD_APP_KEY}"
        }
      }
    }
  }
}
```

Then in Copilot Chat:
```
@blastradius analyze https://github.com/waveaccounting/api-integrations/pull/416
```

### As a CLI

```bash
export GITHUB_TOKEN=ghp_...
export OPENAI_API_KEY=sk-...

python -m blastradius.cli \
  --owner waveaccounting \
  --repo api-integrations \
  --pr 416
```

### As a GitHub Action

Copy `.github/workflows/blastradius.yml` to your repo and add these secrets:
- `BLASTRADIUS_GITHUB_TOKEN` — GitHub PAT with `repo` and `read:org` scopes
- `OPENAI_API_KEY` — OpenAI API key
- `DD_API_KEY` / `DD_APP_KEY` — (optional) Datadog API credentials

## Example Output

```
## 🔴 BlastRadius Report

**Risk Level: HIGH** — PR renames shared gRPC protobuf interfaces used by 3 downstream services

### Downstream Services Affected (3)
| Service | Files | Impact | Deploy Order |
|---------|-------|--------|-------------|
| `waveaccounting/tuktuk` | eventing/registries.py, eventing/events.py | breaking | ① Deploy first |
| `waveaccounting/wave-messages` | tuktuk.proto | breaking | Step 1 |
| `waveaccounting/rpcx-tester` | SendIntegrations...py | non-breaking | ⚡ Non-blocking |

### 📋 Required Deploy Order
1. `wave-messages` — publish new protobuf version ⛔ **BLOCKING**
2. `tuktuk` — register new gRPC handlers ⛔ **BLOCKING**
3. `api-integrations` — this PR

> ⛔ **Do NOT merge** without coordinating deployments with the affected services above.
```

## Architecture

```
blastradius/
├── analyzer.py        # Orchestrator — ties everything together
├── github_client.py   # PR diff reading + org-wide code search
├── datadog_client.py  # Runtime service dependencies + incidents
├── ai_analyzer.py     # OpenAI risk classification
├── report.py          # Markdown report + Mermaid DAG generator
├── mcp_server.py      # MCP server (VS Code Copilot integration)
└── cli.py             # CLI + GitHub Action entrypoint
```

## Built at Wave Hackathon — April 2026
# Test change for blast radius demo
