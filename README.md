# SmartContractAuditTool

> Solidity / EVM smart contract security auditor powered by **static pattern analysis** and **Claude AI**.

[![CI](https://github.com/harunidev/SmartContractAuditTool/actions/workflows/ci.yml/badge.svg)](https://github.com/harunidev/SmartContractAuditTool/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Features

| Layer | What it does |
|-------|-------------|
| **Static analyzer** | 18 pattern rules mapped to the SWC registry — zero dependencies, runs instantly |
| **AI analyzer** | Sends the contract to Claude (claude-opus-4-7) for deep semantic review |
| **CLI** | `audit-contract --file token.sol` — supports single file, batch dir, severity filter |
| **Web UI** | Dark-mode SPA: paste or upload, view expandable findings, download HTML/JSON reports |
| **Reporters** | Self-contained HTML report + machine-readable JSON |
| **Docker** | One-command container deployment |

---

## Detected Vulnerability Classes

| ID | Category | Severity |
|----|----------|----------|
| SWC-107 | Reentrancy | CRITICAL |
| SWC-112 | Uncontrolled Delegatecall | CRITICAL |
| SWC-118 | Unprotected Initializer | CRITICAL |
| SWC-115 | tx.origin Authentication | HIGH |
| SWC-104 | Unchecked Return Value | HIGH |
| SWC-101 | Integer Overflow (< 0.8) | HIGH |
| SWC-120 | Weak Randomness (blockhash) | HIGH |
| SWC-106 | selfdestruct Usage | HIGH |
| SWC-116 | Block Timestamp Dependence | MEDIUM |
| SWC-127 | Inline Assembly | MEDIUM |
| SWC-132 | .transfer() Gas Limit | MEDIUM |
| SWC-128 | Unbounded Loop (DoS) | MEDIUM |
| SWC-114 | ERC20 approve() Race | MEDIUM |
| SWC-103 | Floating Pragma | LOW |
| SWC-020 | Missing Zero-Address Check | LOW |
| SWC-134 | Hardcoded Address | LOW |
| SWC-100 | Implicit Function Visibility | LOW |
| — | Missing Event Emission | INFO |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/harunidev/SmartContractAuditTool.git
cd SmartContractAuditTool

# 2. Install
pip install -r requirements.txt
pip install -e .

# 3. Set API key (optional — needed only for AI analysis)
export ANTHROPIC_API_KEY=sk-ant-...

# 4. Audit a contract
audit-contract --file contracts/vulnerable.sol
```

---

## CLI Usage

```
usage: audit-contract [-h] [--file FILE] [--dir DIR]
                      [--format {html,json,console}] [--output PATH]
                      [--no-ai] [--min-severity LEVEL]
                      [--model MODEL] [--api-key KEY] [--open]
                      {demo,web} ...
```

### Examples

```bash
# Audit a single file — generates vulnerable_audit.html
audit-contract --file token.sol

# Static analysis only, show results in terminal
audit-contract --file token.sol --no-ai --format console

# Export JSON report
audit-contract --file token.sol --format json --output report.json

# Filter — only HIGH and CRITICAL findings
audit-contract --file token.sol --min-severity HIGH

# Batch audit an entire contracts directory
audit-contract --dir ./contracts --no-ai

# Open the HTML report in browser after generation
audit-contract --file token.sol --no-ai --open

# Generate a demo report from the bundled vulnerable contract
audit-contract demo

# Launch the web interface
audit-contract web --port 8080
```

---

## Web Interface

```bash
export ANTHROPIC_API_KEY=sk-ant-...
audit-contract web          # → http://localhost:5000
# or
python main.py web
```

**Features:**
- Paste code or drag-and-drop `.sol` file
- Toggle AI analysis on/off
- Severity filter (INFO → CRITICAL only)
- Click any finding card to expand description + recommendation + SWC link
- Download full HTML report or JSON

---

## Docker

```bash
# Build
docker build -t smart-contract-audit-tool .

# Run with your API key
docker run -p 5000:5000 -e ANTHROPIC_API_KEY=sk-ant-... smart-contract-audit-tool

# Or with docker-compose (reads .env automatically)
cp .env.example .env   # fill in your API key
docker-compose up
```

---

## Project Structure

```
SmartContractAuditTool/
├── audit_tool/
│   ├── analyzer/
│   │   ├── static.py       ← 18-rule pattern scanner
│   │   └── ai_auditor.py   ← Claude API integration
│   ├── reporter/
│   │   ├── html_report.py  ← Self-contained HTML report
│   │   └── json_report.py  ← Machine-readable JSON
│   ├── web/
│   │   ├── app.py          ← Flask API + health endpoint
│   │   └── templates/
│   │       └── index.html  ← Dark-mode SPA
│   ├── cli.py              ← argparse CLI (batch, demo, web sub-commands)
│   └── config.py           ← Env-var configuration
├── contracts/
│   ├── vulnerable.sol      ← Intentionally vulnerable (testing)
│   ├── safe_example.sol    ← Best-practice reference
│   └── defi_example.sol    ← DeFi contract with subtle bugs
├── tests/
│   ├── test_static.py      ← 17 unit tests for pattern scanner
│   ├── test_reporters.py   ← 12 tests for HTML/JSON reporters
│   └── test_cli.py         ← 9 tests for CLI behaviour
├── .github/workflows/
│   └── ci.yml              ← CI: test matrix + Docker build
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  SmartContractAuditTool              │
│                                                     │
│  Input layer                                        │
│  ┌───────────────┐  ┌──────────────────────┐       │
│  │ CLI (argparse)│  │ Web UI (Flask + SPA)  │       │
│  └──────┬────────┘  └──────────┬───────────┘       │
│         │                      │                    │
│  Analysis layer                │                    │
│  ┌──────▼──────────────────────▼──────────────┐    │
│  │ StaticAnalyzer     │  AIAuditor             │    │
│  │ 18 regex patterns  │  Claude API (opus-4-7) │    │
│  │ SWC-mapped         │  JSON structured output│    │
│  └──────┬─────────────┴──────────┬────────────┘    │
│         │                        │                  │
│  Report layer                    │                  │
│  ┌──────▼──────────┐  ┌──────────▼──────┐          │
│  │  HTMLReporter   │  │  JSONReporter   │           │
│  │  Standalone     │  │  Machine-       │           │
│  │  HTML file      │  │  readable JSON  │           │
│  └─────────────────┘  └─────────────────┘          │
└─────────────────────────────────────────────────────┘
```

---

## Development

```bash
# Run all tests (no API key required)
python tests/test_static.py
python tests/test_reporters.py
python tests/test_cli.py

# Install in editable mode
pip install -e .

# Run a quick smoke test
audit-contract demo
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Your Anthropic API key (required for AI analysis) |
| `AUDIT_MODEL` | `claude-opus-4-7` | Claude model to use |
| `AUDIT_WEB_HOST` | `0.0.0.0` | Web server bind host |
| `AUDIT_WEB_PORT` | `5000` | Web server port |
| `AUDIT_WEB_DEBUG` | `false` | Flask debug mode |
| `AUDIT_MAX_UPLOAD_KB` | `512` | Max upload size for web UI |

See `.env.example` for a template.

---

## Disclaimer

This tool is for **educational and authorized security research** purposes only.
Static pattern matching and AI analysis have false positives and false negatives —
**do not use audit results as a sole basis for production deployment decisions**.
Always combine with manual review and formal verification where stakes are high.

---

## License

MIT © 2026 harunidev
