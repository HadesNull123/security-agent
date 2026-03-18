# 🛡️ Security Agent

**AI-Powered Automated Penetration Testing Framework**

Security Agent is an autonomous AI agent that leverages Large Language Models (Gemini, OpenAI, Claude, Ollama) to automate the entire penetration testing lifecycle: **Reconnaissance → Scanning → Analysis → Exploitation → Reporting**.

The AI autonomously selects appropriate tools, analyzes results, generates custom exploit code in a secure sandbox, and produces professional reports — all with built-in safety controls and scope enforcement.

---

## Table of Contents

- [Key Features](#-key-features)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [Docker Deployment](#-docker-deployment)
- [Configuration](#️-configuration)
- [Scan Pipeline](#-scan-pipeline)
- [Architecture Deep Dive](#-architecture-deep-dive)
  - [Vector Memory System](#vector-memory-system)
  - [Exploit Sandbox](#exploit-sandbox)
  - [Report Generation](#report-generation)
- [Extending the Framework](#-extending-the-framework)
  - [Adding a New Tool](#adding-a-new-tool)
  - [Adding a New Skill](#adding-a-new-skill)
- [Project Structure](#-project-structure)
- [Legal Disclaimer](#️-legal-disclaimer)

---

## ✨ Key Features

### 🤖 AI-Driven Orchestration
- **LangChain Agent** with tool-calling — the AI dynamically selects the right tool for each phase
- **4 LLM Providers**: Gemini (default), OpenAI, Anthropic, Ollama (local/offline)
- **Vector Memory** (TF-IDF + cosine similarity) — maintains context across phases without external APIs
- Automatic finding deduplication, severity classification, and risk assessment

### 🔍 27 Integrated Security Tools

| Phase | Tools | Purpose |
|-------|-------|---------|
| **Recon** | Subfinder, Naabu, Katana, httpx, Amass, WhatWeb, Wafw00f, Dnsx | Subdomain enumeration, port scanning, web crawling, technology fingerprinting, WAF detection, DNS resolution |
| **Scanning** | Nuclei, ffuf, Gobuster, Nikto, TestSSL, **Dalfox**, **CRLFuzz**, **CORScanner**, SecretScanner, EmailSecurity, ZAP (API), Acunetix (API) | Vulnerability scanning, fuzzing, directory brute-forcing, SSL/TLS auditing, **XSS scanning**, **CRLF injection**, **CORS misconfiguration**, credential leak detection, email security (SPF/DKIM/DMARC) |
| **Exploitation** | SQLMap, Commix, SearchSploit, Metasploit (RPC), Custom Exploit Engine | SQL injection, command injection, known CVE exploits, AI-generated Python exploits |

### ⚡ Smart Tool Defaults

All tools are pre-configured with optimized defaults for fast scanning. No more waiting 30+ minutes for a single tool:

| Tool | Default Behavior | Speed |
|------|-----------------|-------|
| **Nuclei** | Auto-scan (`-as`) + severity filter (`critical,high,medium`) | ~2-5 min |
| **ffuf** | Filter 404, 40 threads, auto-download wordlist | ~1-3 min |
| **Gobuster** | 40 threads, 10s timeout, auto-download wordlist | ~1-3 min |
| **Nikto** | Max 5 min scan time, 10s/request timeout | max 5 min |
| **TestSSL** | `--fast` mode, 10s connect timeout | ~2-3 min |
| **Dalfox** | XSS scanner, DOM mining, 10 workers, JSON output | ~2-5 min |
| **CRLFuzz** | CRLF injection, silent mode, 25 concurrent | ~1-2 min |
| **CORScanner** | CORS misconfig, 10+ check types, 50 threads | ~1-2 min |
| **Katana** | Max 500 URLs, 100 req/s, depth 3 | ~1-2 min |
| **Naabu** | Top-100 ports, rate 1000 pkt/s | ~30s-1 min |
| **SQLMap** | Level 2, risk 2, 4 threads | ~3-5 min |
| **Commix** | Level 2, 10s timeout | ~2-3 min |

### 📂 Auto-Download Wordlists

Wordlists are **automatically managed** — no manual setup required:
- Checks system paths (`/usr/share/seclists/`, `/usr/share/wordlists/`) first
- If missing, downloads **SecLists common.txt** from GitHub to `~/.secagent/wordlists/`
- Falls back to a built-in minimal wordlist if offline

### 📁 Tool Output Saving

Every tool execution is automatically saved for inspection:
```
data/tool_outputs/latest/
├── subfinder_20250313_174522.json
├── httpx_20250313_174535.json
├── nuclei_20250313_174612.json
└── ffuf_20250313_174701.json
```
Each JSON file contains: command used, execution time, parsed data, raw output preview, and success/error status.

### 🔒 Security & Safety
- **Command Validation** — blocks 40+ dangerous patterns (destructive commands, reverse shells, etc.)
- **Scope Enforcement** — restricts scanning to explicitly authorized targets
- **Safe Mode** — requires confirmation before exploitation (enabled by default)
- **Exploit Sandbox** — AI-generated code runs in a restricted environment with AST validation, import whitelisting, and execution timeouts
- **Metasploit Restrictions** — limited to CVE-specific modules only; disabled in safe mode

### 📊 Professional Reporting
- **Markdown Report** — structured findings with evidence, impact analysis, and remediation guidance
- **PDF Report** — professionally formatted document with severity-coded tables (via reportlab)
- **JSON Export** — machine-readable output for CI/CD pipeline integration
- **LLM Fallback** — if template rendering fails, the AI generates a comprehensive report

### 🖥️ Real-Time Console UI
- Live dashboard (Rich) displaying scan progress across all phases
- Phase tracking, tool execution status, and findings summary
- Activity log with timestamps and token usage monitoring

---

## 🚀 Getting Started

### Prerequisites

```bash
# Python 3.11+ and Go (required for security tools)

# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install -y python3 python3-pip golang-go git curl wget

# macOS:
brew install python go git
```

### Installation

```bash
# Option A: Install from PyPI
pip install security-agent-ai

# Option B: Install from source
cd security_agent
pip install -e .

# Create configuration file
cp .env.example .env

# Configure your LLM API key
nano .env
# Required: Set GOOGLE_API_KEY (or your preferred LLM provider key)
```

### First Scan

```bash
# Missing security tools are AUTOMATICALLY INSTALLED on first run
secagent scan example.com --mode quick
```

---

## 📋 Usage

### Running Scans

```bash
# Quick scan — fast recon + critical vulnerabilities only (~2-5 min)
secagent scan <target> --mode quick

# Normal scan — balanced assessment with exploitation (~10-30 min)
secagent scan <target> --mode normal

# Deep scan — comprehensive with all tools and large wordlists (~30-90 min)
secagent scan <target> --mode deep

# Scan with project specification file (PDF/JSON/MD/YAML)
# AI extracts APIs, parameters, auth methods → targeted scanning
secagent scan <target> --spec /path/to/api_docs.json
secagent scan <target> --spec swagger.yaml --mode deep
```

### Scan Options

```bash
# Multiple targets
secagent scan target1.com target2.com api.target.com

# Specify target type
secagent scan 192.168.1.0/24 --type cidr
secagent scan http://target.com/api --type url
secagent scan 10.0.0.1 --type ip

# Restrict scan scope
secagent scan target.com --scope target.com --scope "*.target.com"

# Disable safe mode (allows automatic exploitation)
secagent scan target.com --no-safe-mode

# Custom output directory
secagent scan target.com -o ./my-reports

# Verbose logging
secagent scan target.com -v
```

### 📄 Spec File Input (AI-Powered)

Provide project documentation and the AI will extract APIs, parameters, and attack surface for targeted scanning:

```bash
# OpenAPI/Swagger spec → AI extracts endpoints
secagent scan https://api.example.com --spec swagger.yaml

# PDF project documentation
secagent scan https://api.example.com --spec project_docs.pdf

# JSON API documentation
secagent scan https://api.example.com --spec api_spec.json

# Markdown technical docs
secagent scan https://api.example.com --spec ARCHITECTURE.md
```

**Supported formats:** PDF, JSON, YAML, Markdown, TXT

**What the AI extracts:**
- API endpoints (method, path, parameters, auth)
- Authentication mechanisms (JWT, OAuth, API keys)
- Technologies and frameworks used
- Sensitive data flows (payment, PII, admin)
- Attack surface (file uploads, admin panels, debug endpoints)
- Test accounts (if documented)
- Additional target domains/subdomains

> **Note:** `--spec` requires a configured LLM provider. The agent will show a clear error if no API key is set.

### Tool Management

```bash
# View installation status of all tools
secagent install-tools

# Install all missing tools automatically
secagent install-tools --all

# Install specific tools
secagent install-tools subfinder nuclei httpx

# View agent configuration and tool availability
secagent status

# Display current configuration
secagent config-show
```

### Running Individual Tools

```bash
# Subdomain enumeration
secagent run-tool example.com --tool subfinder

# Vulnerability scanning with specific tags
secagent run-tool http://example.com --tool nuclei --args '{"tags": "cve"}'

# HTTP probing and technology detection
secagent run-tool example.com --tool httpx

# Port scanning
secagent run-tool example.com --tool naabu --args '{"top_ports": "1000"}'

# Directory brute-forcing
secagent run-tool http://example.com/FUZZ --tool ffuf

# Web server scanning
secagent run-tool http://example.com --tool nikto

# SSL/TLS configuration audit
secagent run-tool example.com --tool testssl

# DNS enumeration
secagent run-tool example.com --tool dnsx
```

> **Tip**: If running from source without pip install, use `python main.py` instead of `secagent`.

---

## 🐳 Docker Deployment (Optional)

```bash
# Build and start the containerized environment
docker compose up -d

# Run a scan
docker compose exec agent secagent scan example.com --mode normal

# View tool status
docker compose exec agent secagent status

# Start with optional services (ZAP + Metasploit)
docker compose --profile full up -d
```

---

## ⚙️ Configuration

All settings are managed via the `.env` file. Copy `.env.example` to `.env` and configure:

### LLM Provider

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | Provider: `gemini`, `openai`, `anthropic`, `ollama` | `gemini` |
| `LLM_MODEL` | Model name | `gemini-2.5-pro` |
| `GOOGLE_API_KEY` | Google Gemini API key | — |
| `OPENAI_API_KEY` | OpenAI API key (optional) | — |
| `ANTHROPIC_API_KEY` | Anthropic API key (optional) | — |
| `OLLAMA_BASE_URL` | Ollama server URL (optional) | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model name | `llama3` |

### External Tool APIs (Optional)

| Variable | Description |
|----------|-------------|
| `ACUNETIX_API_URL` | Acunetix instance URL |
| `ACUNETIX_API_KEY` | Acunetix API key |
| `ZAP_API_URL` | OWASP ZAP API URL |
| `ZAP_API_KEY` | ZAP API key |
| `SHODAN_API_KEY` | Shodan API key |
| `METASPLOIT_RPC_HOST` | Metasploit RPC host |
| `METASPLOIT_RPC_PORT` | Metasploit RPC port |
| `METASPLOIT_RPC_PASSWORD` | Metasploit RPC password |

### Agent Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `TOOL_TIMEOUT` | Maximum execution time per tool (seconds) | `300` |
| `MAX_SCAN_TIME` | Maximum total scan duration (seconds) | `3600` |
| `REPORT_OUTPUT_DIR` | Report output directory | `./reports` |
| `DATABASE_PATH` | SQLite database path | `./data/security_agent.db` |
| `LOG_LEVEL` | Logging level | `INFO` |

---

## 🔄 Scan Pipeline

```
┌─────────────┐    ┌─────────────┐    ┌───────────┐    ┌──────────┐    ┌──────────────┐    ┌───────────┐
│  PHASE 0    │    │    RECON    │    │  SCANNING │    │ ANALYSIS │    │ EXPLOITATION │    │ REPORTING │
│  (optional) │ →  │            │ →  │           │ →  │          │ →  │              │ →  │           │
│             │    │ • Subdomains│   │ • Nuclei  │    │ • AI     │    │ • SQLMap     │    │ • MD      │
│ • Spec File │    │ • Ports    │    │ • ffuf    │    │   dedup  │    │ • Commix     │    │ • PDF     │
│   Analysis  │    │ • Crawling │    │ • Gobuster│    │ • CVSS   │    │ • Custom     │    │ • JSON    │
│ • API       │    │ • Tech ID  │    │ • Nikto   │    │   rating │    │   exploits   │    │           │
│   Extraction│    │ • DNS      │    │ • Dalfox  │    │ • Risk   │    │ • Metasploit │    │           │
│ • LLM Parse │    │ • WAF      │    │ • CRLFuzz │    │   assess │    │   (CVE only) │    │           │
│             │    │            │    │ • CORScan │    │          │    │              │    │           │
│             │    │            │    │ • TestSSL │    │          │    │              │    │           │
└─────────────┘    └─────────────┘    └───────────┘    └──────────┘    └──────────────┘    └───────────┘
```

### Scan Modes

| Mode | Tools Utilized | Duration | Use Case |
|------|---------------|----------|----------|
| **Quick** | Subfinder, httpx, Nuclei (critical/high only) | 2–5 min | Rapid recon and critical vulnerability check |
| **Normal** | All recon + Nuclei + ffuf + analysis + exploitation | 10–30 min | Standard penetration test |
| **Deep** | All tools, full port scan, large wordlists, multiple passes | 30–90 min | Comprehensive security assessment |

---

## 🏗️ Architecture Deep Dive

### Vector Memory System

The agent uses a **fully local** vector memory system — no external embedding APIs, no cloud dependencies. All state is stored in SQLite.

**How it works:**

```
Input Text → Tokenize → TF-IDF Vector → Store in SQLite
                                             ↕
Query Text → Tokenize → TF-IDF Vector → Cosine Similarity → Top-K Results
```

1. **Tokenization**: Text is lowercased, cleaned of special characters, and split into tokens. Common stopwords are removed.

2. **TF-IDF Vectorization**: Each text chunk is converted to a sparse vector using Term Frequency × Inverse Document Frequency:
   - **TF** = `term_count / total_tokens` (how often a term appears in this chunk)
   - **IDF** = `log(total_docs / doc_freq)` (rarity of the term across all stored chunks)
   - Vectors are stored as JSON arrays of `(term, score)` tuples in SQLite.

3. **Cosine Similarity Search**: When querying, the input is vectorized and compared against all stored vectors using cosine similarity. Results are ranked by relevance score.

4. **Memory Categories**: Chunks are tagged with categories for filtered retrieval:
   - `recon_result` — subdomain lists, port scan data, crawled URLs
   - `finding` — discovered vulnerabilities
   - `tool_output` — raw tool execution results
   - `skill` — loaded skill knowledge
   - `analysis` — AI-generated analysis summaries

5. **Persistence**: All data lives in a single SQLite file (`./data/security_agent.db`) using WAL mode for concurrent read/write performance. Memory persists across scan sessions, enabling the agent to learn from previous assessments.

```python
# Memory is used automatically by the agent:
# 1. After each tool run, results are stored
memory.store(tool_output, category="tool_output", session_id=session.id)

# 2. Before each phase, relevant context is recalled
context = memory.search("SQL injection login form", top_k=5)

# 3. Skills are loaded into memory at startup
memory.store(skill_content, category="skill")
```

---

### Exploit Sandbox

The **Custom Exploit Engine** allows the AI to write Python exploit code at runtime. All generated code runs inside a secure sandbox with **6 layers of protection**:

```
AI-Generated Code
    │
    ▼
┌─────────────────────────────────┐
│  Layer 1: AST Validation        │  Parse code → check every node
│  • Block dangerous imports      │  (os, subprocess, shutil, etc.)
│  • Block dangerous calls        │  (os.system, Popen, eval, exec)
│  • Block reverse shell strings  │  (regex detection in string literals)
├─────────────────────────────────┤
│  Layer 2: Import Whitelist      │  Only 30+ safe modules allowed:
│  • requests, socket, ssl        │  (networking)
│  • json, re, base64, hashlib    │  (data handling)
│  • html, xml, struct            │  (parsing)
│  • time, string, math           │  (utilities)
├─────────────────────────────────┤
│  Layer 3: Restricted Builtins   │  Remove: exec, eval, compile,
│                                 │  __import__, globals, locals
├─────────────────────────────────┤
│  Layer 4: Scope Validation      │  Target in code must match
│                                 │  agent's allowed_scope list
├─────────────────────────────────┤
│  Layer 5: Execution Timeout     │  Max 60 seconds (configurable)
│                                 │  Prevents infinite loops
├─────────────────────────────────┤
│  Layer 6: Isolated Directory    │  Each run gets unique /tmp dir
│                                 │  Cleaned up after execution
└─────────────────────────────────┘
    │
    ▼
  Result (stdout/stderr captured)
```

**Blocked Patterns** (detected via AST analysis):

| Category | Examples |
|----------|----------|
| **Dangerous Imports** | `os`, `subprocess`, `shutil`, `ctypes`, `multiprocessing`, `pickle`, `threading`, `asyncio` |
| **Dangerous Calls** | `os.system()`, `subprocess.Popen()`, `eval()`, `exec()`, `shutil.rmtree()`, `socket.bind()` |
| **Reverse Shells** | `bash -i >/dev/tcp/`, `nc -e /bin/sh`, `python -c ...socket...connect`, `mkfifo /tmp/` |
| **Persistence** | `crontab`, `systemctl enable`, `curl|bash` |
| **Filesystem Destruction** | `rm -rf /`, `chmod 777 /` |

**Allowed Modules** for exploit code:

```
requests, socket, ssl, http, http.client, urllib, urllib.parse,
json, re, base64, hashlib, struct, binascii, html, html.parser,
xml, xml.etree, hmac, zlib, gzip, time, string, copy, math,
random, collections, itertools, functools, io, textwrap, datetime
```

---

### Report Generation

Reports are generated automatically at the end of each scan through a **3-tier pipeline**:

```
                    ┌──────────────────────────┐
                    │      ScanSession         │
                    │  • targets               │
                    │  • findings (sorted)      │
                    │  • exploit_results        │
                    │  • tool_executions        │
                    │  • severity_summary       │
                    └────────┬─────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │  Markdown  │  │    PDF     │  │    JSON    │
     │  (Jinja2)  │  │ (reportlab)│  │  (export)  │
     └────────────┘  └────────────┘  └────────────┘
```

**Tier 1 — Markdown Report** (`reporting.py`, Jinja2 template):

| Section | Contents |
|---------|----------|
| Executive Summary | Target, finding count, severity breakdown |
| Scope & Methodology | Target list, tools used, 5-phase pipeline description |
| Findings Summary | Table: title, severity, confidence, affected resource |
| Detailed Findings | Per-finding: severity, CVSS, CVE, evidence (code blocks), remediation |
| Exploitation Results | Table: finding ID, tool used, success/failure, access gained |
| Recommendations | Prioritized: Critical/High → Medium → Low/Info |
| Tool Execution Log | Table: tool name, phase, status, duration |

**Tier 2 — PDF Report** (`pdf_report.py`, reportlab):
- Professional A4 document with cover page and severity-coded color scheme
- Styled tables with alternating row colors
- Automatic fallback to plain text file if reportlab is not installed

**Tier 3 — JSON Export** (`reporting.py`):
- Machine-readable structured data for CI/CD pipeline integration
- Contains all session data: targets, findings, exploit results, tool executions

**LLM Fallback**: If the Jinja2 template fails, the agent sends all findings to the LLM with `REPORTING_PROMPT` and receives a comprehensive markdown report generated by AI.

**Output Location**: `./reports/` (configurable via `REPORT_OUTPUT_DIR`)

```
reports/
├── report_a1b2c3d4_20250313_143022.md    # Markdown
├── report_a1b2c3d4_20250313_143022.pdf   # PDF
└── report_a1b2c3d4_20250313_143022.json  # JSON
```

---

## 🔌 Extending the Framework

### Adding a New Tool

To integrate a new CLI security tool, create 3 files:

#### Step 1: Create the tool wrapper

Create a new file in `src/tools/<phase>/` (e.g., `src/tools/scanner/my_tool.py`):

```python
"""MyTool - Description of what this tool does."""

from __future__ import annotations
from typing import Any
from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult, run_command, parse_json_output


class MyTool(BaseTool):
    name = "mytool"                          # Unique tool name
    description = "What this tool does"      # Description for the AI
    phase = ScanPhase.SCANNING               # RECON, SCANNING, or EXPLOITATION
    # binary_name = "mytool"                 # Override if binary differs from name

    async def _run(self, target: str, **kwargs: Any) -> ToolResult:
        cmd = ["mytool", "-target", target, "-json"]

        # Add optional parameters with smart defaults
        severity = kwargs.get("severity", "critical,high,medium")
        cmd.extend(["-severity", severity])

        # Performance defaults
        cmd.extend(["-timeout", "15"])

        returncode, stdout, stderr = await run_command(cmd, timeout=self.timeout)

        if returncode != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=stderr or f"mytool exited with code {returncode}",
                command_used=" ".join(cmd),
            )

        # Parse output (JSON or text)
        parsed = parse_json_output(stdout)

        return ToolResult(
            tool_name=self.name,
            success=True,
            data={"target": target, "results": parsed},
            raw_output=stdout,
            command_used=" ".join(cmd),
        )
```

> **Note**: Tool output is automatically saved to `data/tool_outputs/` by `BaseTool.run()`. No additional code needed.

#### Step 2: Register the tool

Add import and export in `src/tools/<phase>/__init__.py`:

```python
from src.tools.scanner.my_tool import MyTool
```

Register in `src/agent/engine.py` → `_init_tools()`:

```python
self.scanner_tools["mytool"] = MyTool(timeout=self.config.agent.tool_timeout)
```

Add Pydantic input schema in `src/agent/engine.py` → schemas section:

```python
class MyToolInput(BaseModel):
    target: str = Field(description="Target URL")
    severity: str = Field(default="", description="Severity filter")
```

Register as LangChain tool in `_build_langchain_tools()`:

```python
StructuredTool.from_function(
    coroutine=self.scanner_tools["mytool"].run,
    name="mytool",
    description="What this tool does",
    args_schema=MyToolInput,
)
```

#### Step 3: Add install configuration

In `src/scanner/installer.py` → `TOOL_REGISTRY`:

```python
"mytool": ToolInfo(
    name="mytool",
    binary_name="mytool",
    install_method="go",  # go, pip, apt, or manual
    install_command="go install -v github.com/org/mytool@latest",
    description="What this tool does",
),
```

In `src/scanner/output_filter.py` → `MAX_OUTPUT_TOKENS`:

```python
"mytool": 8000,
```

For Docker, add to `Dockerfile`:

```dockerfile
RUN go install -v github.com/org/mytool/cmd/mytool@latest
```

---

### Adding a New Skill

Skills are Markdown files that teach the AI **how and when** to use tools. The agent loads all skills at startup and injects them into its vector memory.

#### Skill File Format

Create a new file in `src/skills_data/<phase>/` (e.g., `src/skills_data/scanner/my_skill.md`):

```markdown
---
name: my_skill
category: scanner
binary_name: mytool
---

# My Skill — Brief Description

## When to Use
Describe when the AI should use this tool/technique.
Be specific: "Use when target has a login form" or "ALWAYS run during scanning phase."

## How to Use
Explain the tool's CLI interface and key options.

## CLI Flags
```
INPUT:
   -target string   target URL to scan
   -list string     file containing targets

OUTPUT:
   -o string        output file
   -json            JSON output format

OPTIONS:
   -severity string   filter by severity (low,medium,high,critical)
   -threads int       concurrent threads (default 10)
```

## Example Commands
```bash
# Basic scan
mytool -target http://example.com -json

# With severity filter
mytool -target http://example.com -severity high,critical

# Multiple targets from file
mytool -list targets.txt -o results.json
```

## Output Interpretation
- Explain what the AI should look for in the output
- severity:critical → immediate action required
- severity:high → investigate and verify

## Best Practices
- Always use `-json` for parseable output
- Combine with other tools for verification
```

#### Virtual Skills (Composite Workflows)

For scan strategies that combine multiple tools without a dedicated binary:

```markdown
---
name: sensitive_files
category: scanner
binary_name: nuclei
virtual: true
---

# Sensitive File Exposure Detection

## When to Use
ALWAYS include this check during scanning phase for ALL web targets.

## How to Use
This is a **virtual skill** — uses nuclei + ffuf/gobuster with sensitive-file wordlists.

### Step 1: Run nuclei with exposure templates
### Step 2: Fuzz for sensitive paths with ffuf
### Step 3: Analyze and cross-reference findings
```

Skills are automatically loaded from `src/skills_data/` — no code changes needed. Just drop in new `.md` files and restart the agent. The AI reads them from vector memory when deciding which tools to run and how to interpret results.

---

## 📁 Project Structure

```
security_agent/
├── main.py                         # Application entry point
├── pyproject.toml                  # Dependencies, build config, pip packaging
├── .env.example                    # Configuration template
├── Dockerfile                      # Multi-stage build with all security tools
├── docker-compose.yml              # Container orchestration (Agent + ZAP + Metasploit)
├── src/
│   ├── __init__.py
│   ├── cli.py                      # CLI interface (Click + Rich)
│   ├── core/                       # Core infrastructure
│   │   ├── config.py               # Configuration management (pydantic-settings)
│   │   ├── models.py               # Data models (Pydantic)
│   │   └── database.py             # Async SQLite persistence
│   ├── agent/                      # AI orchestration
│   │   ├── engine.py               # Core AI agent orchestrator (LangChain)
│   │   ├── prompts.py              # Phase-specific AI prompts
│   │   ├── schemas.py              # Pydantic input schemas for all tools
│   │   ├── spec_parser.py          # Spec file parser (PDF/JSON/MD/YAML)
│   │   ├── llm_factory.py          # LLM provider factory
│   │   ├── memory.py               # Vector memory (TF-IDF, cosine similarity)
│   │   └── skills.py               # Skill and workflow loader
│   ├── security/                   # Safety and sandboxing
│   │   ├── safety.py               # Command validation and scope enforcement
│   │   └── sandbox.py              # Exploit code sandbox (AST-based validation)
│   ├── scanner/                    # Scanner infrastructure
│   │   ├── installer.py            # Automatic tool installer (go/pip/apt/manual)
│   │   ├── output_filter.py        # Tool output truncation and noise filtering
│   │   └── findings_parser.py      # Structured finding extraction
│   ├── reporting/                  # Report generation
│   │   ├── markdown.py             # Jinja2-based Markdown report generator
│   │   └── pdf.py                  # PDF report generator (reportlab)
│   ├── ui/                         # User interface
│   │   └── console.py              # Real-time Rich dashboard
│   ├── tools/                      # Security tool wrappers
│   │   ├── __init__.py             # BaseTool, run_command, ensure_wordlist,
│   │   │                           # save_tool_output, parse_json_lines
│   │   ├── recon/                  # Reconnaissance (9 tools)
│   │   │   ├── subfinder.py        # Subdomain discovery
│   │   │   ├── naabu.py            # Port scanning
│   │   │   ├── katana.py           # Web crawling
│   │   │   ├── httpx_tool.py       # HTTP probing (Go binary auto-detection)
│   │   │   ├── amass.py            # DNS enumeration
│   │   │   ├── dnsx.py             # DNS resolution
│   │   │   ├── theharvester.py     # OSINT gathering
│   │   │   ├── whatweb.py          # Technology fingerprinting
│   │   │   └── wafw00f.py          # WAF detection
│   │   ├── scanner/                # Scanning (12 tools)
│   │   │   ├── nuclei.py           # Template-based vuln scanner
│   │   │   ├── ffuf.py             # Web fuzzer
│   │   │   ├── gobuster.py         # Directory brute-forcing
│   │   │   ├── nikto.py            # Web server scanner
│   │   │   ├── testssl.py          # SSL/TLS auditing
│   │   │   ├── dalfox.py           # XSS scanner (reflected/stored/DOM)
│   │   │   ├── crlfuzz.py          # CRLF injection scanner
│   │   │   ├── corscanner.py       # CORS misconfiguration scanner
│   │   │   ├── secret_scanner.py   # Credential leak scanner (builtin)
│   │   │   ├── email_security.py   # SPF/DKIM/DMARC checker (builtin)
│   │   │   ├── zap.py              # OWASP ZAP (API)
│   │   │   └── acunetix.py         # Acunetix (API)
│   │   └── exploit/                # Exploitation (5 tools)
│   │       ├── sqlmap.py           # SQL injection
│   │       ├── commix.py           # Command injection
│   │       ├── searchsploit.py     # Exploit-DB search
│   │       ├── metasploit.py       # Metasploit (RPC)
│   │       └── custom_exploit.py   # AI-generated exploit engine
│   └── skills_data/                # Skill definitions (bundled with package)
│       ├── recon/                  # Recon tool guides and workflows
│       ├── scanner/                # Scanner guides and detection strategies
│       ├── exploit/                # Exploitation guides and patterns
│       └── modes/                  # Scan mode configs (quick/normal/deep)
├── reports/                        # Generated reports (auto-created)
├── data/
│   ├── security_agent.db           # SQLite database (auto-created)
│   └── tool_outputs/               # Per-tool JSON output logs (auto-created)
│       └── latest/
│           ├── subfinder_*.json
│           ├── nuclei_*.json
│           └── ...
└── ~/.secagent/wordlists/          # Auto-downloaded wordlists
    └── common.txt                  # SecLists common.txt (~4600 entries)
```

---

## ⚠️ Legal Disclaimer

> **WARNING**: This tool is intended for **authorized security testing only**.
> Only scan targets you have explicit written permission to test.
> Unauthorized scanning is illegal and may violate applicable laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation.
> Always use the `--scope` flag to restrict scanning to authorized domains.
> The authors assume no liability for misuse of this software.

## 📄 License

MIT
