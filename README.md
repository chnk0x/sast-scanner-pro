<img width="868" height="473" alt="Screenshot 01" src="https://github.com/user-attachments/assets/ce5178c1-e839-46e3-b402-5cc112544f9e" />
<div align="center">

<!-- Animated Header Banner -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,50:1e3a5f,100:0ea5e9&height=200&section=header&text=SAST%20SCANNER%20PRO&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=Next-Generation%20AI-Augmented%20Static%20Security%20Testing&descAlignY=58&descSize=16&animation=fadeIn"/>
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f172a,50:1e3a5f,100:0ea5e9&height=200&section=header&text=SAST%20SCANNER%20PRO&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=Next-Generation%20AI-Augmented%20Static%20Security%20Testing&descAlignY=58&descSize=16&animation=fadeIn" alt="SAST Scanner Pro" />
</picture>

<br/>

<!-- Status Badges -->
<p>
  <img src="https://img.shields.io/badge/version-2.0.0-0ea5e9?style=for-the-badge&logo=semver&logoColor=white" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12-3b82f6?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"/>
  <img src="https://img.shields.io/badge/OWASP%20Top%2010-2021-ef4444?style=for-the-badge" alt="OWASP"/>
  <img src="https://img.shields.io/badge/SARIF-v2.1.0-8b5cf6?style=for-the-badge" alt="SARIF"/>
  <img src="https://img.shields.io/badge/CI%2FCD-Ready-22c55e?style=for-the-badge&logo=githubactions&logoColor=white" alt="CI/CD"/>
</p>

<br/>

<!-- Animated typing headline -->
<a href="#">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=20&duration=3000&pause=800&color=0EA5E9&center=true&vCenter=true&multiline=true&width=700&height=80&lines=8+Analysis+Engines+%7C+AI-Augmented+Triage;OWASP+Top+10+%2B+CWE+Mapping+%7C+CVSS+Scoring;HTML+%7C+JSON+%7C+SARIF+%7C+CSV+%7C+Trend+Reports" alt="Typing SVG" />
</a>

<br/><br/>

</div>

---

## ⚡ What Is This?

**SAST Scanner Pro** is AI-augmented **Static Application Security Testing (SAST)** engine written in Python. It goes far beyond simple regex scanning — combining **AST semantic analysis**, **intra-procedural taint tracking**, **Shannon entropy secret detection**, **Software Composition Analysis (SCA)**, **Infrastructure-as-Code (IaC) scanning**, and an optional **AI triage layer** via Ollama — all orchestrated through a clean plugin architecture with 5 output formats.

> Built as a capstone-grade security project. Detected **69 real vulnerabilities** across 25 files in its own test target on its first run.

<br/>

---

## 📸 Screenshots

<br/>
![Uploading Screenshot 01.jpg…]()

### 🖥️ Terminal Scan Output
> Scanning the bundled vulnerable test app (`vulnerable_app/`) across all 7 engines and 4 report formats. 25 files discovered, **69 findings** verified after triage — output to HTML, JSON, and CSV in under a second.

![Terminal scan output showing 25 files discovered, 69 findings verified](screenshots/Screenshot_01.jpg)

<br/>

### 📊 HTML Security Audit Dashboard
> The auto-generated `sast_report.html` — a professional security audit dashboard with severity breakdown cards (25 Critical · 33 High · 10 Medium · 1 Low), a sortable findings table with CWE IDs, OWASP categories, inline code snippets, and per-finding remediation guidance.

![SAST HTML Security Audit Report dashboard showing 69 findings](screenshots/Screenshot_3.jpg)

<br/>

### 🔍 Finding Detail: Taint, Deserialization & Secrets
> Sample findings from the report — a **taint-based insecure deserialization** (`pickle.loads(base64.b64decode(data))`) traced from user-controlled input, an **open redirect** via taint flow, and a **hardcoded admin password** (`ADMIN_PASSWORD = "admin123"`) with its full CVSS 7.5 vector and remediation steps.

![Finding detail showing taint-based insecure deserialization, open redirect, and hardcoded secret](screenshots/Screenshot_5.jpg)

<br/>

---

## 🆕 Feature

| Feature 

🧠 Analysis approach: Regex + AST analysis + taint/data-flow tracking + entropy-based secret detection + AI-assisted triage
📦 Dependency scanning (SCA): Scans requirements.txt and package.json for vulnerable dependencies
☁️ Infrastructure-as-Code scanning: Supports Dockerfile, Terraform, Kubernetes manifests, and Docker Compose files
🕵️ Git history scanning: Detects secrets and sensitive data in commit history and diffs
⚙️ Custom rule engine: YAML-based plugin system for defining custom vulnerability rules
🌐 Multi-language support: Python, JavaScript/TypeScript, Java, Go, PHP, Ruby, C/C++, C#, Terraform, HCL
📊 Output formats: HTML, JSON, SARIF v2.1.0, CSV, Trend dashboard
⚠️ Severity model: CVSS 3.1 scoring with exploitability and confidence ratings
📚 Security standards mapping: OWASP Top 10 2021 + CWE classification
🏗️ Architecture: Modular plugin-based engine system (scanners + reporters)
🔍 Taint analysis: Intra-procedural data-flow tracking for Python applications
🧾 Baseline suppression: JSON fingerprinting to ignore known/accepted findings
⚡ Incremental scanning: File-hash based scanning of only modified files
📈 Trend analysis: Historical vulnerability trends using Chart.js dashboard
🔁 CI/CD integration: SARIF output + GitHub Actions workflow support
🚀 Parallel scanning: Multi-threaded execution using ThreadPoolExecutor
🤖 AI triage: Optional local LLM (Ollama) for reducing false positives
🧪 Test environment: Includes vulnerable Flask application (SecureVault) for testing

<br/>

---

## 🛠️ Installation

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd sast_scanner_pro

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install as a CLI tool
pip install -e .
```

**Requirements:** Python ≥ 3.9 · PyYAML ≥ 6.0 · `openai` ≥ 1.0.0 (for AI triage)

<br/>

---

## 📦 Usage

### Basic Scan — Recommended Full Suite

```bash
python3 -m sast_scanner vulnerable_app \
  --engines regex semantic secret taint sca iac custom \
  --formats html json csv \
  --output sast_reports
```

### Scan Any Directory

```bash
python3 -m sast_scanner /path/to/your/project \
  --engines regex semantic secret taint sca iac \
  --formats html json sarif \
  --output my_reports
```

### All 5 Report Formats + Trend Dashboard

```bash
python3 -m sast_scanner /path/to/code \
  --formats html json sarif csv trend \
  --output reports
```

### AI-Augmented Triage (Requires Local Ollama)

```bash
# Step 1 – Start the Ollama model
ollama run qwen2.5:1.5b

# Step 2 – Run scan with AI triage enabled
python3 -m sast_scanner /path/to/code \
  --ai \
  --ai-model qwen2.5:1.5b
```

### Baseline Workflow (Suppress Known Findings)

```bash
# Create a baseline from current run
python3 -m sast_scanner /path/to/code --create-baseline baseline.json

# Suppress baseline findings in future runs
python3 -m sast_scanner /path/to/code --baseline baseline.json
```

### Incremental Scan (Only Changed Files)

```bash
python3 -m sast_scanner /path/to/code --incremental
```

### Compare Two Report Runs

```bash
python3 compare_reports.py sast_reports/run_1.json sast_reports/run_2.json
```

### Full CLI Reference

```
usage: sast-scanner-pro [-h] [-e ENGINE [ENGINE ...]] [-f FORMAT [FORMAT ...]]
                        [-o OUTPUT] [-c CONFIG] [-w WORKERS] [-v]
                        [--ai] [--ai-model MODEL] [--ai-url URL]
                        [--baseline FILE] [--create-baseline FILE]
                        [--incremental] [--custom-rules DIR]
                        [--git-history]
                        target

positional arguments:
  target                File or directory to scan

options:
  -e, --engines         Engines: regex semantic secret taint sca iac custom
  -f, --formats         Formats: html json sarif csv trend
  -o, --output          Output directory (default: sast_reports)
  -c, --config          Path to config.yaml
  -w, --workers         Parallel workers (default: 4)
  -v, --verbose         Verbose logging
  --ai                  Enable AI triage via Ollama
  --ai-model            Ollama model (default: qwen2.5:1.5b)
  --baseline            Suppress findings in baseline JSON
  --create-baseline     Save current findings as baseline
  --incremental         Scan only changed files
  --custom-rules        Directory of custom YAML rules
  --git-history         Scan git commit history for secrets
```

<br/>

---

## ⚙️ Configuration (`config.yaml`)

```yaml
# Maximum file size to scan (5 MB)
max_file_size: 5242880

# Parallel scan workers
workers: 4

# Per-engine settings
engines:
  regex:
    enabled: true
  semantic:
    enabled: true
  secret:
    enabled: true
    entropy_threshold: 4.5     # Shannon entropy threshold
    entropy_min_len: 20        # Minimum string length for entropy check
  taint:
    enabled: true
  sca:
    enabled: true
  iac:
    enabled: true
  custom:
    enabled: true
    rules_dir: rules           # Path to custom YAML rules

# AI triage (requires local Ollama)
ai:
  enabled: false
  model: qwen2.5:1.5b
  base_url: http://localhost:11434/v1
  api_key: ollama

# Report output
report:
  formats: [html, json, sarif]
  output_dir: sast_reports

# Baseline suppression
baseline:
  # path: baseline.json

# Incremental scanning
incremental:
  enabled: false
  cache: .sast_cache.json
```

<br/>

---

## 🔍 Analysis Engines (8 Total)

<table>
<thead>
<tr>
<th>Engine</th>
<th>Flag</th>
<th>What It Does</th>
<th>Languages</th>
</tr>
</thead>
<tbody>
<tr>
<td><strong>Regex</strong></td>
<td><code>regex</code></td>
<td>Multi-pattern rules for common dangerous constructs — command injection, SQLi, XSS, weak crypto, CORS misconfig, debug flags, SSRF, deserialization, path traversal</td>
<td>All</td>
</tr>
<tr>
<td><strong>Semantic (AST)</strong></td>
<td><code>semantic</code></td>
<td>Python AST traversal via <code>ast.NodeVisitor</code>. Detects dangerous call sites: <code>eval()</code>, <code>exec()</code>, <code>subprocess.run(shell=True)</code>, <code>pickle.loads()</code></td>
<td>Python</td>
</tr>
<tr>
<td><strong>Taint / Data-flow</strong></td>
<td><code>taint</code></td>
<td>Intra-procedural data-flow analysis. Tracks taint from user-controlled <strong>sources</strong> (<code>request.args</code>, <code>request.form</code>, <code>sys.argv</code>) to dangerous <strong>sinks</strong> (<code>os.system</code>, <code>cursor.execute</code>, <code>pickle.loads</code>, <code>redirect</code>) through variable propagation</td>
<td>Python</td>
</tr>
<tr>
<td><strong>Secret Detection</strong></td>
<td><code>secret</code></td>
<td>Combines regex patterns for known secret types (AWS, GitHub, Slack, Stripe, Google, JWT, Bearer, private keys) + <strong>Shannon entropy analysis</strong> + base64/hex detection + unquoted <code>.env</code> secret detection</td>
<td>All</td>
</tr>
<tr>
<td><strong>SCA</strong></td>
<td><code>sca</code></td>
<td>Software Composition Analysis — scans <code>requirements.txt</code> and <code>package.json</code> against a built-in database of known-vulnerable dependency versions</td>
<td>Python · Node</td>
</tr>
<tr>
<td><strong>IaC</strong></td>
<td><code>iac</code></td>
<td>Infrastructure-as-Code scanning for hardcoded secrets, overly permissive security groups (0.0.0.0/0), root/privileged containers, publicly accessible databases, LoadBalancer exposure</td>
<td>Dockerfile · Terraform · Kubernetes YAML · docker-compose</td>
</tr>
<tr>
<td><strong>Custom Rules</strong></td>
<td><code>custom</code></td>
<td>YAML-defined rules with regex patterns, severity, CWE, OWASP, and remediation fields. Ships with <code>securevault.yaml</code> covering Flask debug mode, insecure JWT algorithms, insecure session cookie settings</td>
<td>Any</td>
</tr>
<tr>
<td><strong>Git History</strong></td>
<td><code>--git-history</code></td>
<td>Runs <code>git log -p --all</code> and scans commit diffs for leaked secrets using the same patterns as the Secret engine. Catches credentials committed and later deleted</td>
<td>Any (git repo)</td>
</tr>
</tbody>
</table>

> **AI Engine (optional)** — Connects to a local Ollama-compatible endpoint to classify findings as true or false positives, reducing noise on large codebases. Enable with `--ai`.

<br/>

---

## 🛡️ Vulnerability Categories Detected

| Rule ID | Category | CWE | OWASP 2021 | CVSS |
|---|---|---|---|---|
| `SAST-001` | Hardcoded Secret / API Key | CWE-798 | A07 – Auth Failures | 7.5 |
| `SAST-002` | Command Injection Vector | CWE-78 | A03 – Injection | 9.8 |
| `SAST-003` | SQL Injection Vector | CWE-89 | A03 – Injection | 9.8 |
| `SAST-004` | XSS Sink | CWE-79 | A03 – Injection | 6.1 |
| `SAST-005` | Path Traversal | CWE-22 | A01 – Broken Access Control | 7.5 |
| `SAST-006` | Weak Cryptography (MD5/SHA1) | CWE-327 | A02 – Crypto Failures | 5.9 |
| `SAST-007` | Insecure CORS / SSL Bypass | CWE-942 | A05 – Security Misconfiguration | 7.5 |
| `SAST-008` | Insecure Deserialization | CWE-502 | A08 – Data Integrity Failures | 9.8 |
| `SAST-009` | SSRF | CWE-918 | A10 – SSRF | 8.6 |
| `SAST-010` | Debug Mode / Info Leak | CWE-489 | A05 – Security Misconfiguration | 5.3 |
| `TAINT-001` | Taint-based Data-flow Injection | CWE-78/89/94/918 | A03 – Injection | — |
| `SEC-001` | Pattern / Entropy Secret | CWE-798 | A07 – Auth Failures | — |
| `SCA-001` | Vulnerable Dependency | CWE-1104 | A06 – Vulnerable Components | — |
| `IAC-001` | Hardcoded Secret in IaC | CWE-798 | A07 – Auth Failures | — |
| `IAC-002` | Open Security Group (0.0.0.0/0) | CWE-284 | A01 – Broken Access Control | — |
| `IAC-003` | Root / Privileged Container | CWE-250 | A04 – Insecure Design | — |
| `IAC-004` | Public Database / Storage | CWE-306 | A05 – Security Misconfiguration | — |
| `IAC-005` | LoadBalancer Internet Exposure | — | A01 – Broken Access Control | — |
| `CUSTOM-001` | Flask Debug / Open Host | CWE-489 | A05 – Security Misconfiguration | — |
| `CUSTOM-002` | Insecure JWT Algorithm | CWE-347 | A07 – Auth Failures | — |
| `CUSTOM-003` | Insecure Session Cookie | — | A07 – Auth Failures | — |
| `CUSTOM-*` | User-defined rules | — | — | — |

<br/>

---

## 📊 Report Formats

| Format | File | Purpose |
|---|---|---|
| **HTML** | `sast_report.html` | Interactive audit dashboard — severity cards, sortable table, code snippets, CWE/OWASP badges, remediation guidance |
| **JSON** | `sast_report.json` | Machine-readable full report with all metadata, suitable for automation and tooling |
| **SARIF v2.1.0** | `sast_report.sarif` | OASIS SARIF standard — integrates with GitHub Code Scanning, Azure DevOps, VS Code |
| **CSV** | `sast_report.csv` | Spreadsheet-friendly for risk registers, tracking, and stakeholder reporting |
| **Trend** | `trend_dashboard.html` | Chart.js historical trend dashboard — tracks finding counts across scan runs over time |

<br/>

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    CLI  (argparse + config.yaml)               │
└───────────────────────────────┬────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────┐
│                       SASTScanner                              │
│  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │   FileWalker    │  │  ThreadPoolExec  │  │ Deduplication│  │
│  │ (discover files)│  │  (parallel scan) │  │ (fingerprint)│  │
│  └─────────────────┘  └──────────────────┘  └──────────────┘  │
│  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ CVSS / Exploit  │  │  AI Triage       │  │  Baseline /  │  │
│  │ Scoring         │  │  (optional)      │  │  Incremental │  │
│  └─────────────────┘  └──────────────────┘  └──────────────┘  │
└────────┬───────┬──────────┬──────────┬──────────┬─────────────┘
         │       │          │          │          │
   ┌─────▼──┐ ┌──▼───┐ ┌───▼──┐ ┌────▼──┐ ┌────▼──┐
   │ Regex  │ │ AST  │ │Taint │ │Secret │ │  SCA  │
   │Engine  │ │Seman.│ │Engine│ │Engine │ │Engine │
   └────────┘ └──────┘ └──────┘ └───────┘ └───────┘
   ┌─────────┐ ┌──────────┐ ┌──────────┐
   │   IaC   │ │  Custom  │ │   Git    │
   │  Engine │ │  Rules   │ │  Engine  │
   └─────────┘ └──────────┘ └──────────┘
                                │
                                ▼
                    ┌───────────────────┐
                    │   Finding Model   │
                    │ severity · cvss   │
                    │ confidence · cwe  │
                    │ owasp · remediate │
                    └────────┬──────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
     ┌────────┐        ┌──────────┐       ┌──────────┐
     │  HTML  │        │   JSON   │       │  SARIF   │
     └────────┘        └──────────┘       └──────────┘
          ┌────────┐        ┌──────────┐
          │  CSV   │        │  Trend   │
          └────────┘        └──────────┘
```

<br/>

---

## 📁 Project Structure

```
sast_scanner_pro/
│
├── sast_scanner/                    # Core scanner package
│   ├── engines/                     # Analysis engines (plugin-style)
│   │   ├── regex_engine.py          # Multi-language regex rules
│   │   ├── semantic_engine.py       # Python AST traversal
│   │   ├── taint_engine.py          # Intra-procedural data-flow
│   │   ├── secret_engine.py         # Entropy + pattern secret detection
│   │   ├── sca_engine.py            # Dependency vulnerability scanning
│   │   ├── iac_engine.py            # IaC misconfiguration detection
│   │   ├── git_engine.py            # Git history secret scanning
│   │   ├── custom_rules_engine.py   # YAML-driven custom rules
│   │   ├── ai_engine.py             # Ollama AI triage integration
│   │   └── base_engine.py           # Abstract engine interface
│   │
│   ├── models/                      # Data models
│   │   ├── finding.py               # Finding dataclass (severity, cvss, etc.)
│   │   └── rule.py                  # Rule dataclass
│   │
│   ├── reporters/                   # Output reporters (plugin-style)
│   │   ├── html_reporter.py         # Interactive HTML dashboard
│   │   ├── json_reporter.py         # Machine-readable JSON
│   │   ├── sarif_reporter.py        # OASIS SARIF v2.1.0
│   │   ├── csv_reporter.py          # Spreadsheet CSV
│   │   ├── trend_reporter.py        # Chart.js trend dashboard
│   │   └── base_reporter.py         # Abstract reporter interface
│   │
│   ├── utils/
│   │   ├── file_utils.py            # File walker, content reader
│   │   ├── suppression.py           # Baseline / fingerprint manager
│   │   ├── incremental.py           # File hash cache tracker
│   │   └── logger.py                # Logging setup
│   │
│   ├── scanner.py                   # Main orchestrator
│   └── cli.py                       # CLI entry point (argparse)
│
├── rules/
│   └── securevault.yaml             # Custom YAML rules (Flask, JWT, cookies)
│
├── vulnerable_app/ (Test_sample)    # Realistic test target — SecureVault
│   ├── app.py                       # Flask entry point
│   ├── routes/                      # auth.py · api.py · admin.py · files.py
│   ├── models.py                    # SQLAlchemy models
│   ├── config.py                    # Intentionally vulnerable configuration
│   ├── templates/                   # Jinja2 HTML templates
│   ├── terraform/main.tf            # Vulnerable IaC (Terraform)
│   ├── k8s/deployment.yaml          # Vulnerable Kubernetes manifest
│   ├── Dockerfile                   # Vulnerable container config
│   ├── docker-compose.yml
│   └── .env                         # Hardcoded secrets
│
├── sast_reports/                    # Generated reports (git-ignored)
│   ├── sast_report.html
│   ├── sast_report.json
│   ├── sast_report.sarif
│   ├── sast_report.csv
│   └── trend_dashboard.html
│
├── tests/
│   ├── samples/
│   │   ├── vulnerable.py
│   │   └── vulnerable.js
│   └── test_scanner.py
│
├── docs/
│   └── ARCHITECTURE.md
│
├── .github/workflows/ci.yml        # GitHub Actions — test matrix + SARIF upload
├── compare_reports.py              # CLI diff tool for two JSON reports
├── config.yaml                     # Main configuration
├── requirements.txt
├── pyproject.toml
├── Makefile
└── README.md
```

<br/>

---

## 🧪 Vulnerable Test Application — SecureVault

The `vulnerable_app/` directory contains **SecureVault**, a deliberately insecure Flask file-storage and user management app built to showcase every scanner feature. It contains intentional flaws including:

- **Injection:** SQL Injection, Command Injection, XSS, SSTI
- **Data Flow:** Insecure Deserialization (`pickle.loads`), SSRF, Open Redirect
- **Cryptography:** MD5 password hashing, hardcoded JWT and admin secrets
- **Access Control:** IDOR, Broken Object-Level Authorization, insecure file upload
- **Config:** Debug mode enabled, verbose error disclosure
- **IaC:** Insecure Dockerfile (runs as root), open Terraform security group (0.0.0.0/0), privileged Kubernetes container, public S3 bucket in Terraform

Run the scanner against it to reproduce the **69-finding** report shown in the screenshots above.

```bash
python3 -m sast_scanner "vulnerable_app (Test_sample)" \
  --engines regex semantic secret taint sca iac custom \
  --formats html json csv \
  --output sast_reports
```

<br/>

---

## 🧪 Running Tests

```bash
# Run the full test suite
python3 -m pytest tests/ -v

# Run scanner against sample files only
python3 -m sast_scanner tests/samples/vulnerable.py --formats sarif json
```

<br/>

---

## 🔌 Extending the Scanner

### Add a New Regex Rule
Append a `Rule(...)` object to the `RULES` list in `sast_scanner/engines/regex_engine.py`, or drop a `.yaml` file in the `rules/` directory:

```yaml
rules:
  - id: CUSTOM-100
    name: My Custom Rule
    description: Detects a dangerous pattern.
    severity: HIGH
    confidence: HIGH
    languages: [python]
    patterns:
      - "dangerous_function\\("
    remediation: Use the safe alternative instead.
    cwe_id: CWE-XXX
    owasp_category: "A03:2021 – Injection"
    tags: [custom]
```

### Add a New Engine
```python
from sast_scanner.engines.base_engine import BaseEngine

class MyEngine(BaseEngine):
    name = "myengine"
    def analyze(self, file_path, content, lines):
        # return List[Finding]
        return []

# Register in scanner.py:
# ENGINE_MAP["myengine"] = MyEngine
```

### Add a New Reporter
```python
from sast_scanner.reporters.base_reporter import BaseReporter

class MyReporter(BaseReporter):
    def generate(self, findings, target, metadata):
        # write your output file
        pass

# Register in scanner.py:
# REPORTERS["myformat"] = MyReporter
```

<br/>

---

## 🔄 CI/CD Integration

The included `.github/workflows/ci.yml` tests on Python 3.9 → 3.12, runs the scanner against sample files, and uploads SARIF results as build artifacts. The SARIF output is compatible with **GitHub Code Scanning**, **Azure DevOps Security**, and **VS Code SARIF Viewer**.

```yaml
# From .github/workflows/ci.yml
- name: Run scanner on sample
  run: python -m sast_scanner tests/samples/vulnerable.py --formats sarif json

- name: Upload SARIF report
  uses: actions/upload-artifact@v4
  with:
    name: sast-report-${{ matrix.python-version }}
    path: sast_reports/
```

<br/>

---

## 🏛️ Design Rationale

| Principle | Implementation |
|---|---|
| **Defense in depth** | 8 engines working together reduce both false positives and false negatives |
| **Standards alignment** | OWASP Top 10 2021 and CWE mapping demonstrate security compliance awareness |
| **Risk quantification** | CVSS 3.1 scores, vectors, and exploitability metrics enable finding prioritization |
| **Continuous security** | SARIF output, CI/CD workflow, and trend dashboard enable DevSecOps integration |
| **Maintainability** | Clean separation of concerns — data classes, abstract base classes, plugin-style registration |
| **Extensibility** | New engines and reporters can be added by implementing a 2-method interface |

<br/>

---

## 📜 License & Disclaimer

```
MIT License — For educational use and authorized security testing only.
```

> **⚠️ Important:** This scanner is designed for educational purposes and authorized penetration testing. Always obtain explicit written permission before scanning code or infrastructure that you do not own or have authority over. Unauthorized scanning may be illegal in your jurisdiction.

<br/>

---

<div align="center">

<!-- Footer wave -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0ea5e9,100:0f172a&height=100&section=footer" alt="footer" />

<p>
  <sub>Made by @chnk0x 🛡️ cybersec capstone project · Python 3.9+ · OWASP Top 10 · SARIF v2.1.0</sub>
</p>

</div>
