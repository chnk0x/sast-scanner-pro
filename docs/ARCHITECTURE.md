# SAST-VULN-SCANNER-PRO Architecture

## 1. Design Goals

- **Modularity**: Each analysis engine and reporter is independent and swappable.
- **Extensibility**: New languages, rules, and reporters can be added without touching core logic.
- **Accuracy**: Combine regex, AST-based semantic analysis, intra-procedural taint tracking, entropy-based secret detection, and optional AI triage.
- **Actionability**: Every finding includes severity, confidence, exploitability, CWE, OWASP category, and remediation guidance.
- **CI/CD Ready**: SARIF output integrates with GitHub Code Scanning and Azure DevOps.
- **Enterprise Workflow**: Baseline suppression, incremental scanning, and trend dashboards.

## 2. Core Components

```
┌────────────────────────────────────────────────────────────┐
│                          CLI                                │
│                    (argparse + config.yaml)                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│                     SASTScanner                             │
│  - FileWalker (discover files)                              │
│  - Engine orchestration (ThreadPoolExecutor)              │
│  - Deduplication (semantic fingerprint)                     │
│  - Confidence / exploitability scoring                      │
│  - AI triage (optional)                                     │
│  - Baseline suppression                                     │
│  - Incremental hash cache                                   │
└───────────────────────────┬─────────────────────────────────┘
                            │
    ┌──────────┬───────────┼───────────┬──────────┐
    ▼          ▼           ▼           ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│ Regex  │ │Semantic│ │ Taint  │ │ Secret │ │ SCA    │
└────────┘ └────────┘ └────────┘ └────────┘ └────────┘
    ┌────────┐ ┌────────┐ ┌────────┐
    │ IaC    │ │ Custom │ │ Git    │
    └────────┘ └────────┘ └────────┘
                            │
                            ▼
               ┌────────────────────┐
               │   Finding Model    │
               │ Severity/Confidence/CVSS/CWE/Exploitability  │
               └────────────────────┘
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
      ┌────────┐      ┌────────┐      ┌────────┐
      │ HTML   │      │ JSON   │      │ SARIF  │
      └────────┘      └────────┘      └────────┘
           ┌────────┐      ┌────────┐
           │ CSV    │      │ Trend  │
           └────────┘      └────────┘
```

## 3. Engines

### Regex Engine
Multi-language regex rules for common dangerous patterns (command injection, SQL injection, XSS, weak crypto, etc.). Each rule includes negative patterns to reduce false positives.

### Semantic Engine
Python AST traversal using `ast.NodeVisitor`. Detects dangerous call sites such as `eval()`, `exec()`, `subprocess.run(..., shell=True)`, and `pickle.loads()`.

### Taint Engine
Basic intra-procedural data-flow analysis for Python. Tracks variables assigned from taint sources (`request.args`, `request.form`, `request.json`, etc.) and reports when they reach dangerous sinks (`os.system`, `subprocess`, `db.session.execute`, `pickle.loads`, `redirect`, etc.).

### Secret Engine
Pattern matching for known secret types (AWS, GitHub, Slack, JWT, Stripe) plus Shannon entropy analysis, base64/hex detection, and `.env` style unquoted secrets.

### SCA Engine
Scans `requirements.txt` and `package.json` against a built-in database of known vulnerable dependencies.

### IaC Engine
Scans Dockerfile, docker-compose, Terraform, and Kubernetes YAML for hardcoded secrets, open security groups, root containers, public databases, and missing health probes.

### Git Engine
Runs `git log -p --all` and scans diffs for leaked secrets using the same patterns as the secret engine.

### Custom Rules Engine
Loads user-defined YAML rules containing regex patterns, severity, CWE, OWASP, and remediation fields.

### AI Engine (Optional)
Connects to a local Ollama-compatible API to classify findings as true or false positives. Requires `ai.enabled: true` or `--ai` flag.

## 4. Reporters

- **HTML**: Professional dashboard with severity cards and sortable findings table.
- **JSON**: Machine-readable report with full metadata and finding list.
- **SARIF**: OASIS SARIF v2.1.0 for GitHub/Azure security dashboards.
- **CSV**: Spreadsheet-friendly import for tracking and risk registers.
- **Trend**: Appends scan metadata to a JSON history file and renders a Chart.js trend dashboard.

## 5. Enterprise Features

### Baseline / Suppression
A JSON baseline file stores fingerprints of accepted findings. Subsequent scans suppress these findings.

### Incremental Scanning
A file hash cache tracks changes between scans. Only modified files are rescanned, improving performance.

### Report Comparison
`compare_reports.py` compares two JSON reports and lists new and resolved findings.

### Trend Dashboard
The `trend` reporter maintains historical scan counts and renders an HTML dashboard for trend analysis.

## 6. Extending the Scanner

### Add a new regex rule
Edit `sast_scanner/engines/regex_engine.py` and append a `Rule` to the `RULES` list, or add a YAML rule under `rules/`.

### Add a new engine
1. Create a class inheriting from `BaseEngine`.
2. Implement `analyze(file_path, content, lines) -> List[Finding]`.
3. Register it in `SASTScanner.ENGINE_MAP` in `scanner.py`.

### Add a new reporter
1. Create a class inheriting from `BaseReporter`.
2. Implement `generate(findings, target, metadata)`.
3. Register it in `SASTScanner.REPORTERS` in `scanner.py`.

## 7. Senior-Level Rationale

- **Defense in depth**: Multiple engines reduce both false positives and false negatives.
- **Standards alignment**: CWE and OWASP mapping demonstrate compliance awareness.
- **Risk quantification**: CVSS scores and exploitability metrics support prioritization.
- **Automation**: SARIF, CI/CD workflow, and trend analysis enable continuous security monitoring.
- **Maintainability**: Clean separation of concerns, data classes, and plugin architecture.
