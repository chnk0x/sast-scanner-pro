# SecureVault (Vulnerable App for SAST Testing)

A realistic Flask-based file storage and user management application intentionally built with security flaws for authorized testing and educational use.

## ⚠️ Warning
This application is **intentionally vulnerable**. Do not deploy in production or on public networks. Use only in isolated, authorized environments.

## 🚀 Quick Start

```bash
cd vulnerable_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Visit `http://localhost:5000`.

## 🐳 Docker

```bash
docker-compose up --build
```

## 🐞 Vulnerabilities Included

| Category | Location | CWE |
|---|---|---|
| SQL Injection | `routes/auth.py`, `routes/api.py`, `app.py` | CWE-89 |
| Command Injection | `app.py:/ping`, `routes/api.py:/exec` | CWE-78 |
| XSS | `templates/profile.html`, `app.py:/profile` | CWE-79 |
| Path Traversal | `routes/files.py:/download` | CWE-22 |
| Insecure Deserialization | `app.py:/deserialize` | CWE-502 |
| SSRF | `app.py:/fetch` | CWE-918 |
| Weak Cryptography | `config.py`, `routes/auth.py` (MD5) | CWE-327 |
| Hardcoded Secrets | `config.py`, `Dockerfile`, `docker-compose.yml`, `k8s/` | CWE-798 |
| IDOR / Broken Access Control | `routes/admin.py`, `routes/files.py`, `routes/api.py` | CWE-284 |
| Open Redirect | `app.py:/redirect` | CWE-601 |
| Insecure File Upload | `routes/files.py:/upload` | CWE-434 |
| Info Disclosure | `app.py:/health`, `routes/admin.py:/config` | CWE-209 |
| Debug Mode Enabled | `config.py`, `app.py` | CWE-489 |
| Insecure IaC | `terraform/main.tf`, `k8s/deployment.yaml` | CWE-942 |

## 🧪 Testing with the Scanner

```bash
cd ..
python3 -m sast_scanner vulnerable_app --formats html json sarif csv
```
