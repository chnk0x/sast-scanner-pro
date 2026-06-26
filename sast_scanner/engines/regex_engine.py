"""Regex-based SAST engine."""
import re
from pathlib import Path
from typing import List

from .base_engine import BaseEngine
from ..models import Finding, Rule, Severity, Confidence


# CVSS vectors are approximate for demonstration
RULES = [
    Rule(
        id="SAST-001",
        name="Hardcoded Secret / API Key",
        description="Detected a potential hardcoded secret, password, token, or API key in source code.",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        engine="regex",
        languages=["python", "javascript", "typescript", "java", "go", "php", "ruby", "c", "cpp", "csharp", "yaml", "json"],
        patterns=[
            r"(?i)(password|passwd|secret|api_key|apikey|auth_token|jwt_secret|private_key|aws_secret|aws_access_key|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-+=/@]{8,}['\"]",
        ],
        negative_patterns=[
            r"example", r"sample", r"placeholder", r"your_", r"<", r">", r"example\.com", r"password\s*=[\s'\"]*\*+",
        ],
        cwe_id="CWE-798",
        owasp_category="A07:2021 – Identification and Authentication Failures",
        remediation="Store secrets in environment variables, a dedicated vault (e.g., HashiCorp Vault, AWS Secrets Manager), or encrypted configuration files. Never commit secrets to source control.",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        tags=["secret", "credential", "hardcoded"],
    ),
    Rule(
        id="SAST-002",
        name="Command Injection Vector",
        description="Use of dangerous function that may execute arbitrary shell commands with user-controlled input.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        engine="regex",
        languages=["python", "javascript", "typescript", "java", "php", "ruby", "go", "c", "cpp"],
        patterns=[
            r"(?:\bos\.system\(|\bsubprocess\.(?:call|Popen|run)\(|\bexec\(|\beval\(|\binput\(|shell=True|\bchild_process\.(?:exec|execSync)\(|\bpopen\(|\bsystem\(|\bpassthru\(|\bproc_open\(|\bRuntime\.getRuntime\(\)\.exec)",
        ],
        cwe_id="CWE-78",
        owasp_category="A03:2021 – Injection",
        remediation="Avoid shell execution. Use parameterized APIs, allow-lists, and input validation. If unavoidable, use exec with an array of arguments rather than string concatenation.",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        tags=["injection", "command", "rce"],
    ),
    Rule(
        id="SAST-003",
        name="SQL Injection Vector",
        description="Possible SQL injection via string concatenation or raw query execution.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        engine="regex",
        languages=["python", "javascript", "typescript", "java", "php", "ruby", "go", "csharp"],
        patterns=[
            r"(?:\.execute\s*\(\s*['\"].*%\s*\+|SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*['\"]\s*[\+\{]|\.raw\(|query\s*\(\s*['\"].*\$|cursor\.execute\(.*[\+\{]|\.query\(\s*[`\"'].*\$\{|\.execute\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)|session\.execute\s*\(\s*[a-zA-Z_])",
        ],
        cwe_id="CWE-89",
        owasp_category="A03:2021 – Injection",
        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings. Employ ORM query builders with bound parameters.",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        tags=["injection", "sql", "database"],
    ),
    Rule(
        id="SAST-004",
        name="Cross-Site Scripting (XSS) Sink",
        description="Untrusted data may be rendered into the DOM or page without sanitization.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        engine="regex",
        languages=["javascript", "typescript", "php", "html", "python"],
        patterns=[
            r"(?:innerHTML\s*=|outerHTML\s*=|document\.write\(|dangerouslySetInnerHTML|echo\s+\$_(GET|POST|REQUEST|COOKIE)|\.html\(|render_template_string|mark_safe\(|res\.send\s*\(.*\+|res\.send\s*\(.*req\.query|\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\|\s*safe\s*\}\})",
        ],
        cwe_id="CWE-79",
        owasp_category="A03:2021 – Injection",
        remediation="Encode output context-appropriately (HTML, JavaScript, URL, CSS). Use safe frameworks that auto-escape. Sanitize HTML with DOMPurify or equivalent.",
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        tags=["xss", "injection", "html"],
    ),
    Rule(
        id="SAST-005",
        name="Path Traversal / Unsafe File Access",
        description="User-controlled path may allow traversal outside the intended directory.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        engine="regex",
        languages=["python", "javascript", "typescript", "java", "php", "go", "ruby", "c", "cpp"],
        patterns=[
            r"(?:\.\./\.\.|send_file\(|fs\.readFile\(.*req\.|cat\s+/etc/passwd|open\(.*\+|read\(.*\+|FileInputStream\s*\(\s*.*\+\s*)",
        ],
        cwe_id="CWE-22",
        owasp_category="A01:2021 – Broken Access Control",
        remediation="Validate and canonicalize paths. Use allow-lists, chroot/jails, or sandboxed APIs. Reject path traversal sequences and restrict file access to intended directories.",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        tags=["path", "traversal", "lfi"],
    ),
    Rule(
        id="SAST-006",
        name="Weak Cryptographic Algorithm",
        description="Use of deprecated or weak cryptographic hash/algorithm (MD5, SHA1, DES, ECB mode).",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        engine="regex",
        languages=["*"],
        patterns=[
            r"(?i)(md5\(|sha1\(|crypto\.createHash\(['\"]md5['\"]|MD5_Init|DES_ecb_encrypt|ECB|TripleDES|\.Create\(['\"]MD5['\"]|\.Create\(['\"]SHA1['\"])",
        ],
        cwe_id="CWE-327",
        owasp_category="A02:2021 – Cryptographic Failures",
        remediation="Use modern algorithms (SHA-256/SHA-3, AES-GCM, Argon2id/bcrypt/scrypt for passwords). Avoid MD5 and SHA1 for any security purpose.",
        cvss_score=7.4,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        tags=["crypto", "weak-hash", "md5"],
    ),
    Rule(
        id="SAST-007",
        name="Insecure CORS / Network Binding",
        description="Overly permissive CORS or binding to all network interfaces.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        engine="regex",
        languages=["javascript", "typescript", "python", "java", "go", "yaml"],
        patterns=[
            r"(?:allowAllOrigins|cors\s*:\s*.*['\"]\*['\"]|0\.0\.0\.0|verify_ssl\s*=\s*False|verify\s*=\s*False|InsecureSkipVerify|ssl_verify\s*=\s*False)",
        ],
        cwe_id="CWE-942",
        owasp_category="A05:2021 – Security Misconfiguration",
        remediation="Restrict CORS origins to trusted domains. Bind to localhost or specific interfaces in production. Always verify TLS certificates.",
        cvss_score=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        tags=["cors", "ssl", "misconfiguration"],
    ),
    Rule(
        id="SAST-008",
        name="Insecure Deserialization",
        description="Use of unsafe deserialization or pickle/unsafe marshal operations.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        engine="regex",
        languages=["python", "javascript", "java", "php", "ruby"],
        patterns=[
            r"(?:pickle\.loads|yaml\.load\(|yaml\.unsafe_load|ObjectInputStream|readObject\(|unserialize\(|JSON\.parse\(.*eval|marshal\.loads)",
        ],
        cwe_id="CWE-502",
        owasp_category="A08:2021 – Software and Data Integrity Failures",
        remediation="Use safe serialization formats (JSON). For Python, use yaml.safe_load. Never deserialize untrusted data with pickle or Java ObjectInputStream.",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        tags=["deserialization", "pickle", "rce"],
    ),
    Rule(
        id="SAST-009",
        name="SSRF / Unsafe URL Fetch",
        description="Network request may be manipulated to access internal services.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        engine="regex",
        languages=["python", "javascript", "typescript", "java", "go", "php", "ruby"],
        patterns=[
            r"(?:requests\.(get|post|put|delete)\s*\(.*\+|urllib\.request\.urlopen\(.*\+|fetch\s*\(\s*.*\+|http\.Get\s*\(\s*.*\+|curl_exec\s*\(.*\$)",
        ],
        cwe_id="CWE-918",
        owasp_category="A10:2021 – Server-Side Request Forgery (SSRF)",
        remediation="Validate and sanitize URLs. Use allow-lists, block internal/reserved IP ranges, and disable redirects or follow them with validation.",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        tags=["ssrf", "network", "url"],
    ),
    Rule(
        id="SAST-010",
        name="Dangerous Debug / Development Mode",
        description="Debug mode or verbose error messages may leak sensitive information in production.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        engine="regex",
        languages=["python", "javascript", "typescript", "java", "go", "php", "ruby"],
        patterns=[
            r"(?:debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True|app\.use\(errorhandler\(|app\.use\(morgan\(|flask\.run\(.*debug)",
        ],
        cwe_id="CWE-489",
        owasp_category="A05:2021 – Security Misconfiguration",
        remediation="Disable debug mode and stack traces in production. Use a centralized logging system and generic error pages.",
        cvss_score=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        tags=["debug", "misconfiguration", "info-disclosure"],
    ),
]


class RegexEngine(BaseEngine):
    """Multi-language regex-based SAST engine."""

    name = "regex"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.rules = RULES

    def _language_for(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        mapping = {
            ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
            ".tsx": "typescript", ".java": "java", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
            ".h": "c", ".hpp": "cpp", ".go": "go", ".php": "php", ".rb": "ruby",
            ".cs": "csharp", ".swift": "swift", ".kt": "kotlin", ".rs": "rust",
            ".html": "html", ".xml": "xml", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        }
        return mapping.get(ext, "*")

    def _is_negative(self, snippet: str) -> bool:
        lowered = snippet.lower()
        return any(re.search(np, lowered) for np in set().union(*[r.negative_patterns for r in self.rules]))

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        language = self._language_for(file_path)
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for rule in self.rules:
                if language not in rule.languages and "*" not in rule.languages:
                    continue
                for pattern in rule.compiled_patterns:
                    if pattern.search(stripped):
                        if rule.negative_patterns and any(re.search(np, stripped.lower()) for np in rule.negative_patterns):
                            continue
                        findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            file_path=str(file_path),
                            line_number=line_num,
                            column=line.find(stripped) + 1,
                            snippet=stripped[:200],
                            remediation=rule.remediation,
                            cwe_id=rule.cwe_id,
                            owasp_category=rule.owasp_category,
                            cvss_score=rule.cvss_score,
                            cvss_vector=rule.cvss_vector,
                            engine=self.name,
                            tags=rule.tags,
                        ))
                        break  # one finding per rule per line
        return findings
