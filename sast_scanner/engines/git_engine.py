"""Git history scanning for leaked secrets."""
import re
import subprocess
from pathlib import Path
from typing import List

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


SECRET_PATTERNS = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("AWS Secret Access Key", r"['\"]([A-Za-z0-9/+=]{40})['\"]", Severity.CRITICAL),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36}", Severity.CRITICAL),
    ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", Severity.CRITICAL),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-+=/]{16,})['\"]", Severity.HIGH),
    ("Generic Secret", r"(?i)(secret|password|passwd|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-+=/]{12,})['\"]", Severity.HIGH),
    ("Private Key", r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", Severity.HIGH),
    ("Google API Key", r"AIza[0-9A-Za-z_-]{35}", Severity.CRITICAL),
    ("Base64 High-Entropy", r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", Severity.MEDIUM),
]

FALSE_POSITIVE_TERMS = ["example", "sample", "placeholder", "your_", "test", "dummy", "fake", "none", "null", "changeme"]


class GitEngine(BaseEngine):
    """Scans git commit history for leaked secrets."""

    name = "git"

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        # This engine operates on the repository, not on a single file.
        return []

    def scan_repository(self, repo_path: Path) -> List[Finding]:
        """Scan git history for secrets in diffs."""
        findings = []
        if not (repo_path / ".git").is_dir():
            return findings

        try:
            result = subprocess.run(
                ["git", "log", "-p", "--all"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
                errors="ignore",
            )
            if result.returncode != 0:
                return findings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return findings

        current_commit = "unknown"
        for line_num, line in enumerate(result.stdout.splitlines(), 1):
            if line.startswith("commit "):
                current_commit = line.split()[1][:8]
            if line.startswith("+") or line.startswith("-"):
                content_line = line[1:].strip()
                for name, pattern, severity in SECRET_PATTERNS:
                    for match in re.finditer(pattern, content_line):
                        candidate = match.group(0)
                        if any(term in candidate.lower() for term in FALSE_POSITIVE_TERMS):
                            continue
                        findings.append(Finding(
                            rule_id="GIT-001",
                            rule_name=f"Leaked Secret in Git History: {name}",
                            description=f"Potential {name} found in git commit history.",
                            severity=severity,
                            confidence=Confidence.HIGH,
                            file_path=str(repo_path),
                            line_number=line_num,
                            column=match.start() + 1,
                            snippet=content_line[:200],
                            remediation="Rotate the exposed credential, remove it from git history (e.g., git-filter-repo), and move secrets to a vault.",
                            cwe_id="CWE-798",
                            owasp_category="A07:2021 – Identification and Authentication Failures",
                            engine=self.name,
                            tags=["secret", "git", "history"],
                            metadata={"commit": current_commit},
                        ))
        return findings
