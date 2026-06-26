"""Secret detection engine with entropy, encoding, and keyword checks."""
import math
import re
from pathlib import Path
from typing import List

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


# Common secret patterns
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, Confidence.CERTAIN),
    ("AWS Secret Access Key", r"['\"]([A-Za-z0-9/+=]{40})['\"]", Severity.CRITICAL, Confidence.HIGH),
    ("GitHub Personal Access Token", r"ghp_[A-Za-z0-9_]{36}", Severity.CRITICAL, Confidence.CERTAIN),
    ("GitHub OAuth Token", r"gho_[A-Za-z0-9_]{36}", Severity.CRITICAL, Confidence.CERTAIN),
    ("Slack Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", Severity.CRITICAL, Confidence.CERTAIN),
    ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9_\-+=/]{20,}", Severity.HIGH, Confidence.HIGH),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", Severity.HIGH, Confidence.HIGH),
    ("Google API Key", r"AIza[0-9A-Za-z_-]{35}", Severity.CRITICAL, Confidence.CERTAIN),
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", Severity.CRITICAL, Confidence.HIGH),
    ("Azure Key Vault URL", r"https://[a-zA-Z0-9-]+\.vault\.azure\.net/", Severity.MEDIUM, Confidence.MEDIUM),
    ("Stripe Secret Key", r"sk_(live|test)_[0-9a-zA-Z]{24,}", Severity.CRITICAL, Confidence.CERTAIN),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-+=/]{16,})['\"]", Severity.HIGH, Confidence.MEDIUM),
    ("Generic Secret", r"(?i)(secret|password|passwd|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-+=/]{12,})['\"]", Severity.HIGH, Confidence.MEDIUM),
    ("Private Key", r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL, Confidence.CERTAIN),
    ("Base64 High-Entropy String", r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]", Severity.MEDIUM, Confidence.LOW),
    ("Hex High-Entropy String", r"['\"]([a-fA-F0-9]{32,})['\"]", Severity.MEDIUM, Confidence.LOW),
    ("URL Encoded Secret", r"['\"]([A-Za-z0-9%]{30,}%[A-Fa-f0-9]{2}[A-Za-z0-9%]*)['\"]", Severity.LOW, Confidence.LOW),
    ("Unquoted Environment Secret", r"(?i)^(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|SECRET_KEY|JWT_SECRET|ADMIN_PASSWORD|DB_PASSWORD|TOKEN)\s*=\s*([a-zA-Z0-9_\-+=/]{8,})", Severity.CRITICAL, Confidence.HIGH),
]

# Entropy configuration
HIGH_ENTROPY_MIN_LEN = 20
HIGH_ENTROPY_THRESHOLD = 4.5


class SecretEngine(BaseEngine):
    """Detects hardcoded secrets using pattern matching, entropy, and encoding checks."""

    name = "secret"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.entropy_threshold = config.get("entropy_threshold", HIGH_ENTROPY_THRESHOLD) if config else HIGH_ENTROPY_THRESHOLD
        self.entropy_min_len = config.get("entropy_min_len", HIGH_ENTROPY_MIN_LEN) if config else HIGH_ENTROPY_MIN_LEN

    def _shannon_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        entropy = 0.0
        length = len(value)
        for char in set(value):
            p = value.count(char) / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _is_likely_false_positive(self, value: str) -> bool:
        lowered = value.lower()
        false_positive_terms = [
            "example", "sample", "placeholder", "your_", "test", "dummy", "fake",
            "none", "null", "undefined", "true", "false", "changeme", "password123",
            "http://", "https://", "localhost", "127.0.0.1", "example.com", "example.org",
        ]
        return any(term in lowered for term in false_positive_terms) or len(set(value)) <= 3

    def _is_base64_candidate(self, value: str) -> bool:
        if len(value) < 20:
            return False
        if re.match(r"^[A-Za-z0-9+/]+={0,2}$", value) and self._shannon_entropy(value) >= self.entropy_threshold:
            return True
        return False

    def _is_hex_candidate(self, value: str) -> bool:
        if len(value) < 32:
            return False
        return bool(re.match(r"^[a-fA-F0-9]+$", value))

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Pattern-based detection
            for name, pattern, severity, confidence in SECRET_PATTERNS:
                for match in re.finditer(pattern, stripped):
                    candidate = match.group(0)
                    if self._is_likely_false_positive(candidate):
                        continue
                    # For base64/hex high-entropy rules, verify candidate
                    if name == "Base64 High-Entropy String" and not self._is_base64_candidate(match.group(1)):
                        continue
                    if name == "Hex High-Entropy String" and not self._is_hex_candidate(match.group(1)):
                        continue
                    findings.append(Finding(
                        rule_id="SEC-001",
                        rule_name=f"Hardcoded Secret: {name}",
                        description=f"Potential {name} detected in source code.",
                        severity=severity,
                        confidence=confidence,
                        file_path=str(file_path),
                        line_number=line_num,
                        column=match.start() + 1,
                        snippet=stripped[:200],
                        remediation="Remove secrets from source code. Use environment variables, a secrets manager, or encrypted vaults. Rotate any exposed credentials immediately.",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        engine=self.name,
                        tags=["secret", "credential", "entropy"],
                    ))
            # Entropy-based detection for high-entropy strings on assignment lines
            if re.search(r"(?i)(key|secret|token|password|auth|credential)\s*[:=]\s*['\"]([A-Za-z0-9_\-+=/]+)['\"]", stripped):
                match = re.search(r"['\"]([A-Za-z0-9_\-+=/]+)['\"]", stripped)
                if match:
                    value = match.group(1)
                    if len(value) >= self.entropy_min_len and self._shannon_entropy(value) >= self.entropy_threshold:
                        if not self._is_likely_false_positive(value) and not any(re.search(p[1], value) for p in SECRET_PATTERNS):
                            findings.append(Finding(
                                rule_id="SEC-002",
                                rule_name="High-Entropy Secret String",
                                description="A high-entropy string was assigned to a variable resembling a secret/token.",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                file_path=str(file_path),
                                line_number=line_num,
                                column=match.start() + 1,
                                snippet=stripped[:200],
                                remediation="Audit the string. If it is a secret, rotate it and move it to a secure vault.",
                                cwe_id="CWE-798",
                                owasp_category="A07:2021 – Identification and Authentication Failures",
                                engine=self.name,
                                tags=["secret", "entropy"],
                            ))
        return findings
