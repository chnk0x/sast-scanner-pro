"""Infrastructure-as-Code (IaC) scanning engine."""
import re
from pathlib import Path
from typing import List

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


IAC_RULES = [
    {
        "id": "IAC-001",
        "name": "Hardcoded Secret in IaC",
        "pattern": r"(?i)(password|secret|token|key)\s*[:=]\s*['\"][a-zA-Z0-9_\-+=/]{8,}['\"]",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "remediation": "Use vaults, environment variables, or secret management systems. Never hardcode secrets in IaC.",
    },
    {
        "id": "IAC-002",
        "name": "Overly Permissive Security Group / Open Ingress",
        "pattern": r"(?i)(cidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\s*\]|ingress\s*\{\s*from_port\s*=\s*0\s+to_port\s*=\s*65535)",
        "severity": Severity.HIGH,
        "cwe": "CWE-284",
        "owasp": "A01:2021 – Broken Access Control",
        "remediation": "Restrict ingress to specific CIDR blocks and required ports. Avoid 0.0.0.0/0 with all ports open.",
    },
    {
        "id": "IAC-003",
        "name": "Container Running as Root / Privileged",
        "pattern": r"(?i)(runAsUser\s*:\s*0|privileged\s*:\s*true|USER\s+root|RUN\s+.*\buseradd\b|runAsNonRoot\s*:\s*false)",
        "severity": Severity.HIGH,
        "cwe": "CWE-250",
        "owasp": "A04:2021 – Insecure Design",
        "remediation": "Run containers as non-root users. Drop privileged capabilities and use least-privilege security contexts.",
    },
    {
        "id": "IAC-004",
        "name": "Publicly Accessible Database / Storage",
        "pattern": r"(?i)(publicly_accessible\s*=\s*true|publicly_accessible\s*:\s*true|public_network_access_enabled\s*=\s*true|acl\s*=\s*['\"]public-read['\"])",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-306",
        "owasp": "A05:2021 – Security Misconfiguration",
        "remediation": "Disable public access on databases and storage. Use private subnets, VPC endpoints, and IAM policies.",
    },
    {
        "id": "IAC-005",
        "name": "LoadBalancer Exposing Service to Internet",
        "pattern": r"(?i)(type\s*:\s*LoadBalancer|type\s*=\s*['\"]LoadBalancer['\"])",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-284",
        "owasp": "A01:2021 – Broken Access Control",
        "remediation": "Use ClusterIP or internal LoadBalancer annotations. Place public-facing services behind an ingress controller with TLS.",
    },
    {
        "id": "IAC-006",
        "name": "Insecure Host Mount / Broad Volume Mount",
        "pattern": r"(?i)(volumes:\s*-?\s*\/:\/host|mountPath\s*:\s*\/host|bind\s*:\s*\/:\/)",
        "severity": Severity.HIGH,
        "cwe": "CWE-276",
        "owasp": "A04:2021 – Insecure Design",
        "remediation": "Mount only the specific host paths required. Avoid mounting the entire root filesystem.",
    },
    {
        "id": "IAC-007",
        "name": "Debug / Development Environment Enabled",
        "pattern": r"(?i)(FLASK_ENV\s*[=:]\s*['\"]development['\"]|DEBUG\s*[=:]\s*True|debug\s*:\s*true)",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-489",
        "owasp": "A05:2021 – Security Misconfiguration",
        "remediation": "Disable debug mode in production and use production-ready environment settings.",
    },
    {
        "id": "IAC-008",
        "name": "Missing Health/Readiness Probe",
        "pattern": r"(?i)(livenessProbe|readinessProbe)",
        "severity": Severity.LOW,
        "negative": True,
        "cwe": "CWE-710",
        "owasp": "A05:2021 – Security Misconfiguration",
        "remediation": "Add liveness and readiness probes to ensure resilience and safe rollouts.",
    },
]


class IACEngine(BaseEngine):
    """Scans IaC files (Dockerfile, Terraform, Kubernetes YAML, docker-compose)."""

    name = "iac"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.rules = IAC_RULES
        for rule in self.rules:
            rule["compiled"] = re.compile(rule["pattern"], re.IGNORECASE)
            if rule.get("negative"):
                rule["negative_compiled"] = re.compile(rule["pattern"], re.IGNORECASE)

    def _is_iac_file(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return (
            name in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}
            or file_path.suffix in {".tf", ".tfvars", ".hcl"}
            or (file_path.suffix in {".yaml", ".yml"} and "k8s" in str(file_path).lower())
        )

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        if not self._is_iac_file(file_path):
            return []

        findings = []
        has_health_probe = False
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.search(r"(?i)(livenessProbe|readinessProbe)", stripped):
                has_health_probe = True
            for rule in self.rules:
                if rule.get("negative"):
                    continue
                if rule["compiled"].search(stripped):
                    findings.append(Finding(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        description=f"IaC scanning detected {rule['name']}.",
                        severity=rule["severity"],
                        confidence=Confidence.HIGH,
                        file_path=str(file_path),
                        line_number=line_num,
                        column=line.find(stripped) + 1,
                        snippet=stripped[:200],
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe"],
                        owasp_category=rule["owasp"],
                        engine=self.name,
                        tags=["iac", "infrastructure"],
                    ))

        # Negative rule: missing health probes in K8s deployment only if file is k8s yaml
        if "k8s" in str(file_path).lower() and not has_health_probe:
            rule = next((r for r in self.rules if r.get("negative")), None)
            if rule:
                findings.append(Finding(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    description=f"IaC scanning detected {rule['name']}.",
                    severity=rule["severity"],
                    confidence=Confidence.LOW,
                    file_path=str(file_path),
                    line_number=1,
                    column=1,
                    snippet="Kubernetes manifest without liveness/readiness probes",
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe"],
                    owasp_category=rule["owasp"],
                    engine=self.name,
                    tags=["iac", "kubernetes"],
                ))
        return findings
