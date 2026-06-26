"""Software Composition Analysis (SCA) engine for dependency files."""
import json
import re
from pathlib import Path
from typing import List, Dict

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


# Known vulnerable dependency patterns (name -> vulnerable versions)
VULN_DEPS: Dict[str, List[dict]] = {
    "Flask": [
        {"version": "<2.2.5", "severity": Severity.HIGH, "cwe": "CWE-94", "description": "Flask before 2.2.5 has a memory-view related memory leak and potential code execution."},
    ],
    "Werkzeug": [
        {"version": "<2.3.7", "severity": Severity.HIGH, "cwe": "CWE-22", "description": "Werkzeug before 2.3.7 has a path traversal issue in the debugger."},
    ],
    "PyJWT": [
        {"version": "<2.4.0", "severity": Severity.CRITICAL, "cwe": "CWE-347", "description": "PyJWT before 2.4.0 allows algorithm confusion with none."},
    ],
    "requests": [
        {"version": "<2.31.0", "severity": Severity.MEDIUM, "cwe": "CWE-918", "description": "Requests before 2.31.0 may follow requests to local addresses (SSRF)."},
    ],
    "PyYAML": [
        {"version": "<6.0.1", "severity": Severity.CRITICAL, "cwe": "CWE-502", "description": "PyYAML before 6.0.1 may allow arbitrary code execution via yaml.load."},
    ],
    "flask-sqlalchemy": [
        {"version": "<3.0.5", "severity": Severity.MEDIUM, "cwe": "CWE-89", "description": "Potential SQL injection via raw queries in older versions."},
    ],
    "Jinja2": [
        {"version": "<3.1.3", "severity": Severity.HIGH, "cwe": "CWE-94", "description": "Jinja2 before 3.1.3 has a sandbox escape vulnerability."},
    ],
    "python-dotenv": [
        {"version": "<1.0.0", "severity": Severity.LOW, "cwe": "CWE-732", "description": "Older python-dotenv may expose secrets in logs."},
    ],
}


def _parse_version(version: str) -> tuple:
    """Simple version parser."""
    clean = version.strip().lstrip("=<>!~*")
    parts = []
    for part in clean.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            break
    return tuple(parts)


def _version_matches_constraint(installed: str, constraint: str) -> bool:
    """Roughly check if installed version satisfies a vulnerable constraint."""
    installed_v = _parse_version(installed)
    constraint_v = _parse_version(constraint)
    if not installed_v or not constraint_v:
        return False

    if constraint.startswith("<"):
        # installed < constraint_v means vulnerable
        for i in range(max(len(installed_v), len(constraint_v))):
            a = installed_v[i] if i < len(installed_v) else 0
            b = constraint_v[i] if i < len(constraint_v) else 0
            if a < b:
                return True
            if a > b:
                return False
        return False
    if constraint.startswith(">="):
        return False  # Not used in our dataset but handle shape
    return False


class SCAEngine(BaseEngine):
    """Scans dependency manifests for known vulnerable libraries."""

    name = "sca"

    def _scan_requirements(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~*]+)?\s*([a-zA-Z0-9_.-]+)?", line)
            if not match:
                continue
            name = match.group(1)
            version = match.group(3) or "unknown"
            for vuln in VULN_DEPS.get(name, []):
                if _version_matches_constraint(version, vuln["version"]):
                    findings.append(Finding(
                        rule_id="SCA-001",
                        rule_name=f"Vulnerable Dependency: {name}",
                        description=f"{name} {version} matches vulnerable constraint {vuln['version']}. {vuln['description']}",
                        severity=vuln["severity"],
                        confidence=Confidence.HIGH,
                        file_path=str(file_path),
                        line_number=line_num,
                        column=1,
                        snippet=line,
                        remediation=f"Upgrade {name} to a version not affected by {vuln['version']}. Check the advisory for the latest patched version.",
                        cwe_id=vuln["cwe"],
                        owasp_category="A06:2021 – Vulnerable and Outdated Components",
                        engine=self.name,
                        tags=["sca", "dependency", "vulnerable-component"],
                    ))
        return findings

    def _scan_package_json(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        for name, version in deps.items():
            for vuln in VULN_DEPS.get(name, []):
                if _version_matches_constraint(version, vuln["version"]):
                    findings.append(Finding(
                        rule_id="SCA-001",
                        rule_name=f"Vulnerable Dependency: {name}",
                        description=f"{name} {version} matches vulnerable constraint {vuln['version']}. {vuln['description']}",
                        severity=vuln["severity"],
                        confidence=Confidence.HIGH,
                        file_path=str(file_path),
                        line_number=1,
                        column=1,
                        snippet=f"{name}: {version}",
                        remediation=f"Upgrade {name} to a patched version.",
                        cwe_id=vuln["cwe"],
                        owasp_category="A06:2021 – Vulnerable and Outdated Components",
                        engine=self.name,
                        tags=["sca", "dependency", "vulnerable-component"],
                    ))
        return findings

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        if file_path.name == "requirements.txt":
            return self._scan_requirements(file_path, content)
        if file_path.name == "package.json":
            return self._scan_package_json(file_path, content)
        return []
