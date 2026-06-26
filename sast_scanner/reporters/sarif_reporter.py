"""SARIF v2.1.0 reporter for CI/CD integration."""
import json
import datetime
from pathlib import Path
from typing import List

from .base_reporter import BaseReporter
from ..models import Finding


class SARIFReporter(BaseReporter):
    """Generates a SARIF report compatible with GitHub Code Scanning and Azure DevOps."""

    name = "sarif"
    extension = "sarif"

    def generate(self, findings: List[Finding], target: str, metadata: dict = None) -> None:
        metadata = metadata or {}
        rules = {}
        results = []
        for f in findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_name,
                    "shortDescription": {"text": f.description},
                    "fullDescription": {"text": f.remediation},
                    "defaultConfiguration": {"level": self._sarif_level(f.severity.value)},
                    "properties": {
                        "cwe": f.cwe_id,
                        "owasp": f.owasp_category,
                        "cvss_score": f.cvss_score,
                        "tags": f.tags,
                    },
                }
            results.append({
                "ruleId": f.rule_id,
                "level": self._sarif_level(f.severity.value),
                "message": {"text": f"{f.rule_name}: {f.description}\n\nRemediation: {f.remediation}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": f.column,
                            "snippet": {"text": f.snippet},
                        },
                    },
                }],
                "properties": {
                    "confidence": f.confidence.value,
                    "engine": f.engine,
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SAST-VULN-SCANNER-PRO",
                        "version": metadata.get("version", "2.0.0"),
                        "informationUri": "https://github.com/example/sast-vuln-scanner-pro",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": datetime.datetime.now().isoformat(),
                }],
            }],
        }
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

    @staticmethod
    def _sarif_level(severity: str) -> str:
        mapping = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
        return mapping.get(severity.upper(), "warning")
