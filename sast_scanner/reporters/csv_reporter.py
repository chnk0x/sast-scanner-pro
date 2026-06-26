"""CSV reporter for spreadsheet analysis."""
import csv
from pathlib import Path
from typing import List

from .base_reporter import BaseReporter
from ..models import Finding


class CSVReporter(BaseReporter):
    """Generates a CSV report for spreadsheet import."""

    name = "csv"
    extension = "csv"

    def generate(self, findings: List[Finding], target: str, metadata: dict = None) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "finding_id", "rule_id", "rule_name", "severity", "confidence", "file_path",
                "line_number", "column", "snippet", "description", "remediation",
                "cwe_id", "owasp_category", "cvss_score", "cvss_vector", "engine", "tags", "false_positive"
            ])
            for f in sorted(findings, key=lambda x: x.severity_rank):
                writer.writerow([
                    f.finding_id, f.rule_id, f.rule_name, f.severity.value, f.confidence.value,
                    f.file_path, f.line_number, f.column, f.snippet, f.description, f.remediation,
                    f.cwe_id or "", f.owasp_category or "", f.cvss_score or "", f.cvss_vector or "",
                    f.engine, "|".join(f.tags), f.is_false_positive
                ])
