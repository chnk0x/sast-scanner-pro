"""JSON reporter."""
import json
import datetime
from pathlib import Path
from typing import List

from .base_reporter import BaseReporter
from ..models import Finding


class JSONReporter(BaseReporter):
    """Generates a machine-readable JSON report."""

    name = "json"
    extension = "json"

    def generate(self, findings: List[Finding], target: str, metadata: dict = None) -> None:
        metadata = metadata or {}
        report = {
            "metadata": {
                "scanner": "SAST-VULN-SCANNER-PRO",
                "version": metadata.get("version", "2.0.0"),
                "target": target,
                "generated_at": datetime.datetime.now().isoformat(),
                "total_findings": len(findings),
            },
            "summary": self._severity_counts(findings),
            "findings": [f.to_dict() for f in findings],
        }
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
