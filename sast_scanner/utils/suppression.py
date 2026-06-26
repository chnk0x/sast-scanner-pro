"""Baseline and suppression utilities."""
import json
from pathlib import Path
from typing import List, Set, Tuple

from ..models import Finding


class BaselineManager:
    """Manages a baseline of known/accepted findings so they can be suppressed."""

    def __init__(self, baseline_path: str = None):
        self.baseline_path = Path(baseline_path) if baseline_path else None
        self.baseline: Set[str] = set()
        if self.baseline_path and self.baseline_path.exists():
            self._load()

    def _finding_key(self, finding: Finding) -> str:
        return f"{finding.rule_id}:{finding.file_path}:{finding.line_number}:{finding.snippet[:80]}"

    def _load(self):
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.baseline = {entry.get("key") for entry in data.get("findings", []) if entry.get("key")}
        except Exception:
            self.baseline = set()

    def is_suppressed(self, finding: Finding) -> bool:
        return self._finding_key(finding) in self.baseline

    def filter(self, findings: List[Finding]) -> List[Finding]:
        return [f for f in findings if not self.is_suppressed(f)]

    def create(self, findings: List[Finding], output_path: str):
        """Create a new baseline file from current findings."""
        entries = []
        for f in findings:
            entries.append({
                "key": self._finding_key(f),
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "snippet": f.snippet[:200],
            })
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"findings": entries}, f, indent=2)
