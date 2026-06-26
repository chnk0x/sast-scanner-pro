"""Base reporter interface."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from ..models import Finding


class BaseReporter(ABC):
    """Base class for report generators."""

    name = "base"
    extension = ""

    def __init__(self, output_path: str):
        self.output_path = Path(output_path)

    @abstractmethod
    def generate(self, findings: List[Finding], target: str, metadata: dict = None) -> None:
        pass

    def _severity_counts(self, findings: List[Finding]) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
