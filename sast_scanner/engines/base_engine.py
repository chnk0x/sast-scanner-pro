"""Base engine interface."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from ..models import Finding


class BaseEngine(ABC):
    """Base class for all SAST analysis engines."""

    name = "base"

    def __init__(self, config: dict = None):
        self.config = config or {}

    @abstractmethod
    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        """Analyze a file and return findings."""
        pass

    def is_enabled(self) -> bool:
        return self.config.get("enabled", True)
