"""Rule definitions for SAST engines."""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Pattern
import re

from .finding import Severity, Confidence


@dataclass
class Rule:
    """A detection rule."""
    id: str
    name: str
    description: str
    severity: Severity
    confidence: Confidence
    engine: str
    languages: List[str] = field(default_factory=lambda: ["*"])
    patterns: List[str] = field(default_factory=list)
    compiled_patterns: List[Pattern] = field(default_factory=list, repr=False)
    negative_patterns: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.compiled_patterns and self.patterns:
            self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.patterns]
