"""Data models for SAST findings."""
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
from enum import Enum
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    TENTATIVE = "TENTATIVE"


@dataclass
class Finding:
    """Represents a single security finding."""
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_number: int
    column: int = 0
    snippet: str = ""
    remediation: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    engine: str = "unknown"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    is_false_positive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return order.get(self.severity, 99)
