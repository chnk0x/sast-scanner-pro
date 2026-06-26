"""Custom user-defined rules engine loaded from YAML files."""
import re
from pathlib import Path
from typing import List

import yaml

from .base_engine import BaseEngine
from ..models import Finding, Rule, Severity, Confidence


class CustomRulesEngine(BaseEngine):
    """Loads and applies user-defined regex rules from YAML."""

    name = "custom"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.rules_dir = Path(config.get("rules_dir", "rules")) if config else Path("rules")
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Rule]:
        rules = []
        if not self.rules_dir.exists():
            return rules
        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                for item in data.get("rules", []):
                    rules.append(self._build_rule(item))
            except Exception as exc:
                continue
        return rules

    def _build_rule(self, item: dict) -> Rule:
        return Rule(
            id=item.get("id", "CUSTOM-001"),
            name=item.get("name", "Custom Rule"),
            description=item.get("description", ""),
            severity=Severity(item.get("severity", "MEDIUM").upper()),
            confidence=Confidence(item.get("confidence", "MEDIUM").upper()),
            engine=self.name,
            languages=item.get("languages", ["*"]),
            patterns=item.get("patterns", []),
            negative_patterns=item.get("negative_patterns", []),
            cwe_id=item.get("cwe_id"),
            owasp_category=item.get("owasp_category"),
            remediation=item.get("remediation", "Review the finding and remediate according to your security policy."),
            cvss_score=item.get("cvss_score"),
            cvss_vector=item.get("cvss_vector"),
            tags=item.get("tags", ["custom"]),
        )

    def _language_for(self, file_path: Path) -> str:
        ext = file_path.suffix.lower()
        mapping = {
            ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
            ".tsx": "typescript", ".java": "java", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
            ".h": "c", ".hpp": "cpp", ".go": "go", ".php": "php", ".rb": "ruby",
            ".cs": "csharp", ".swift": "swift", ".kt": "kotlin", ".rs": "rust",
            ".html": "html", ".xml": "xml", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        }
        return mapping.get(ext, "*")

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        language = self._language_for(file_path)
        findings = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            for rule in self.rules:
                if language not in rule.languages and "*" not in rule.languages:
                    continue
                for pattern in rule.compiled_patterns:
                    if pattern.search(stripped):
                        if rule.negative_patterns and any(re.search(np, stripped.lower()) for np in rule.negative_patterns):
                            continue
                        findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            file_path=str(file_path),
                            line_number=line_num,
                            column=line.find(stripped) + 1,
                            snippet=stripped[:200],
                            remediation=rule.remediation,
                            cwe_id=rule.cwe_id,
                            owasp_category=rule.owasp_category,
                            cvss_score=rule.cvss_score,
                            cvss_vector=rule.cvss_vector,
                            engine=self.name,
                            tags=rule.tags,
                        ))
                        break
        return findings
