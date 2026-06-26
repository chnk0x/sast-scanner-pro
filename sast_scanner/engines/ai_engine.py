"""AI-assisted triage engine (optional, local Ollama)."""
import json
import re
from pathlib import Path
from typing import List, Optional

from .base_engine import BaseEngine
from ..models import Finding, Severity, Confidence


class AIEngine(BaseEngine):
    """Uses a local LLM via Ollama-compatible API to classify findings as true/false positives."""

    name = "ai_triage"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.config = config or {}
        self.enabled = self.config.get("enabled", False)
        self.model = self.config.get("model", "qwen2.5:1.5b")
        self.base_url = self.config.get("base_url", "http://localhost:11434/v1")
        self.api_key = self.config.get("api_key", "ollama")
        self.client = None
        if self.enabled:
            try:
                from openai import OpenAI
                self.client = OpenAI(base_url=self.base_url, api_key=self.api_key)
            except Exception:
                self.enabled = False

    def is_enabled(self) -> bool:
        return self.enabled and self.client is not None

    def analyze(self, file_path: Path, content: str, lines: List[str]) -> List[Finding]:
        # AI engine does not directly detect; it triages findings from other engines.
        return []

    def triage(self, finding: Finding) -> Optional[Finding]:
        """Return the finding with AI-verified confidence, or mark false positive."""
        if not self.is_enabled():
            return finding

        prompt = f"""[SYSTEM: You are a strict binary security classification bot.]
Analyze the following code finding and respond with ONLY a JSON object.

Vulnerability: {finding.rule_name}
File: {finding.file_path}
Line: {finding.line_number}
Code snippet: {finding.snippet}

Tasks:
1. Determine if this is a REAL VULNERABILITY or FALSE ALARM.
2. If real, provide a concise explanation and severity recommendation (CRITICAL, HIGH, MEDIUM, LOW).

Response format exactly:
{{"classification": "REAL VULNERABILITY" or "FALSE ALARM", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "reason": "short explanation"}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
            )
            text = response.choices[0].message.content.strip()
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                result = json.loads(match.group(0))
                classification = result.get("classification", "").upper()
                if "FALSE" in classification:
                    finding.is_false_positive = True
                    finding.confidence = Confidence.TENTATIVE
                else:
                    sev = result.get("severity", finding.severity.value).upper()
                    try:
                        finding.severity = Severity(sev)
                    except ValueError:
                        pass
                    finding.metadata["ai_reason"] = result.get("reason", "")
                    finding.confidence = Confidence.HIGH
        except Exception as exc:
            finding.metadata["ai_error"] = str(exc)
        return finding
