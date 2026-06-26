"""SAST Scanner orchestrator."""
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Optional, Type, Tuple

from .engines import (
    BaseEngine, RegexEngine, SemanticEngine, SecretEngine, AIEngine,
    TaintEngine, SCAEngine, IACEngine, GitEngine, CustomRulesEngine,
)
from .models import Finding, Confidence
from .utils import FileWalker, read_file_lines, setup_logger
from .utils.suppression import BaselineManager
from .utils.incremental import IncrementalTracker
from .reporters import BaseReporter, HTMLReporter, JSONReporter, SARIFReporter, CSVReporter, TrendReporter


class SASTScanner:
    """Orchestrates multiple engines and reporters to perform a SAST scan."""

    REPORTERS: Dict[str, Type[BaseReporter]] = {
        "html": HTMLReporter,
        "json": JSONReporter,
        "sarif": SARIFReporter,
        "csv": CSVReporter,
        "trend": TrendReporter,
    }

    ENGINE_MAP: Dict[str, Type[BaseEngine]] = {
        "regex": RegexEngine,
        "semantic": SemanticEngine,
        "secret": SecretEngine,
        "taint": TaintEngine,
        "sca": SCAEngine,
        "iac": IACEngine,
        "custom": CustomRulesEngine,
    }

    def __init__(
        self,
        target: str,
        engines: Optional[List[str]] = None,
        output_formats: Optional[List[str]] = None,
        output_dir: str = "sast_reports",
        config: Optional[dict] = None,
        workers: int = 4,
        logger=None,
        baseline: Optional[str] = None,
        incremental: bool = False,
        custom_rules_dir: Optional[str] = None,
    ):
        self.target = Path(target).resolve()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}
        self.workers = max(1, workers)
        self.logger = logger or setup_logger()
        self.baseline = BaselineManager(baseline)
        self.incremental = IncrementalTracker() if incremental else None
        self.custom_rules_dir = custom_rules_dir
        self.engines = self._build_engines(engines or ["regex", "semantic", "secret"])
        self.output_formats = output_formats or ["html"]
        self.ai_engine = self._build_ai_engine()
        self.git_engine = GitEngine({})

    def _build_engines(self, names: List[str]) -> List[BaseEngine]:
        engines = []
        for name in names:
            if name in self.ENGINE_MAP:
                cfg = self.config.get("engines", {}).get(name, {})
                if name == "custom" and self.custom_rules_dir:
                    cfg = cfg.copy()
                    cfg["rules_dir"] = self.custom_rules_dir
                engines.append(self.ENGINE_MAP[name](cfg))
        return engines

    def _build_ai_engine(self) -> Optional[AIEngine]:
        ai_cfg = self.config.get("ai", {})
        if ai_cfg.get("enabled", False):
            engine = AIEngine(ai_cfg)
            if engine.is_enabled():
                self.logger.info("AI triage engine enabled (model: %s)", ai_cfg.get("model", "default"))
                return engine
            else:
                self.logger.warning("AI triage requested but Ollama client is unavailable.")
        return None

    def _scan_file(self, file_path: Path) -> List[Finding]:
        lines = read_file_lines(file_path)
        if not lines:
            return []
        content = "".join(lines)
        findings = []
        for engine in self.engines:
            if engine.is_enabled():
                try:
                    findings.extend(engine.analyze(file_path, content, lines))
                except Exception as exc:
                    self.logger.debug("Engine %s failed on %s: %s", engine.name, file_path, exc)
        return findings

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate by semantic fingerprint (rule category + file + line + snippet prefix)."""
        seen = set()
        unique = []
        for f in findings:
            # Normalize by vulnerability category and location
            category = f.rule_name.split(":")[0].split("(")[0].strip()
            key = (category, f.file_path, f.line_number, f.snippet[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _score_confidence(self, finding: Finding) -> Finding:
        """Adjust confidence based on available evidence."""
        signals = 0
        if finding.snippet and len(finding.snippet) > 10:
            signals += 1
        if finding.cwe_id:
            signals += 1
        if finding.cvss_score:
            signals += 1
        if finding.engine in ("semantic", "taint"):
            signals += 2
        if finding.engine in ("regex", "secret"):
            signals += 1
        if signals >= 5:
            finding.confidence = Confidence.CERTAIN
        elif signals >= 3:
            finding.confidence = Confidence.HIGH
        elif signals >= 2:
            finding.confidence = Confidence.MEDIUM
        else:
            finding.confidence = Confidence.LOW
        return finding

    def _assess_exploitability(self, finding: Finding) -> Finding:
        """Add a rough exploitability score (0-10) based on severity and reachability."""
        score = 5.0
        if finding.severity.value == "CRITICAL":
            score += 2.5
        elif finding.severity.value == "HIGH":
            score += 1.5
        elif finding.severity.value == "MEDIUM":
            score += 0.5
        if finding.engine in ("taint", "semantic"):
            score += 1.5
        if finding.engine == "regex":
            score += 0.5
        if finding.cwe_id in ("CWE-78", "CWE-89", "CWE-94", "CWE-502"):
            score += 1.0
        finding.metadata["exploitability_score"] = round(min(score, 10), 1)
        return finding

    def _triage(self, findings: List[Finding]) -> List[Finding]:
        if not self.ai_engine:
            return [f for f in findings if not f.is_false_positive]
        triaged = []
        for f in findings:
            triaged_finding = self.ai_engine.triage(f)
            if triaged_finding and not triaged_finding.is_false_positive:
                triaged.append(triaged_finding)
        return triaged

    def _apply_baseline(self, findings: List[Finding]) -> List[Finding]:
        if not self.baseline.baseline_path:
            return findings
        filtered = self.baseline.filter(findings)
        suppressed = len(findings) - len(filtered)
        if suppressed:
            self.logger.info("Suppressed %d known/accepted findings via baseline", suppressed)
        return filtered

    def scan(self) -> List[Finding]:
        """Run the full scan and return verified findings."""
        if not self.target.exists():
            raise FileNotFoundError(f"Target does not exist: {self.target}")

        self.logger.info("Starting SAST scan on %s", self.target)
        walker = FileWalker(str(self.target), max_size=self.config.get("max_file_size", 5 * 1024 * 1024))
        files = list(walker.iter_files())

        if self.incremental:
            files = self.incremental.changed_files(files)
            self.logger.info("Incremental mode: %d changed files to scan out of %d", len(files), len(list(walker.iter_files())))

        self.logger.info("Discovered %d scannable files", len(files))

        all_findings: List[Finding] = []
        if files:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
                futures = {executor.submit(self._scan_file, fp): fp for fp in files}
                for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    fp = futures[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        if findings:
                            self.logger.info("[%d/%d] %s -> %d finding(s)", idx, len(files), fp.name, len(findings))
                    except Exception as exc:
                        self.logger.warning("Failed to scan %s: %s", fp, exc)

        # Git history scanning if target is a repository
        if self.target.is_dir() and (self.target / ".git").is_dir():
            self.logger.info("Scanning git history for leaked secrets")
            git_findings = self.git_engine.scan_repository(self.target)
            all_findings.extend(git_findings)
            self.logger.info("Git history findings: %d", len(git_findings))

        all_findings = self._deduplicate(all_findings)
        all_findings = [self._score_confidence(self._assess_exploitability(f)) for f in all_findings]
        self.logger.info("Raw findings before triage: %d", len(all_findings))
        verified = self._triage(all_findings)
        verified = self._apply_baseline(verified)
        self.logger.info("Verified findings after triage/baseline: %d", len(verified))

        if self.incremental and files:
            self.incremental.update(files)

        return verified

    def report(self, findings: List[Finding]) -> List[Path]:
        """Generate reports in requested formats."""
        generated = []
        metadata = {"version": "2.0.0"}
        for fmt in self.output_formats:
            cls = self.REPORTERS.get(fmt)
            if not cls:
                self.logger.warning("Unknown report format: %s", fmt)
                continue
            if cls == TrendReporter:
                path = self.output_dir / f"trend_dashboard.{cls.extension}"
            else:
                path = self.output_dir / f"sast_report.{cls.extension}"
            try:
                if cls == TrendReporter:
                    reporter = TrendReporter(str(path), trend_json=str(self.output_dir / "trend.json"))
                else:
                    reporter = cls(str(path))
                reporter.generate(findings, str(self.target), metadata)
                generated.append(path)
                self.logger.info("Generated report: %s", path)
            except Exception as exc:
                self.logger.error("Failed to generate %s report: %s", fmt, exc)
        return generated

    def create_baseline(self, output_path: str):
        """Create a baseline from the current scan results."""
        findings = self.scan()
        self.baseline.create(findings, output_path)
        self.logger.info("Baseline created at %s with %d findings", output_path, len(findings))

    def run(self) -> List[Finding]:
        """Convenience method: scan and report."""
        findings = self.scan()
        self.report(findings)
        return findings
