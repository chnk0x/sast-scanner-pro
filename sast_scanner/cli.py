"""Command-line interface for SAST scanner."""
import argparse
import sys
from pathlib import Path
from typing import List

import yaml

from .scanner import SASTScanner
from .utils import setup_logger


def load_config(path: str) -> dict:
    """Load YAML or JSON config."""
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            if config_path.suffix in (".yaml", ".yml"):
                return yaml.safe_load(f) or {}
            return {}
    except Exception:
        return {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast-scanner-pro",
        description="SAST-VULN-SCANNER-PRO: Senior-level AI-augmented static security scanner.",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "-e", "--engines",
        nargs="+",
        default=["regex", "semantic", "secret", "taint", "sca", "iac"],
        choices=["regex", "semantic", "secret", "taint", "sca", "iac", "custom"],
        help="Analysis engines to enable (default: regex semantic secret taint sca iac)",
    )
    parser.add_argument(
        "-f", "--formats",
        nargs="+",
        default=["html", "json"],
        choices=["html", "json", "sarif", "csv", "trend"],
        help="Report formats to generate (default: html json)",
    )
    parser.add_argument("-o", "--output", default="sast_reports", help="Output directory for reports")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to YAML config file")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Parallel scan workers")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--ai", action="store_true", help="Enable AI triage via Ollama")
    parser.add_argument("--ai-model", default="qwen2.5:1.5b", help="Ollama model name for AI triage")
    parser.add_argument("--ai-url", default="http://localhost:11434/v1", help="Ollama API base URL")
    parser.add_argument("--baseline", help="Path to baseline JSON file to suppress known findings")
    parser.add_argument("--create-baseline", help="Create a baseline from current findings and save to path")
    parser.add_argument("--incremental", action="store_true", help="Only scan changed files since last run")
    parser.add_argument("--custom-rules", help="Directory containing custom YAML rule files")
    parser.add_argument("--git-history", action="store_true", help="Scan git history for secrets (enabled automatically if .git exists)")
    return parser


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logger = setup_logger(level=10 if args.verbose else 20)
    config = load_config(args.config)

    # Merge AI settings from CLI
    if args.ai:
        config.setdefault("ai", {})
        config["ai"]["enabled"] = True
        config["ai"]["model"] = args.ai_model
        config["ai"]["base_url"] = args.ai_url
        config["ai"]["api_key"] = "ollama"

    if not Path(args.target).exists():
        logger.error("Target path does not exist: %s", args.target)
        return 1

    scanner = SASTScanner(
        target=args.target,
        engines=args.engines,
        output_formats=args.formats,
        output_dir=args.output,
        config=config,
        workers=args.workers,
        logger=logger,
        baseline=args.baseline,
        incremental=args.incremental,
        custom_rules_dir=args.custom_rules,
    )

    if args.create_baseline:
        scanner.create_baseline(args.create_baseline)
        return 0

    findings = scanner.run()

    print("\n" + "=" * 60)
    print(f"Scan complete: {len(findings)} verified finding(s)")
    print("=" * 60)
    return 0 if len(findings) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
