#!/usr/bin/env python3
"""Compare two SAST JSON reports and show new/resolved findings."""
import json
import sys
from pathlib import Path


def load_findings(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("findings", [])


def fingerprint(finding: dict) -> str:
    return "|".join([
        finding.get("rule_id", ""),
        finding.get("rule_name", ""),
        finding.get("file_path", ""),
        str(finding.get("line_number", 0)),
        finding.get("snippet", "")[:80],
    ])


def compare(old_path: str, new_path: str):
    old = {fingerprint(f): f for f in load_findings(old_path)}
    new = {fingerprint(f): f for f in load_findings(new_path)}

    new_findings = [new[k] for k in new if k not in old]
    resolved = [old[k] for k in old if k not in new]
    unchanged = [new[k] for k in new if k in old]

    print(f"\nOld report: {old_path}")
    print(f"New report: {new_path}")
    print(f"New findings: {len(new_findings)}")
    print(f"Resolved findings: {len(resolved)}")
    print(f"Unchanged findings: {len(unchanged)}")

    if new_findings:
        print("\n🔴 New Findings")
        for f in new_findings:
            print(f"  [{f.get('severity')}] {f.get('rule_name')} at {f.get('file_path')}:{f.get('line_number')}")

    if resolved:
        print("\n🟢 Resolved Findings")
        for f in resolved:
            print(f"  [{f.get('severity')}] {f.get('rule_name')} at {f.get('file_path')}:{f.get('line_number')}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <old_report.json> <new_report.json>")
        sys.exit(1)
    compare(sys.argv[1], sys.argv[2])
