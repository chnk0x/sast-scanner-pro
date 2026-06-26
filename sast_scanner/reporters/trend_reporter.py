"""Trend dashboard reporter for historical scan data."""
import json
import datetime
from pathlib import Path
from typing import List, Dict

from .base_reporter import BaseReporter
from ..models import Finding, Severity


class TrendReporter(BaseReporter):
    """Appends scan results to a JSON trend file and generates an HTML trend dashboard."""

    name = "trend"
    extension = "html"

    def __init__(self, output_path: str, trend_json: str = "trend.json"):
        super().__init__(output_path)
        self.trend_json = Path(trend_json)

    def _severity_counts(self, findings: List[Finding]) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _load_history(self) -> List[dict]:
        if not self.trend_json.exists():
            return []
        try:
            with open(self.trend_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_history(self, history: List[dict]):
        self.trend_json.parent.mkdir(parents=True, exist_ok=True)
        with open(self.trend_json, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def generate(self, findings: List[Finding], target: str, metadata: dict = None) -> None:
        metadata = metadata or {}
        counts = self._severity_counts(findings)
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "target": target,
            "total": len(findings),
            "severity_counts": counts,
            "version": metadata.get("version", "2.0.0"),
        }
        history = self._load_history()
        history.append(entry)
        self._save_history(history)

        # Generate HTML trend dashboard
        labels = [h["timestamp"][:10] + " " + h["timestamp"][11:16] for h in history]
        critical = [h["severity_counts"].get("CRITICAL", 0) for h in history]
        high = [h["severity_counts"].get("HIGH", 0) for h in history]
        medium = [h["severity_counts"].get("MEDIUM", 0) for h in history]
        low = [h["severity_counts"].get("LOW", 0) for h in history]
        total = [h["total"] for h in history]

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAST Trend Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #f5f7fa; color: #2c3e50; margin: 0; }}
  .header {{ background: #1a252f; color: white; padding: 30px; text-align: center; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }}
  th {{ background: #34495e; color: white; }}
</style>
</head>
<body>
  <div class="header">
    <h1>📈 SAST Trend Dashboard</h1>
    <p>Historical vulnerability findings across scans</p>
  </div>
  <div class="container">
    <div class="card">
      <canvas id="trendChart" height="80"></canvas>
    </div>
    <div class="card">
      <h2>Scan History</h2>
      <table>
        <tr><th>Date</th><th>Target</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
        {''.join(f'<tr><td>{h["timestamp"][:16]}</td><td>{h["target"]}</td><td>{h["total"]}</td><td>{h["severity_counts"].get("CRITICAL",0)}</td><td>{h["severity_counts"].get("HIGH",0)}</td><td>{h["severity_counts"].get("MEDIUM",0)}</td><td>{h["severity_counts"].get("LOW",0)}</td></tr>' for h in history)}
      </table>
    </div>
  </div>
  <script>
    const ctx = document.getElementById('trendChart').getContext('2d');
    new Chart(ctx, {{
      type: 'line',
      data: {{
        labels: {json.dumps(labels)},
        datasets: [
          {{ label: 'Critical', data: {critical}, borderColor: '#e74c3c', tension: 0.3 }},
          {{ label: 'High', data: {high}, borderColor: '#e67e22', tension: 0.3 }},
          {{ label: 'Medium', data: {medium}, borderColor: '#f1c40f', tension: 0.3 }},
          {{ label: 'Low', data: {low}, borderColor: '#2ecc71', tension: 0.3 }},
          {{ label: 'Total', data: {total}, borderColor: '#3498db', tension: 0.3 }}
        ]
      }},
      options: {{
        responsive: true,
        plugins: {{ title: {{ display: true, text: 'Findings Over Time' }} }},
        scales: {{ y: {{ beginAtZero: true }} }}
      }}
    }});
  </script>
</body>
</html>"""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
