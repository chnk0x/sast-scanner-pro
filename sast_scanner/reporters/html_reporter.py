"""HTML dashboard reporter."""
import datetime
import html
from pathlib import Path
from typing import List

from .base_reporter import BaseReporter
from ..models import Finding, Severity


class HTMLReporter(BaseReporter):
    """Generates a client-ready HTML security audit report."""

    name = "html"
    extension = "html"

    def generate(self, findings: List[Finding], target: str, metadata: dict = None) -> None:
        metadata = metadata or {}
        counts = self._severity_counts(findings)
        total = len(findings)
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = ""
        for f in sorted(findings, key=lambda x: x.severity_rank):
            severity_color = {
                Severity.CRITICAL: "#e74c3c",
                Severity.HIGH: "#e67e22",
                Severity.MEDIUM: "#f1c40f",
                Severity.LOW: "#2ecc71",
                Severity.INFO: "#3498db",
            }.get(f.severity, "#95a5a6")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{severity_color}">{f.severity.value}</span></td>
              <td><strong>{html.escape(f.rule_name)}</strong><br><small>{html.escape(f.rule_id)}</small></td>
              <td>
                <code>{html.escape(f.file_path)}</code><br>
                <small>Line {f.line_number}, Col {f.column}</small>
              </td>
              <td><pre class="code-snippet">{html.escape(f.snippet)}</pre></td>
              <td>
                <p>{html.escape(f.description)}</p>
                <p><strong>CWE:</strong> {html.escape(f.cwe_id or "N/A")}<br>
                <strong>OWASP:</strong> {html.escape(f.owasp_category or "N/A")}<br>
                <strong>CVSS:</strong> {f.cvss_score or "N/A"} {html.escape(f.cvss_vector or "")}</p>
                <p><strong>Remediation:</strong> {html.escape(f.remediation)}</p>
                <p><strong>Engine:</strong> {html.escape(f.engine)} | <strong>Confidence:</strong> {html.escape(f.confidence.value)}</p>
              </td>
            </tr>
            """
        if not rows:
            rows = '<tr><td colspan="5" class="text-center">No verified security findings detected. 🎉</td></tr>'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAST Security Audit Report</title>
<style>
  :root {{ --bg: #f5f7fa; --card: #ffffff; --text: #2c3e50; --accent: #3498db; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0; }}
  .header {{ background: linear-gradient(135deg, #1a252f 0%, #2c3e50 100%); color: white; padding: 40px 30px; text-align: center; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 30px 0; }}
  .card {{ background: var(--card); border-radius: 10px; padding: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); text-align: center; }}
  .card h3 {{ margin: 0 0 10px; font-size: 0.95rem; color: #7f8c8d; }}
  .card .number {{ font-size: 2.2rem; font-weight: 700; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); box-shadow: 0 4px 15px rgba(0,0,0,0.08); border-radius: 10px; overflow: hidden; }}
  th, td {{ padding: 14px 16px; text-align: left; border-bottom: 1px solid #ecf0f1; vertical-align: top; }}
  th {{ background: #34495e; color: white; font-weight: 600; }}
  tr:hover {{ background: #f8f9fa; }}
  .badge {{ display: inline-block; padding: 5px 10px; border-radius: 5px; color: white; font-weight: 700; font-size: 0.8rem; }}
  .code-snippet {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; margin: 0; }}
  .text-center {{ text-align: center; color: #7f8c8d; }}
  .footer {{ text-align: center; padding: 20px; color: #7f8c8d; font-size: 0.85rem; }}
</style>
</head>
<body>
  <div class="header">
    <h1>🛡️ SAST Security Audit Report</h1>
    <p>Next-Generation Static Application Security Testing</p>
  </div>
  <div class="container">
    <div class="summary">
      <div class="card"><h3>Total Findings</h3><div class="number">{total}</div></div>
      <div class="card"><h3>Critical</h3><div class="number" style="color:#e74c3c">{counts['CRITICAL']}</div></div>
      <div class="card"><h3>High</h3><div class="number" style="color:#e67e22">{counts['HIGH']}</div></div>
      <div class="card"><h3>Medium</h3><div class="number" style="color:#f1c40f">{counts['MEDIUM']}</div></div>
      <div class="card"><h3>Low</h3><div class="number" style="color:#2ecc71">{counts['LOW']}</div></div>
    </div>
    <p><strong>Target:</strong> <code>{html.escape(target)}</code><br>
    <strong>Scan Date:</strong> {date}<br>
    <strong>Scanner Version:</strong> {html.escape(metadata.get('version', '2.0.0'))}</p>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Vulnerability</th>
          <th>Location</th>
          <th>Code Snippet</th>
          <th>Details & Remediation</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
  <div class="footer">
    Generated by SAST-VULN-SCANNER-PRO · Senior Cyber Security Project
  </div>
</body>
</html>"""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
