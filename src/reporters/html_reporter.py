import datetime
from typing import Any, List
from .base import BaseReporter


class HTMLReporter(BaseReporter):
    def generate(self, results: Any, output_path: str = "") -> str:
        if isinstance(results, list):
            findings: List[dict] = []
            total_files = 0
            for r in results:
                if hasattr(r, "findings"):
                    findings.extend(r.findings)
                    total_files += r.total_files
                elif isinstance(r, dict):
                    findings.extend(r.get("findings", []))
                    total_files += r.get("total_files", 0)
        elif hasattr(results, "findings"):
            findings = results.findings
            total_files = results.total_files
        else:
            findings = []
            total_files = 0

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "medium") if isinstance(f, dict) else "medium"
            if sev in severity_counts:
                severity_counts[sev] += 1

        rows_html = ""
        for i, f in enumerate(findings, 1):
            if isinstance(f, dict):
                sev = f.get("severity", "medium")
                subtype = f.get("subtype", "unknown")
                file_path = f.get("file_path", "")
                risk = f.get("risk", "")
                context = f.get("context", "")
                line = f.get("line", 0)
                masked = f.get("value", "")

                color = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745"}.get(sev, "#6c757d")

                rows_html += f"""
                <tr>
                    <td>{i}</td>
                    <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
                    <td>{subtype}</td>
                    <td><code>{masked}</code></td>
                    <td>{file_path}:{line}</td>
                    <td>{context[:80]}</td>
                </tr>"""

        report_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DataGuardian Scan Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
    header h1 {{ font-size: 24px; margin-bottom: 5px; }}
    header p {{ opacity: 0.8; font-size: 14px; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
    .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
    .card h3 {{ font-size: 12px; text-transform: uppercase; color: #6c757d; margin-bottom: 5px; }}
    .card .value {{ font-size: 28px; font-weight: 700; }}
    .severity-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }}
    .sev-card {{ padding: 15px; border-radius: 8px; color: white; text-align: center; }}
    .sev-card h4 {{ font-size: 12px; opacity: 0.9; margin-bottom: 5px; }}
    .sev-card .count {{ font-size: 24px; font-weight: 700; }}
    table {{ width: 100%; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-collapse: collapse; }}
    th {{ background: #f8f9fa; padding: 12px 15px; text-align: left; font-size: 12px; text-transform: uppercase; color: #6c757d; border-bottom: 2px solid #dee2e6; }}
    td {{ padding: 10px 15px; border-bottom: 1px solid #eee; font-size: 13px; }}
    tr:hover {{ background: #f8f9fa; }}
    code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
    .badge {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
    .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>🛡️ DataGuardian Scan Report</h1>
        <p>Generated: {report_time} | Total Findings: {len(findings)} | Files Scanned: {total_files}</p>
    </header>

    <div class="summary">
        <div class="card">
            <h3>Files Scanned</h3>
            <div class="value">{total_files}</div>
        </div>
        <div class="card">
            <h3>Total Findings</h3>
            <div class="value">{len(findings)}</div>
        </div>
        <div class="card">
            <h3>Categories</h3>
            <div class="value">{len(set(f.get('category', 'unknown') for f in findings if isinstance(f, dict)))}</div>
        </div>
        <div class="card">
            <h3>Report Time</h3>
            <div class="value" style="font-size:16px">{report_time}</div>
        </div>
    </div>

    <div class="severity-cards">
        <div class="sev-card" style="background:#dc3545">
            <h4>Critical</h4>
            <div class="count">{severity_counts["critical"]}</div>
        </div>
        <div class="sev-card" style="background:#fd7e14">
            <h4>High</h4>
            <div class="count">{severity_counts["high"]}</div>
        </div>
        <div class="sev-card" style="background:#ffc107;color:#333">
            <h4>Medium</h4>
            <div class="count">{severity_counts["medium"]}</div>
        </div>
        <div class="sev-card" style="background:#28a745">
            <h4>Low</h4>
            <div class="count">{severity_counts["low"]}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Value</th>
                <th>Location</th>
                <th>Context</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else "<tr><td colspan='6' style='text-align:center;padding:30px;color:#6c757d'>No findings detected</td></tr>"}
        </tbody>
    </table>

    <div class="footer">
        DataGuardian v1.0.0 &mdash; Data Security Scanner
    </div>
</div>
</body>
</html>"""

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        return html
