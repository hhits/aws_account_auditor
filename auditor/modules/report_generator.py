import json
import os
import logging
import csv
from datetime import datetime
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def save_findings_json(findings, output_path):
    try:
        with open(output_path, "w") as f:
            json.dump(findings, f, indent=2)
        os.chmod(output_path, 0o600)
        logger.info(f"Saved JSON findings to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save JSON findings: {str(e)}")

def save_findings_csv(findings, output_path):
    try:
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["AccountId", "Region", "Service", "Check", "Status", "Severity", "FindingType", "Details", "Recommendation", "Timestamp", "Compliance"])
            writer.writeheader()
            for finding in findings:
                finding["Compliance"] = json.dumps(finding.get("Compliance", {}))
                writer.writerow(finding)
        os.chmod(output_path, 0o600)
        logger.info(f"Saved CSV findings to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save CSV findings: {str(e)}")

def save_findings_html(findings, output_path):
    try:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding.get("Severity", "Low")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        with open(output_path, "w") as f:
            f.write(f"""
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .Critical {{ color: #d32f2f; font-weight: bold; }}
        .High {{ color: #f44336; }}
        .Medium {{ color: #ff9800; }}
        .Low {{ color: #4caf50; }}
        .ERROR {{ background-color: #ffebee; }}
        .WARNING {{ background-color: #fff3e0; }}
        .SKIPPED {{ background-color: #fff9c4; }}
        .summary {{ margin-bottom: 20px; padding: 10px; background-color: #e3f2fd; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>AWS Multi-Account Audit Findings</h1>
    <div class="summary">
        <p><strong>Generated:</strong> {datetime.now(central).strftime('%Y-%m-%d %H:%M:%S %Z')}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
        <p><strong>By Severity:</strong> Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, Medium: {severity_counts['Medium']}, Low: {severity_counts['Low']}</p>
    </div>
    <table>
        <tr>
            <th>Account ID</th>
            <th>Region</th>
            <th>Service</th>
            <th>Check</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Finding Type</th>
            <th>Details</th>
            <th>Recommendation</th>
            <th>Timestamp</th>
            <th>Compliance</th>
        </tr>
""")
            for finding in findings:
                status = finding.get("Status", "")
                severity = finding.get("Severity", "Low")
                compliance = json.dumps(finding.get("Compliance", {}))
                f.write(f"""
        <tr class="{status}">
            <td>{finding.get('AccountId', '')}</td>
            <td>{finding.get('Region', '')}</td>
            <td>{finding.get('Service', '')}</td>
            <td>{finding.get('Check', '')}</td>
            <td>{status}</td>
            <td class="{severity}">{severity}</td>
            <td>{finding.get('FindingType', '')}</td>
            <td>{finding.get('Details', '')}</td>
            <td>{finding.get('Recommendation', '')}</td>
            <td>{finding.get('Timestamp', '')}</td>
            <td>{compliance}</td>
        </tr>
""")
            f.write("</table></body></html>")
        os.chmod(output_path, 0o600)
        logger.info(f"Saved HTML findings to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save HTML findings: {str(e)}")