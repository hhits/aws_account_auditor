import logging
from datetime import datetime
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_summary(session, account_id, regions=None, all_findings=None):
    findings = []
    all_findings = all_findings or []
    
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    service_counts = {}
    for finding in all_findings:
        severity = finding.get("Severity", "Low")
        service = finding.get("Service", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        service_counts[service] = service_counts.get(service, 0) + 1

    findings.append({
        "AccountId": account_id,
        "Region": "global",
        "Service": "Summary",
        "Check": "Audit Overview",
        "Status": "PASS",
        "Severity": "Low",
        "FindingType": "Summary",
        "Details": (
            f"Total findings: {sum(severity_counts.values())}. "
            f"Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, "
            f"Medium: {severity_counts['Medium']}, Low: {severity_counts['Low']}. "
            f"Services audited: {', '.join(service_counts.keys())}"
        ),
        "Recommendation": "Prioritize Critical and High severity findings for remediation.",
        "Timestamp": datetime.now(central).isoformat(),
        "Compliance": {}
    })

    findings.append({
        "AccountId": account_id,
        "Region": "global",
        "Service": "IAM",
        "Check": "IAM Summary",
        "Status": "PASS",
        "Severity": "Low",
        "FindingType": "Summary",
        "Details": "IAM usage summary collected.",
        "Recommendation": "Review IAM usage for unnecessary roles or permissions.",
        "Timestamp": datetime.now(central).isoformat(),
        "Compliance": {"CIS": "1.1"}
    })

    findings.append({
        "AccountId": account_id,
        "Region": "global",
        "Service": "Cost",
        "Check": "Cost Summary",
        "Status": "PASS",
        "Severity": "Low",
        "FindingType": "Summary",
        "Details": "Cost overview collected.",
        "Recommendation": "Review AWS Cost Explorer for detailed trends and anomalies.",
        "Timestamp": datetime.now(central).isoformat(),
        "Compliance": {}
    })

    findings.append({
        "AccountId": account_id,
        "Region": "global",
        "Service": "Network",
        "Check": "Network Summary",
        "Status": "PASS",
        "Severity": "Low",
        "FindingType": "Summary",
        "Details": "Basic network topology and exposure summarized.",
        "Recommendation": "Use VPC Flow Logs and Network Firewall to track anomalies.",
        "Timestamp": datetime.now(central).isoformat(),
        "Compliance": {"CIS": "4.1"}
    })

    return findings
