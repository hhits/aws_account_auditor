STANDARD_FINDING = {
    "AccountId": str,  # Always use AccountId
    "Region": str,
    "Service": str,  # e.g., EC2, S3, IAM
    "Check": str,  # Specific check name
    "Status": str,  # PASS, WARNING, FAIL, ERROR, SKIPPED
    "Severity": str,  # Low, Medium, High, Critical
    "FindingType": str,  # e.g., Network, Storage, Access
    "Details": str,  # Human-readable description
    "Recommendation": str,  # Actionable remediation steps
    "Timestamp": str,  # ISO format
    "Compliance": dict  # e.g., {"CIS": "3.1", "PCI": "Req-7"}
}