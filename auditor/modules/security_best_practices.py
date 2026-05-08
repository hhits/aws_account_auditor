import logging
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_security_hub(session, account_id, region):
    """Audit AWS Security Hub configuration."""
    findings = []
    try:
        securityhub_client = session.client('securityhub', region_name=region)
        
        # Check if Security Hub is enabled
        try:
            securityhub_client.describe_hub()
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAccessException':
                logger.info(f"Security Hub is not enabled in account {account_id} region {region}", extra={"account_id": account_id})
                findings.append({
                    "AccountId": account_id,
                    "Region": region,
                    "Service": "SecurityHub",
                    "Check": "Security Hub Enabled",
                    "Status": "WARNING",
                    "Severity": "Medium",
                    "FindingType": "Compliance",
                    "Details": "Security Hub is not enabled in this account/region.",
                    "Recommendation": "Enable Security Hub: aws securityhub enable-security-hub",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {}
                })
                return findings
            raise

        # Proceed with audit if enabled
        response = securityhub_client.get_enabled_standards()
        standards = response.get('StandardsSubscriptions', [])
        if not standards:
            findings.append({
                "AccountId": account_id,
                "Region": region,
                "Service": "SecurityHub",
                "Check": "Security Standards Enabled",
                "Status": "FAIL",
                "Severity": "High",
                "FindingType": "Compliance",
                "Details": "No security standards are enabled.",
                "Recommendation": "Enable a standard: aws securityhub enable-security-standard --standards-arn arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "1.1"}
            })
        else:
            findings.append({
                "AccountId": account_id,
                "Region": region,
                "Service": "SecurityHub",
                "Check": "Security Standards Enabled",
                "Status": "PASS",
                "Severity": "Low",
                "FindingType": "Compliance",
                "Details": f"{len(standards)} standards enabled: {', '.join(std['StandardsArn'] for std in standards)}",
                "Recommendation": "No action needed.",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "1.1"}
            })

    except ClientError as e:
        logger.error(f"Error auditing Security Hub in {region}: {str(e)}", extra={"account_id": account_id})
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "SecurityHub",
            "Check": "Security Hub Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Compliance",
            "Details": str(e),
            "Recommendation": "Verify IAM permissions for securityhub:GetEnabledStandards.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_security_hub_all_regions(session, account_id, regions):
    """Run Security Hub audit across all specified regions."""
    all_findings = []
    for region in regions:
        findings = audit_security_hub(session, account_id, region)
        all_findings.extend(findings)
    return all_findings