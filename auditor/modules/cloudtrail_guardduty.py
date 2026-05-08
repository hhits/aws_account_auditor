import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_cloudtrail(session, account_id, region):
    """Audit CloudTrail configuration."""
    findings = []
    try:
        cloudtrail_client = session.client('cloudtrail', region_name=region)
        
        # Use direct call to get all trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        if not trails:
            findings.append({
                "AccountId": account_id,
                "Region": region,
                "Service": "CloudTrail",
                "Check": "CloudTrail Enabled",
                "Status": "FAIL",
                "Severity": "High",
                "FindingType": "Compliance",
                "Details": "No CloudTrail trails found in this region.",
                "Recommendation": "Create a trail: aws cloudtrail create-trail --name MyTrail --s3-bucket-name my-bucket",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "3.1"}
            })
        else:
            for trail in trails:
                trail_name = trail.get('Name', 'Unknown')
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                try:
                    status = cloudtrail_client.get_trail_status(Name=trail_name)
                    is_logging = status.get('IsLogging', False)
                    if not is_logging:
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "CloudTrail",
                            "Check": "CloudTrail Logging",
                            "Status": "FAIL",
                            "Severity": "Critical",
                            "FindingType": "Compliance",
                            "Details": f"Trail {trail_name} is not logging.",
                            "Recommendation": f"Start logging: aws cloudtrail start-logging --name {trail_name}",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "3.2"}
                        })
                    else:
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "CloudTrail",
                            "Check": "CloudTrail Logging",
                            "Status": "PASS",
                            "Severity": "Low",
                            "FindingType": "Compliance",
                            "Details": f"Trail {trail_name} is logging, multi-region: {is_multi_region}.",
                            "Recommendation": "No action needed.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "3.2"}
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'TrailNotFoundException':
                        logger.warning(f"Trail {trail_name} not found or inaccessible in {region}, skipping status check", extra={"account_id": account_id})
                    else:
                        logger.error(f"Error checking status for trail {trail_name} in {region}: {str(e)}", extra={"account_id": account_id})
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "CloudTrail",
                            "Check": "CloudTrail Status Check",
                            "Status": "ERROR",
                            "Severity": "Low",
                            "FindingType": "Compliance",
                            "Details": str(e),
                            "Recommendation": "Verify trail configuration or IAM permissions.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {}
                        })

    except ClientError as e:
        logger.error(f"Error auditing CloudTrail in {region}: {str(e)}", extra={"account_id": account_id})
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "CloudTrail",
            "Check": "CloudTrail Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Compliance",
            "Details": str(e),
            "Recommendation": "Verify IAM permissions for cloudtrail:DescribeTrails.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_cloudtrail_all_regions(session, account_id, regions):
    """Run CloudTrail audit across all specified regions in parallel."""
    all_findings = []
    with ThreadPoolExecutor(max_workers=len(regions)) as executor:
        for result in executor.map(lambda r: audit_cloudtrail(session, account_id, r), regions):
            all_findings.extend(result)
    return all_findings