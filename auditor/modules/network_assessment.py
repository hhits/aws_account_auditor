import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_network(session, account_id, region):
    """Audit network configurations (e.g., security groups, ELBs)."""
    findings = []
    try:
        # Use the provided session with correct service name 'elbv2'
        ec2_client = session.client('ec2', region_name=region)
        elbv2_client = session.client('elbv2', region_name=region)

        # Audit security groups
        paginator = ec2_client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                for perm in sg.get('IpPermissions', []):
                    from_port = str(perm.get('FromPort', 'All'))
                    to_port = str(perm.get('ToPort', 'All'))
                    proto = perm.get('IpProtocol', 'All')
                    open_cidrs = [
                        ip['CidrIp'] for ip in perm.get('IpRanges', []) if ip.get('CidrIp') == '0.0.0.0/0'
                    ] + [
                        ip['CidrIpv6'] for ip in perm.get('Ipv6Ranges', []) if ip.get('CidrIpv6') == '::/0'
                    ]
                    for cidr in open_cidrs:
                        details = f"Security group {sg_id} allows {proto} from {from_port}-{to_port} to {cidr}."
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "EC2",
                            "Check": "Security Group Public Access",
                            "Status": "FAIL",
                            "Severity": "Critical",
                            "FindingType": "Network",
                            "Details": details,
                            "Recommendation": f"Restrict access: aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol {proto} --port {from_port} --cidr {cidr}",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "4.3.1", "NIST": "SC-7"}
                        })

        # Audit ELBs
        elb_paginator = elbv2_client.get_paginator('describe_load_balancers')
        for page in elb_paginator.paginate():
            for elb in page.get('LoadBalancers', []):
                try:
                    # Get listeners to obtain ListenerArn
                    listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=elb['LoadBalancerArn'])
                    listeners = listeners_response.get('Listeners', [])
                    for listener in listeners:
                        attributes_response = elbv2_client.describe_listener_attributes(
                            ListenerArn=listener['ListenerArn']  # Ensure ListenerArn is used
                        )
                        attributes = attributes_response.get('ListenerAttributes', [])
                        if attributes:
                            access_log_enabled = any(
                                attr.get('Key') == 'access_logs.s3.enabled' and attr.get('Value', 'false').lower() == 'true'
                                for attr in attributes
                            )
                            if not access_log_enabled:
                                details = f"ELB {elb['LoadBalancerName']} has access logging disabled for listener {listener['ListenerArn']}."
                                findings.append({
                                    "AccountId": account_id,
                                    "Region": region,
                                    "Service": "ELBv2",
                                    "Check": "ELB Access Logging",
                                    "Status": "WARNING",
                                    "Severity": "Medium",
                                    "FindingType": "Network",
                                    "Details": details,
                                    "Recommendation": f"Enable access logging: aws elbv2 modify-listener-attributes --listener-arn {listener['ListenerArn']} --attributes AccessLog={{Enabled=true}}",
                                    "Timestamp": datetime.now(central).isoformat(),
                                    "Compliance": {"CIS": "4.3.2"}
                                })
                except ClientError as e:
                    logger.warning(f"Error auditing ELB {elb.get('LoadBalancerName', 'Unknown')}: {str(e)}", extra={"account_id": account_id})

    except ClientError as e:
        logger.error(f"Error auditing network in {region}: {str(e)}", extra={"account_id": account_id})
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "Network",
            "Check": "Network Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Network",
            "Details": str(e),
            "Recommendation": "Verify IAM permissions for ec2:DescribeSecurityGroups and elbv2:DescribeLoadBalancers.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except Exception as e:
        logger.error(f"Unexpected error in network audit for {account_id} in {region}: {str(e)}", extra={"account_id": account_id})
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "Network",
            "Check": "Network Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Network",
            "Details": str(e),
            "Recommendation": "Review logs and verify network audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_network_all_regions(session, account_id, regions):
    """Run network audit across all specified regions in parallel."""
    all_findings = []
    with ThreadPoolExecutor(max_workers=len(regions)) as executor:
        for result in executor.map(lambda r: audit_network(session, account_id, r), regions):
            all_findings.extend(result)
    return all_findings