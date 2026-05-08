import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

from auditor.utils.aws_utils import call_with_backoff, validate_inputs

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_ebs_volumes(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_volumes')
        for page in paginator.paginate(Filters=[{'Name': 'encrypted', 'Values': ['false']}]):
            for vol in page.get('Volumes', []):
                volume_id = vol['VolumeId']
                volume_type = vol.get('VolumeType', 'Unknown')
                findings.append({
                    "AccountId": account_id,
                    "Region": region,
                    "Service": "EC2",
                    "Check": "Unencrypted EBS Volume",
                    "Status": "WARNING",
                    "Severity": "Medium",
                    "FindingType": "Storage",
                    "Details": f"Volume {volume_id} ({volume_type}) is not encrypted.",
                    "Recommendation": f"Encrypt volume: aws ec2 modify-volume --volume-id {volume_id} --encrypted",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {"CIS": "2.2.1", "NIST": "SC-13", "AWS-Well-Architected": "SEC-04"}
                })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "EC2",
            "Check": "EBS Volume Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Storage",
            "Details": f"Error auditing EBS volumes: {str(e)}",
            "Recommendation": "Verify IAM permissions for ec2:DescribeVolumes.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_kms_keys(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        kms = session.client('kms', region_name=region)
        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page.get('Keys', []):
                key_id = key['KeyId']
                try:
                    # Check key policy
                    policy = call_with_backoff(kms, 'get_key_policy', KeyId=key_id, PolicyName='default')['Policy']
                    policy_doc = json.loads(policy)
                    statements = policy_doc.get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        principal = stmt.get('Principal', {})
                        if principal.get('AWS') == '*' or principal.get('AWS', []) == ['*']:
                            findings.append({
                                "AccountId": account_id,
                                "Region": region,
                                "Service": "KMS",
                                "Check": "KMS Key Policy",
                                "Status": "WARNING",
                                "Severity": "High",
                                "FindingType": "Access",
                                "Details": f"KMS key {key_id} has overly permissive policy.",
                                "Recommendation": f"Restrict key policy: aws kms put-key-policy --key-id {key_id} --policy-name default --policy '<restrictive-policy>'",
                                "Timestamp": datetime.now(central).isoformat(),
                                "Compliance": {"CIS": "2.3.1", "NIST": "AC-6", "AWS-Well-Architected": "SEC-03"}
                            })
                    # Check key rotation
                    rotation_status = call_with_backoff(kms, 'get_key_rotation_status', KeyId=key_id)
                    if not rotation_status.get('KeyRotationEnabled'):
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "KMS",
                            "Check": "KMS Key Rotation",
                            "Status": "WARNING",
                            "Severity": "Medium",
                            "FindingType": "Encryption",
                            "Details": f"KMS key {key_id} has rotation disabled.",
                            "Recommendation": f"Enable key rotation: aws kms enable-key-rotation --key-id {key_id}",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "2.2.2", "NIST": "SC-12"}
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] != "NotFoundException":
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "KMS",
                            "Check": "KMS Key Check",
                            "Status": "ERROR",
                            "Severity": "Low",
                            "FindingType": "Access",
                            "Details": f"Error checking key {key_id}: {str(e)}",
                            "Recommendation": "Verify IAM permissions for kms:GetKeyPolicy and kms:GetKeyRotationStatus.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {}
                        })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "KMS",
            "Check": "KMS Key Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing KMS keys: {str(e)}",
            "Recommendation": "Verify IAM permissions for kms:ListKeys.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_eks_clusters(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        eks = session.client('eks', region_name=region)
        paginator = eks.get_paginator('list_clusters')
        for page in paginator.paginate():
            for cluster in page.get('clusters', []):
                try:
                    cluster_info = call_with_backoff(eks, 'describe_cluster', name=cluster)['cluster']
                    # Check public endpoint
                    if cluster_info.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False):
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "EKS",
                            "Check": "EKS Public Endpoint",
                            "Status": "FAIL",
                            "Severity": "High",
                            "FindingType": "Network",
                            "Details": f"EKS cluster {cluster} has a public endpoint.",
                            "Recommendation": f"Restrict endpoint: aws eks update-cluster-config --name {cluster} --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "4.1.1", "NIST": "SC-7", "AWS-Well-Architected": "SEC-05"}
                        })
                    # Check control plane logging
                    logging_config = cluster_info.get('logging', {}).get('clusterLogging', [])
                    enabled_logs = [log_type for log in logging_config for log_type in log.get('types', []) if log.get('enabled')]
                    required_logs = ['api', 'audit', 'authenticator']
                    missing_logs = [log for log in required_logs if log not in enabled_logs]
                    if missing_logs:
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "EKS",
                            "Check": "EKS Control Plane Logging",
                            "Status": "WARNING",
                            "Severity": "Medium",
                            "FindingType": "Logging",
                            "Details": f"EKS cluster {cluster} is missing control plane logs: {', '.join(missing_logs)}.",
                            "Recommendation": f"Enable logging: aws eks update-cluster-config --name {cluster} --logging 'clusterLogging=[{{\"types\":{json.dumps(required_logs)},\"enabled\":true}}]'",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "2.2.3", "NIST": "AU-3"}
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] != "ResourceNotFoundException":
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "EKS",
                            "Check": "EKS Cluster Check",
                            "Status": "ERROR",
                            "Severity": "Low",
                            "FindingType": "Network",
                            "Details": f"Error checking cluster {cluster}: {str(e)}",
                            "Recommendation": "Verify IAM permissions for eks:DescribeCluster.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {}
                        })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "EKS",
            "Check": "EKS Cluster Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Network",
            "Details": f"Error auditing EKS clusters: {str(e)}",
            "Recommendation": "Verify IAM permissions for eks:ListClusters.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_lambda_functions(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        lambda_client = session.client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_functions')
        deprecated_runtimes = ['python3.6', 'python3.7', 'nodejs12.x', 'nodejs10.x', 'ruby2.5']
        for page in paginator.paginate():
            for func in page.get('Functions', []):
                func_name = func['FunctionName']
                runtime = func.get('Runtime', 'Unknown')
                # Check for deprecated runtimes
                if runtime in deprecated_runtimes:
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "Lambda",
                        "Check": "Lambda Runtime",
                        "Status": "WARNING",
                        "Severity": "Medium",
                        "FindingType": "Security",
                        "Details": f"Lambda function {func_name} uses deprecated runtime {runtime}.",
                        "Recommendation": f"Update runtime: aws lambda update-function-configuration --function-name {func_name} --runtime python3.9",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "4.1.2", "NIST": "SI-2"}
                    })
                # Check for public function URLs
                try:
                    url_config = call_with_backoff(lambda_client, 'get_function_url_config', FunctionName=func_name)
                    if url_config.get('AuthType') == 'NONE':
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "Lambda",
                            "Check": "Lambda URL Exposure",
                            "Status": "FAIL",
                            "Severity": "Critical",
                            "FindingType": "PublicAccess",
                            "Details": f"Lambda function {func_name} has a public URL with no authentication.",
                            "Recommendation": f"Add authentication: aws lambda update-function-url-config --function-name {func_name} --auth-type AWS_IAM",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "4.1.2", "NIST": "AC-6"}
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] != "ResourceNotFoundException":
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "Lambda",
                            "Check": "Lambda URL Check",
                            "Status": "ERROR",
                            "Severity": "Low",
                            "FindingType": "Security",
                            "Details": f"Error checking URL config for {func_name}: {str(e)}",
                            "Recommendation": "Verify IAM permissions for lambda:GetFunctionUrlConfig.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {}
                        })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "Lambda",
            "Check": "Lambda Function Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Security",
            "Details": f"Error auditing Lambda functions: {str(e)}",
            "Recommendation": "Verify IAM permissions for lambda:ListFunctions.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_macie_protection(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        macie = session.client('macie2', region_name=region)
        status = call_with_backoff(macie, 'get_macie_session').get('status')
        if status != 'ENABLED':
            findings.append({
                "AccountId": account_id,
                "Region": region,
                "Service": "Macie",
                "Check": "Macie Protection",
                "Status": "FAIL",
                "Severity": "High",
                "FindingType": "DataProtection",
                "Details": f"Amazon Macie is {status} in region {region}.",
                "Recommendation": f"Enable Macie: aws macie2 enable-macie --region {region}",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "2.4.3", "NIST": "SI-13", "AWS-Well-Architected": "SEC-04"}
            })
        else:
            findings.append({
                "AccountId": account_id,
                "Region": region,
                "Service": "Macie",
                "Check": "Macie Protection",
                "Status": "PASS",
                "Severity": "Low",
                "FindingType": "DataProtection",
                "Details": f"Amazon Macie is enabled in region {region}.",
                "Recommendation": "No action needed.",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "2.4.3", "NIST": "SI-13"}
            })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "Macie",
            "Check": "Macie Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "DataProtection",
            "Details": f"Error auditing Macie: {str(e)}",
            "Recommendation": "Verify IAM permissions for macie2:GetMacieSession.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_cyber_region(session, account_id, region):
    findings = []
    try:
        findings.extend(audit_ebs_volumes(session, account_id, region))
        findings.extend(audit_kms_keys(session, account_id, region))
        findings.extend(audit_eks_clusters(session, account_id, region))
        findings.extend(audit_lambda_functions(session, account_id, region))
        findings.extend(audit_macie_protection(session, account_id, region))
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "Cyber",
            "Check": "Region Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Unexpected error in region audit: {str(e)}",
            "Recommendation": "Review logs and verify cyber audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_cyber(session, account_id, regions):
    findings = []
    try:
        validate_inputs(session, account_id, regions)
        max_workers = min(len(regions), 4)  # Adjust workers based on region count
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(
                lambda region: audit_cyber_region(session, account_id, region),
                regions
            )
            for result in results:
                findings.extend(result)
        logger.info(f"Completed cyber audit for account {account_id} with {len(findings)} findings.", extra={"account_id": account_id})
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "Cyber",
            "Check": "Cyber Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session, account_id, and regions.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "Cyber",
            "Check": "Cyber Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Unexpected error in cyber audit: {str(e)}",
            "Recommendation": "Review logs and verify cyber audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings