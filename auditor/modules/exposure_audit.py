import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

from auditor.utils.aws_utils import call_with_backoff, validate_inputs

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_s3_exposure(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id, ["global"])
        s3_client = session.client('s3')
        buckets = call_with_backoff(s3_client, 'list_buckets').get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                region = call_with_backoff(s3_client, 'get_bucket_location', Bucket=bucket_name).get('LocationConstraint') or "us-east-1"
            except ClientError as e:
                if e.response['Error']['Code'] == "NoSuchBucket":
                    continue
                raise

            # Check Block Public Access
            try:
                block_public = call_with_backoff(s3_client, 'get_public_access_block', Bucket=bucket_name)
                if not all(block_public['PublicAccessBlockConfiguration'].get(key, False) for key in [
                    'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'
                ]):
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "S3",
                        "Check": "S3 Block Public Access",
                        "Status": "FAIL",
                        "Severity": "Critical",
                        "FindingType": "PublicAccess",
                        "Details": f"S3 bucket {bucket_name} has incomplete Block Public Access settings.",
                        "Recommendation": f"Enable all Block Public Access settings: aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "2.1.1", "PCI": "Req-7", "NIST": "AC-6"}
                    })
            except ClientError as e:
                if e.response['Error']['Code'] != "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "S3",
                        "Check": "S3 Block Public Access Check",
                        "Status": "ERROR",
                        "Severity": "Low",
                        "FindingType": "Error",
                        "Details": f"Error checking Block Public Access for bucket {bucket_name}: {str(e)}",
                        "Recommendation": "Verify IAM permissions for s3:GetPublicAccessBlock.",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {}
                    })

            # Check public policy
            try:
                policy_status = call_with_backoff(s3_client, 'get_bucket_policy_status', Bucket=bucket_name)
                if policy_status['PolicyStatus'].get('IsPublic'):
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "S3",
                        "Check": "S3 Public Bucket Policy",
                        "Status": "FAIL",
                        "Severity": "Critical",
                        "FindingType": "PublicAccess",
                        "Details": f"S3 bucket {bucket_name} is public via bucket policy.",
                        "Recommendation": f"Apply a restrictive bucket policy: aws s3api put-bucket-policy --bucket {bucket_name} --policy file://restrict-policy.json",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "2.1.1", "PCI": "Req-7", "NIST": "AC-6"}
                    })
            except ClientError as e:
                if e.response['Error']['Code'] != "NoSuchBucketPolicy":
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "S3",
                        "Check": "S3 Policy Check",
                        "Status": "ERROR",
                        "Severity": "Low",
                        "FindingType": "Error",
                        "Details": f"Error checking bucket {bucket_name} policy: {str(e)}",
                        "Recommendation": "Verify IAM permissions for s3:GetBucketPolicyStatus.",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {}
                    })

            # Check ACL
            try:
                acl = call_with_backoff(s3_client, 'get_bucket_acl', Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') in [
                        'http://acs.amazonaws.com/groups/global/AllUsers',
                        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    ]:
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "S3",
                            "Check": "S3 ACL Exposure",
                            "Status": "FAIL",
                            "Severity": "Critical",
                            "FindingType": "PublicAccess",
                            "Details": f"S3 bucket {bucket_name} has public ACL ({grantee.get('URI')}).",
                            "Recommendation": f"Remove public ACL: aws s3api put-bucket-acl --bucket {bucket_name} --acl private",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "2.1.1", "PCI": "Req-7", "NIST": "AC-6"}
                        })
            except ClientError as e:
                findings.append({
                    "AccountId": account_id,
                    "Region": region,
                    "Service": "S3",
                    "Check": "S3 ACL Check",
                    "Status": "ERROR",
                    "Severity": "Low",
                    "FindingType": "Error",
                    "Details": f"Error checking bucket {bucket_name} ACL: {str(e)}",
                    "Recommendation": "Verify IAM permissions for s3:GetBucketAcl.",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {}
                })

            # Check encryption
            try:
                call_with_backoff(s3_client, 'get_bucket_encryption', Bucket=bucket_name)
                findings.append({
                    "AccountId": account_id,
                    "Region": region,
                    "Service": "S3",
                    "Check": "S3 Encryption",
                    "Status": "PASS",
                    "Severity": "Low",
                    "FindingType": "Storage",
                    "Details": f"S3 bucket {bucket_name} has encryption enabled.",
                    "Recommendation": "No action needed.",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {"CIS": "2.1.2", "NIST": "SC-13"}
                })
            except ClientError as e:
                if e.response['Error']['Code'] == "ServerSideEncryptionConfigurationNotFoundError":
                    encryption_config = {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "S3",
                        "Check": "S3 Encryption",
                        "Status": "WARNING",
                        "Severity": "Medium",
                        "FindingType": "Storage",
                        "Details": f"S3 bucket {bucket_name} has no encryption configured.",
                        "Recommendation": f"Enable encryption: aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{json.dumps(encryption_config)}'",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "2.1.2", "NIST": "SC-13"}
                    })
                else:
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "S3",
                        "Check": "S3 Encryption Check",
                        "Status": "ERROR",
                        "Severity": "Low",
                        "FindingType": "Error",
                        "Details": f"Error checking bucket {bucket_name} encryption: {str(e)}",
                        "Recommendation": "Verify IAM permissions for s3:GetBucketEncryption.",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {}
                    })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "S3",
            "Check": "S3 Exposure Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing S3 buckets: {str(e)}",
            "Recommendation": "Verify IAM permissions for s3:ListBuckets.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_security_groups(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator('describe_security_groups')
        sensitive_ports = [22, 3389, 3306, 5432]  # SSH, RDP, MySQL, PostgreSQL
        for page in paginator.paginate():
            for sg in page.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                for permission in sg.get('IpPermissions', []):
                    from_port = permission.get('FromPort', -1)
                    to_port = permission.get('ToPort', -1)
                    protocol = permission.get('IpProtocol', 'All')
                    is_sensitive = from_port in sensitive_ports or to_port in sensitive_ports or (from_port == -1 and to_port == -1)
                    port_range = 'All' if from_port == -1 else f"{from_port}-{to_port}"
                    open_cidrs = [
                        (ip.get('CidrIp'), '0.0.0.0/0')
                        for ip in permission.get('IpRanges', [])
                        if ip.get('CidrIp') == '0.0.0.0/0'
                    ] + [
                        (ip.get('CidrIpv6'), '::/0')
                        for ip in permission.get('Ipv6Ranges', [])
                        if ip.get('CidrIpv6') == '::/0'
                    ]
                    for _, cidr in open_cidrs:
                        if is_sensitive:
                            findings.append({
                                "AccountId": account_id,
                                "Region": region,
                                "Service": "EC2",
                                "Check": "Security Group Exposure",
                                "Status": "FAIL",
                                "Severity": "Critical",
                                "FindingType": "PublicAccess",
                                "Details": f"Security group {sg_id} allows public access to {port_range} ({protocol}) from {cidr}.",
                                "Recommendation": f"Restrict inbound rule: aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol {protocol} --port {from_port} --cidr {cidr}",
                                "Timestamp": datetime.now(central).isoformat(),
                                "Compliance": {"CIS": "4.3.1", "PCI": "Req-1", "NIST": "SC-7", "AWS-Well-Architected": "SEC-05"}
                            })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "EC2",
            "Check": "Security Group Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing security groups: {str(e)}",
            "Recommendation": "Verify IAM permissions for ec2:DescribeSecurityGroups.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_elb_exposure(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        elbv2 = session.client("elbv2", region_name=region)
        paginator = elbv2.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page.get('LoadBalancers', []):
                lb_name = lb['LoadBalancerName']
                lb_arn = lb['LoadBalancerArn']
                if lb["Scheme"] == "internet-facing":
                    listeners = call_with_backoff(elbv2, 'describe_listeners', LoadBalancerArn=lb_arn)["Listeners"]
                    for listener in listeners:
                        if listener["Protocol"] == "HTTP":
                            findings.append({
                                "AccountId": account_id,
                                "Region": region,
                                "Service": "ELBv2",
                                "Check": "ELB Listener Protocol",
                                "Status": "FAIL",
                                "Severity": "High",
                                "FindingType": "PublicAccess",
                                "Details": f"Load Balancer {lb_name} uses insecure HTTP listener.",
                                "Recommendation": f"Update to HTTPS: aws elbv2 modify-listener --listener-arn {listener['ListenerArn']} --protocol HTTPS",
                                "Timestamp": datetime.now(central).isoformat(),
                                "Compliance": {"CIS": "4.1.3", "NIST": "SC-8"}
                            })
                        elif listener["Protocol"] == "HTTPS":
                            attributes = call_with_backoff(elbv2, 'describe_listener_attributes', ListenerArn=listener['ListenerArn'])['Attributes']
                            ssl_policy = next((attr['Value'] for attr in attributes if attr['Key'] == 'ssl_policy'), None)
                            if ssl_policy and "TLSv1.0" in ssl_policy:
                                findings.append({
                                    "AccountId": account_id,
                                    "Region": region,
                                    "Service": "ELBv2",
                                    "Check": "ELB TLS Version",
                                    "Status": "WARNING",
                                    "Severity": "Medium",
                                    "FindingType": "PublicAccess",
                                    "Details": f"Load Balancer {lb_name} uses outdated TLS policy ({ssl_policy}).",
                                    "Recommendation": f"Update to modern TLS policy: aws elbv2 modify-listener --listener-arn {listener['ListenerArn']} --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06",
                                    "Timestamp": datetime.now(central).isoformat(),
                                    "Compliance": {"CIS": "4.1.3", "NIST": "SC-8"}
                                })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "ELBv2",
            "Check": "ELB Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing ELBs: {str(e)}",
            "Recommendation": "Verify IAM permissions for elbv2:DescribeLoadBalancers and elbv2:DescribeListeners.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_rds_exposure(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page.get('DBInstances', []):
                db_instance = db['DBInstanceIdentifier']
                if db.get('PubliclyAccessible', False):
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "RDS",
                        "Check": "RDS Public Access",
                        "Status": "FAIL",
                        "Severity": "Critical",
                        "FindingType": "PublicAccess",
                        "Details": f"RDS instance {db_instance} is publicly accessible.",
                        "Recommendation": f"Disable public access: aws rds modify-db-instance --db-instance-identifier {db_instance} --no-publicly-accessible",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "4.1.1", "PCI": "Req-1", "NIST": "SC-7"}
                    })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "RDS",
            "Check": "RDS Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing RDS instances: {str(e)}",
            "Recommendation": "Verify IAM permissions for rds:DescribeDBInstances.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_ebs_snapshots(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator('describe_snapshots')
        for page in paginator.paginate(OwnerIds=['self']):
            for snapshot in page.get('Snapshots', []):
                snapshot_id = snapshot['SnapshotId']
                try:
                    permissions = call_with_backoff(ec2, 'describe_snapshot_attribute', SnapshotId=snapshot_id, Attribute='createVolumePermission')
                    for perm in permissions.get('CreateVolumePermissions', []):
                        if perm.get('Group') == 'all':
                            findings.append({
                                "AccountId": account_id,
                                "Region": region,
                                "Service": "EC2",
                                "Check": "EBS Snapshot Exposure",
                                "Status": "FAIL",
                                "Severity": "Critical",
                                "FindingType": "PublicAccess",
                                "Details": f"EBS snapshot {snapshot_id} is publicly accessible.",
                                "Recommendation": f"Restrict snapshot access: aws ec2 modify-snapshot-attribute --snapshot-id {snapshot_id} --attribute createVolumePermission --operation-type remove --group-names all",
                                "Timestamp": datetime.now(central).isoformat(),
                                "Compliance": {"CIS": "4.1.2", "PCI": "Req-7", "NIST": "AC-6"}
                            })
                except ClientError as e:
                    if e.response['Error']['Code'] != "InvalidSnapshot.NotFound":
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "EC2",
                            "Check": "EBS Snapshot Check",
                            "Status": "ERROR",
                            "Severity": "Low",
                            "FindingType": "Error",
                            "Details": f"Error checking snapshot {snapshot_id}: {str(e)}",
                            "Recommendation": "Verify IAM permissions for ec2:DescribeSnapshotAttribute.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {}
                        })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "EC2",
            "Check": "EBS Snapshot Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing EBS snapshots: {str(e)}",
            "Recommendation": "Verify IAM permissions for ec2:DescribeSnapshots.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_cloudfront_exposure(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        cloudfront = session.client("cloudfront", region_name=region)
        paginator = cloudfront.get_paginator('list_distributions')
        for page in paginator.paginate():
            distribution_list = page.get('DistributionList', {}).get('Items', [])
            for dist in distribution_list:
                dist_id = dist['Id']
                domain_name = dist['DomainName']
                viewer_protocol = dist['DefaultCacheBehavior']['ViewerProtocolPolicy']
                if viewer_protocol in ['allow-all', 'http-only']:
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "CloudFront",
                        "Check": "CloudFront Protocol",
                        "Status": "FAIL",
                        "Severity": "High",
                        "FindingType": "PublicAccess",
                        "Details": f"CloudFront distribution {dist_id} ({domain_name}) allows HTTP ({viewer_protocol}).",
                        "Recommendation": f"Update to HTTPS-only: aws cloudfront update-distribution --id {dist_id} --default-cache-behavior ViewerProtocolPolicy=https-only",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "4.1.3", "NIST": "SC-8", "AWS-Well-Architected": "SEC-05"}
                    })
                # Check TLS version — ViewerCertificate is a top-level distribution field, not inside DefaultCacheBehavior
                ssl_support = dist.get('ViewerCertificate', {}).get('MinimumProtocolVersion', 'TLSv1')
                if ssl_support in ['TLSv1', 'TLSv1_2016']:
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "CloudFront",
                        "Check": "CloudFront TLS Version",
                        "Status": "WARNING",
                        "Severity": "Medium",
                        "FindingType": "PublicAccess",
                        "Details": f"CloudFront distribution {dist_id} uses outdated TLS version ({ssl_support}).",
                        "Recommendation": f"Update to TLSv1.2 or higher: aws cloudfront update-distribution --id {dist_id} --viewer-certificate MinimumProtocolVersion=TLSv1.2_2021",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "4.1.3", "NIST": "SC-8"}
                    })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "CloudFront",
            "Check": "CloudFront Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing CloudFront distributions: {str(e)}",
            "Recommendation": "Verify IAM permissions for cloudfront:ListDistributions.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_api_gateway_exposure(session, account_id, region):
    findings = []
    try:
        validate_inputs(session, account_id, [region])
        apigateway = session.client("apigateway", region_name=region)
        paginator = apigateway.get_paginator('get_rest_apis')
        for page in paginator.paginate():
            for api in page.get('items', []):
                api_id = api['id']
                api_name = api['name']
                # Check stages for public access
                stages = call_with_backoff(apigateway, 'get_stages', restApiId=api_id)['item']
                for stage in stages:
                    stage_name = stage['stageName']
                    # Check for missing authorization
                    resources = call_with_backoff(apigateway, 'get_resources', restApiId=api_id)['items']
                    for resource in resources:
                        for method, settings in resource.get('resourceMethods', {}).items():
                            auth_type = settings.get('authorizationType', 'NONE')
                            if auth_type == 'NONE':
                                findings.append({
                                    "AccountId": account_id,
                                    "Region": region,
                                    "Service": "APIGateway",
                                    "Check": "API Gateway Authorization",
                                    "Status": "FAIL",
                                    "Severity": "Critical",
                                    "FindingType": "PublicAccess",
                                    "Details": f"API Gateway {api_name} (stage: {stage_name}) has resource {resource['id']} with no authorization for {method}.",
                                    "Recommendation": f"Add authorization (e.g., IAM, Lambda): aws apigateway update-method --rest-api-id {api_id} --resource-id {resource['id']} --http-method {method} --authorization-type AWS_IAM",
                                    "Timestamp": datetime.now(central).isoformat(),
                                    "Compliance": {"CIS": "4.1.2", "PCI": "Req-6", "NIST": "AC-6"}
                                })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "APIGateway",
            "Check": "API Gateway Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing API Gateway: {str(e)}",
            "Recommendation": "Verify IAM permissions for apigateway:GetRestApis, apigateway:GetStages, apigateway:GetResources.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_exposure_region(session, account_id, region):
    findings = []
    try:
        findings.extend(audit_security_groups(session, account_id, region))
        findings.extend(audit_elb_exposure(session, account_id, region))
        findings.extend(audit_rds_exposure(session, account_id, region))
        findings.extend(audit_ebs_snapshots(session, account_id, region))
        findings.extend(audit_cloudfront_exposure(session, account_id, region))
        findings.extend(audit_api_gateway_exposure(session, account_id, region))
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "Exposure",
            "Check": "Region Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Unexpected error in region audit: {str(e)}",
            "Recommendation": "Review logs and verify exposure audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_exposure(session, account_id, regions):
    findings = []
    try:
        validate_inputs(session, account_id, regions)
        findings.extend(audit_s3_exposure(session, account_id))
        max_workers = min(len(regions), 4)  # Adjust workers based on region count
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(
                lambda region: audit_exposure_region(session, account_id, region),
                regions
            )
            for result in results:
                findings.extend(result)
        logger.info(f"Completed exposure audit for account {account_id} with {len(findings)} findings.", extra={"account_id": account_id})
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "Exposure",
            "Check": "Exposure Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session, account_id, and regions.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "Exposure",
            "Check": "Exposure Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Unexpected error in exposure audit: {str(e)}",
            "Recommendation": "Review logs and verify exposure audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings
def audit_lambda_urls(session, account_id, region):
    findings = []
    try:
        lambda_client = session.client("lambda", region_name=region)
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page.get('Functions', []):
                func_name = func['FunctionName']
                config = call_with_backoff(lambda_client, 'get_function_url_config', FunctionName=func_name)
                if config.get('AuthType') == 'NONE':
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "Lambda",
                        "Check": "Lambda URL Exposure",
                        "Status": "FAIL",
                        "Severity": "Critical",
                        "FindingType": "PublicAccess",
                        "Details": f"Lambda function {func_name} has publicly accessible URL with no authentication.",
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
                "Check": "Lambda URL Audit",
                "Status": "ERROR",
                "Severity": "Low",
                "FindingType": "Error",
                "Details": f"Error auditing Lambda URLs: {str(e)}",
                "Recommendation": "Verify IAM permissions for lambda:ListFunctions and lambda:GetFunctionUrlConfig.",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {}
            })
    return findings
def audit_beanstalk_exposure(session, account_id, region):
    findings = []
    try:
        beanstalk = session.client("elasticbeanstalk", region_name=region)
        paginator = beanstalk.get_paginator('describe_environments')
        for page in paginator.paginate():
            for env in page.get('Environments', []):
                env_name = env['EnvironmentName']
                if not env.get('EndpointURL'):
                    continue
                try:
                    resources = beanstalk.describe_environment_resources(EnvironmentName=env_name)
                    load_balancers = resources.get('EnvironmentResources', {}).get('LoadBalancers', [])
                    if load_balancers:
                        findings.append({
                            "AccountId": account_id,
                            "Region": region,
                            "Service": "ElasticBeanstalk",
                            "Check": "Beanstalk Public Exposure",
                            "Status": "WARNING",
                            "Severity": "High",
                            "FindingType": "PublicAccess",
                            "Details": f"Elastic Beanstalk environment {env_name} is internet-facing with a load balancer.",
                            "Recommendation": f"Review load balancer configuration for {env_name} and restrict public access if unnecessary.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "4.1.1", "NIST": "SC-7"}
                        })
                except ClientError as e:
                    logger.warning(f"Could not describe resources for Beanstalk env {env_name}: {str(e)}", extra={"account_id": account_id})
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": region,
            "Service": "ElasticBeanstalk",
            "Check": "Beanstalk Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Error",
            "Details": f"Error auditing Beanstalk environments: {str(e)}",
            "Recommendation": "Verify IAM permissions for elasticbeanstalk:DescribeEnvironments.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings
