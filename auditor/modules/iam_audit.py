import logging
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

from auditor.utils.aws_utils import call_with_backoff, validate_inputs, get_credential_report

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")


def audit_iam_users(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id)
        iam = session.client('iam')
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                user_name = user['UserName']
                last_used = user.get('PasswordLastUsed')
                if not last_used:
                    findings.append({
                        "AccountId": account_id,
                        "Region": "global",
                        "Service": "IAM",
                        "Check": "IAM User Activity",
                        "Status": "WARNING",
                        "Severity": "Medium",
                        "FindingType": "Access",
                        "Details": f"IAM user {user_name} has never used their password.",
                        "Recommendation": f"Review user {user_name} for deactivation: aws iam delete-login-profile --user-name {user_name}",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "1.4", "NIST": "IA-5"}
                    })
                else:
                    findings.append({
                        "AccountId": account_id,
                        "Region": "global",
                        "Service": "IAM",
                        "Check": "IAM User Activity",
                        "Status": "PASS",
                        "Severity": "Low",
                        "FindingType": "Access",
                        "Details": f"IAM user {user_name} is active.",
                        "Recommendation": "No action needed.",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "1.4", "NIST": "IA-5"}
                    })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM User Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing users: {str(e)}",
            "Recommendation": "Verify IAM permissions for iam:ListUsers.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM User Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session and account_id.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings


def audit_iam_mfa(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id)
        iam = session.client('iam')
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                user_name = user['UserName']
                try:
                    mfa_devices = call_with_backoff(iam, 'list_mfa_devices', UserName=user_name)['MFADevices']
                    if not mfa_devices and user.get('PasswordLastUsed'):
                        findings.append({
                            "AccountId": account_id,
                            "Region": "global",
                            "Service": "IAM",
                            "Check": "IAM MFA",
                            "Status": "FAIL",
                            "Severity": "Critical",
                            "FindingType": "Access",
                            "Details": f"IAM user {user_name} has console access but no MFA enabled.",
                            "Recommendation": f"Enable MFA for {user_name} via AWS Console.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "1.2", "PCI": "Req-8", "NIST": "IA-2"}
                        })
                    elif mfa_devices:
                        mfa_type = "Virtual" if any(d['SerialNumber'].startswith('arn:') for d in mfa_devices) else "Hardware"
                        findings.append({
                            "AccountId": account_id,
                            "Region": "global",
                            "Service": "IAM",
                            "Check": "IAM MFA",
                            "Status": "PASS",
                            "Severity": "Low",
                            "FindingType": "Access",
                            "Details": f"IAM user {user_name} has {mfa_type} MFA enabled.",
                            "Recommendation": "No action needed.",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "1.2", "PCI": "Req-8", "NIST": "IA-2"}
                        })
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        logger.info(f"No MFA devices for user {user_name}, skipping.")
                    else:
                        raise
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM MFA Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing MFA: {str(e)}",
            "Recommendation": "Verify IAM permissions for iam:ListMFADevices.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM MFA Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session and account_id.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings


def audit_iam_credential_report(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id)
        iam = session.client('iam')
        rows = get_credential_report(iam)
        for row in rows:
            user_name = row['user']
            key1_active = row.get('access_key_1_active', 'false') == 'true'
            key2_active = row.get('access_key_2_active', 'false') == 'true'
            key1_last_rotated = row.get('access_key_1_last_rotated', 'N/A')
            key2_last_rotated = row.get('access_key_2_last_rotated', 'N/A')

            if key1_active or key2_active:
                findings.append({
                    "AccountId": account_id,
                    "Region": "global",
                    "Service": "IAM",
                    "Check": "IAM Access Key",
                    "Status": "WARNING",
                    "Severity": "High",
                    "FindingType": "Access",
                    "Details": f"IAM user {user_name} has active access key(s).",
                    "Recommendation": f"Rotate or delete access keys for {user_name}: aws iam delete-access-key --user-name {user_name} --access-key-id <key-id>",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {"CIS": "1.4", "NIST": "IA-5"}
                })

            for key_num, last_rotated_str in [(1, key1_last_rotated), (2, key2_last_rotated)]:
                if last_rotated_str and last_rotated_str != 'N/A':
                    from dateutil import parser as dateutil_parser
                    rotation_date = dateutil_parser.parse(last_rotated_str)
                    days_old = (datetime.now(central) - rotation_date.replace(tzinfo=central)).days
                    if days_old > 90:
                        findings.append({
                            "AccountId": account_id,
                            "Region": "global",
                            "Service": "IAM",
                            "Check": f"IAM Access Key Age (Key {key_num})",
                            "Status": "WARNING",
                            "Severity": "High",
                            "FindingType": "Access",
                            "Details": f"IAM user {user_name} access key {key_num} is {days_old} days old.",
                            "Recommendation": f"Rotate access key for {user_name}: aws iam update-access-key --user-name {user_name} --access-key-id <key-id>",
                            "Timestamp": datetime.now(central).isoformat(),
                            "Compliance": {"CIS": "1.4", "NIST": "IA-5"}
                        })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Credential Report Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing credential report: {str(e)}",
            "Recommendation": "Verify IAM permissions for iam:GetCredentialReport and iam:GenerateCredentialReport.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Credential Report Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session and account_id.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings


def audit_iam_roles(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id)
        iam = session.client('iam')
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                role_name = role['RoleName']
                try:
                    trust_policy = call_with_backoff(iam, 'get_role', RoleName=role_name)['Role']['AssumeRolePolicyDocument']
                    statements = trust_policy.get('Statement', [])
                    for stmt in statements:
                        principal = stmt.get('Principal', {})
                        if 'AWS' in principal:
                            aws_principals = principal['AWS']
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            for aws_principal in aws_principals:
                                if aws_principal == '*' or not aws_principal.startswith('arn:aws:iam::'):
                                    findings.append({
                                        "AccountId": account_id,
                                        "Region": "global",
                                        "Service": "IAM",
                                        "Check": "IAM Role Trust Policy",
                                        "Status": "WARNING",
                                        "Severity": "High",
                                        "FindingType": "Access",
                                        "Details": f"IAM role {role_name} has overly permissive trust policy for principal {aws_principal}.",
                                        "Recommendation": f"Restrict trust policy for {role_name} to specific AWS accounts or services.",
                                        "Timestamp": datetime.now(central).isoformat(),
                                        "Compliance": {"CIS": "1.5", "NIST": "AC-6"}
                                    })
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        logger.info(f"No trust policy for role {role_name}, skipping.")
                    else:
                        raise
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Role Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing roles: {str(e)}",
            "Recommendation": "Verify IAM permissions for iam:ListRoles and iam:GetRole.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Role Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session and account_id.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings


def audit_root_account(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id)
        iam = session.client('iam')
        summary = call_with_backoff(iam, 'get_account_summary')
        root_mfa = summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0)
        if not root_mfa:
            findings.append({
                "AccountId": account_id,
                "Region": "global",
                "Service": "IAM",
                "Check": "Root Account MFA",
                "Status": "FAIL",
                "Severity": "Critical",
                "FindingType": "Access",
                "Details": "Root account does not have MFA enabled.",
                "Recommendation": "Enable MFA for the root account via AWS Console.",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "1.1", "PCI": "Req-8", "NIST": "IA-2"}
            })
        else:
            findings.append({
                "AccountId": account_id,
                "Region": "global",
                "Service": "IAM",
                "Check": "Root Account MFA",
                "Status": "PASS",
                "Severity": "Low",
                "FindingType": "Access",
                "Details": "Root account has MFA enabled.",
                "Recommendation": "No action needed.",
                "Timestamp": datetime.now(central).isoformat(),
                "Compliance": {"CIS": "1.1", "PCI": "Req-8", "NIST": "IA-2"}
            })

        # Generate the report independently — does not depend on audit_iam_credential_report running first.
        rows = get_credential_report(iam)
        for row in rows:
            if row.get('user') == '<root_account>':
                password_last_used = row.get('password_last_used', 'N/A')
                key1_last_used = row.get('access_key_1_last_used_date', 'N/A')
                key2_last_used = row.get('access_key_2_last_used_date', 'N/A')
                used_values = [v for v in [password_last_used, key1_last_used, key2_last_used] if v and v != 'N/A']
                if used_values:
                    findings.append({
                        "AccountId": account_id,
                        "Region": "global",
                        "Service": "IAM",
                        "Check": "Root Account Usage",
                        "Status": "WARNING",
                        "Severity": "Critical",
                        "FindingType": "Access",
                        "Details": f"Root account was used recently (password: {password_last_used}, key1: {key1_last_used}, key2: {key2_last_used}).",
                        "Recommendation": "Avoid using root account; use IAM roles instead.",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"CIS": "1.1", "NIST": "AC-2"}
                    })
                break
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "Root Account Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing root account: {str(e)}",
            "Recommendation": "Verify IAM permissions for iam:GetAccountSummary and iam:GetCredentialReport.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "Root Account Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session and account_id.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings


def audit_iam_policies(session, account_id):
    findings = []
    try:
        validate_inputs(session, account_id)
        iam = session.client('iam')
        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page.get('Policies', []):
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                try:
                    policy_version = call_with_backoff(iam, 'get_policy', PolicyArn=policy_arn)['Policy']
                    default_version_id = policy_version['DefaultVersionId']
                    policy_doc = call_with_backoff(iam, 'get_policy_version', PolicyArn=policy_arn, VersionId=default_version_id)['PolicyVersion']['Document']
                    statements = policy_doc.get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        actions = stmt.get('Action', [])
                        resources = stmt.get('Resource', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if any(a in ('*', '*:*') for a in actions) or any(r == '*' for r in resources):
                            findings.append({
                                "AccountId": account_id,
                                "Region": "global",
                                "Service": "IAM",
                                "Check": "IAM Policy Permissions",
                                "Status": "WARNING",
                                "Severity": "High",
                                "FindingType": "Access",
                                "Details": f"IAM policy {policy_name} has overly permissive permissions (Actions: {actions}, Resources: {resources}).",
                                "Recommendation": f"Restrict policy {policy_name} to specific actions and resources.",
                                "Timestamp": datetime.now(central).isoformat(),
                                "Compliance": {"CIS": "1.5", "NIST": "AC-6", "AWS-Well-Architected": "SEC-03"}
                            })
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        logger.info(f"No policy version for {policy_name}, skipping.")
                    else:
                        raise
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Policy Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Access",
            "Details": f"Error auditing policies: {str(e)}",
            "Recommendation": "Verify IAM permissions for iam:ListPolicies and iam:GetPolicyVersion.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    except ValueError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Policy Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Input validation error: {str(e)}",
            "Recommendation": "Ensure valid session and account_id.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings


def audit_iam(session, account_id, regions=None):
    """Main IAM audit function."""
    findings = []
    try:
        findings.extend(audit_iam_users(session, account_id))
        findings.extend(audit_iam_mfa(session, account_id))
        findings.extend(audit_iam_credential_report(session, account_id))
        findings.extend(audit_iam_roles(session, account_id))
        findings.extend(audit_root_account(session, account_id))
        findings.extend(audit_iam_policies(session, account_id))
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "IAM",
            "Check": "IAM Audit",
            "Status": "ERROR",
            "Severity": "Low",
            "FindingType": "Configuration",
            "Details": f"Unexpected error in IAM audit: {str(e)}",
            "Recommendation": "Review logs and verify IAM audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings
