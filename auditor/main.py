import sys
import os
# Ensure project root is on sys.path so 'auditor.*' imports work whether this
# file is run directly (python auditor/main.py) or as a module (python -m auditor.main).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fcntl
import logging
import json
from contextlib import contextmanager
from datetime import datetime
from zoneinfo import ZoneInfo
import boto3
import time
from botocore.exceptions import ClientError
from botocore.exceptions import UnauthorizedSSOTokenError, SSOTokenLoadError
from auditor.modules.orchestrator import run_all_audits, get_sub_accounts
from auditor.modules.report_generator import save_findings_json, save_findings_csv, save_findings_html
from auditor.modules.audit_config import load_config

# Define Central Time
central = ZoneInfo("America/Chicago")

LOCK_FILE = os.path.join(os.path.dirname(__file__), ".audit.lock")

@contextmanager
def audit_lock():
    """Prevent concurrent audit runs via an exclusive file lock."""
    with open(LOCK_FILE, "w") as lf:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another audit is already running. Exiting.")
            sys.exit(1)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)

# Custom formatter to handle missing account_id
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, 'account_id'):
            record.account_id = 'N/A'
        return super().format(record)

# Setup logger
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = CustomFormatter(
    fmt="%(asctime)s [%(levelname)s] Account:%(account_id)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Define US regions only
US_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]

def apply_severity_overrides(findings, config):
    """Apply severity overrides from config to findings."""
    severity_overrides = config.get("severity_overrides", {})
    for finding in findings:
        check = finding.get("Check", "")
        if check in severity_overrides:
            finding["Severity"] = severity_overrides[check]
    return findings

def generate_summary_statistics(findings):
    """Generate summary statistics for findings."""
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    service_counts = {}
    for finding in findings:
        severity = finding.get("Severity", "Low")
        service = finding.get("Service", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        service_counts[service] = service_counts.get(service, 0) + 1
    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "service_counts": service_counts,
        "accounts_audited": len(set(f.get("AccountId", "") for f in findings)),
        "regions_audited": len(set(f.get("Region", "") for f in findings if f.get("Region")))
    }

def assume_audit_deployer_role(sso_profile, deployer_role_arn):
    """Assume the AuditDeployer role using SSO profile."""
    if not deployer_role_arn:
        logger.error("No deployer_role_arn found in configuration.", extra={"account_id": "N/A"})
        return None
    try:
        session = boto3.Session(profile_name=sso_profile)
        sts_client = session.client('sts')
        response = sts_client.assume_role(
            RoleArn=deployer_role_arn,
            RoleSessionName='AuditDeployerSession'
        )
        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
    except ClientError as e:
        logger.error(f"Failed to assume AuditDeployer role: {str(e)}", extra={"account_id": "N/A"})
        return None

def assume_cross_account_audit_role(deployer_session, audit_role_name, target_account_id, external_id):
    """Assume the AuditRole in the target account using the deployer session."""
    if not target_account_id.isdigit() or len(target_account_id) != 12:
        logger.error(f"Invalid account_id: {target_account_id}", extra={"account_id": target_account_id})
        return None
    if not audit_role_name:
        logger.error("Invalid audit_role_name", extra={"account_id": target_account_id})
        return None
    if not external_id:
        logger.error("Missing audit_role_external_id in config", extra={"account_id": target_account_id})
        return None

    sts_client = deployer_session.client('sts')
    role_arn = f"arn:aws:iam::{target_account_id}:role/{audit_role_name}"

    for attempt in range(3):
        try:
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='AuditSession',
                ExternalId=external_id
            )
            return boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.error(f"Access denied for {role_arn}: {str(e)}", extra={"account_id": target_account_id})
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
            logger.error(f"Failed to assume role for account {target_account_id}: {str(e)}", extra={"account_id": target_account_id})
            return None
    return None

def main():
    # Load config from the same directory as main.py
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if not os.path.exists(config_path):
        logger.error(f"Configuration file {config_path} not found. Please create a valid config.yaml.", extra={"account_id": "N/A"})
        print(f"Error: Configuration file {config_path} not found.")
        return
    
    config = load_config(config_path)
    if not config:
        logger.error("Failed to load configuration. Please check config.yaml for errors.", extra={"account_id": "N/A"})
        print("Error: Invalid config.yaml.")
        return

    # Get accounts from config or AWS Organizations
    use_organizations = config.get("use_organizations", False)
    if use_organizations:
        sso_profile = config.get("sso_profile", "")
        if not sso_profile:
            logger.error("No sso_profile found in configuration for Organizations account discovery.", extra={"account_id": "N/A"})
            print("Error: Missing sso_profile in config.yaml.")
            return
        session = boto3.Session(profile_name=sso_profile)
        accounts = get_sub_accounts(session, use_organizations=True)
    else:
        accounts = config.get("accounts", [])

    if not accounts:
        logger.error("No accounts found in the configuration or Organizations. Please specify accounts in config.yaml or enable use_organizations.", extra={"account_id": "N/A"})
        print("Error: No accounts found.")
        return
    
    DEPLOYER_ROLE_ARN = config.get("deployer_role_arn", "")
    AUDIT_ROLE_NAME = config.get("audit_role_name", "")
    EXTERNAL_ID = config.get("audit_role_external_id", "")
    SSO_PROFILE = config.get("sso_profile", "")
    REPORT_DIR = config.get("report_dir", "auditor/reports")

    for param, value in [
        ("deployer_role_arn", DEPLOYER_ROLE_ARN),
        ("audit_role_name", AUDIT_ROLE_NAME),
        ("audit_role_external_id", EXTERNAL_ID),
        ("sso_profile", SSO_PROFILE),
        ("report_dir", REPORT_DIR)
    ]:
        if not value:
            logger.error(f"No {param} found in the configuration.", extra={"account_id": "N/A"})
            print(f"Error: Missing {param} in config.yaml.")
            return

    # Assume AuditDeployer role first
    deployer_session = assume_audit_deployer_role(SSO_PROFILE, DEPLOYER_ROLE_ARN)
    if deployer_session is None:
        logger.error("Failed to assume AuditDeployer role. Aborting audit.", extra={"account_id": "N/A"})
        return

    all_findings = []
    timestamp = datetime.now(central).strftime("%Y%m%d_%H%M%S")

    for account_id in accounts:
        logger.info(f"Auditing account: {account_id}", extra={"account_id": account_id})
        try:
            # Assume AuditRole in the target account using the deployer session
            session = assume_cross_account_audit_role(deployer_session, AUDIT_ROLE_NAME, account_id, EXTERNAL_ID)
            if session is None:
                logger.error(f"Skipping audit for account {account_id} due to role assumption failure.", extra={"account_id": account_id})
                continue

            # Use regions from config or default to US_REGIONS
            region_list = config.get("regions", US_REGIONS)

            # Run selected audits based on config
            findings = run_all_audits(account_id, session, region_list)

            # Standardize findings
            for f in findings:
                f.setdefault("AccountId", account_id)
                f.setdefault("Region", region_list[0] if region_list else "global")
                f.setdefault("Service", "Unknown")
                f.setdefault("Check", "Unknown")
                f.setdefault("FindingType", "Unknown")
                f.setdefault("Severity", "Low")
                f.setdefault("Timestamp", datetime.now(central).isoformat())
                f.setdefault("Compliance", {})

            # Filter permission-denied findings
            filtered_findings = []
            for f in findings:
                message = f.get("Details", "").lower()
                if any(err in message for err in [
                    "explicit deny",
                    "accessdenied",
                    "not authorized to perform",
                    "unauthorizedoperation"
                ]):
                    logger.warning(f"Skipping finding due to access restrictions: {message}", extra={"account_id": account_id})
                    continue
                filtered_findings.append(f)

            skipped_count = len(findings) - len(filtered_findings)
            if skipped_count:
                logger.info(f"Skipped {skipped_count} findings due to access restrictions.", extra={"account_id": account_id})

            # Apply severity overrides
            filtered_findings = apply_severity_overrides(filtered_findings, config)

            all_findings.extend(filtered_findings)
            logger.info(f"Completed audit for account {account_id} with {len(filtered_findings)} findings.", extra={"account_id": account_id})

        except Exception as e:
            logger.error(f"Error auditing {account_id}: {str(e)}", extra={"account_id": account_id})

    # Generate summary statistics
    summary_stats = generate_summary_statistics(all_findings)
    logger.info(
        f"Audit summary: {json.dumps(summary_stats, indent=2)}",
        extra={"account_id": "N/A"}
    )

    # Save all results
    os.makedirs(REPORT_DIR, exist_ok=True)
    base_filename = os.path.join(REPORT_DIR, f"audit_report_{timestamp}")
    
    # Save JSON
    save_findings_json(all_findings, f"{base_filename}.json")
    
    # Save CSV
    save_findings_csv(all_findings, f"{base_filename}.csv")
    
    # Save HTML
    save_findings_html(all_findings, f"{base_filename}.html")

    print("\n📦 Audit complete. Findings saved to:")
    print(f"  - JSON: {base_filename}.json")
    print(f"  - CSV: {base_filename}.csv")
    print(f"  - HTML: {base_filename}.html")

if __name__ == "__main__":
    try:
        with audit_lock():
            main()
    except (UnauthorizedSSOTokenError, SSOTokenLoadError):
        profile = "unknown"
        try:
            from auditor.modules.audit_config import load_config
            cfg = load_config(os.path.join(os.path.dirname(__file__), "config.yaml"))
            profile = cfg.get("sso_profile", profile)
        except Exception:
            pass
        print(f"\n❌ AWS SSO session expired. Run:\n\n    aws sso login --profile {profile}\n\nThen retry the audit.")
        sys.exit(1)