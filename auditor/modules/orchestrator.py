import logging

from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor
from auditor.modules.network_assessment import audit_network_all_regions
from auditor.modules.cloudtrail_guardduty import audit_cloudtrail_all_regions
from auditor.modules.security_best_practices import audit_security_hub_all_regions
from auditor.modules.iam_audit import audit_iam
from auditor.modules.cost_optimization import audit_cost
from auditor.modules.exposure_audit import audit_exposure
from auditor.modules.aws_cyber_audit import audit_cyber

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

# Mapping of audit functions (adjusted to match module exports)
AUDIT_FUNCTIONS = {
    "network": audit_network_all_regions,
    "cloudtrail": audit_cloudtrail_all_regions,
    "security_hub": audit_security_hub_all_regions,
    "iam": audit_iam,
    "cost_optimization": audit_cost,
    "exposure": audit_exposure,
    "cyber": audit_cyber
}

def get_sub_accounts(session, use_organizations=False):
    """Retrieve sub-accounts from AWS Organizations or config."""
    if use_organizations:
        org_client = session.client('organizations')
        response = org_client.list_accounts()
        return [account['Id'] for account in response['Accounts']]
    return []  # Placeholder for config-based accounts

def run_all_audits(account_id, session, regions, config=None):
    """Run all audit modules concurrently."""
    all_findings = []
    config = config or {}
    enabled_audits = config.get("enabled_audits", AUDIT_FUNCTIONS.keys())

    with ThreadPoolExecutor(max_workers=len(enabled_audits)) as executor:
        future_to_audit = {
            executor.submit(audit_func, session, account_id, regions): audit_name
            for audit_name, audit_func in AUDIT_FUNCTIONS.items()
            if audit_name in enabled_audits
        }
        for future in future_to_audit:
            try:
                findings = future.result()
                all_findings.extend(findings)
                logger.info(f"Completed {future_to_audit[future]} audit for {account_id}", extra={"account_id": account_id})
            except Exception as e:
                logger.error(f"Error in {future_to_audit[future]} audit for {account_id}: {str(e)}", extra={"account_id": account_id})

    return all_findings