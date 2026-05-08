# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r auditor/requirements.txt
```

### Run the auditor (CLI)
```bash
python3 -m auditor.main
```

### Launch the Streamlit dashboard
```bash
streamlit run auditor/dashboard.py
```

### Run tests
```bash
python3 -m pytest auditor/tests/
```

## Architecture

This tool audits multiple AWS accounts for security, IAM, network exposure, cost, and compliance issues. It uses a two-hop role assumption chain and runs all audit modules concurrently.

### Auth chain
1. Local AWS SSO profile (configured in `auditor/config.yaml` as `sso_profile`) authenticates to the management account.
2. `main.py` assumes the `AuditDeployer` role (in the management account) using `deployer_role_arn`.
3. For each target account, the AuditDeployer session then assumes `AuditRole` (deployed to every account via CloudFormation StackSet) using ExternalId `audit-access`.

### Execution flow
`main.py` → loads `config.yaml` → resolves account list (from config or AWS Organizations) → for each account assumes AuditRole → calls `orchestrator.run_all_audits()` → saves results as JSON/CSV/HTML in `auditor/reports/`.

The orchestrator (`auditor/modules/orchestrator.py`) runs all enabled audit modules concurrently via `ThreadPoolExecutor`. Each module receives `(session, account_id, regions)` and returns a list of findings.

### Audit modules (`auditor/modules/`)
| Module | Key file |
|---|---|
| IAM best practices | `iam_audit.py` |
| Network exposure | `network_assessment.py` |
| Cost optimization | `cost_optimization.py` |
| Public exposure (S3, AMIs, etc.) | `exposure_audit.py` |
| CloudTrail & GuardDuty | `cloudtrail_guardduty.py` |
| Security Hub findings | `security_best_practices.py` |
| Cyber posture | `aws_cyber_audit.py` |

### Finding schema
All modules must return findings that conform to `auditor/modules/constants.py:STANDARD_FINDING`:
```
AccountId, Region, Service, Check, Status (PASS/WARNING/FAIL/ERROR/SKIPPED),
Severity (Low/Medium/High/Critical), FindingType, Details, Recommendation,
Timestamp (ISO), Compliance (dict, e.g. {"CIS": "3.1"})
```
`main.py` filters out access-denied findings (checking `Details` for known error strings) and applies severity overrides from config before saving.

### Dashboard
`auditor/dashboard.py` is a standalone Streamlit app. It reads the latest JSON report from `auditor/reports/`, provides filter controls (account, region, service, severity), and renders Plotly charts. It does not call AWS directly.

### Infrastructure files (root level)
- `auditrole_stackset_template.yaml` — CloudFormation template deployed via StackSet to create `AuditRole` in every target account.
- `deploy_audit_deployer.yaml` — CloudFormation template for the `AuditDeployer` role in the management account.
- `delete_role.sh`, `delete_stackset_instances.sh`, `force_delete_auditrole_stacks.py`, `delete_createauditrole_stacks.py` — cleanup utilities for removing StackSet instances and roles.
- `auto-deploy.json` — StackSet auto-deployment configuration.

### Configuration (`auditor/config.yaml`)
Key fields: `sso_profile`, `deployer_role_arn`, `audit_role_name`, `report_dir`, `regions`, `accounts`, `use_organizations` (when true, accounts are fetched from AWS Organizations instead of the static list), `severity_overrides` (map of check name → severity).
