import os
import sys
import time
import logging
from datetime import datetime, timezone
from uuid import UUID

import boto3
from botocore.exceptions import ClientError
from celery import Task
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

# Make auditor importable inside the worker container
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../.."))

from app.celery_app import celery_app
from app.models import AuditJob, Finding, AwsConfig, AwsAccount
from auditor.modules.orchestrator import run_all_audits

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ["DATABASE_URL"]
# Celery workers use sync SQLAlchemy
engine = create_engine(DATABASE_URL)

US_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]


def _assume_role(sts, role_arn: str, session_name: str, external_id: str):
    kwargs = dict(RoleArn=role_arn, RoleSessionName=session_name)
    if external_id:
        kwargs["ExternalId"] = external_id
    resp = sts.assume_role(**kwargs)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


@celery_app.task(bind=True, max_retries=0)
def run_audit_task(self: Task, job_id: str, user_id: str):
    with Session(engine) as db:
        job = db.get(AuditJob, UUID(job_id))
        if not job:
            return

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            config = db.scalar(select(AwsConfig).where(AwsConfig.user_id == UUID(user_id)))
            if not config:
                raise RuntimeError("No AWS configuration found for user")

            accounts_rows = db.scalars(
                select(AwsAccount).where(AwsAccount.user_id == UUID(user_id))
            ).all()
            account_ids = [a.account_id for a in accounts_rows]
            if not account_ids:
                raise RuntimeError("No AWS accounts configured")

            regions = config.regions or US_REGIONS

            # Assume customer's deployer role using the SaaS app's own IAM credentials
            app_sts = boto3.client("sts")
            deployer_session = _assume_role(
                app_sts,
                config.deployer_role_arn,
                "SaaSAuditDeployer",
                config.deployer_external_id,
            )

            all_findings = []
            audited_accounts = []

            for account_id in account_ids:
                try:
                    deployer_sts = deployer_session.client("sts")
                    audit_session = _assume_role(
                        deployer_sts,
                        f"arn:aws:iam::{account_id}:role/{config.audit_role_name}",
                        "SaaSAuditSession",
                        config.audit_role_external_id,
                    )
                except ClientError as e:
                    logger.error(f"Could not assume audit role in {account_id}: {e}")
                    continue

                findings = run_all_audits(
                    account_id, audit_session, regions,
                    config={"enabled_audits": config.enabled_audits},
                )

                now = datetime.now(timezone.utc)
                for f in findings:
                    # Skip access-denied noise
                    detail = f.get("Details", "").lower()
                    if any(k in detail for k in ["explicit deny", "accessdenied", "not authorized", "unauthorizedoperation"]):
                        continue

                    ts = None
                    raw_ts = f.get("Timestamp")
                    if raw_ts:
                        try:
                            ts = datetime.fromisoformat(raw_ts)
                        except ValueError:
                            ts = now

                    all_findings.append(Finding(
                        job_id=UUID(job_id),
                        user_id=UUID(user_id),
                        account_id=f.get("AccountId", account_id),
                        region=f.get("Region", ""),
                        service=f.get("Service", ""),
                        check_name=f.get("Check", ""),
                        status=f.get("Status", ""),
                        severity=f.get("Severity", "Low"),
                        finding_type=f.get("FindingType", ""),
                        details=f.get("Details", ""),
                        recommendation=f.get("Recommendation", ""),
                        timestamp=ts,
                        compliance=f.get("Compliance", {}),
                    ))

                audited_accounts.append(account_id)

            # Bulk insert findings
            db.add_all(all_findings)
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            job.accounts_audited = audited_accounts
            job.total_findings = len(all_findings)
            db.commit()

        except Exception as exc:
            job.status = "failed"
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = str(exc)
            db.commit()
            logger.exception(f"Audit job {job_id} failed: {exc}")
