import csv
import io
import logging
import random
import time

from boto3.session import Session
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def call_with_backoff(client, method, **kwargs):
    """Execute an AWS API call with exponential backoff on throttling errors."""
    for attempt in range(3):
        try:
            return getattr(client, method)(**kwargs)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ["Throttling", "RequestLimitExceeded"]:
                sleep_time = (2 ** attempt) + random.uniform(0, 0.1)
                logger.warning(f"Throttling on {method}, retrying in {sleep_time:.2f}s")
                time.sleep(sleep_time)
            else:
                raise
    raise ClientError(
        {"Error": {"Code": "MaxRetriesExceeded", "Message": f"Max retries exceeded for {method}"}},
        method,
    )


def validate_inputs(session, account_id, regions=None):
    """Validate common audit function inputs."""
    if not isinstance(session, Session):
        raise ValueError("Invalid session provided")
    if not isinstance(account_id, str) or not account_id.isdigit() or len(account_id) != 12:
        raise ValueError("Invalid account_id: must be a 12-digit string")
    if regions is not None:
        if not isinstance(regions, list) or not all(isinstance(r, str) for r in regions):
            raise ValueError("Regions must be a list of strings")


def get_credential_report(iam):
    """Generate (if needed) and return the IAM credential report as a list of dicts."""
    for _ in range(10):
        response = iam.generate_credential_report()
        if response["State"] == "COMPLETE":
            break
        time.sleep(1)
    else:
        raise RuntimeError("Credential report generation timed out after 10 seconds")

    content = iam.get_credential_report()["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def is_valid_finding(finding):
    """Return False if the finding represents a permission-denied error, True otherwise."""
    msg = finding.get("Details", finding.get("Message", "")).lower()
    return not any(
        err in msg
        for err in ["not authorized", "explicit deny", "unauthorizedoperation", "accessdenied"]
    )
