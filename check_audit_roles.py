import boto3
import yaml
from botocore.exceptions import ClientError

with open("auditor/modules/audit_config.yaml", "r") as f:
    config = yaml.safe_load(f)

accounts = config.get("accounts", [])
profiles = config.get("profiles", [])

for acc_id, profile in zip(accounts, profiles):
    print(f"🔍 Checking {acc_id} (profile: {profile})")
    try:
        session = boto3.Session(profile_name=profile)
        iam = session.client("iam")
        iam.get_role(RoleName="AuditRole")
        print(f"✅ AuditRole found in {acc_id}")
    except ClientError as e:
        if "NoSuchEntity" in str(e):
            print(f"❌ AuditRole NOT found in {acc_id}")
        else:
            print(f"⚠️  Error in {acc_id}: {str(e)}")
