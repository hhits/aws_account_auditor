import boto3
import yaml
import re
from botocore.exceptions import ClientError

STACK_NAME_PREFIX = "StackSet-DeployAuditRole"
REGION = "us-west-1"  # Specify the region where the stacks are deployed

with open("auditor/modules/audit_config.yaml", "r") as f:
    config = yaml.safe_load(f)

accounts = config["accounts"]
profiles = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22"]

def delete_matching_stacks(profile, account_id):
    print(f"\n🔍 Checking account {account_id} (profile: {profile})...")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    cf = session.client("cloudformation")

    try:
        stacks = cf.describe_stacks()["Stacks"]
        matching = [
            s for s in stacks
            if re.match(rf"{STACK_NAME_PREFIX}-.*", s["StackName"])
        ]

        if not matching:
            print(f"ℹ️ No {STACK_NAME_PREFIX}-* stack found.")
            return

        for stack in matching:
            name = stack["StackName"]
            print(f"🧹 Deleting stack {name}...")
            cf.delete_stack(StackName=name)
            waiter = cf.get_waiter("stack_delete_complete")
            waiter.wait(StackName=name)
            print(f"✅ Deleted {name}")

    except ClientError as e:
        print(f"❌ {e.response['Error']['Message']}")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

def main():
    if len(accounts) != len(profiles):
        print("❌ Mismatch between accounts and profiles")
        return

    for account_id, profile in zip(accounts, profiles):
        delete_matching_stacks(profile, account_id)

if __name__ == "__main__":
    main()
