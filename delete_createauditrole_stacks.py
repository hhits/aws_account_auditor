import boto3
import yaml
import time
from botocore.exceptions import ClientError

# Load audit_config.yaml
with open("auditor/modules/audit_config.yaml", "r") as f:
    config = yaml.safe_load(f)

accounts = config["accounts"]
profiles = config["profiles"]
STACK_NAME = "CreateAuditRole"
REGION = "us-east-1"

def delete_stack(profile, account_id):
    print(f"\n🔍 Checking account {account_id} (profile: {profile})...")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    cf = session.client("cloudformation")

    try:
        stacks = cf.describe_stacks()
        stack_names = [stack["StackName"] for stack in stacks["Stacks"]]
        if STACK_NAME not in stack_names:
            print(f"ℹ️  Stack {STACK_NAME} not found. Skipping...")
            return

        print(f"🧹 Deleting stack {STACK_NAME}...")
        cf.delete_stack(StackName=STACK_NAME)

        # Wait for deletion to complete
        waiter = cf.get_waiter("stack_delete_complete")
        print(f"⏳ Waiting for deletion of {STACK_NAME}...")
        waiter.wait(StackName=STACK_NAME)
        print(f"✅ Stack deleted in account {account_id}.")

    except ClientError as e:
        print(f"❌ Error in account {account_id}: {e.response['Error']['Message']}")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

def main():
    if len(accounts) != len(profiles):
        print("❌ Mismatch between number of accounts and profiles in audit_config.yaml.")
        return

    for account_id, profile in zip(accounts, profiles):
        delete_stack(profile, account_id)

if __name__ == "__main__":
    main()
