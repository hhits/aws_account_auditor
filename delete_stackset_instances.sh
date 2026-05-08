#!/bin/bash

# StackSet name
STACKSET_NAME="StackSet-DeployAuditRole-83566009-4a07-4146-ad36-16c2568019c7"

# Region where StackSet was deployed
REGION="us-east-1"

# Extract profiles from ~/.aws/config
CONFIG_FILE="$HOME/.aws/config"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Error: AWS config file not found at $CONFIG_FILE"
  exit 1
fi
PROFILES=$(grep -E '^\[profile ' "$CONFIG_FILE" | sed 's/^\[profile \(.*\)\]$/\1/' | sort)
if grep -q '^\[default\]' "$CONFIG_FILE"; then
  PROFILES="default\n$PROFILES"
fi
PROFILES_ARRAY=($PROFILES)

if [ ${#PROFILES_ARRAY[@]} -eq 0 ]; then
  echo "No profiles found in $CONFIG_FILE"
  exit 1
fi

for PROFILE in "${PROFILES_ARRAY[@]}"; do
  echo "Processing profile: $PROFILE"

  # Get account ID for logging
  ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text 2>/dev/null)
  if [ -z "$ACCOUNT_ID" ]; then
    echo "Failed to get account ID for profile $PROFILE. Skipping..."
    continue
  fi
  echo "Account ID: $ACCOUNT_ID"

  # Check if stack instances exist for this account
  STACK_INSTANCES=$(aws cloudformation list-stack-instances \
    --stack-set-name "$STACKSET_NAME" \
    --region "$REGION" \
    --profile "$PROFILE" \
    --query "Summaries[?Account=='$ACCOUNT_ID'].{StackId:StackId,Status:Status}" \
    --output json 2>/dev/null)

  if [ -z "$STACK_INSTANCES" ] || [ "$STACK_INSTANCES" == "[]" ]; then
    echo "No stack instances found for $STACKSET_NAME in account $ACCOUNT_ID"
    continue
  fi

  # Parse stack instances
  echo "$STACK_INSTANCES" | jq -r '.[] | .StackId + " " + .Status' | while read -r STACK_ID STATUS; do
    echo "Found stack instance: $STACK_ID (Status: $STATUS)"
    
    if [ "$STATUS" != "CURRENT" ] && [ "$STATUS" != "OUTDATED" ]; then
      echo "Stack instance is in $STATUS state, skipping deletion"
      continue
    fi

    # Delete the stack instance
    echo "Deleting stack instance for account $ACCOUNT_ID in region $REGION"
    aws cloudformation delete-stack-instances \
      --stack-set-name "$STACKSET_NAME" \
      --accounts "$ACCOUNT_ID" \
      --regions "$REGION" \
      --no-retain-stacks \
      --region "$REGION" \
      --profile "$PROFILE" 2>/dev/null
    
    if [ $? -eq 0 ]; then
      echo "Successfully initiated deletion of stack instance for account $ACCOUNT_ID"
    else
      echo "Failed to delete stack instance for account $ACCOUNT_ID"
    fi
  done
done