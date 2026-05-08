#!/bin/bash

ROLE_NAME="AuditRole"
REGION="us-west-1"

PROFILES=(
    "0" "1" "2" "3" "4" "5" "6" "7" "8" "9"
    "10" "11" "12" "13" "14" "15" "16" "17"
    "18" "19" "20" "21" "22"
)

for PROFILE in "${PROFILES[@]}"; do
  echo "🔄 Processing profile: $PROFILE"

  ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --query Account --output text)
  echo "📛 Account ID: $ACCOUNT_ID"

  while IFS= read -r POLICY_ARN; do
    [[ -z "$POLICY_ARN" ]] && continue
    echo "📤 Detaching managed policy: $POLICY_ARN"
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN" --profile "$PROFILE" --region "$REGION"
  done < <(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --profile "$PROFILE" --region "$REGION" --query 'AttachedPolicies[].PolicyArn' --output text | tr '\t' '\n')

  while IFS= read -r POLICY_NAME; do
    [[ -z "$POLICY_NAME" ]] && continue
    echo "🗑️ Deleting inline policy: $POLICY_NAME"
    aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" --profile "$PROFILE" --region "$REGION"
  done < <(aws iam list-role-policies --role-name "$ROLE_NAME" --profile "$PROFILE" --region "$REGION" --query 'PolicyNames[]' --output text | tr '\t' '\n')

  while IFS= read -r INSTANCE_PROFILE; do
    [[ -z "$INSTANCE_PROFILE" ]] && continue
    echo "🧹 Removing from instance profile: $INSTANCE_PROFILE"
    aws iam remove-role-from-instance-profile --instance-profile-name "$INSTANCE_PROFILE" --role-name "$ROLE_NAME" --profile "$PROFILE" --region "$REGION"
    echo "❌ Deleting instance profile: $INSTANCE_PROFILE"
    aws iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE" --profile "$PROFILE" --region "$REGION"
  done < <(aws iam list-instance-profiles-for-role --role-name "$ROLE_NAME" --profile "$PROFILE" --region "$REGION" --query 'InstanceProfiles[].InstanceProfileName' --output text | tr '\t' '\n')

  echo "❌ Deleting role: $ROLE_NAME"
  aws iam delete-role --role-name "$ROLE_NAME" --profile "$PROFILE" --region "$REGION"
  echo "✅ Role deleted in account $ACCOUNT_ID"
done
echo "🎉 All roles deleted successfully!"
