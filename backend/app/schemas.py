from __future__ import annotations
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, field_validator
import re

AUDIT_CHOICES = {"iam", "network", "exposure", "cloudtrail", "security_hub", "cost_optimization", "cyber"}
REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d$")


class AwsConfigIn(BaseModel):
    deployer_role_arn: str
    deployer_external_id: str
    audit_role_name: str = "AuditRole"
    audit_role_external_id: str
    regions: list[str] = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    use_organizations: bool = False
    enabled_audits: list[str] = list(AUDIT_CHOICES)

    @field_validator("deployer_role_arn")
    @classmethod
    def valid_arn(cls, v: str) -> str:
        if not v.startswith("arn:aws:iam::") or ":role/" not in v:
            raise ValueError("Must be a valid IAM role ARN")
        return v

    @field_validator("regions")
    @classmethod
    def valid_regions(cls, v: list[str]) -> list[str]:
        for r in v:
            if not REGION_RE.match(r):
                raise ValueError(f"Invalid region: {r}")
        return v

    @field_validator("enabled_audits")
    @classmethod
    def valid_audits(cls, v: list[str]) -> list[str]:
        invalid = set(v) - AUDIT_CHOICES
        if invalid:
            raise ValueError(f"Unknown audit modules: {invalid}")
        return v


class AwsConfigOut(AwsConfigIn):
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AwsAccountIn(BaseModel):
    account_id: str
    account_name: str = ""

    @field_validator("account_id")
    @classmethod
    def valid_account_id(cls, v: str) -> str:
        if not v.isdigit() or len(v) != 12:
            raise ValueError("Must be a 12-digit AWS account ID")
        return v


class AwsAccountOut(AwsAccountIn):
    id: UUID
    created_at: datetime

    class Config:
        from_attributes = True


class AuditJobOut(BaseModel):
    id: UUID
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    accounts_audited: list[str]
    total_findings: int
    error_message: Optional[str]

    class Config:
        from_attributes = True


class FindingOut(BaseModel):
    id: UUID
    account_id: str
    region: str
    service: str
    check_name: str
    status: str
    severity: str
    finding_type: str
    details: str
    recommendation: str
    timestamp: Optional[datetime]
    compliance: dict

    class Config:
        from_attributes = True


class FindingFilters(BaseModel):
    severity: Optional[str] = None
    service: Optional[str] = None
    account_id: Optional[str] = None
    status: Optional[str] = None
    page: int = 1
    page_size: int = 50
