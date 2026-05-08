import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, ForeignKey, ARRAY
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class AwsConfig(Base):
    __tablename__ = "aws_configs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    deployer_role_arn = Column(Text, nullable=False)
    deployer_external_id = Column(Text, nullable=False)
    audit_role_name = Column(Text, nullable=False, default="AuditRole")
    audit_role_external_id = Column(Text, nullable=False)
    regions = Column(ARRAY(Text), nullable=False, default=lambda: ["us-east-1", "us-east-2", "us-west-1", "us-west-2"])
    use_organizations = Column(Boolean, default=False)
    enabled_audits = Column(ARRAY(Text), nullable=False, default=lambda: ["iam", "network", "exposure", "cloudtrail", "security_hub", "cost_optimization", "cyber"])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AwsAccount(Base):
    __tablename__ = "aws_accounts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    account_id = Column(Text, nullable=False)
    account_name = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditJob(Base):
    __tablename__ = "audit_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    status = Column(Text, nullable=False, default="pending")  # pending | running | completed | failed
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    accounts_audited = Column(ARRAY(Text), default=lambda: [])
    total_findings = Column(Integer, default=0)
    error_message = Column(Text)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True), ForeignKey("audit_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    account_id = Column(Text, nullable=False)
    region = Column(Text, default="")
    service = Column(Text, default="")
    check_name = Column(Text, default="")
    status = Column(Text, default="")
    severity = Column(Text, default="Low")
    finding_type = Column(Text, default="")
    details = Column(Text, default="")
    recommendation = Column(Text, default="")
    timestamp = Column(DateTime)
    compliance = Column(JSONB, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
