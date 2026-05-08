from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.auth import get_current_user
from app.database import get_db
from app.models import AuditJob, Finding, AwsConfig, AwsAccount
from app.schemas import AuditJobOut, FindingOut
from app.tasks.audit_tasks import run_audit_task
from uuid import UUID
from typing import Optional

router = APIRouter()


@router.post("", response_model=AuditJobOut, status_code=202)
async def trigger_audit(user_id: str = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    uid = UUID(user_id)

    config = await db.scalar(select(AwsConfig).where(AwsConfig.user_id == uid))
    if not config:
        raise HTTPException(status_code=400, detail="AWS configuration not found. Set up your config first.")

    # Block if an audit is already running for this user
    running = await db.scalar(
        select(AuditJob).where(AuditJob.user_id == uid, AuditJob.status.in_(["pending", "running"]))
    )
    if running:
        raise HTTPException(status_code=409, detail="An audit is already in progress.")

    job = AuditJob(user_id=uid)
    db.add(job)
    await db.commit()
    await db.refresh(job)

    run_audit_task.delay(str(job.id), user_id)
    return job


@router.get("", response_model=list[AuditJobOut])
async def list_audits(
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, le=100),
):
    rows = await db.scalars(
        select(AuditJob).where(AuditJob.user_id == UUID(user_id)).order_by(AuditJob.created_at.desc()).limit(limit)
    )
    return rows.all()


@router.get("/{job_id}", response_model=AuditJobOut)
async def get_audit(job_id: str, user_id: str = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    job = await db.scalar(
        select(AuditJob).where(AuditJob.id == UUID(job_id), AuditJob.user_id == UUID(user_id))
    )
    if not job:
        raise HTTPException(status_code=404, detail="Audit job not found")
    return job


@router.get("/{job_id}/findings", response_model=list[FindingOut])
async def get_findings(
    job_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    severity: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, le=200),
):
    uid = UUID(user_id)
    jid = UUID(job_id)

    # Verify job belongs to user
    job = await db.scalar(select(AuditJob).where(AuditJob.id == jid, AuditJob.user_id == uid))
    if not job:
        raise HTTPException(status_code=404, detail="Audit job not found")

    q = select(Finding).where(Finding.job_id == jid, Finding.user_id == uid)
    if severity:
        q = q.where(Finding.severity == severity)
    if service:
        q = q.where(Finding.service == service)
    if account_id:
        q = q.where(Finding.account_id == account_id)
    if status:
        q = q.where(Finding.status == status)

    q = q.offset((page - 1) * page_size).limit(page_size)
    rows = await db.scalars(q)
    return rows.all()


@router.get("/{job_id}/summary")
async def get_findings_summary(
    job_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    uid = UUID(user_id)
    jid = UUID(job_id)

    job = await db.scalar(select(AuditJob).where(AuditJob.id == jid, AuditJob.user_id == uid))
    if not job:
        raise HTTPException(status_code=404, detail="Audit job not found")

    rows = await db.execute(
        select(Finding.severity, func.count().label("count"))
        .where(Finding.job_id == jid, Finding.user_id == uid)
        .group_by(Finding.severity)
    )
    severity_counts = {row.severity: row.count for row in rows}

    rows = await db.execute(
        select(Finding.service, func.count().label("count"))
        .where(Finding.job_id == jid, Finding.user_id == uid)
        .group_by(Finding.service)
    )
    service_counts = {row.service: row.count for row in rows}

    return {
        "total": job.total_findings,
        "by_severity": severity_counts,
        "by_service": service_counts,
        "accounts_audited": job.accounts_audited,
    }
