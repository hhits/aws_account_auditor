from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.auth import get_current_user
from app.database import get_db
from app.models import AwsConfig
from app.schemas import AwsConfigIn, AwsConfigOut
from uuid import UUID

router = APIRouter()


@router.get("", response_model=AwsConfigOut)
async def get_config(user_id: str = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    row = await db.scalar(select(AwsConfig).where(AwsConfig.user_id == UUID(user_id)))
    if not row:
        raise HTTPException(status_code=404, detail="No configuration found")
    return row


@router.put("", response_model=AwsConfigOut)
async def upsert_config(
    body: AwsConfigIn,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    uid = UUID(user_id)
    row = await db.scalar(select(AwsConfig).where(AwsConfig.user_id == uid))
    if row:
        for field, value in body.model_dump().items():
            setattr(row, field, value)
    else:
        row = AwsConfig(user_id=uid, **body.model_dump())
        db.add(row)
    await db.commit()
    await db.refresh(row)
    return row
