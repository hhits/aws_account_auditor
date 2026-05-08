from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.auth import get_current_user
from app.database import get_db
from app.models import AwsAccount
from app.schemas import AwsAccountIn, AwsAccountOut
from uuid import UUID

router = APIRouter()


@router.get("", response_model=list[AwsAccountOut])
async def list_accounts(user_id: str = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(AwsAccount).where(AwsAccount.user_id == UUID(user_id)))
    return rows.all()


@router.post("", response_model=AwsAccountOut, status_code=201)
async def add_account(
    body: AwsAccountIn,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    uid = UUID(user_id)
    existing = await db.scalar(
        select(AwsAccount).where(AwsAccount.user_id == uid, AwsAccount.account_id == body.account_id)
    )
    if existing:
        raise HTTPException(status_code=409, detail="Account already added")
    row = AwsAccount(user_id=uid, **body.model_dump())
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/{account_id}", status_code=204)
async def remove_account(
    account_id: str,
    user_id: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    uid = UUID(user_id)
    result = await db.execute(
        delete(AwsAccount).where(AwsAccount.user_id == uid, AwsAccount.account_id == account_id)
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Account not found")
