import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.db import models
from app.schemas import AuthLogin, AuthRegister, Token
from app.core.security import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=Token)
async def register(payload: AuthRegister, session: AsyncSession = Depends(get_db)) -> Token:
    result = await session.execute(select(models.User).where(models.User.email == payload.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = models.User(id=str(uuid.uuid4()), email=payload.email, password_hash=hash_password(payload.password))
    session.add(user)

    workspace = models.Workspace(id=str(uuid.uuid4()), name="Default Workspace", owner_id=user.id)
    session.add(workspace)

    membership = models.Membership(id=str(uuid.uuid4()), user_id=user.id, workspace_id=workspace.id, role="owner")
    session.add(membership)

    project = models.Project(id=str(uuid.uuid4()), workspace_id=workspace.id, name="Default Project")
    session.add(project)

    await session.commit()

    token = create_access_token(user.id)
    return Token(access_token=token)


@router.post("/login", response_model=Token)
async def login(payload: AuthLogin, session: AsyncSession = Depends(get_db)) -> Token:
    result = await session.execute(select(models.User).where(models.User.email == payload.email))
    user = result.scalars().first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user.id)
    return Token(access_token=token)
