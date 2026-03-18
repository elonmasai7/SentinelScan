from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import get_db
from app.db import models

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_db),
) -> models.User:
    settings = get_settings()
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await session.get(models.User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def require_project_access(
    project_id: str,
    user: models.User,
    session: AsyncSession,
) -> models.Project:
    result = await session.execute(
        select(models.Project)
        .join(models.Workspace)
        .join(models.Membership, models.Membership.workspace_id == models.Workspace.id)
        .where(models.Project.id == project_id)
        .where(models.Membership.user_id == user.id)
    )
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=403, detail="No access to project")
    return project
