import uuid

from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hash_password
from app.db import models
from app.db.session import AsyncSessionLocal


async def seed_demo_user() -> None:
    settings = get_settings()
    if not settings.demo_seed:
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(models.User).where(models.User.email == settings.demo_email))
        existing = result.scalars().first()
        if existing:
            return

        user = models.User(
            id=str(uuid.uuid4()),
            email=settings.demo_email,
            password_hash=hash_password(settings.demo_password),
        )
        session.add(user)

        workspace = models.Workspace(
            id=str(uuid.uuid4()),
            name="Demo Workspace",
            owner_id=user.id,
        )
        session.add(workspace)

        membership = models.Membership(
            id=str(uuid.uuid4()),
            user_id=user.id,
            workspace_id=workspace.id,
            role="owner",
        )
        session.add(membership)

        project = models.Project(
            id=str(uuid.uuid4()),
            workspace_id=workspace.id,
            name="Demo Project",
        )
        session.add(project)

        await session.commit()
