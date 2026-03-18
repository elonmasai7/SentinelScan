import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.db import models
from app.schemas import WorkspaceOut, ProjectOut
from app.api.deps import get_current_user

router = APIRouter(prefix="/org", tags=["org"])


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[WorkspaceOut]:
    result = await session.execute(
        select(models.Workspace)
        .join(models.Membership, models.Membership.workspace_id == models.Workspace.id)
        .where(models.Membership.user_id == user.id)
    )
    workspaces = result.scalars().all()
    return [WorkspaceOut(id=w.id, name=w.name) for w in workspaces]


@router.post("/workspaces", response_model=WorkspaceOut)
async def create_workspace(
    name: str,
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> WorkspaceOut:
    workspace = models.Workspace(id=str(uuid.uuid4()), name=name, owner_id=user.id)
    session.add(workspace)
    membership = models.Membership(id=str(uuid.uuid4()), user_id=user.id, workspace_id=workspace.id, role="owner")
    session.add(membership)
    await session.commit()
    return WorkspaceOut(id=workspace.id, name=workspace.name)


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(
    workspace_id: str | None = None,
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ProjectOut]:
    query = (
        select(models.Project)
        .join(models.Workspace)
        .join(models.Membership, models.Membership.workspace_id == models.Workspace.id)
        .where(models.Membership.user_id == user.id)
    )
    if workspace_id:
        query = query.where(models.Project.workspace_id == workspace_id)
    result = await session.execute(query)
    projects = result.scalars().all()
    return [ProjectOut(id=p.id, name=p.name, workspace_id=p.workspace_id) for p in projects]


@router.post("/projects", response_model=ProjectOut)
async def create_project(
    workspace_id: str,
    name: str,
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ProjectOut:
    result = await session.execute(
        select(models.Membership).where(
            models.Membership.workspace_id == workspace_id,
            models.Membership.user_id == user.id,
        )
    )
    if not result.scalars().first():
        raise HTTPException(status_code=403, detail="No access to workspace")

    project = models.Project(id=str(uuid.uuid4()), workspace_id=workspace_id, name=name)
    session.add(project)
    await session.commit()
    return ProjectOut(id=project.id, name=project.name, workspace_id=project.workspace_id)
