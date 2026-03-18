from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.api.router import router as api_router
from app.api.auth import router as auth_router
from app.api.projects import router as org_router
from app.core.seed import seed_demo_user
from app.demo.router import router as demo_router
from app.db.session import engine, Base

settings = get_settings()

app = FastAPI(title=settings.app_name, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed_demo_user()


app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(org_router, prefix=settings.api_prefix)
app.include_router(api_router, prefix=settings.api_prefix)
app.include_router(demo_router)


@app.get("/")
async def root() -> dict:
    return {"status": "ok", "service": settings.app_name}
