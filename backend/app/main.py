from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy import text
from redis.asyncio import Redis
import logging
import time

from app.core.config import get_settings
from app.api.router import router as api_router
from app.api.auth import router as auth_router
from app.api.projects import router as org_router
from app.core.seed import seed_demo_user
from app.core.logging import setup_logging
from app.core.ratelimit import check_rate_limit
from app.demo.router import router as demo_router
from app.db.session import engine, Base

settings = get_settings()
setup_logging()
logger = logging.getLogger("sentinelscan")

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


tags_metadata = [
    {"name": "auth", "description": "Authentication and access tokens."},
    {"name": "org", "description": "Workspaces, projects, and membership."},
    {"name": "scan", "description": "Scan execution and results."},
    {"name": "demo", "description": "Intentionally vulnerable demo endpoints."},
    {"name": "health", "description": "Health and readiness checks."},
]

app = FastAPI(title=settings.app_name, version="0.1.0")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description="Enterprise-ready REST API security validation platform.",
        routes=app.routes,
        tags=tags_metadata,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
    }
    schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    start = time.perf_counter()
    request_id = request.headers.get("X-Request-ID") or f"req-{id(request)}"

    path = request.url.path
    if path not in {"/healthz", "/readyz", "/docs", "/openapi.json"}:
        client_ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()
        try:
            allowed, remaining = await check_rate_limit(redis_client, client_ip)
        except Exception:
            allowed, remaining = True, settings.rate_limit_per_minute
        if not allowed:
            response = Response(status_code=429, content="Rate limit exceeded")
            response.headers["X-RateLimit-Remaining"] = "0"
            return response

    response: Response = await call_next(request)
    duration_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    logger.info(
        "request",
        extra={
            "extra": {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": request.client.host,
            }
        },
    )
    return response


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


@app.get("/healthz", tags=["health"])
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz", tags=["health"])
async def readyz() -> dict:
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    return {"status": "ready"}
