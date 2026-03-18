from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from sqlalchemy import text
from redis.asyncio import Redis
import logging
import time
import uuid

from app.core.config import get_settings
from app.api.router import router as api_router
from app.api.auth import router as auth_router
from app.api.projects import router as org_router
from app.core.seed import seed_demo_data
from app.core.logging import setup_logging
from app.core.ratelimit import check_rate_limit
from app.core.metrics import REQUEST_COUNT, REQUEST_LATENCY, render_metrics
from app.core.telemetry import setup_telemetry
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
    {"name": "metrics", "description": "Prometheus metrics."},
]

app = FastAPI(title=settings.app_name, version="0.1.0")
setup_telemetry(app)


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
    request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4()}"
    traceparent = request.headers.get("traceparent")
    trace_id = None
    span_id = None
    if traceparent:
        parts = traceparent.split("-")
        if len(parts) == 4:
            trace_id = parts[1]
            span_id = parts[2]
    if not trace_id or not span_id:
        trace_id = uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]
        traceparent = f"00-{trace_id}-{span_id}-01"
    request.state.rate_remaining = settings.rate_limit_per_minute

    path = request.url.path
    if path not in {"/healthz", "/readyz", "/docs", "/openapi.json", "/metrics"}:
        client_ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()
        try:
            allowed, remaining, retry_after, reset_at = await check_rate_limit(redis_client, client_ip)
        except Exception:
            allowed, remaining, retry_after, reset_at = True, settings.rate_limit_per_minute, 0, 0
        request.state.rate_remaining = remaining
        request.state.rate_reset = reset_at
        if not allowed:
            response = Response(status_code=429, content="Rate limit exceeded")
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_per_minute)
            if reset_at:
                response.headers["X-RateLimit-Reset"] = str(reset_at)
            response.headers["Retry-After"] = str(retry_after)
            response.headers["X-Request-ID"] = request_id
            response.headers["traceparent"] = traceparent
            return response

    response: Response = await call_next(request)
    duration_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["traceparent"] = traceparent
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-RateLimit-Remaining"] = str(getattr(request.state, "rate_remaining", settings.rate_limit_per_minute))
    response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_per_minute)
    reset_at = getattr(request.state, "rate_reset", 0)
    if reset_at:
        response.headers["X-RateLimit-Reset"] = str(reset_at)

    REQUEST_COUNT.labels(method=request.method, path=request.url.path, status=str(response.status_code)).inc()
    REQUEST_LATENCY.labels(method=request.method, path=request.url.path).observe(duration_ms / 1000)

    logger.info(
        "request",
        extra={
            "extra": {
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
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
        # Lightweight migration for new findings columns (idempotent)
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS plugin VARCHAR"))
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe VARCHAR"))
        await conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation TEXT"))
    await seed_demo_data()


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


@app.get("/metrics", tags=["metrics"])
async def metrics(request: Request) -> Response:
    if not settings.metrics_enabled:
        return Response(status_code=404)
    if settings.metrics_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header != f"Bearer {settings.metrics_token}":
            return Response(status_code=401, content="Unauthorized")
    data, content_type = render_metrics()
    return Response(content=data, media_type=content_type)
    data, content_type = render_metrics()
    return Response(content=data, media_type=content_type)
