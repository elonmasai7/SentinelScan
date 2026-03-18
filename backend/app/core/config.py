from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "SentinelScan"
    environment: str = "development"
    api_prefix: str = "/api"

    database_url: str = "postgresql+asyncpg://postgres:postgres@db:5432/sentinelscan"
    redis_url: str = "redis://redis:6379/0"
    request_timeout_s: float = 10.0
    max_concurrency: int = 10
    rate_limit_probe_requests: int = 10
    user_agent: str = "SentinelScan/0.1"
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60
    demo_seed: bool = True
    demo_email: str = "demo@sentinelscan.io"
    demo_password: str = "DemoPass123!"


@lru_cache
def get_settings() -> Settings:
    return Settings()
