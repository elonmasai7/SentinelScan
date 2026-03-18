import asyncio

from app.core.celery_app import celery_app
from app.services.scanner import run_scan_background


@celery_app.task(name="app.tasks.scans.run_scan_task")
def run_scan_task(scan_id: str, target_url: str, bearer_token: str | None) -> None:
    asyncio.run(run_scan_background(scan_id, target_url, bearer_token))
