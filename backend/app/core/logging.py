import json
import logging
from datetime import datetime


def setup_logging() -> None:
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "message": record.getMessage(),
                "logger": record.name,
            }
            if hasattr(record, "extra") and isinstance(record.extra, dict):
                payload.update(record.extra)
            return json.dumps(payload)

    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
