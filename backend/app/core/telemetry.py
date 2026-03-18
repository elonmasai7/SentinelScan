from __future__ import annotations

from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from app.core.config import get_settings


def setup_telemetry(app) -> None:
    settings = get_settings()
    if not settings.otel_enabled:
        return

    headers = {}
    if settings.otel_exporter_otlp_headers:
        for pair in settings.otel_exporter_otlp_headers.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                headers[key.strip()] = value.strip()

    resource = Resource.create({"service.name": settings.otel_service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=settings.otel_exporter_otlp_endpoint,
        headers=headers or None,
        insecure=True,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
