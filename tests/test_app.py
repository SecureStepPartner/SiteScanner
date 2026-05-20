import asyncio

from app.main import app, health


def test_health_endpoint_returns_ok() -> None:
    response = asyncio.run(health())

    assert response.status == "ok"


def test_openapi_exposes_scan_routes() -> None:
    schema = app.openapi()

    assert "/scan" in schema["paths"]
    assert "/scan/{scan_id}" in schema["paths"]
