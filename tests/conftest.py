import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import database
from app.config import get_settings
from app.models import Base
from app.services.cache import NullCache, set_cache
from app.services.queue import set_queue

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
TEST_DB_URL = os.getenv("TEST_DATABASE_URL", "sqlite://")  # CI also runs against Postgres


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    get_settings.cache_clear()
    engine = database.configure(TEST_DB_URL)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    set_cache(NullCache())
    set_queue(None)
    yield
    Base.metadata.drop_all(engine)
    engine.dispose()
    get_settings.cache_clear()


@pytest.fixture
def client():
    from app.main import app

    return TestClient(app)


@pytest.fixture
def db():
    with database.SessionLocal() as session:
        yield session


@pytest.fixture
def nmap_xml() -> str:
    return (SAMPLES / "nmap_scan.xml").read_text()


@pytest.fixture
def nessus_xml() -> str:
    return (SAMPLES / "nessus_scan.nessus").read_text()


def upload(client, content: str, fmt: str, **form):
    return client.post(
        "/ingest/upload",
        files={"file": (f"scan.{fmt}", content.encode(), "application/xml")},
        data={"format": fmt, **{k: str(v).lower() if isinstance(v, bool) else v for k, v in form.items()}},
    )
