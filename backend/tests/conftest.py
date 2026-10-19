from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.parser import parse_events
from app.schemas import DetectionConfig, SecurityEventIn

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_auth_logs.json"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def detection_config() -> DetectionConfig:
    return DetectionConfig()


@pytest.fixture
def sample_payload() -> dict:
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def sample_events(sample_payload: dict) -> list[SecurityEventIn]:
    return [SecurityEventIn.model_validate(item) for item in sample_payload["events"]]


@pytest.fixture
def parsed_sample(sample_events: list[SecurityEventIn]):
    return parse_events(sample_events)


def make_event(**overrides) -> SecurityEventIn:
    payload = {
        "event_id": "evt-test-001",
        "timestamp": "2026-03-15T10:00:00Z",
        "event_type": "authentication",
        "username": "alice",
        "source_ip": "192.0.2.10",
        "action": "login",
        "status": "success",
    }
    payload.update(overrides)
    return SecurityEventIn.model_validate(payload)
