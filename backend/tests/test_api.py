from __future__ import annotations

from fastapi.testclient import TestClient

from app.schemas import SecurityEventIn


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "sentinelx-detection-engine"


def test_list_rules(client: TestClient) -> None:
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    body = response.json()
    assert {item["rule_id"] for item in body} == {"AUTH-001", "AUTH-002", "AUTH-003"}
    assert all("thresholds" in item and "limitations" in item for item in body)


def test_analyze_sample(client: TestClient, sample_events: list[SecurityEventIn]) -> None:
    response = client.post(
        "/api/v1/analyze",
        json={"events": [event.model_dump() for event in sample_events]},
    )
    assert response.status_code == 200
    summary = response.json()["summary"]
    assert summary["total_events_analyzed"] == 27
    assert summary["total_alerts_generated"] >= 3
    assert "alerts" in summary


def test_analyze_empty_batch(client: TestClient) -> None:
    response = client.post("/api/v1/analyze", json={"events": []})
    assert response.status_code == 200
    summary = response.json()["summary"]
    assert summary["total_events_analyzed"] == 0
    assert summary["alerts"] == []


def test_analyze_rejects_missing_fields(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "events": [
                {
                    "timestamp": "2026-03-15T10:00:00Z",
                    "event_type": "authentication",
                    "username": "alice",
                    "source_ip": "192.0.2.10",
                    "action": "login",
                }
            ]
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "Request validation failed."
    assert "details" in body


def test_analyze_rejects_invalid_timestamp(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "events": [
                {
                    "event_id": "evt-bad-ts",
                    "timestamp": "2026-03-15T10:00:00",
                    "event_type": "authentication",
                    "username": "alice",
                    "source_ip": "192.0.2.10",
                    "action": "login",
                    "status": "success",
                }
            ]
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "One or more events failed validation."
    assert body["details"][0]["field"] == "timestamp"
    assert body["details"][0]["index"] == 0


def test_analyze_rejects_invalid_types(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "events": [
                {
                    "timestamp": 99,
                    "event_type": "authentication",
                    "username": "alice",
                    "source_ip": "192.0.2.10",
                    "action": "login",
                    "status": "success",
                }
            ]
        },
    )
    assert response.status_code == 422


def test_unknown_route_uses_structured_error(client: TestClient) -> None:
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"] == "Not found."
