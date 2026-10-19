from __future__ import annotations

from datetime import timezone

import pytest
from pydantic import ValidationError

from app.parser import (
    BatchParseError,
    EventParseError,
    parse_event,
    parse_events,
    parse_timestamp,
)
from app.schemas import SecurityEventIn
from tests.conftest import make_event


def test_parse_valid_event_normalizes_fields() -> None:
    event = make_event(
        event_type=" Authentication ",
        action="LOGIN",
        status="Failed",
        username=" Alice ",
        timestamp="2026-03-15T15:30:00+05:30",
        hostname=" Host-1 ",
    )
    parsed = parse_event(event)
    assert parsed.event_type == "authentication"
    assert parsed.action == "login"
    assert parsed.status == "failure"
    assert parsed.username == "Alice"
    assert parsed.username_normalized == "alice"
    assert parsed.hostname == "Host-1"
    assert parsed.timestamp.tzinfo is not None
    assert parsed.timestamp.utcoffset() == timezone.utc.utcoffset(parsed.timestamp)
    assert parsed.timestamp.hour == 10
    assert parsed.original["status"] == "Failed"


def test_parse_zulu_timestamp() -> None:
    parsed = parse_timestamp("2026-03-15T10:00:00Z")
    assert parsed.tzinfo is not None
    assert parsed.isoformat() == "2026-03-15T10:00:00+00:00"


def test_reject_naive_timestamp() -> None:
    with pytest.raises(EventParseError, match="timezone-aware"):
        parse_timestamp("2026-03-15T10:00:00")


def test_reject_invalid_timestamp() -> None:
    with pytest.raises(EventParseError, match="ISO 8601"):
        parse_timestamp("not-a-timestamp")


def test_reject_invalid_source_ip() -> None:
    with pytest.raises(EventParseError, match="source_ip"):
        parse_event(make_event(source_ip="not-an-ip"))


def test_missing_required_fields() -> None:
    with pytest.raises(ValidationError):
        SecurityEventIn.model_validate(
            {
                "timestamp": "2026-03-15T10:00:00Z",
                "event_type": "authentication",
                "username": "alice",
                "source_ip": "192.0.2.10",
                "action": "login",
            }
        )


def test_invalid_data_types() -> None:
    with pytest.raises(ValidationError):
        SecurityEventIn.model_validate(
            {
                "timestamp": 12345,
                "event_type": "authentication",
                "username": ["alice"],
                "source_ip": "192.0.2.10",
                "action": "login",
                "status": "success",
            }
        )


def test_batch_rejects_malformed_event_with_index() -> None:
    events = [make_event(), make_event(event_id="evt-bad", timestamp="2026-03-15T10:00:00")]
    with pytest.raises(BatchParseError) as exc_info:
        parse_events(events)
    assert exc_info.value.errors[0].index == 1
    assert exc_info.value.errors[0].field == "timestamp"


def test_duplicate_event_ids_are_collapsed() -> None:
    events = [
        make_event(event_id="evt-dup", status="failure"),
        make_event(event_id="evt-dup", status="failure"),
        make_event(event_id="evt-other", username="bob", source_ip="192.0.2.11"),
    ]
    parsed = parse_events(events)
    assert len(parsed) == 2
    assert [item.event_id for item in parsed] == ["evt-dup", "evt-other"]


def test_generated_event_id_is_stable_for_identical_payloads() -> None:
    first = parse_event(make_event(event_id=None))
    second = parse_event(make_event(event_id=None))
    assert first.event_id == second.event_id
    assert first.event_id.startswith("evt-")


def test_sensitive_fields_are_dropped() -> None:
    event = SecurityEventIn.model_validate(
        {
            "timestamp": "2026-03-15T10:00:00Z",
            "event_type": "authentication",
            "username": "alice",
            "source_ip": "192.0.2.10",
            "action": "login",
            "status": "success",
            "password": "should-not-be-kept",
            "token": "should-not-be-kept",
        }
    )
    assert "password" not in event.model_dump()
    dumped = parse_event(event).original
    assert "password" not in dumped
    assert "token" not in dumped
