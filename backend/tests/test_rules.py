from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.engine import evaluate
from app.parser import parse_events
from app.rules.authentication import (
    detect_multiple_account_failures,
    detect_repeated_failed_logins,
    detect_success_after_failures,
)
from app.schemas import DetectionConfig, SecurityEventIn
from tests.conftest import make_event

UTC = timezone.utc
BASE = datetime(2026, 3, 15, 10, 0, 0, tzinfo=UTC)


def _ts(offset_seconds: int) -> str:
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _failed(index: int, *, ip: str = "203.0.113.50", user: str = "dave", offset: int) -> SecurityEventIn:
    return make_event(
        event_id=f"evt-{index:03d}",
        timestamp=_ts(offset),
        username=user,
        source_ip=ip,
        status="failure",
    )


def _success(index: int, *, ip: str = "203.0.113.50", user: str = "dave", offset: int) -> SecurityEventIn:
    return make_event(
        event_id=f"evt-{index:03d}",
        timestamp=_ts(offset),
        username=user,
        source_ip=ip,
        status="success",
    )


def test_repeated_failures_alert_at_threshold() -> None:
    events = parse_events([_failed(i, offset=i * 10) for i in range(5)])
    alerts = detect_repeated_failed_logins(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-001"
    assert alerts[0].event_count == 5
    assert alerts[0].source_ip == "203.0.113.50"
    assert alerts[0].evidence == [f"evt-{i:03d}" for i in range(5)]


def test_no_alert_below_threshold() -> None:
    events = parse_events([_failed(i, offset=i * 10) for i in range(4)])
    alerts = detect_repeated_failed_logins(events, DetectionConfig())
    assert alerts == []


def test_failures_outside_window_do_not_count() -> None:
    events = parse_events(
        [
            _failed(0, offset=0),
            _failed(1, offset=60),
            _failed(2, offset=120),
            _failed(3, offset=180),
            _failed(4, offset=301),
        ]
    )
    alerts = detect_repeated_failed_logins(events, DetectionConfig())
    assert alerts == []


def test_one_grouped_alert_for_overlapping_failures() -> None:
    events = parse_events([_failed(i, offset=i * 20) for i in range(8)])
    alerts = detect_repeated_failed_logins(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].event_count == 8


def test_multiple_usernames_from_one_source() -> None:
    events = parse_events(
        [
            _failed(0, user="eve", ip="203.0.113.60", offset=0),
            _failed(1, user="frank", ip="203.0.113.60", offset=30),
            _failed(2, user="grace", ip="203.0.113.60", offset=60),
        ]
    )
    alerts = detect_multiple_account_failures(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-002"
    assert set(alerts[0].usernames) == {"eve", "frank", "grace"}


def test_multiple_failures_same_username_is_not_auth_002() -> None:
    events = parse_events([_failed(i, offset=i * 10) for i in range(5)])
    alerts = detect_multiple_account_failures(events, DetectionConfig())
    assert alerts == []


def test_success_after_repeated_failures() -> None:
    events = parse_events(
        [_failed(i, user="heidi", ip="203.0.113.70", offset=i * 15) for i in range(5)]
        + [_success(5, user="heidi", ip="203.0.113.70", offset=80)]
    )
    alerts = detect_success_after_failures(events, DetectionConfig())
    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-003"
    assert alerts[0].severity.value == "critical"
    assert "evt-005" in alerts[0].evidence
    assert alerts[0].event_count == 6


def test_success_without_enough_failures_is_not_auth_003() -> None:
    events = parse_events(
        [
            _failed(0, user="heidi", ip="203.0.113.70", offset=0),
            _failed(1, user="heidi", ip="203.0.113.70", offset=10),
            _success(2, user="heidi", ip="203.0.113.70", offset=20),
        ]
    )
    alerts = detect_success_after_failures(events, DetectionConfig())
    assert alerts == []


def test_success_from_different_ip_is_not_correlated() -> None:
    events = parse_events(
        [_failed(i, user="heidi", ip="203.0.113.70", offset=i * 10) for i in range(5)]
        + [_success(5, user="heidi", ip="203.0.113.71", offset=60)]
    )
    alerts = detect_success_after_failures(events, DetectionConfig())
    assert alerts == []


def test_engine_emits_stable_structured_alerts() -> None:
    events = parse_events([_failed(i, offset=i * 10) for i in range(5)])
    first = evaluate(events, DetectionConfig())
    second = evaluate(events, DetectionConfig())
    assert first == second
    alert = first[0]
    assert alert.alert_id.startswith("alert-")
    assert alert.rule_id == "AUTH-001"
    assert alert.title
    assert alert.description
    assert alert.recommended_action
    assert "not classified as malicious solely" in alert.description
    assert alert.evidence
