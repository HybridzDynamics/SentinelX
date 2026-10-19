from __future__ import annotations

from app.schemas import AnalyzeRequest, DetectionConfig, SecurityEventIn
from app.services.analyzer import analyze_request, list_rules
from tests.conftest import make_event


def test_empty_input_returns_zeroed_summary() -> None:
    result = analyze_request(AnalyzeRequest(events=[], config=DetectionConfig()))
    summary = result.summary
    assert summary.total_events_analyzed == 0
    assert summary.total_alerts_generated == 0
    assert summary.distinct_source_ips == 0
    assert summary.affected_usernames == 0
    assert summary.alerts == []
    assert summary.alerts_by_severity.high == 0
    assert summary.alerts_by_severity.critical == 0


def test_sample_dataset_produces_expected_rules(sample_events: list[SecurityEventIn]) -> None:
    result = analyze_request(AnalyzeRequest(events=sample_events, config=DetectionConfig()))
    summary = result.summary
    rule_ids = {alert.rule_id for alert in summary.alerts}
    assert summary.total_events_analyzed == 27
    assert "AUTH-001" in rule_ids
    assert "AUTH-002" in rule_ids
    assert "AUTH-003" in rule_ids

    burst = next(
        alert
        for alert in summary.alerts
        if alert.rule_id == "AUTH-001" and alert.source_ip == "203.0.113.50"
    )
    assert burst.event_count == 5
    assert "evt-burst-outside-window" not in burst.evidence

    spray = next(alert for alert in summary.alerts if alert.rule_id == "AUTH-002")
    assert spray.source_ip == "203.0.113.60"
    assert set(spray.usernames) == {"eve", "frank", "grace"}

    follow = next(alert for alert in summary.alerts if alert.rule_id == "AUTH-003")
    assert follow.source_ip == "203.0.113.70"
    assert follow.usernames == ["heidi"]
    assert "evt-follow-006" in follow.evidence

    assert not any(alert.source_ip == "203.0.113.80" for alert in summary.alerts)
    assert not any(alert.source_ip == "203.0.113.51" for alert in summary.alerts)
    assert not any(alert.source_ip == "198.51.100.10" for alert in summary.alerts)
    assert not any(alert.source_ip == "192.0.2.10" for alert in summary.alerts)

    assert summary.total_alerts_generated == len(summary.alerts)
    assert summary.alerts_by_severity.high + summary.alerts_by_severity.critical == summary.total_alerts_generated
    assert summary.distinct_source_ips == 8
    assert summary.affected_usernames == 10


def test_summary_counts_are_derived_from_alerts(sample_events: list[SecurityEventIn]) -> None:
    result = analyze_request(AnalyzeRequest(events=sample_events))
    high = sum(1 for alert in result.summary.alerts if alert.severity.value == "high")
    critical = sum(1 for alert in result.summary.alerts if alert.severity.value == "critical")
    assert result.summary.alerts_by_severity.high == high
    assert result.summary.alerts_by_severity.critical == critical


def test_duplicate_events_do_not_inflate_counts() -> None:
    events = [
        make_event(event_id="evt-a", status="failure", source_ip="203.0.113.50", username="dave"),
        make_event(event_id="evt-a", status="failure", source_ip="203.0.113.50", username="dave"),
    ]
    result = analyze_request(AnalyzeRequest(events=events))
    assert result.summary.total_events_analyzed == 1


def test_list_rules_exposes_thresholds_and_limitations() -> None:
    rules = list_rules(DetectionConfig())
    ids = [rule.rule_id for rule in rules]
    assert ids == ["AUTH-001", "AUTH-002", "AUTH-003"]
    for rule in rules:
        assert rule.thresholds
        assert rule.limitations
        assert rule.description
