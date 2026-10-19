"""Analyze a batch of security events and build an incident summary."""

from __future__ import annotations

from app.engine import evaluate
from app.parser import EventParseError, parse_events
from app.rules.authentication import AUTHENTICATION_RULES
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    DetectionConfig,
    IncidentSummary,
    RuleInfo,
    Severity,
    SeverityCounts,
)


def analyze_request(payload: AnalyzeRequest) -> AnalyzeResponse:
    if len(payload.events) > payload.config.max_events:
        raise EventParseError(
            f"A maximum of {payload.config.max_events} events is allowed per analysis.",
            field="events",
        )
    parsed = parse_events(payload.events)
    alerts = evaluate(parsed, payload.config)

    severity_counts = SeverityCounts()
    for alert in alerts:
        if alert.severity == Severity.LOW:
            severity_counts.low += 1
        elif alert.severity == Severity.MEDIUM:
            severity_counts.medium += 1
        elif alert.severity == Severity.HIGH:
            severity_counts.high += 1
        elif alert.severity == Severity.CRITICAL:
            severity_counts.critical += 1

    source_ips = {event.source_ip for event in parsed}
    usernames = {event.username_normalized for event in parsed}

    summary = IncidentSummary(
        total_events_analyzed=len(parsed),
        total_alerts_generated=len(alerts),
        alerts_by_severity=severity_counts,
        distinct_source_ips=len(source_ips),
        affected_usernames=len(usernames),
        alerts=alerts,
    )
    return AnalyzeResponse(summary=summary)


def list_rules(config: DetectionConfig | None = None) -> list[RuleInfo]:
    cfg = config or DetectionConfig()
    return [
        RuleInfo(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            thresholds=rule.threshold_map(cfg),
            limitations=list(rule.limitations),
        )
        for rule in AUTHENTICATION_RULES
    ]
