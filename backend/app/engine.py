"""Deterministic rules engine: run authentication detections and stamp alert IDs."""

from __future__ import annotations

import hashlib
from datetime import timezone

from app.rules.authentication import AUTHENTICATION_RULES
from app.schemas import Alert, DetectionConfig, ParsedEvent


def _alert_id(alert: Alert) -> str:
    material = "|".join(
        [
            alert.rule_id,
            alert.source_ip or "",
            alert.detected_at.astimezone(timezone.utc).isoformat(),
            ",".join(alert.evidence),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"alert-{digest}"


def evaluate(events: list[ParsedEvent], config: DetectionConfig) -> list[Alert]:
    """Run all rules and return stable, sorted alerts.

    Alert identifiers are derived from rule, source IP, detection time, and
    evidence IDs so repeated analysis of the same input produces the same output.
    """
    alerts: list[Alert] = []
    for rule in AUTHENTICATION_RULES:
        for alert in rule.detect(events, config):
            alerts.append(alert.model_copy(update={"alert_id": _alert_id(alert)}))

    alerts.sort(key=lambda item: (item.detected_at, item.rule_id, item.alert_id))
    return alerts
