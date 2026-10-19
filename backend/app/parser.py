"""Validate and normalize inbound security events.

This module never executes commands, contacts remote hosts, or treats event
contents as instructions. Sensitive field names are dropped before parsing.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any

from app.schemas import ParsedEvent, SecurityEventIn

AUTH_EVENT_TYPES = frozenset({"authentication", "login", "auth", "logon"})
AUTH_ACTIONS = frozenset({"login", "authenticate", "logon", "ssh_login"})

STATUS_FAILURE = frozenset({"failure", "failed", "fail", "unsuccessful", "denied", "error", "invalid"})
STATUS_SUCCESS = frozenset({"success", "succeeded", "ok", "allowed", "pass"})


class EventParseError(ValueError):
    """Raised when a single event cannot be parsed."""

    def __init__(self, message: str, *, index: int | None = None, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.index = index
        self.field = field


class BatchParseError(ValueError):
    """Raised when one or more events in a batch are invalid."""

    def __init__(self, errors: list[EventParseError]) -> None:
        super().__init__("One or more events failed validation.")
        self.errors = errors


def parse_timestamp(value: str) -> datetime:
    """Parse a timezone-aware ISO 8601 timestamp and return UTC.

    Accepted forms include ``YYYY-MM-DDTHH:MM:SSZ`` and offsets such as
    ``YYYY-MM-DDTHH:MM:SS+00:00``. Fractional seconds are allowed.
    """
    raw = value.strip()
    if not raw:
        raise EventParseError("timestamp is required.", field="timestamp")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise EventParseError(
            "timestamp must be ISO 8601 with a timezone offset, for example 2026-03-15T10:00:00Z.",
            field="timestamp",
        ) from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise EventParseError(
            "timestamp must be timezone-aware (include Z or an offset such as +00:00).",
            field="timestamp",
        )
    return parsed.astimezone(timezone.utc)


def normalize_status(value: str) -> str:
    token = value.strip().lower()
    if token in STATUS_SUCCESS:
        return "success"
    if token in STATUS_FAILURE:
        return "failure"
    return token


def normalize_name(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _validate_source_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise EventParseError(
            "source_ip must be a valid IPv4 or IPv6 address.",
            field="source_ip",
        ) from exc


def _stable_event_id(event: SecurityEventIn, timestamp: datetime) -> str:
    material = "|".join(
        [
            timestamp.isoformat(),
            normalize_name(event.event_type),
            event.username.strip(),
            event.source_ip.strip(),
            normalize_name(event.action),
            normalize_status(event.status),
            (event.hostname or "").strip(),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"evt-{digest}"


def parse_event(event: SecurityEventIn, *, index: int | None = None) -> ParsedEvent:
    try:
        timestamp = parse_timestamp(event.timestamp)
        source_ip = _validate_source_ip(event.source_ip)
        event_type = normalize_name(event.event_type)
        action = normalize_name(event.action)
        status = normalize_status(event.status)
        username = event.username.strip()
        if not username:
            raise EventParseError("username must not be empty.", field="username")
        hostname = event.hostname.strip() if event.hostname else None
        event_id = event.event_id.strip() if event.event_id else _stable_event_id(event, timestamp)
        original = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "username": event.username,
            "source_ip": event.source_ip,
            "action": event.action,
            "status": event.status,
            "hostname": event.hostname,
        }
        return ParsedEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            username=username,
            username_normalized=username.casefold(),
            source_ip=source_ip,
            action=action,
            status=status,
            hostname=hostname,
            original=original,
        )
    except EventParseError as exc:
        raise EventParseError(exc.message, index=index, field=exc.field) from exc


def parse_events(events: list[SecurityEventIn]) -> list[ParsedEvent]:
    """Parse a batch. Invalid events fail the entire batch (fail closed)."""
    errors: list[EventParseError] = []
    parsed: list[ParsedEvent] = []
    for index, event in enumerate(events):
        try:
            parsed.append(parse_event(event, index=index))
        except EventParseError as exc:
            errors.append(exc)
    if errors:
        raise BatchParseError(errors)
    return deduplicate_events(parsed)


def deduplicate_events(events: list[ParsedEvent]) -> list[ParsedEvent]:
    """Keep the first occurrence of each event_id; identical IDs are ignored."""
    seen: set[str] = set()
    unique: list[ParsedEvent] = []
    for event in events:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        unique.append(event)
    return unique


def is_authentication_event(event: ParsedEvent) -> bool:
    return event.event_type in AUTH_EVENT_TYPES or event.action in AUTH_ACTIONS
