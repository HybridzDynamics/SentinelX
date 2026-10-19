"""Pydantic models for security events, configuration, alerts, and API payloads.

Accepted timestamp format
-------------------------
Timestamps must be timezone-aware ISO 8601 strings. Examples:

- ``2026-03-15T10:00:00Z``
- ``2026-03-15T10:00:00+00:00``
- ``2026-03-15T15:30:00+05:30``

Naive timestamps (no offset or ``Z``) are rejected so analysis remains
reproducible across timezones. Internally, all timestamps are normalized to UTC.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


MAX_EVENTS_PER_REQUEST = 10_000
MAX_STRING_LENGTH = 256
SENSITIVE_FIELD_NAMES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "session",
        "session_id",
        "sessionid",
        "credential",
        "credentials",
    }
)


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionConfig(BaseModel):
    """Configurable demonstration thresholds. These are not universal security defaults."""

    model_config = ConfigDict(extra="forbid")

    failed_login_threshold: int = Field(default=5, ge=1, le=10_000)
    failed_login_window_seconds: int = Field(default=300, ge=1, le=86_400)
    multi_account_username_threshold: int = Field(default=3, ge=2, le=10_000)
    multi_account_window_seconds: int = Field(default=300, ge=1, le=86_400)
    success_after_fail_threshold: int = Field(default=5, ge=1, le=10_000)
    success_after_fail_window_seconds: int = Field(default=300, ge=1, le=86_400)
    max_events: int = Field(default=MAX_EVENTS_PER_REQUEST, ge=1, le=MAX_EVENTS_PER_REQUEST)


class SecurityEventIn(BaseModel):
    """Inbound security event. Extra keys are ignored; sensitive names are stripped."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    event_id: str | None = Field(default=None, max_length=MAX_STRING_LENGTH)
    timestamp: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=MAX_STRING_LENGTH)
    username: str = Field(min_length=1, max_length=MAX_STRING_LENGTH)
    source_ip: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=MAX_STRING_LENGTH)
    status: str = Field(min_length=1, max_length=MAX_STRING_LENGTH)
    hostname: str | None = Field(default=None, max_length=MAX_STRING_LENGTH)

    @model_validator(mode="before")
    @classmethod
    def drop_sensitive_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                key: value
                for key, value in data.items()
                if str(key).lower() not in SENSITIVE_FIELD_NAMES
            }
        return data


class ParsedEvent(BaseModel):
    """Normalized event used by the detection engine."""

    event_id: str
    timestamp: datetime
    event_type: str
    username: str
    username_normalized: str
    source_ip: str
    action: str
    status: str
    hostname: str | None = None
    original: dict[str, Any]


class Alert(BaseModel):
    alert_id: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    source_ip: str | None = None
    usernames: list[str] = Field(default_factory=list)
    detected_at: datetime
    event_count: int = Field(ge=0)
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str


class SeverityCounts(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class IncidentSummary(BaseModel):
    total_events_analyzed: int
    total_alerts_generated: int
    alerts_by_severity: SeverityCounts
    distinct_source_ips: int
    affected_usernames: int
    alerts: list[Alert]


class AnalyzeRequest(BaseModel):
    events: list[SecurityEventIn] = Field(default_factory=list)
    config: DetectionConfig = Field(default_factory=DetectionConfig)

    @field_validator("events")
    @classmethod
    def enforce_event_limit(cls, events: list[SecurityEventIn]) -> list[SecurityEventIn]:
        if len(events) > MAX_EVENTS_PER_REQUEST:
            raise ValueError(
                f"A maximum of {MAX_EVENTS_PER_REQUEST} events is allowed per request."
            )
        return events


class AnalyzeResponse(BaseModel):
    summary: IncidentSummary


class RuleInfo(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Severity
    thresholds: dict[str, int]
    limitations: list[str]


class HealthResponse(BaseModel):
    status: str
    service: str
    module: str
    version: str


class ErrorDetail(BaseModel):
    message: str
    index: int | None = None
    field: str | None = None


class ErrorResponse(BaseModel):
    error: str
    details: list[ErrorDetail] = Field(default_factory=list)
