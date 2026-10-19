"""Transparent authentication detection rules.

These rules describe observed authentication patterns. A match is not a
determination that an IP address or account is malicious. Thresholds are
demonstration defaults and should be tuned per environment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.parser import is_authentication_event
from app.schemas import Alert, DetectionConfig, ParsedEvent, Severity

RuleFn = Callable[[list[ParsedEvent], DetectionConfig], list[Alert]]


@dataclass(frozen=True)
class AuthenticationRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    limitations: tuple[str, ...]
    detect: RuleFn

    def threshold_map(self, config: DetectionConfig) -> dict[str, int]:
        if self.rule_id == "AUTH-001":
            return {
                "failed_login_threshold": config.failed_login_threshold,
                "failed_login_window_seconds": config.failed_login_window_seconds,
            }
        if self.rule_id == "AUTH-002":
            return {
                "multi_account_username_threshold": config.multi_account_username_threshold,
                "multi_account_window_seconds": config.multi_account_window_seconds,
            }
        return {
            "success_after_fail_threshold": config.success_after_fail_threshold,
            "success_after_fail_window_seconds": config.success_after_fail_window_seconds,
        }


def _failed_auth(events: list[ParsedEvent]) -> list[ParsedEvent]:
    return [
        event
        for event in events
        if is_authentication_event(event) and event.status == "failure"
    ]


def _successful_auth(events: list[ParsedEvent]) -> list[ParsedEvent]:
    return [
        event
        for event in events
        if is_authentication_event(event) and event.status == "success"
    ]


def _sorted(events: list[ParsedEvent]) -> list[ParsedEvent]:
    return sorted(events, key=lambda event: (event.timestamp, event.event_id))


def _group_by_ip(events: list[ParsedEvent]) -> dict[str, list[ParsedEvent]]:
    grouped: dict[str, list[ParsedEvent]] = {}
    for event in events:
        grouped.setdefault(event.source_ip, []).append(event)
    return grouped


def cluster_by_sliding_window(
    events: list[ParsedEvent],
    *,
    window: timedelta,
    qualifies: Callable[[list[ParsedEvent]], bool],
) -> list[list[ParsedEvent]]:
    """Mark events that sit in at least one qualifying window, then group bursts.

    Overlapping qualifying windows become a single cluster so one incident is
    reported instead of one alert per event.
    """
    ordered = _sorted(events)
    if not ordered:
        return []

    n = len(ordered)
    in_incident = [False] * n
    left = 0
    for right in range(n):
        while ordered[right].timestamp - ordered[left].timestamp > window:
            left += 1
        window_events = ordered[left : right + 1]
        if qualifies(window_events):
            for index in range(left, right + 1):
                in_incident[index] = True

    clusters: list[list[ParsedEvent]] = []
    current: list[ParsedEvent] = []
    for index, event in enumerate(ordered):
        if not in_incident[index]:
            if current:
                clusters.append(current)
                current = []
            continue
        if current and event.timestamp - current[-1].timestamp > window:
            clusters.append(current)
            current = [event]
        else:
            current.append(event)
    if current:
        clusters.append(current)
    return clusters


def detect_repeated_failed_logins(
    events: list[ParsedEvent],
    config: DetectionConfig,
) -> list[Alert]:
    """AUTH-001: many failed authentications from one source IP in a time window."""
    window = timedelta(seconds=config.failed_login_window_seconds)
    threshold = config.failed_login_threshold
    alerts: list[Alert] = []

    for source_ip, ip_events in _group_by_ip(_failed_auth(events)).items():
        clusters = cluster_by_sliding_window(
            ip_events,
            window=window,
            qualifies=lambda batch, limit=threshold: len(batch) >= limit,
        )
        for cluster in clusters:
            usernames = _unique_usernames(cluster)
            count = len(cluster)
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="AUTH-001",
                    title="Repeated Failed Login Attempts",
                    severity=Severity.HIGH,
                    description=(
                        f"{count} failed authentication attempt(s) from {source_ip} "
                        f"were observed within {config.failed_login_window_seconds} seconds, "
                        f"which exceeds the configured threshold of {threshold}. "
                        "This pattern can occur during password guessing, misconfigured "
                        "clients, or a user repeatedly entering incorrect credentials. "
                        "The source IP is not classified as malicious solely because this "
                        "rule matched."
                    ),
                    source_ip=source_ip,
                    usernames=usernames,
                    detected_at=_last_timestamp(cluster),
                    event_count=count,
                    evidence=_evidence_ids(cluster),
                    recommended_action=(
                        "Review the authentication records for this source IP, confirm "
                        "whether the activity is expected, and investigate account lockout "
                        "or credential-reset status. Do not block the address automatically."
                    ),
                )
            )
    return alerts


def detect_multiple_account_failures(
    events: list[ParsedEvent],
    config: DetectionConfig,
) -> list[Alert]:
    """AUTH-002: one source IP fails against several distinct usernames."""
    window = timedelta(seconds=config.multi_account_window_seconds)
    threshold = config.multi_account_username_threshold
    alerts: list[Alert] = []

    for source_ip, ip_events in _group_by_ip(_failed_auth(events)).items():
        clusters = cluster_by_sliding_window(
            ip_events,
            window=window,
            qualifies=lambda batch, limit=threshold: len(_unique_usernames(batch)) >= limit,
        )
        for cluster in clusters:
            usernames = _unique_usernames(cluster)
            if len(usernames) < threshold:
                continue
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="AUTH-002",
                    title="Failed Authentication Across Multiple Accounts",
                    severity=Severity.HIGH,
                    description=(
                        f"Source IP {source_ip} produced failed authentication outcomes for "
                        f"{len(usernames)} distinct username(s) within "
                        f"{config.multi_account_window_seconds} seconds, which exceeds the "
                        f"configured threshold of {threshold}. This can resemble credential "
                        "spraying, a shared NAT gateway with several users, or a directory "
                        "sync error. Matching this rule does not by itself prove hostile intent."
                    ),
                    source_ip=source_ip,
                    usernames=usernames,
                    detected_at=_last_timestamp(cluster),
                    event_count=len(cluster),
                    evidence=_evidence_ids(cluster),
                    recommended_action=(
                        "Compare the attempted usernames with valid accounts, check whether "
                        "the source is a known shared egress point, and review identity-provider "
                        "logs. Do not disable accounts automatically from this alert."
                    ),
                )
            )
    return alerts


def detect_success_after_failures(
    events: list[ParsedEvent],
    config: DetectionConfig,
) -> list[Alert]:
    """AUTH-003: a success after a burst of failures for the same user and IP."""
    window = timedelta(seconds=config.success_after_fail_window_seconds)
    threshold = config.success_after_fail_threshold
    alerts: list[Alert] = []

    by_identity: dict[tuple[str, str], list[ParsedEvent]] = {}
    for event in events:
        if not is_authentication_event(event):
            continue
        if event.status not in {"failure", "success"}:
            continue
        key = (event.source_ip, event.username_normalized)
        by_identity.setdefault(key, []).append(event)

    for (source_ip, _), identity_events in by_identity.items():
        ordered = _sorted(identity_events)
        successes = [event for event in ordered if event.status == "success"]
        failures = [event for event in ordered if event.status == "failure"]
        matched_successes: list[ParsedEvent] = []
        related: dict[str, ParsedEvent] = {}
        for success in successes:
            prior = [
                event
                for event in failures
                if success.timestamp - window <= event.timestamp < success.timestamp
            ]
            if len(prior) < threshold:
                continue
            matched_successes.append(success)
            related[success.event_id] = success
            for event in prior:
                related[event.event_id] = event
        if not matched_successes:
            continue
        clusters = cluster_by_sliding_window(
            list(related.values()),
            window=window,
            qualifies=lambda batch, limit=threshold: (
                sum(1 for item in batch if item.status == "failure") >= limit
                and any(item.status == "success" for item in batch)
            ),
        )
        for cluster in clusters:
            fail_count = sum(1 for item in cluster if item.status == "failure")
            success_event = [item for item in cluster if item.status == "success"][-1]
            alerts.append(
                Alert(
                    alert_id="",
                    rule_id="AUTH-003",
                    title="Successful Login After Repeated Failures",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Username '{success_event.username}' authenticated successfully from "
                        f"{source_ip} after {fail_count} failed attempt(s) within "
                        f"{config.success_after_fail_window_seconds} seconds (threshold "
                        f"{threshold}). This may indicate a guessed password, a user who "
                        "eventually entered the correct credential, or a shared workstation. "
                        "The successful login is not treated as unauthorized solely because "
                        "this rule matched."
                    ),
                    source_ip=source_ip,
                    usernames=_unique_usernames(cluster),
                    detected_at=success_event.timestamp,
                    event_count=len(cluster),
                    evidence=_evidence_ids(cluster),
                    recommended_action=(
                        "Verify the successful session with the account owner, review session "
                        "metadata (hostname, MFA, geo if available in other logs), and check "
                        "for additional access after the login. Do not terminate the session "
                        "automatically from this engine."
                    ),
                )
            )
    return alerts


def _unique_usernames(events: list[ParsedEvent]) -> list[str]:
    seen: set[str] = set()
    names: list[str] = []
    for event in events:
        key = event.username_normalized
        if key in seen:
            continue
        seen.add(key)
        names.append(event.username)
    return names


def _evidence_ids(events: list[ParsedEvent]) -> list[str]:
    return [event.event_id for event in _sorted(events)]


def _last_timestamp(events: list[ParsedEvent]) -> datetime:
    return _sorted(events)[-1].timestamp


AUTH_001_LIMITATIONS = (
    "Counts failed authentication events only; lockouts, MFA denials, and protocol-specific "
    "errors may be labeled differently in source logs.",
    "Shared NAT, VPN concentrators, and jump hosts can concentrate legitimate failures.",
    "Demonstration default of 5 failures in 5 minutes is not a universal security threshold.",
    "Does not inspect password values and cannot distinguish typos from guessing.",
)
AUTH_002_LIMITATIONS = (
    "Username comparison is case-insensitive after normalization and may collapse distinct "
    "directory identities that differ only by case.",
    "A corporate proxy can make many users appear as one source IP.",
    "Does not confirm whether attempted usernames exist in the directory.",
)
AUTH_003_LIMITATIONS = (
    "Requires failures and the later success to share both username and source IP.",
    "A success from a different IP after failures elsewhere is not correlated.",
    "Cannot determine whether multi-factor authentication was satisfied.",
    "Legitimate users who mistype a password several times will also match.",
)


AUTHENTICATION_RULES: tuple[AuthenticationRule, ...] = (
    AuthenticationRule(
        rule_id="AUTH-001",
        title="Repeated Failed Login Attempts",
        description=(
            "Detects multiple failed authentication attempts from the same source IP "
            "within a configurable time window and emits one grouped alert per burst."
        ),
        severity=Severity.HIGH,
        limitations=AUTH_001_LIMITATIONS,
        detect=detect_repeated_failed_logins,
    ),
    AuthenticationRule(
        rule_id="AUTH-002",
        title="Failed Authentication Across Multiple Accounts",
        description=(
            "Detects a source IP that generates failed authentication outcomes against "
            "multiple distinct usernames within a configurable time window."
        ),
        severity=Severity.HIGH,
        limitations=AUTH_002_LIMITATIONS,
        detect=detect_multiple_account_failures,
    ),
    AuthenticationRule(
        rule_id="AUTH-003",
        title="Successful Login After Repeated Failures",
        description=(
            "Detects a successful authentication that follows a burst of failed attempts "
            "for the same username and source IP within a configurable time window."
        ),
        severity=Severity.CRITICAL,
        limitations=AUTH_003_LIMITATIONS,
        detect=detect_success_after_failures,
    ),
)
