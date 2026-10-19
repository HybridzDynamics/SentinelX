# SentinelX

Defensive cybersecurity incident investigation platform. This repository currently ships **Module 01: Explainable Security Detection Engine**, a working, independently testable rules-based analyzer.

The engine accepts structured authentication events, applies deterministic detection rules, and returns alerts with evidence and plain-language explanations. It does not scan networks, attempt logins, block IP addresses, or disable accounts.

## What Module 01 does

- Validates and normalizes JSON security events.
- Detects three authentication patterns:
  - **AUTH-001** repeated failed logins from one source IP.
  - **AUTH-002** failed authentications against multiple usernames from one source IP.
  - **AUTH-003** a successful login after a burst of failures for the same username and source IP.
- Groups related events into a single alert instead of alerting on every matching row.
- Returns an incident summary derived from the analysis that was just performed.
- Exposes a small FastAPI service for health, rule metadata, and batch analysis.

A rule match describes observed behavior. It does **not** classify a source IP as malicious by itself.

## Architecture and data flow

```text
JSON events
    -> Pydantic request models (app/schemas.py)
    -> parser (app/parser.py)  validate, normalize, deduplicate
    -> rules engine (app/engine.py + app/rules/authentication.py)
    -> analyzer (app/services/analyzer.py)  alerts + summary
    -> FastAPI (app/main.py)  optional HTTP API
```

Rule definitions are kept separate from parsing, alert generation, and HTTP routing.

### Accepted timestamp format

Timestamps must be **timezone-aware ISO 8601**. Examples:

- `2026-03-15T10:00:00Z`
- `2026-03-15T10:00:00+00:00`
- `2026-03-15T15:30:00+05:30`

Naive timestamps such as `2026-03-15T10:00:00` are rejected. Values are normalized to UTC before detection.

Required event fields: `timestamp`, `event_type`, `username`, `source_ip`, `action`, `status`. Optional: `event_id`, `hostname`.

## Repository layout

```text
SentinelX/
  README.md
  CONTRIBUTING.md
  requirements.txt
  backend/
    app/
      main.py              HTTP API
      schemas.py           request/response models
      parser.py            validation and normalization
      engine.py            rule orchestration
      rules/authentication.py
      services/analyzer.py
    tests/
    data/sample_auth_logs.json
```

## Requirements

- Python 3.11
- Windows PowerShell (commands below)

## Setup (Windows PowerShell)

From the repository root:

```powershell
cd C:\Users\moham\Desktop\SentinelX
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `py -3.11` is not available, use `python -m venv .venv` with a 3.11 interpreter.

## Run the tests

```powershell
cd C:\Users\moham\Desktop\SentinelX
.\.venv\Scripts\Activate.ps1
cd backend
pytest
```

## Start the API

From the repository root, with the virtual environment active:

```powershell
cd C:\Users\moham\Desktop\SentinelX
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Interactive docs: http://127.0.0.1:8000/docs

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service health |
| `GET` | `/api/v1/rules` | Rule catalog, thresholds, limitations |
| `POST` | `/api/v1/analyze` | Analyze a batch of events |

Maximum request body size: **1 MiB**. Maximum events per request: **10,000**.

### Example: health

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/health -Method Get | ConvertTo-Json
```

### Example: list rules

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/rules -Method Get | ConvertTo-Json -Depth 6
```

### Example: analyze the sample dataset

```powershell
$sample = Get-Content -Raw -Path .\backend\data\sample_auth_logs.json | ConvertFrom-Json
$body = @{ events = $sample.events } | ConvertTo-Json -Depth 8
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/analyze -Method Post -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
```

A compact JSON request looks like:

```json
{
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2026-03-15T11:00:00Z",
      "event_type": "authentication",
      "username": "dave",
      "source_ip": "203.0.113.50",
      "action": "login",
      "status": "failure"
    }
  ],
  "config": {
    "failed_login_threshold": 5,
    "failed_login_window_seconds": 300
  }
}
```

`config` is optional. Omit it to use demonstration defaults.

### Example alert shape

Alert identifiers, counts, and evidence are generated from the supplied events. They are not hardcoded demonstration strings.

```json
{
  "alert_id": "alert-...",
  "rule_id": "AUTH-001",
  "title": "Repeated Failed Login Attempts",
  "severity": "high",
  "description": "Multiple failed authentication attempts exceeded the configured threshold...",
  "source_ip": "203.0.113.50",
  "usernames": ["dave"],
  "detected_at": "2026-03-15T11:01:20Z",
  "event_count": 5,
  "evidence": ["evt-burst-001", "evt-burst-002"],
  "recommended_action": "Review the authentication records..."
}
```

## Changing detection thresholds

Pass a `config` object in `POST /api/v1/analyze`, or construct `DetectionConfig` in code.

| Setting | Default | Used by |
| --- | --- | --- |
| `failed_login_threshold` | 5 | AUTH-001 |
| `failed_login_window_seconds` | 300 | AUTH-001 |
| `multi_account_username_threshold` | 3 | AUTH-002 |
| `multi_account_window_seconds` | 300 | AUTH-002 |
| `success_after_fail_threshold` | 5 | AUTH-003 |
| `success_after_fail_window_seconds` | 300 | AUTH-003 |
| `max_events` | 10000 | Analyzer |

These defaults are for demonstration only. They are not universal production thresholds.

## Sample dataset

`backend/data/sample_auth_logs.json` is synthetic. It uses RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and includes:

- Normal successful logins
- Isolated failed logins
- Repeated failures from one IP
- Failures spread outside the 5-minute window
- Failures against multiple usernames
- A successful login after repeated failures
- Four in-window failures (below AUTH-001 threshold)

## Git branches (GitHub)

See [CONTRIBUTING.md](CONTRIBUTING.md). Current module branch:

```text
feature/module-01-explainable-detection-engine
```

Publish that branch (after review of local tests):

```powershell
git push -u origin feature/module-01-explainable-detection-engine
git push -u origin develop
```

Open a pull request from the feature branch into `develop`.

## Security and safe use

- Process only logs you are authorized to analyze.
- Do not point this engine at live authentication services.
- Do not use alerts as an automatic block or disable signal.
- Event fields named `password`, `token`, `cookie`, and similar are dropped during parsing.
- Error responses avoid echoing raw event payloads.

## Known limitations

- Only authentication-style events are evaluated (`event_type` or `action` in a small allow-list). Other log types are stored in the analyzed count but do not fire these rules.
- Shared NAT, VPN egress, and jump hosts can concentrate legitimate failures onto one IP (false positives).
- AUTH-003 requires the failures and the later success to share both username and source IP.
- The engine cannot see MFA, lockout policy, or whether a username exists.
- Thresholds are not adaptive. Tune them per environment.
- Duplicate events are collapsed by `event_id` only. Distinct IDs with identical fields are counted separately.

## What this module does not include

No frontend, no AI agent, no autonomous response, and no SIEM platform. Those are out of scope until this module is finished and validated.
