# Contributing to SentinelX

This repository uses a simple GitHub flow so each module can be reviewed independently.

## Branch model

| Branch | Purpose |
| --- | --- |
| `main` | Stable, documented snapshots. Do not commit experimental work here. |
| `develop` | Integration branch for completed modules. |
| `feature/<module>-<short-name>` | One module or feature per branch. |
| `fix/<short-name>` | Bug fixes against `develop`. |
| `docs/<short-name>` | Documentation-only changes. |

Module 01 lives on:

```text
feature/module-01-explainable-detection-engine
```

## PowerShell workflow

From the repository root:

```powershell
git fetch origin
git checkout develop
git pull origin develop
git checkout -b feature/module-02-short-name
```

Commit only related files. Use a short message that explains why the change exists:

```powershell
git add path\to\file
git commit -m "Add module 02 skeleton for event ingestion."
git push -u origin HEAD
```

Open a pull request:

- base: `develop`
- compare: your `feature/*` branch

After review and tests pass, merge into `develop`. Promote `develop` to `main` when a module is ready to be treated as stable.

## Rules for this project

- Implement one independently testable module at a time.
- Do not mark unfinished work as operational.
- Keep detection logic deterministic and free of real-world blocking actions.
- Run `pytest` from `backend` before opening a pull request.
