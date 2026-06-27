"""Anonymous, local-only telemetry for Vigil.

Collects only: rule_id, severity, file_ext, timestamp.
Never: file path, code snippet, finding message, or any user-identifiable data.

Stored at ~/.vigil/events.jsonl (line-delimited JSON).
Opt-out: set VIGIL_NO_TELEMETRY=1 or add `telemetry = false` to .vigilrc.

Events are local-only by default — no network calls are made in this module.
A future `vigil stats` command or opt-in upload path can read events.jsonl.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .rules.base import Finding

_EVENTS_FILE = Path.home() / ".vigil" / "events.jsonl"
_OPT_OUT_ENV = "VIGIL_NO_TELEMETRY"


def _is_opted_out(telemetry_config: bool = True) -> bool:
    if not telemetry_config:
        return True
    return os.environ.get(_OPT_OUT_ENV, "").strip() not in ("", "0")


def record(findings: list["Finding"], telemetry_enabled: bool = True) -> None:
    """Append one event per finding to ~/.vigil/events.jsonl.

    Silently swallows all errors — telemetry must never break the scan.
    """
    if _is_opted_out(telemetry_enabled) or not findings:
        return
    try:
        _EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        with _EVENTS_FILE.open("a") as fh:
            for f in findings:
                ext = f.file_path.suffix if f.file_path else ""
                event = {
                    "ts": ts,
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "file_ext": ext,
                }
                fh.write(json.dumps(event) + "\n")
    except Exception:  # noqa: BLE001
        pass


def summary() -> dict:
    """Return aggregated stats from local events.jsonl. Returns {} if no data."""
    try:
        if not _EVENTS_FILE.exists():
            return {}
        counts: dict[str, int] = {}
        total = 0
        with _EVENTS_FILE.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    key = ev.get("rule_id", "unknown")
                    counts[key] = counts.get(key, 0) + 1
                    total += 1
                except json.JSONDecodeError:
                    continue
        return {"total_findings": total, "by_rule": counts}
    except Exception:  # noqa: BLE001
        return {}
