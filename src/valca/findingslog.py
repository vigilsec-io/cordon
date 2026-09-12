"""Persistent findings log — append-only JSONL at ~/.vigil/findings.jsonl.

Every scan that produces findings appends one record per finding.
Provides a local audit trail across sessions: what was caught, when, and in which file.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from .rules.base import Finding


def _log_path() -> Path:
    env = os.environ.get("VIGIL_LOG_PATH")
    if env:
        p = Path(env)
        return p if p.suffix == ".jsonl" else p / "findings.jsonl"
    return Path.home() / ".vigil" / "findings.jsonl"


def append(findings: list[Finding], session_id: str | None = None) -> None:
    """Append findings to the persistent log. No-op if findings is empty."""
    if not findings:
        return
    log = _log_path()
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with log.open("a") as fh:
            for f in findings:
                record: dict = {
                    "ts": ts,
                    "file": str(f.file_path),
                    "rule": f.rule_id,
                    "severity": f.severity.value,
                    "title": (f.message or "")[:120],
                    "detail": (f.fix or "")[:120],
                }
                if session_id:
                    record["session_id"] = session_id
                fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # log failures are never fatal


def read(
    project: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Read findings from the log, newest last, with optional filters."""
    log = _log_path()
    if not log.exists():
        return []
    entries: list[dict] = []
    try:
        with log.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if project and project not in e.get("file", ""):
                    continue
                if severity and e.get("severity", "").upper() != severity.upper():
                    continue
                if since and e.get("ts", "") < since:
                    continue
                entries.append(e)
    except OSError:
        return []
    return entries[-limit:]
