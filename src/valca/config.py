from __future__ import annotations
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ValcaConfig:
    disabled_rules: list[str] = field(default_factory=list)
    min_severity: str | None = None
    exclude_paths: list[str] = field(default_factory=list)
    telemetry: bool = True


def load_config(start: Path) -> ValcaConfig:
    """Walk up from start looking for .vigilrc (TOML format).

    Searches the given path (or its parent if a file) and all ancestor
    directories until the filesystem root. Returns defaults if not found.
    """
    current = start if start.is_dir() else start.parent
    while True:
        # ".valcarc" is the current name; ".vigilrc" is still honoured because a
        # config that is silently ignored re-enables rules the user had disabled
        # and scans paths they had excluded — a failure mode with no visible signal.
        candidate = next(
            (c for c in (current / ".valcarc", current / ".vigilrc") if c.is_file()),
            None,
        )
        if candidate is not None:
            try:
                with open(candidate, "rb") as f:
                    data = tomllib.load(f)
            except Exception:
                return ValcaConfig()
            return ValcaConfig(
                disabled_rules=data.get("disabled_rules", []),
                min_severity=data.get("min_severity"),
                exclude_paths=data.get("exclude_paths", []),
                telemetry=data.get("telemetry", True),
            )
        parent = current.parent
        if parent == current:
            break
        current = parent
    return ValcaConfig()
