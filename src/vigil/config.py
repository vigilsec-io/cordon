from __future__ import annotations
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class VigilConfig:
    disabled_rules: list[str] = field(default_factory=list)
    min_severity: str | None = None
    exclude_paths: list[str] = field(default_factory=list)


def load_config(start: Path) -> VigilConfig:
    """Walk up from start looking for .vigilrc (TOML format).

    Searches the given path (or its parent if a file) and all ancestor
    directories until the filesystem root. Returns defaults if not found.
    """
    current = start if start.is_dir() else start.parent
    while True:
        candidate = current / ".vigilrc"
        if candidate.is_file():
            try:
                with open(candidate, "rb") as f:
                    data = tomllib.load(f)
            except Exception:
                return VigilConfig()
            return VigilConfig(
                disabled_rules=data.get("disabled_rules", []),
                min_severity=data.get("min_severity"),
                exclude_paths=data.get("exclude_paths", []),
            )
        parent = current.parent
        if parent == current:
            break
        current = parent
    return VigilConfig()
