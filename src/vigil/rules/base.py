from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: dict["Severity", int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file_path: Path
    line: int | None = None
    snippet: str | None = None
    fix: str | None = None
    # Semantic category for deduplication when multiple rules catch the same root cause.
    # e.g. "root_user", "unpinned_image", "secret_in_layer"
    category: str | None = None


class Rule(ABC):
    id: str
    name: str
    severity: Severity

    @abstractmethod
    def applies_to(self, path: Path) -> bool:
        """Return True if this rule should run against this file."""
        ...

    @abstractmethod
    def check(self, path: Path) -> list[Finding]:
        """Run the check and return any findings."""
        ...
