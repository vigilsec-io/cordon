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

# Hard cap on snippet length, enforced regardless of what a rule passes in.
# A matched line is never legitimately this long to show a human; the cap
# also bounds how much attacker-controlled text (e.g. injected instructions
# riding along in a matched line) can flow back into an AI assistant's
# context via the hook's output.
_MAX_SNIPPET_LEN = 200


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

    def __post_init__(self) -> None:
        if self.snippet and len(self.snippet) > _MAX_SNIPPET_LEN:
            self.snippet = self.snippet[: _MAX_SNIPPET_LEN - 1] + "…"


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
