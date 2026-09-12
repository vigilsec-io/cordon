"""Guardrail: no test may construct a live Engine() that writes real telemetry
to the developer's actual ~/.vigil/events.jsonl.

This caught a real bug (2026-07-16): 13 unmocked Engine() calls across
test_engine.py, test_compliance.py, and test_rules_agency.py were silently
polluting real telemetry on every pytest run, making VGL-D001 look like the
most-triggered rule in production (it was mostly test noise) and VGL-A002
look like a 0%-precision rule (one suppression test, run hundreds of times).

Every Engine(...) construction in tests/ must either:
  - pass telemetry_enabled=False, or
  - be in a file that patches telemetry._EVENTS_FILE (the real telemetry tests).
"""
import re
from pathlib import Path

TESTS_DIR = Path(__file__).parent

_ENGINE_CALL = re.compile(r"\bEngine\(")


def test_no_test_leaks_telemetry():
    violations = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name == "test_no_telemetry_leak.py":
            continue
        text = path.read_text()
        patches_events_file = "_EVENTS_FILE" in text
        for i, line in enumerate(text.splitlines(), 1):
            if _ENGINE_CALL.search(line) and "telemetry_enabled=False" not in line:
                if patches_events_file:
                    continue  # this file mocks the real file — safe by design
                violations.append(f"{path.name}:{i}: {line.strip()}")

    assert not violations, (
        "Engine() constructed without telemetry_enabled=False, and this file "
        "doesn't patch telemetry._EVENTS_FILE — this will write real events "
        "to the developer's actual ~/.vigil/events.jsonl on every test run:\n"
        + "\n".join(violations)
    )
