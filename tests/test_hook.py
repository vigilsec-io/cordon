"""Smoke tests for plugin/hook.sh — path boundary, size guard, env stripping,
and timeout wiring (tickets #54, #56, #57). Shells out to the real script
against the repo's own venv, mirroring how Claude Code actually invokes it.
"""
import json
import os
import subprocess
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
HOOK = REPO_ROOT / "plugin" / "hook.sh"

_VULNERABLE_YAML = """\
name: AI Review
on:
  issues:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - run: claude --print "Review this issue"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
"""


def _run_hook(file_path: Path, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    payload = json.dumps({"tool_input": {"file_path": str(file_path)}})
    env = os.environ.copy()
    env.pop("VIGIL_PROJECT_ROOT", None)
    # This is a subprocess call — there's no in-process telemetry to patch, so
    # opt out via the env var Vigil already supports. Otherwise every test run
    # writes real events into the developer's actual ~/.vigil/events.jsonl.
    env["VIGIL_NO_TELEMETRY"] = "1"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=15,
    )


def _working_executable() -> str | None:
    """Return a scanner that actually runs.

    Presence on PATH is not enough: a stale entry-point script from an earlier
    install stays executable but fails to import. That is the same trap the hook
    itself guards against, so the test guard must apply it too — otherwise these
    tests run against a broken binary and fail for the wrong reason.
    """
    candidates = [
        shutil.which("valca"),
        shutil.which("vigil"),
        str(REPO_ROOT / "venv" / "bin" / "valca"),
        str(REPO_ROOT / "venv" / "bin" / "vigil"),
    ]
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        try:
            proc = subprocess.run(
                [candidate, "--help"], capture_output=True, timeout=15, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0:
            return candidate
    return None


@pytest.fixture(autouse=True)
def _skip_if_no_venv_vigil():
    if _working_executable() is None:
        pytest.skip("no working valca/vigil executable — run `pip install -e .` first")


def test_vulnerable_file_inside_project_blocks(tmp_path):
    # Must be inside the repo root for the boundary check to allow it.
    target = REPO_ROOT / "_hook_test_tmp.yml"
    target.write_text(_VULNERABLE_YAML)
    try:
        result = _run_hook(target)
        assert result.returncode == 2
        assert "BLOCKED" in result.stderr
        assert "VGL-GHA009" in result.stderr
    finally:
        target.unlink(missing_ok=True)


def test_file_outside_project_root_skipped_silently(tmp_path):
    outside = tmp_path / "outside.yml"
    outside.write_text(_VULNERABLE_YAML)
    result = _run_hook(outside, extra_env={"VIGIL_PROJECT_ROOT": str(REPO_ROOT)})
    assert result.returncode == 0
    assert result.stdout == ""


def test_large_file_skipped(tmp_path):
    target = REPO_ROOT / "_hook_test_big.yml"
    target.write_text("on:\n  issues:\n" + ("# x\n" * 400_000))  # >1MB
    try:
        result = _run_hook(target)
        assert result.returncode == 0
        assert result.stdout == ""
    finally:
        target.unlink(missing_ok=True)


def test_credential_env_vars_not_leaked_to_scan(tmp_path):
    target = REPO_ROOT / "_hook_test_env.yml"
    target.write_text(_VULNERABLE_YAML)
    try:
        result = _run_hook(target, extra_env={"ANTHROPIC_API_KEY": "sk-hook-test-sentinel"})
        assert "sk-hook-test-sentinel" not in result.stdout
        assert "sk-hook-test-sentinel" not in result.stderr
    finally:
        target.unlink(missing_ok=True)


def test_nonexistent_file_exits_clean():
    result = _run_hook(REPO_ROOT / "_does_not_exist.yml")
    assert result.returncode == 0
    assert result.stdout == ""


def test_malformed_stdin_exits_clean():
    result = subprocess.run(
        ["bash", str(HOOK)],
        input="not json at all",
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=15,
    )
    assert result.returncode == 0
