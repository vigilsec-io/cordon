"""Tests for vigil init — hook wiring and permission healing."""
import json
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil.cli import _run_init


@pytest.fixture
def hook_sh(tmp_path):
    hook = tmp_path / "plugin" / "hook.sh"
    hook.parent.mkdir()
    hook.write_text("#!/bin/sh\necho ok\n")
    hook.chmod(0o644)  # no execute — simulates git clone stripping the bit
    return hook


@pytest.fixture
def settings_dir(tmp_path):
    return tmp_path / "claude"


def test_init_fixes_execute_permission(hook_sh, settings_dir, monkeypatch):
    monkeypatch.setattr("vigil.cli._find_hook_sh", lambda: hook_sh)
    monkeypatch.setattr("vigil.cli.Path.home", lambda: settings_dir.parent)
    settings_path = settings_dir / ".claude" / "settings.json"

    with patch("vigil.cli.Path.cwd", return_value=settings_dir):
        _run_init(global_install=False)

    assert hook_sh.stat().st_mode & 0o111, "hook.sh should be executable after vigil init"


def test_init_hook_already_executable_no_change(hook_sh, settings_dir, monkeypatch):
    hook_sh.chmod(0o755)
    original_mode = hook_sh.stat().st_mode
    monkeypatch.setattr("vigil.cli._find_hook_sh", lambda: hook_sh)

    with patch("vigil.cli.Path.cwd", return_value=settings_dir):
        _run_init(global_install=False)

    assert hook_sh.stat().st_mode == original_mode


def test_init_writes_hook_to_settings(hook_sh, settings_dir, monkeypatch):
    monkeypatch.setattr("vigil.cli._find_hook_sh", lambda: hook_sh)

    settings_path = settings_dir / ".claude" / "settings.json"
    with patch("vigil.cli.Path.cwd", return_value=settings_dir):
        _run_init(global_install=False)

    assert settings_path.exists()
    data = json.loads(settings_path.read_text())
    hooks = data["hooks"]["PostToolUse"]
    assert any("vigil" in h["hooks"][0]["command"] for h in hooks)


def test_init_idempotent(hook_sh, settings_dir, monkeypatch, capsys):
    monkeypatch.setattr("vigil.cli._find_hook_sh", lambda: hook_sh)

    with patch("vigil.cli.Path.cwd", return_value=settings_dir):
        _run_init(global_install=False)
        _run_init(global_install=False)  # second call should be a no-op

    out = capsys.readouterr().out
    assert out.count("already installed") == 1
