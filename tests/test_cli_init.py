"""Tests for vigil init — hook wiring and permission healing."""
import json
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


def test_init_fixes_execute_permission(hook_sh, tmp_path):
    with patch("vigil.cli._find_hook_sh", return_value=hook_sh), \
         patch("vigil.cli.Path.cwd", return_value=tmp_path):
        _run_init(global_install=False)

    assert hook_sh.stat().st_mode & 0o111, "hook.sh should be executable after vigil init"


def test_init_hook_already_executable_no_change(hook_sh, tmp_path):
    hook_sh.chmod(0o755)
    original_mode = hook_sh.stat().st_mode

    with patch("vigil.cli._find_hook_sh", return_value=hook_sh), \
         patch("vigil.cli.Path.cwd", return_value=tmp_path):
        _run_init(global_install=False)

    assert hook_sh.stat().st_mode == original_mode


def test_init_writes_hook_to_settings(hook_sh, tmp_path):
    with patch("vigil.cli._find_hook_sh", return_value=hook_sh), \
         patch("vigil.cli.Path.cwd", return_value=tmp_path):
        _run_init(global_install=False)

    settings_path = tmp_path / ".claude" / "settings.json"
    assert settings_path.exists()
    data = json.loads(settings_path.read_text())
    hooks = data["hooks"]["PostToolUse"]
    commands = [h["hooks"][0]["command"] for h in hooks]
    assert any(Path(cmd).name == "hook.sh" for cmd in commands)


def test_init_idempotent(hook_sh, tmp_path, capsys):
    with patch("vigil.cli._find_hook_sh", return_value=hook_sh), \
         patch("vigil.cli.Path.cwd", return_value=tmp_path):
        _run_init(global_install=False)
        _run_init(global_install=False)  # second call must be a no-op

    out = capsys.readouterr().out
    assert out.count("already installed") == 1
