"""A replayed no-op never imports the install graph (owner: cli-startup-import-budget).

``apm install`` dispatches to ``commands/install_entry.py``; only a fast-path
miss imports ``commands/install.py`` and the ~750 modules behind it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.component, pytest.mark.promise("P-OWN-cli-startup-import-budget")]

_PROBE = """
import sys
from unittest.mock import patch
from click.testing import CliRunner
from apm_cli.cli import cli

calls = []
def replay(options, run, project_root=None):
    calls.append(sorted(options))
    if {miss!r}:
        return run()
    sys.stdout.write("replayed\\n")
    return None

with patch("apm_cli.install.noop_fast_path.run_with_fast_path", replay):
    result = CliRunner().invoke(cli, ["install", "--only", "apm"])
print("EXIT", result.exit_code)
print("OUT", result.output.splitlines()[:1])
print("CALLS", len(calls), "dry_run" in calls[0])
print("HEAVY", "apm_cli.commands.install" in sys.modules)
"""


def _isolated_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    for name in ("HOME", "APM_HOME"):
        (tmp_path / name).mkdir()
        env[name] = str(tmp_path / name)
    env["USERPROFILE"] = env["HOME"]
    return env


def test_replayed_noop_does_not_import_the_install_graph(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(miss=False)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=tmp_path,
        env=_isolated_env(tmp_path),
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.splitlines() == [
        "EXIT 0",
        "OUT ['replayed']",
        "CALLS 1 True",
        "HEAVY False",
    ]


def test_fast_path_miss_runs_the_install_body(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(miss=True)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=tmp_path,
        env=_isolated_env(tmp_path),
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    lines = result.stdout.splitlines()
    assert lines[2] == "CALLS 1 True"
    assert lines[3] == "HEAVY True"
