"""Recorder and replay rules of the no-op install fast path (noop_fast_path.py).

The lifecycle module tests/lifecycle/security/test_noop_fast_path.py proves
the fast path against the real CLI; these cases pin the recorder's own
fail-closed rules: only a recorded no-op is replayed, any changed input
re-runs, and an instrumentation gap or an unreadable stamp records nothing.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from apm_cli.install import noop_fast_path as fp

pytestmark = [pytest.mark.unit, pytest.mark.promise("P-INV-I2")]

_SUMMARY = "No changes -- install state already up to date in 1.2s."


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "apm.lock.yaml").write_text("lockfile_version: '1'\n", encoding="utf-8")
    (root / "input.txt").write_text("v1\n", encoding="utf-8")
    monkeypatch.setenv("APM_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("APM_INSTALL_FAST_PATH", raising=False)
    monkeypatch.chdir(root)
    monkeypatch.setattr(fp, "policy_fingerprint", lambda _root: "found|org:test|abc")
    monkeypatch.setattr(fp, "deployed_hashes_intact", lambda _root: True)
    return root


class _Install:
    """A stand-in install: reads its input, optionally writes, prints a summary."""

    def __init__(self, root: Path, *, write: bool = False, summary: str = _SUMMARY) -> None:
        self.root = root
        self.write = write
        self.summary = summary
        self.calls = 0

    def __call__(self) -> None:
        self.calls += 1
        (self.root / "input.txt").read_text(encoding="utf-8")
        os.path.exists(self.root / "probed-but-absent")
        if self.write:
            (self.root / "output.txt").write_text("x", encoding="utf-8")
        print("[*] Installing")
        print(self.summary)


def _install(run: _Install) -> None:
    fp.run_with_fast_path({}, run, project_root=run.root)


def test_a_recorded_noop_is_replayed_without_running(project, capsys) -> None:
    run = _Install(project)
    _install(run)
    _install(run)
    out = capsys.readouterr().out
    assert run.calls == 1
    assert out.count("[*] Installing") == 2
    assert out.count("No changes -- install state already up to date in ") == 2
    assert "1.2s" in out.splitlines()[1]


@pytest.mark.parametrize(
    "change",
    [
        lambda root: (root / "input.txt").write_text("v2\n", encoding="utf-8"),
        lambda root: (root / "probed-but-absent").mkdir(),
        lambda root: (root / "apm.lock.yaml").unlink(),
    ],
    ids=["read-file-content", "probed-path-appears", "lockfile-removed"],
)
def test_any_changed_input_runs_the_full_install(project, change) -> None:
    run = _Install(project)
    _install(run)
    change(project)
    _install(run)
    assert run.calls == 2


def test_policy_or_deployed_hash_change_runs_the_full_install(project, monkeypatch) -> None:
    run = _Install(project)
    _install(run)
    monkeypatch.setattr(fp, "policy_fingerprint", lambda _root: "found|org:test|tightened")
    _install(run)
    assert run.calls == 2
    monkeypatch.setattr(fp, "deployed_hashes_intact", lambda _root: False)
    _install(run)
    assert run.calls == 3


def test_a_run_that_writes_records_no_stamp(project) -> None:
    run = _Install(project, write=True)
    _install(run)
    _install(run)
    assert run.calls == 2


def test_a_run_without_the_noop_summary_records_no_stamp(project) -> None:
    run = _Install(project, summary="Installed 1 package in 1.0s.")
    _install(run)
    _install(run)
    assert run.calls == 2


def test_an_instrumentation_gap_records_no_stamp(project, monkeypatch) -> None:
    monkeypatch.setattr(fp, "_probing", lambda original: original)
    run = _Install(project)
    _install(run)
    _install(run)
    assert run.calls == 2


def test_an_unreadable_stamp_runs_the_full_install(project) -> None:
    run = _Install(project)
    _install(run)
    for stamp in (Path(os.environ["APM_CACHE_DIR"]) / "noop_v1").glob("*.json"):
        stamp.write_text("{not json", encoding="utf-8")
    _install(run)
    assert run.calls == 2


def test_the_fast_path_can_be_disabled(project, monkeypatch) -> None:
    run = _Install(project)
    _install(run)
    monkeypatch.setenv("APM_INSTALL_FAST_PATH", "0")
    _install(run)
    assert run.calls == 2


def test_only_a_plain_reinstall_is_eligible() -> None:
    assert fp.eligible({"frozen": True}) is (os.name != "nt")
    for option in ("packages", "update", "refresh", "dry_run", "root", "global_"):
        assert fp.eligible({option: ("x",)}) is False
    assert fp.eligible({"mcp_name": "srv"}) is False
