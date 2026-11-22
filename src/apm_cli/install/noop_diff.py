"""Stateless no-op install: exit early when the desired state is already deployed.

``apm install`` on an unchanged project runs the whole pipeline and then
reports ``No changes``. This module decides the same answer from state alone,
with no memo: the desired state is the lockfile plus the package copies in
``apm_modules``; the actual state is the deployed files and configs. When the
two agree and every live gate still admits them, nothing would change.

Every check reads current bytes (content hashes, never mtimes) and every gate
is evaluated live on each run:

- the lockfile was written by this APM version (rendering is unchanged);
- org policy is discovered and routed live; any blocking, unresolved, stale,
  failed or warning outcome takes the full pipeline, which reports it;
- every locked package copy in ``apm_modules`` exists and proves its locked
  content (the install copy-validity owner);
- the ``apm audit --ci`` baseline owner passes: manifest/lock identity,
  deployment ledger owners, deployed files present, no orphans, targets
  current, skill subsets, MCP config consistency, native MCP ownership,
  deployed content hashes, local-bundle hooks, hook approval pins and the
  executables gate (approvals and denylist) against the live policy;
- when a policy is in force, its dependency and disk checks all pass.

Anything outside that set (local, registry or marketplace sources, LSP
servers, a policy warning, any failing or warning check) runs the full
pipeline. ``APM_INSTALL_FAST_PATH=0`` turns the early exit off.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

DISABLE_ENV = "APM_INSTALL_FAST_PATH"
_DISABLED = frozenset({"0", "false", "no", "off"})


def disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "").strip().lower() in _DISABLED


# Options a no-op may carry; any other set option takes the full pipeline.
_NEUTRAL_OPTIONS = frozenset({"frozen", "parallel_downloads"})


def eligible(options: dict[str, Any], argv: list[str] | None) -> bool:
    """Only a plain project re-install of the manifest (optionally ``--frozen``)."""
    if disabled() or argv is None:
        return False
    if any(a == "--policy" or a.startswith("--policy=") for a in argv):
        return False
    return not any(
        value not in (None, False, (), [], "")
        for name, value in options.items()
        if name not in _NEUTRAL_OPTIONS
    )


def _policy_admits(project_root: Path) -> tuple[bool, Any]:
    """Discover org policy live; (admits, fetch result)."""
    from apm_cli.policy.discovery import policy_disabled_by_env
    from apm_cli.policy.outcome_routing import classify_project_policy, discover_trust_policy

    if policy_disabled_by_env():
        return False, None
    fetch = discover_trust_policy(project_root)
    route = classify_project_policy(project_root, fetch_result=fetch)
    if route.blocks or route.unresolved:
        return False, fetch
    if fetch.cache_stale or fetch.fetch_error or fetch.warnings:
        return False, fetch
    return True, fetch


def _copies_valid(project_root: Path, lock: Any) -> bool:
    """Every locked remote package copy exists and proves its locked content."""
    from apm_cli.constants import APM_MODULES_DIR
    from apm_cli.drift import locked_copy_is_stale
    from apm_cli.install.source_helpers import locked_content_mismatch

    modules = project_root / APM_MODULES_DIR
    for key, dep in lock.dependencies.items():
        if key == ".":
            continue
        if getattr(dep, "source", None) is not None:
            return False  # local, registry, marketplace: the full pipeline decides
        try:
            path = dep.to_dependency_ref().get_install_path(modules)
        except (ValueError, OSError):
            return False
        if not path.is_dir() or locked_copy_is_stale(dep, path):
            return False
        if locked_content_mismatch(key, dep, path, lockfile=lock):
            return False
    return True


def _sources_scan_clean(project_root: Path, lock: Any) -> bool:
    """No package file the pre-deploy security scan reads carries any finding.

    The full pipeline re-scans each package's deployable sources on every
    install and reports warnings even when nothing is redeployed. Scanning
    every file of each copy (a superset) with the same scanner keeps that
    verdict and output: any finding, of any severity, takes the full pipeline.
    """
    from apm_cli.constants import APM_MODULES_DIR
    from apm_cli.security.content_scanner import ContentScanner

    modules = project_root / APM_MODULES_DIR
    for key, dep in lock.dependencies.items():
        if key == ".":
            continue
        root = dep.to_dependency_ref().get_install_path(modules)
        for directory, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                if ContentScanner.scan_file(Path(directory) / name):
                    return False
    return True


def _install_audit_off() -> bool:
    """The opt-in install-time audit phase would not run (it rescans every install)."""
    from apm_cli.core.experimental import is_enabled

    return not is_enabled("external_scanners")


def _gates_current(state: Any, fetch: Any) -> str | None:
    """The audit owner's narrow gate checks on the one parsed state; None when all pass.

    Deployed bytes are compared by ``desired_state.actual_vs_desired``. The
    audit's hidden-Unicode sweep of unrecorded files under the deploy trees
    is an audit step, not an install step, so it is not part of a no-op; the
    install's own pre-deploy scan is kept (``_sources_scan_clean``).
    """
    from apm_cli.constants import APM_MODULES_DIR
    from apm_cli.install.exec_gate import exec_policy_from_discovery
    from apm_cli.policy import ci_checks as ci

    root, lock, manifest, targets = state.project_root, state.lock, state.manifest, state.targets
    checks = (
        lambda: ci._check_ref_consistency(manifest, lock),
        lambda: ci._check_deployment_ledger_owners(lock),
        lambda: ci._check_no_orphans(manifest, lock),
        lambda: ci._check_lockfile_targets_current(root, lock, user_scope=False),
        lambda: ci._check_skill_subset_consistency(manifest, lock, root),
        lambda: ci._check_config_consistency(manifest, lock),
        lambda: ci._check_native_mcp_ownership(root, lock, targets, user_scope=False),
        lambda: ci._check_local_bundle_hooks(
            root, lock, manifest, targets, user_scope=False, no_policy=False
        ),
        lambda: ci._check_hook_approval_pins(
            root,
            root,
            lock,
            manifest,
            user_scope=False,
            no_policy=False,
            prepared_replay=None,
            targets=targets,
        ),
        lambda: ci._check_exec_status_current(
            root,
            lock,
            manifest,
            targets,
            user_scope=False,
            modules_root=root / APM_MODULES_DIR,
            policy_provider=lambda: exec_policy_from_discovery(lambda: fetch),
        ),
    )
    for check in checks:
        result = check()
        if not result.passed or getattr(result, "warned", False):
            return result.name
    return None


def _policy_checks_pass(project_root: Path, fetch: Any) -> bool:
    policy = getattr(fetch, "policy", None) if fetch is not None and fetch.found else None
    if policy is None or getattr(policy, "enforcement", None) == "off":
        return True
    from apm_cli.policy.policy_checks import run_policy_checks

    result = run_policy_checks(project_root, policy, fail_fast=True)
    return all(check.passed for check in result.checks)


def full_run_reason(project_root: Path) -> str | None:
    """Why a plain install of *project_root* would change something; None if it would not."""
    from apm_cli.deps.lockfile import installed_apm_version
    from apm_cli.install.desired_state import actual_vs_desired, build_desired_state
    from apm_cli.policy.ci_checks import resolve_audit_scope

    state = build_desired_state(project_root)
    if state is None:
        return "no lockfile or apm.yml"
    lock = state.lock
    if lock.apm_version != installed_apm_version():
        return "lockfile from another APM version"
    if lock.lsp_servers or lock.local_deployed_files or lock.local_staged_files:
        return "local content or LSP"
    root, user_scope, _targets = resolve_audit_scope(project_root, lock)
    if user_scope or root != project_root:
        return "scope"
    admits, fetch = _policy_admits(project_root)
    if not admits:
        return "org policy"
    if not _copies_valid(project_root, lock):
        return "package copies"
    if not _install_audit_off():
        return "install-time audit enabled"
    if not _sources_scan_clean(project_root, lock):
        return "security scan findings"
    if not actual_vs_desired(state).empty:
        return "deployed files differ"
    failed = _gates_current(state, fetch)
    if failed:
        return failed
    if not _policy_checks_pass(project_root, fetch):
        return "policy checks"
    return None


def invocation_argv() -> list[str] | None:
    """The arguments the root group parsed (``cli.py``); never ``sys.argv``."""
    import click

    ctx = click.get_current_context(silent=True)
    raw = ctx.meta.get("apm_raw_args") if ctx is not None else None
    return list(raw) if isinstance(raw, (list, tuple)) else None


def try_noop(options: dict[str, Any], argv: list[str] | None, project_root: Path) -> bool:
    """Print the no-op summary and return True when nothing would change.

    Any error or doubt returns False: the caller runs the full pipeline.
    """
    started = time.perf_counter()
    if not eligible(options, argv):
        return False
    try:
        reason = full_run_reason(project_root)
    except Exception as error:
        reason = f"error {type(error).__name__}"
    trace = os.environ.get(DISABLE_ENV, "").strip().lower() == "trace"
    if reason is not None:
        if trace:
            _trace(f"[i] install fast path: full run ({reason})")
        return False
    from apm_cli.utils.console import _rich_info

    elapsed = time.perf_counter() - started
    _rich_info(f"No changes -- install state already up to date in {elapsed:.1f}s.", symbol="info")
    if trace:
        _trace("[i] install fast path: no-op (desired state already deployed)")
    return True


def _trace(text: str) -> None:
    import contextlib
    import sys

    from apm_cli.utils.console import ascii_safe

    with contextlib.suppress(Exception):
        sys.stderr.write(ascii_safe(text) + "\n")
