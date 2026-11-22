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
from collections.abc import Callable
from pathlib import Path
from typing import Any

DISABLE_ENV = "APM_INSTALL_FAST_PATH"
_DISABLED = frozenset({"0", "false", "no", "off"})


def disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "").strip().lower() in _DISABLED


# Options a no-op may carry; any other set option takes the full pipeline.
# --frozen prints its own verification lines; until they are rendered here it
# takes the full pipeline (output parity, rule (a)).
_NEUTRAL_OPTIONS = frozenset({"parallel_downloads"})


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
    # Output parity: any other outcome is announced by the full pipeline
    # (rule (a): a line the early exit does not render takes the full run).
    from apm_cli.policy.outcome_routing import POLICY_NOT_PUBLISHED_OUTCOMES

    if getattr(fetch, "outcome", None) not in POLICY_NOT_PUBLISHED_OUTCOMES:
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


def _lock_reason(lock: Any, *, renders_mcp: bool = False) -> str | None:
    from apm_cli.deps.lockfile import installed_apm_version

    if lock.apm_version != installed_apm_version():
        return "lockfile from another APM version"
    if lock.lsp_servers or lock.local_deployed_files or lock.local_staged_files:
        return "local content or LSP"
    del renders_mcp  # both paths run the real MCP phase
    return None


def full_run_reason(project_root: Path) -> str | None:
    """Why a plain install of *project_root* would change something; None if it would not."""
    from apm_cli.install.desired_state import actual_vs_desired, build_desired_state
    from apm_cli.policy.ci_checks import resolve_audit_scope

    state = build_desired_state(project_root)
    if state is None:
        return "no lockfile or apm.yml"
    lock = state.lock
    root, user_scope, _targets = resolve_audit_scope(project_root, lock)
    fetch: list[Any] = []

    def policy_admits() -> bool:
        admits, result = _policy_admits(project_root)
        fetch.append(result)
        return admits

    checks: tuple[tuple[str, Callable[[], object]], ...] = (
        ("lockfile", lambda: _lock_reason(lock)),
        ("scope", lambda: user_scope or root != project_root),
        ("org policy", lambda: not policy_admits()),
        ("package copies", lambda: not _copies_valid(project_root, lock)),
        ("install-time audit enabled", lambda: not _install_audit_off()),
        ("security scan findings", lambda: not _sources_scan_clean(project_root, lock)),
        ("deployed files differ", lambda: not actual_vs_desired(state).empty),
        ("gates", lambda: _gates_current(state, fetch[0])),
        ("policy checks", lambda: not _policy_checks_pass(project_root, fetch[0])),
    )
    for reason, failed in checks:
        found = failed()
        if found:
            return found if isinstance(found, str) else reason
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
    _render_noop(project_root, started)
    if trace:
        _trace("[i] install fast path: no-op (desired state already deployed)")
    return True


def _render_noop(project_root: Path, started: float) -> None:
    """Print what the full pipeline prints for this no-op, through the same owners.

    Header and target line (``InstallLogger``, ``target_detection``), one
    cached-package header and ``(files unchanged)`` line per locked package in
    install order (depth, then identity), then the post-install summary.
    """
    from apm_cli.core.command_logger import InstallLogger
    from apm_cli.core.scope import manifest_file
    from apm_cli.core.target_detection import format_provenance, resolve_targets
    from apm_cli.deps.lockfile import LockFile, get_lockfile_path
    from apm_cli.install.summary import render_post_install_summary
    from apm_cli.models.apm_package import APMPackage, package_target_declaration
    from apm_cli.utils.short_sha import format_short_sha

    lock = LockFile.read(get_lockfile_path(project_root))
    manifest = APMPackage.from_apm_yml(manifest_file(project_root))
    logger = InstallLogger(verbose=False, dry_run=False, partial=False)
    logger.resolution_start(to_install_count=0, lockfile_count=0, update_count=0)
    resolved = resolve_targets(
        project_root, flag=None, yaml_targets=package_target_declaration(manifest).restriction()
    )
    logger.announce_targets(format_provenance(resolved))
    for dep in lock.get_all_dependencies():
        if dep.get_unique_key() == ".":
            continue
        dep_ref = dep.to_dependency_ref()
        name = str(dep_ref) if dep_ref.is_virtual else dep_ref.repo_url
        ref = dep.resolved_ref or dep_ref.reference or ""
        sha = format_short_sha(dep.resolved_commit) if dep.resolved_commit else ""
        logger.download_complete(name, ref=ref, sha=sha, cached=True)
        logger.tree_item("  |-- (files unchanged)")
    services = _run_services(project_root, manifest, lock, logger)
    render_post_install_summary(
        logger=logger,
        apm_count=0,
        mcp_count=services.mcp_count,
        lsp_count=services.lsp_count,
        apm_diagnostics=logger.diagnostics,
        force=False,
        elapsed_seconds=time.perf_counter() - started,
    )


def _run_services(project_root: Path, manifest: Any, lock: Any, logger: Any) -> Any:
    """The install's MCP/LSP reconciliation phase itself, as a plain install runs it.

    It prints the MCP block and parked-server warnings exactly as the full
    pipeline does, and repairs a drifted server config the same way.
    """
    from types import SimpleNamespace

    from apm_cli.constants import InstallMode
    from apm_cli.core.scope import InstallScope
    from apm_cli.deps.lockfile import get_lockfile_path
    from apm_cli.install.service import FrozenDisposition
    from apm_cli.install.service_integration import run_service_integrations
    from apm_cli.install.template import effective_allow_map
    from apm_cli.policy.outcome_routing import discover_trust_policy

    trust = SimpleNamespace(
        policy_fetch=discover_trust_policy(project_root),
        source_root=project_root,
        project_root=project_root,
        scope=InstallScope.PROJECT,
        apm_package=manifest,
        logger=logger,
        dry_run=False,
        exec_trust_ctx=None,
        exec_allow_map=None,
    )
    allow_map = effective_allow_map(trust)
    command = SimpleNamespace(
        project_root=project_root,
        scope=InstallScope.PROJECT,
        install_mode=InstallMode.ALL,
        logger=logger,
        runtime=None,
        exclude=None,
        trust_transitive_mcp=False,
        no_policy=False,
        verbose=False,
        force=False,
        update=False,
        exec_allow_map=allow_map,
        exec_allow_resolved=trust.exec_trust_ctx is not None,
        mcp_policy_enforced=False,
    )
    mcp_deps = manifest.get_all_mcp_dependencies()
    return run_service_integrations(
        command,
        apm_package=manifest,
        mcp_deps=mcp_deps if isinstance(mcp_deps, list) else [],
        lock_path=get_lockfile_path(project_root),
        existing_lock=lock,
        old_mcp_servers=set(lock.mcp_servers),
        old_mcp_configs=dict(lock.mcp_configs),
        old_mcp_provenance=dict(lock.mcp_config_provenance),
        old_mcp_target_servers=dict(lock.mcp_target_servers),
        old_mcp_target_servers_present=lock._mcp_target_servers_present,
        diagnostics=logger.diagnostics,
        explicit_target=None,
        target_decision=None,
        active_package_keys=frozenset(k for k in lock.dependencies if k != "."),
        frozen_disposition=FrozenDisposition(replay=False),
    )


def _trace(text: str) -> None:
    import contextlib
    import sys

    from apm_cli.utils.console import ascii_safe

    with contextlib.suppress(Exception):
        sys.stderr.write(ascii_safe(text) + "\n")
