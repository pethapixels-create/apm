"""Desired deployment state of a project and its difference from what is on disk.

One builder shared by the install fast paths (#4770, lane C):

- the stateless no-op (``install/noop_diff.py``) exits when the difference is
  empty and every live gate still admits the state;
- diff-apply writes only the missing or differing files.

The desired state is what the lockfile records: one parsed ``LockFile`` and
``apm.yml``, the canonical deployment ledger (``DeploymentLedgerCodec``) and,
from it, the explicit list of deployed files with their content hashes and
owners. Building it reads no network and spawns nothing. The actual state is
read from disk by content hash (``utils.content_hash.compute_file_hash``),
never by mtime.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DesiredFile:
    """One deployed file the lockfile records."""

    path: str  # as recorded: project-relative, or target-relative for its target
    sha256: str | None  # the recorded content hash envelope, None when unhashed
    owner: str  # the dependency key that actively owns it
    kind: str  # LocatorKind value: project-relative | target-relative
    target: str


@dataclass(frozen=True)
class DesiredState:
    project_root: Path
    lock: Any  # LockFile
    manifest: Any  # APMPackage
    ledger: Any  # DeploymentLedger: the rows a converged install persists
    targets: Sequence[Any]  # resolved TargetProfile objects
    files: tuple[DesiredFile, ...]


@dataclass(frozen=True)
class Diff:
    """Recorded files that are absent, differ by content hash, or resolve unsafely."""

    missing: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.missing or self.changed or self.unresolved)


def build_desired_state(project_root: Path) -> DesiredState | None:
    """Parse the lockfile and ``apm.yml`` once; ``None`` when either is absent."""
    from apm_cli.core.scope import manifest_file
    from apm_cli.deps.lockfile import LockFile, get_lockfile_path
    from apm_cli.models.apm_package import APMPackage
    from apm_cli.policy.ci_checks import resolve_audit_scope

    lock = LockFile.read(get_lockfile_path(project_root))
    manifest_path = manifest_file(project_root)
    if lock is None or not manifest_path.is_file():
        return None
    manifest = APMPackage.from_apm_yml(manifest_path)
    _root, _user_scope, targets = resolve_audit_scope(project_root, lock)
    return state_from(project_root, lock, manifest, targets)


def state_from(
    project_root: Path, lock: Any, manifest: Any, targets: Sequence[Any]
) -> DesiredState:
    """The desired state of already parsed inputs (the pipeline holds them in ctx)."""
    from apm_cli.core.deployment_ledger import DeploymentLedgerCodec
    from apm_cli.core.deployment_state import LocatorKind

    ledger = DeploymentLedgerCodec.from_lockfile(lock)
    files = tuple(
        DesiredFile(
            path=record.locator.value,
            sha256=record.content_hash,
            owner=record.active_owner,
            kind=record.locator.kind.value,
            target=record.locator.target,
        )
        for _key, record in sorted(ledger.records.items())
        if record.locator.kind != LocatorKind.URI
    )
    return DesiredState(project_root, lock, manifest, ledger, targets, files)


def actual_vs_desired(state: DesiredState) -> Diff:
    """Compare the deployed files on disk with the desired state, by content hash.

    A recorded file that is absent counts even when gitignored: an install
    redeploys it, unlike ``apm audit``, which skips it by design.
    """
    from apm_cli.policy.ci_checks import _resolve_deployed_file_path, verify_deployed_file_hashes

    missing = []
    for dep in state.lock.dependencies.values():
        for rel_path in dep.deployed_files:
            if "://" in rel_path:
                continue
            path = _resolve_deployed_file_path(rel_path, state.project_root, state.targets)
            if (
                path is None
                or not path.exists()
                or (Path(rel_path).is_absolute() and path.is_symlink())
            ):
                missing.append(rel_path)
    drift, unresolved = verify_deployed_file_hashes(state.project_root, state.lock, state.targets)
    return Diff(
        missing=tuple(sorted(missing)),
        changed=tuple(sorted(d.path for d in drift)),
        unresolved=tuple(sorted(unresolved)),
    )


EMPTY = "empty"
APPLY = "apply"
FULL = "full"

# InstallContext options under which integrate must run in full.
_FULL_RUN_OPTIONS = (
    "update_refs",
    "dry_run",
    "lockfile_only",
    "force",
    "refresh",
    "only_packages",
    "skill_subset_from_cli",
    "target_override",
    "audit_override",
    "trust_transitive_mcp",
    "legacy_skill_paths",
)


def plan_for(ctx: Any) -> str:
    """How the integrate phase may run for *ctx*: EMPTY, APPLY or FULL.

    EMPTY only when the desired state is already deployed and every gate the
    integrate phase applies would decide as recorded; any doubt is FULL. The
    org policy is the one the pipeline already routed (``ctx.policy_fetch``).
    APPLY is decided by the diff-apply owner (not yet wired).
    """
    from apm_cli.core.scope import is_user_scope
    from apm_cli.deps.lockfile import installed_apm_version
    from apm_cli.install import noop_diff as proof

    try:
        if proof.disabled() or any(getattr(ctx, name, None) for name in _FULL_RUN_OPTIONS):
            return FULL
        lock = ctx.existing_lockfile
        root = Path(ctx.project_root)
        if lock is None or is_user_scope(ctx.scope) or ctx.no_policy:
            return FULL
        if lock.apm_version != installed_apm_version():
            return FULL
        if lock.lsp_servers or lock.local_deployed_files or lock.local_staged_files:
            return FULL
        if not (
            proof._copies_valid(root, lock)
            and proof._install_audit_off()
            and proof._sources_scan_clean(root, lock)
        ):
            return FULL
        state = state_from(root, lock, ctx.apm_package, ctx.targets or ())
        if not actual_vs_desired(state).empty:
            return FULL
        if proof._gates_current(state, ctx.policy_fetch) is not None:
            return FULL
    except Exception:
        return FULL
    return EMPTY
