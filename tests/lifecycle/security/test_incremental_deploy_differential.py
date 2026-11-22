"""Install after any input change equals a fresh full deploy of the same inputs (lane C).

PROMISE: P-INV-I1 -- the lock (the deployment ledger) matches what is deployed;
P-INV-I4 -- a stricter policy or a withdrawn approval never leaves an executable
deployed; P-LAW-ownership.preserve_unowned -- a user's file at a managed path
and a destination that leaves the project are never written through
(source: tests/lifecycle/oracles.py, install/exec_gate.py, utils/path_security.py).

Differential oracle for an incremental deploy ("deploy only what changed vs the
lockfile"): an incremental world converges, takes one change and runs
``apm install``; a fresh world receives the same final inputs (package source,
apm.yml, org policy, the user's approval store) and runs ``apm install`` once.
Their project and HOME bytes and their lock (identity fields normalized) must
match. Two changes have no fresh equivalent (a user's edit, a symlinked
destination): there the edited path keeps the user's bytes or the outside tree
is untouched, and everything else still equals the fresh deploy.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
import yaml

from tests.lifecycle import driver
from tests.lifecycle.world import World
from tests.lifecycle.world.clone import clone
from tests.lifecycle.world.scopes import use_policy
from tests.lifecycle.world.services import ORG
from tests.utils.local_package import LocalPackageFactory

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.integration,
    pytest.mark.lifecycle_smoke,
    pytest.mark.promise("P-INV-I1", "P-INV-I4", "P-LAW-ownership.preserve_unowned"),
]

_KIT = "c-kit"
_KIT_SPEC = f"../../authored/{_KIT}"
_SKILL = "---\nname: {name}\ndescription: Lifecycle kit skill.\n---\n\n{body}\n"
_RULE = '---\napplyTo: "**"\n---\n\n{body}\n'
_SKILL_PATH = ".agents/skills/c-alpha/SKILL.md"


@dataclass(frozen=True)
class Inputs:
    """Everything a user controls that can change deployed output."""

    skills: tuple[tuple[str, str], ...] = (("c-alpha", "Use alpha."),)
    rules: tuple[tuple[str, str], ...] = (("c-rule", "Follow the kit rule."),)
    targets: tuple[str, ...] = ("copilot",)
    policy: str = "allow"
    approved: bool = True


_BASE = Inputs()
_BOTH = replace(_BASE, targets=("copilot", "claude"))


def _author(world: World, inputs: Inputs) -> None:
    root = world.root / "authored" / _KIT
    if root.exists():
        shutil.rmtree(root)
    factory = LocalPackageFactory(root.parent)
    package = factory.create(_KIT, version="1.0.0")
    for name, body in inputs.skills:
        factory.add_skill(package, name, _SKILL.format(name=name, body=body))
    for name, body in inputs.rules:
        factory.add_instruction(package, name, _RULE.format(body=body))


def _declare(world: World, inputs: Inputs) -> None:
    manifest = world.project / "apm.yml"
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["targets"] = list(inputs.targets)
    data.setdefault("dependencies", {})["apm"] = [world.packages["p-exec:git"].spec, _KIT_SPEC]
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")


def _set_inputs(world: World, inputs: Inputs) -> None:
    use_policy(world, inputs.policy)
    _author(world, inputs)
    _declare(world, inputs)


def _install(world: World):
    return driver.run(world, ("install",))


def _converge(world: World, inputs: Inputs) -> None:
    _set_inputs(world, inputs)
    first = _install(world)
    assert first.returncode == 0, first.stdout + first.stderr
    if inputs.approved:
        approved = driver.run(world, ("approve", "--user", "p-exec"))
        assert approved.returncode == 0, approved.stdout + approved.stderr
        again = _install(world)
        assert again.returncode == 0, again.stdout + again.stderr
    assert (world.project / _SKILL_PATH).is_file(), "the kit skill must deploy"


def _revoke_user_approval(world: World) -> None:
    config = world.apm_home / "config.json"
    data = json.loads(config.read_text(encoding="utf-8"))
    allow = data.get("executables", {}).get("allow", {})
    ref = world.packages["p-exec:git"]
    identities = (ref.spec, ref.name, f"{ORG}/{ref.name}")
    dropped = [k for k in list(allow) if any(k == i or k.startswith(i + "#") for i in identities)]
    assert dropped, f"no user approval of p-exec to revoke in {allow}"
    for key in dropped:
        del allow[key]
    config.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _apply_inputs(world: World, start: Inputs, end: Inputs) -> None:
    """Move *world* from *start* to *end* the way a user would, between two installs."""
    if (end.skills, end.rules) != (start.skills, start.rules):
        _author(world, end)
    if end.targets != start.targets:
        _declare(world, end)
    if end.policy != start.policy:
        use_policy(world, end.policy)
    if start.approved and not end.approved:
        _revoke_user_approval(world)


# -- out-of-band changes (no input edit; the fresh twin is the plain converged state) ---


def _delete_deployed(world: World) -> tuple[str, ...]:
    (world.project / _SKILL_PATH).unlink()
    return ()


def _edit_deployed(world: World) -> tuple[str, ...]:
    path = world.project / _SKILL_PATH
    path.write_bytes(path.read_bytes() + b"\nmy local note\n")
    return (_SKILL_PATH,)


def _symlink_destination(world: World) -> tuple[str, ...]:
    outside = world.root / "outside-skill"
    outside.mkdir()
    (outside / "SKILL.md").write_text("not APM's file\n", encoding="ascii")
    deployed = world.project / _SKILL_PATH
    shutil.rmtree(deployed.parent)
    deployed.parent.symlink_to(outside, target_is_directory=True)
    return (str(Path(_SKILL_PATH).parent.as_posix()),)


@dataclass(frozen=True)
class Change:
    start: Inputs
    end: Inputs
    out_of_band: Callable[[World], tuple[str, ...]] | None = None


CHANGES: dict[str, Change] = {
    "file-content": Change(_BASE, replace(_BASE, skills=(("c-alpha", "Use alpha, v2."),))),
    "file-rename": Change(_BASE, replace(_BASE, skills=(("c-beta", "Use alpha."),))),
    "file-delete": Change(_BASE, replace(_BASE, rules=())),
    "target-added": Change(_BASE, _BOTH),
    "target-removed": Change(_BOTH, _BASE),
    "policy-denies-executables": Change(_BASE, replace(_BASE, policy="exec-deny-all")),
    "approval-revoked": Change(_BASE, replace(_BASE, approved=False)),
    "locked-file-missing": Change(_BASE, _BASE, _delete_deployed),
    "user-edited-deployed-file": Change(_BASE, _BASE, _edit_deployed),
    "symlinked-destination": Change(_BASE, _BASE, _symlink_destination),
}

# Caches (git objects, policy) are not deployed state.
_HOME_CACHES = (".cache", "Library/Caches", ".apm/logs")
# Per-checkout identity: a random installation id and receipts keyed by the project path.
_IDENTITY = (".apm-local", ".apm/deployment-receipts")


def _digest(root: Path, skip: tuple[str, ...], world: World) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if any(rel == s or rel.startswith(s + "/") for s in skip):
            continue
        if path.is_symlink():
            files[rel] = "link:" + str(path.readlink()).replace(str(world.root), "<ROOT>")
        elif path.is_file():
            data = path.read_bytes().replace(str(world.root).encode(), b"<ROOT>")
            files[rel] = hashlib.sha256(data).hexdigest()
    return files


def _without_identity(node: object, root: str) -> object:
    if isinstance(node, dict):
        return {
            k: _without_identity(v, root)
            for k, v in node.items()
            if not re.search(r"install(ation)?_?id|receipt|generated_at", str(k))
        }
    if isinstance(node, list):
        return [_without_identity(v, root) for v in node]
    return node.replace(root, "<ROOT>") if isinstance(node, str) else node


def _comparable(world: World, exempt: tuple[str, ...] = ()) -> dict[str, object]:
    """Deployed state comparable across two worlds: identity fields and paths normalized."""
    lock = yaml.safe_load((world.project / "apm.lock.yaml").read_text(encoding="utf-8"))
    project_skip = (".git", "apm.lock.yaml", "apm.yml", *_IDENTITY, *exempt)
    return {
        "project": _digest(world.project, project_skip, world),
        "home": _digest(world.home, _HOME_CACHES + _IDENTITY, world),
        "manifest": yaml.safe_load((world.project / "apm.yml").read_text(encoding="utf-8")),
        "lock": _without_identity(lock, str(world.root)),
    }


def _structural(a: object, b: object, path: str = "") -> list[str]:
    """Paths where two parsed documents differ, with both values."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in sorted(a.keys() | b.keys(), key=str):
            out += _structural(a.get(key), b.get(key), f"{path}.{key}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [
            d
            for i, (x, y) in enumerate(zip(a, b, strict=True))
            for d in _structural(x, y, f"{path}[{i}]")
        ]
    return [] if a == b else [f"{path}: incremental={a!r} fresh={b!r}"]


def _shown(world: World, root_id: str, rel: str) -> str:
    root = world.project if root_id == "project" else world.home
    path = root / rel
    if not path.is_file() or path.stat().st_size > 2000:
        return "<absent>" if not path.exists() else "<large>"
    return path.read_text(encoding="utf-8", errors="replace").replace(str(world.root), "<ROOT>")


def _diff(left: dict, right: dict, worlds: tuple[World, World]) -> list[str]:
    lines = []
    for key in sorted(left.keys() | right.keys()):
        a, b = left.get(key), right.get(key)
        if key in ("project", "home"):
            for path in sorted(a.keys() | b.keys()):
                if a.get(path) != b.get(path):
                    lines.append(
                        f"{key}:{path}: incremental={_shown(worlds[0], key, path)!r} "
                        f"fresh={_shown(worlds[1], key, path)!r}"
                    )
        else:
            lines += [f"{key}{d}" for d in _structural(a, b)]
    return lines


@pytest.mark.parametrize("change", sorted(CHANGES))
def test_install_after_a_change_equals_a_fresh_deploy(
    lifecycle_template: World, tmp_path: Path, change: str
) -> None:
    spec = CHANGES[change]
    incremental = clone(lifecycle_template, tmp_path / "incremental")
    fresh = clone(lifecycle_template, tmp_path / "fresh")
    incremental.services.reset()
    fresh.services.reset()

    _converge(incremental, spec.start)
    exempt: tuple[str, ...] = ()
    user_bytes = outside = None
    if spec.out_of_band is not None:
        exempt = spec.out_of_band(incremental)
        if change == "user-edited-deployed-file":
            user_bytes = (incremental.project / _SKILL_PATH).read_bytes()
        if change == "symlinked-destination":
            outside = _digest(incremental.root / "outside-skill", (), incremental)
    else:
        _apply_inputs(incremental, spec.start, spec.end)
    after = _install(incremental)

    # The fresh twin: the same final inputs, the user's approval store included, no history.
    _set_inputs(fresh, spec.end)
    config = incremental.apm_home / "config.json"
    if config.is_file():
        text = config.read_text(encoding="utf-8").replace(str(incremental.root), str(fresh.root))
        (fresh.apm_home / "config.json").write_text(text, encoding="utf-8")
    reference = _install(fresh)

    assert reference.returncode == 0, reference.stdout + reference.stderr
    evidence = f"\n--- incremental install\n{after.stdout}{after.stderr}"
    if change == "symlinked-destination":
        assert _digest(incremental.root / "outside-skill", (), incremental) == outside, (
            "install wrote through a symlinked destination" + evidence
        )
    else:
        assert after.returncode == 0, evidence
    if user_bytes is not None:
        assert (incremental.project / _SKILL_PATH).read_bytes() == user_bytes, (
            "install overwrote the user's edit of a deployed file" + evidence
        )
    problems = _diff(
        _comparable(incremental, exempt), _comparable(fresh, exempt), (incremental, fresh)
    )
    assert not problems, f"{change}: incremental != fresh deploy\n" + "\n".join(problems) + evidence
