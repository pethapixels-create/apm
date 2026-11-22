"""No-op install fast path: replay a verified no-op instead of re-running it.

``apm install`` on an unchanged project runs the whole pipeline and then
reports ``No changes``. This module memoizes that answer the way a build
system memoizes a step: it records every input one full no-op run observed,
and a later run replays the recorded output only when each input is still
bit-identical. Anything unknown or different falls through to the full
pipeline; the fast path never skips a check, it proves the check would see
the same bytes.

Recording (a full run, on every eligible invocation that is not a hit):

- every file opened for reading (``open`` audit event) -> SHA-256 of content;
- every directory listed (``os.listdir`` / ``os.scandir``) -> its entries,
  each with type, size and mtime;
- every path probed with ``os.stat`` / ``os.lstat`` / ``os.readlink`` ->
  type, size, mtime and link target;
- every environment variable read -> folded into one digest;
- the effective org policy -> fingerprint (re-discovered on every run);
- the output the command printed.

A stamp is written only when the recorded run was itself a no-op: it wrote
nothing, made no network call, ran no subprocess other than the policy
discovery ``git remote``, never prompted, exited 0 and printed the
``No changes`` summary. Because that run wrote nothing, its inputs are also
its outputs; a run whose inputs are byte-identical repeats it exactly.

Replay (a hit) additionally re-runs, every time: org policy discovery with
its unchanged cache-freshness rules, and the lockfile's deployed-file
content-hash verification (``verify_deployed_file_hashes``). It writes
nothing. ``APM_INSTALL_FAST_PATH=0`` disables the fast path.
"""

from __future__ import annotations

import functools
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

_SCHEMA = 1
_DISABLE_ENV = "APM_INSTALL_FAST_PATH"
_STAMP_BUCKET = "noop_v1"
_SUMMARY = re.compile(r"No changes -- install state already up to date in \d+\.\ds\.")
_SUMMARY_PLACEHOLDER = "\x00APM_ELAPSED\x00"
_SUMMARY_TEMPLATE = "No changes -- install state already up to date in {elapsed:.1f}s."
# Subprocesses a recorded no-op may run: org policy discovery reads the project
# remote (re-evaluated live on every replay) and GitPython probes the version.
_ALLOWED_GIT_SUBCOMMANDS = frozenset({"remote", "version"})
_WRITE_EVENTS = frozenset(
    {
        "os.remove",
        "os.rmdir",
        "os.rename",
        "os.mkdir",
        "os.symlink",
        "os.link",
        "os.truncate",
        "os.chmod",
        "os.chown",
        "os.utime",
        "os.chflags",
        "os.lchflags",
        "os.lchmod",
        "os.setxattr",
        "os.removexattr",
        "shutil.copyfile",
        "shutil.copymode",
        "shutil.copystat",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "shutil.make_archive",
        "shutil.unpack_archive",
    }
)
_VIOLATION_EVENTS = frozenset(
    {
        "socket.connect",
        "socket.getaddrinfo",
        "socket.sendto",
        "socket.bind",
        "urllib.Request",
        "builtins.input",
        "getpass.getpass",
        "sqlite3.connect",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "os.startfile",
        "pty.spawn",
        "ctypes.dlopen",
    }
)
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


# ---------------------------------------------------------------------------
# Eligibility and keys
# ---------------------------------------------------------------------------


def _disabled() -> bool:
    if sys.platform == "win32":
        # os.path.exists and friends are C functions on Windows: the probe
        # recorder cannot observe them, so the fast path never engages.
        return True
    return os.environ.get(_DISABLE_ENV, "").strip().lower() in {"0", "false", "no", "off"}


# ``APM_INSTALL_FAST_PATH=trace`` reports each decision on stderr (tests, benchmarks).


def eligible(options: dict[str, Any]) -> bool:
    """Only a plain re-install of the manifest (optionally ``--frozen``) qualifies."""
    if _disabled():
        return False
    if options.get("packages") or options.get("mcp_name") is not None:
        return False
    if options.get("update") or options.get("refresh") or options.get("dry_run"):
        return False
    return not options.get("root") and not options.get("global_")


def _code_identity() -> dict[str, Any]:
    from apm_cli import __version__

    package_dir = Path(__file__).resolve().parents[1]
    newest = 0
    if not getattr(sys, "frozen", False):
        for dirpath, _dirnames, filenames in os.walk(package_dir):
            for name in filenames:
                if name.endswith(".py"):
                    newest = max(newest, os.stat(os.path.join(dirpath, name)).st_mtime_ns)
    else:
        newest = os.stat(sys.executable).st_mtime_ns
    return {
        "version": __version__,
        "package": str(package_dir),
        "newest_source_ns": newest,
        "python": sys.version,
        "executable": sys.executable,
    }


def _invocation_key(argv: list[str]) -> dict[str, Any]:
    tty = []
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            tty.append(bool(stream.isatty()))
        except (AttributeError, ValueError):
            tty.append(False)
    try:
        columns = os.get_terminal_size().columns if tty[1] else None
    except OSError:
        columns = None
    return {
        "schema": _SCHEMA,
        "argv": list(argv),
        "cwd": os.getcwd(),
        "tty": tty,
        "columns": columns,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
    }


def _stamp_path(key: dict[str, Any]) -> Path:
    from apm_cli.cache.paths import get_cache_root

    digest = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
    return get_cache_root(ensure=False) / _STAMP_BUCKET / f"{digest}.json"


# ---------------------------------------------------------------------------
# Fingerprints of the observed inputs
# ---------------------------------------------------------------------------


def _file_digest(path: str) -> str | None:
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        return "dir"
    except OSError as error:
        return f"error:{error.errno}"


def _probe(path: str) -> list[Any] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        return [f"error:{error.errno}"]
    entry: list[Any] = [stat.S_IFMT(info.st_mode), info.st_mode, info.st_size, info.st_mtime_ns]
    if stat.S_ISLNK(info.st_mode):
        try:
            entry.append(os.readlink(path))
        except OSError as error:
            entry.append(f"error:{error.errno}")
        try:
            target = os.stat(path)
            entry.append([stat.S_IFMT(target.st_mode), target.st_size, target.st_mtime_ns])
        except OSError as error:
            entry.append(f"error:{error.errno}")
    return entry


def _listing(path: str) -> list[Any] | None:
    try:
        with os.scandir(path) as entries:
            rows = []
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                    rows.append([entry.name, info.st_mode, info.st_size, info.st_mtime_ns])
                except OSError as error:
                    rows.append([entry.name, f"error:{error.errno}"])
    except FileNotFoundError:
        return None
    except OSError as error:
        return [f"error:{error.errno}"]
    rows.sort(key=lambda row: row[0])
    return rows


def _env_digest(names: list[str] | None) -> str:
    environ = dict(os.environ)
    selected = sorted(environ) if names is None else sorted(set(names))
    hasher = hashlib.sha256()
    for name in selected:
        value = environ.get(name)
        hasher.update(name.encode("utf-8", "surrogateescape") + b"\x00")
        hasher.update(
            b"\x01" if value is None else b"\x02" + value.encode("utf-8", "surrogateescape")
        )
        hasher.update(b"\x00")
    return hasher.hexdigest()


def policy_fingerprint(project_root: Path) -> str | None:
    """Re-discover the org policy (unchanged freshness rules); ``None`` refuses the fast path.

    Only outcomes whose routing output is constant qualify: a stale cache, a
    fetch failure or a blocking outcome always takes the full pipeline.
    """
    from apm_cli.policy.discovery import discover_policy_with_chain, policy_disabled_by_env

    if policy_disabled_by_env():
        return "disabled-by-env"
    try:
        result = discover_policy_with_chain(project_root)
    except Exception:
        return None
    if result.cache_stale or result.fetch_error or result.error or result.warnings:
        return None
    if result.outcome not in {"found", "absent", "no_git_remote", "empty", "disabled"}:
        return None
    policy_bytes = b""
    if result.policy is not None:
        try:
            from dataclasses import asdict, is_dataclass

            data = asdict(result.policy) if is_dataclass(result.policy) else repr(result.policy)
            policy_bytes = json.dumps(data, sort_keys=True, default=repr).encode()
        except Exception:
            return None
    digest = hashlib.sha256(policy_bytes).hexdigest()
    return f"{result.outcome}|{result.source}|{digest}"


def deployed_hashes_intact(project_root: Path) -> bool:
    """Every content hash the lockfile records still matches the deployed bytes."""
    from apm_cli.deps.lockfile import LockFile, get_lockfile_path
    from apm_cli.policy.ci_checks import verify_deployed_file_hashes

    lock = LockFile.read(get_lockfile_path(project_root))
    if lock is None:
        return False
    mismatches, unresolved = verify_deployed_file_hashes(project_root, lock)
    return not mismatches and not unresolved


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------


def _under(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root + os.sep) for root in roots)


class _Recorder:
    """Observed inputs of one run.

    *excluded_roots* (interpreter, APM code, stamps, policy cache) are neither
    inputs nor writes. A write under *scratch_roots* (the temp dir) is allowed
    unless it is also under *protected_roots* (the project).
    """

    def __init__(
        self,
        excluded_roots: tuple[str, ...],
        scratch_roots: tuple[str, ...] = (),
        protected_roots: tuple[str, ...] = (),
        expiring_roots: tuple[str, ...] = (),
        immutable_roots: tuple[str, ...] = (),
    ) -> None:
        self.reads: set[str] = set()
        self.listed: set[str] = set()
        self.probed: set[str] = set()
        self.env: set[str] = set()
        self.env_all = False
        self.violations: list[str] = []
        self.excluded_roots = excluded_roots
        self.scratch_roots = scratch_roots
        self.protected_roots = protected_roots
        # Caches whose answer depends on the clock (TTL) are not replayable;
        # content-addressed git buckets inside them are.
        self.expiring_roots = expiring_roots
        self.immutable_roots = immutable_roots

    def _path(self, value: Any) -> str | None:
        if isinstance(value, int) or value is None:
            return None
        try:
            text = os.fsdecode(os.fspath(value))
        except TypeError:
            return None
        return os.path.abspath(text)

    def _excluded(self, path: str) -> bool:
        return _under(path, self.excluded_roots)

    def _scratch(self, path: str) -> bool:
        return _under(path, self.scratch_roots) and not _under(path, self.protected_roots)

    def violate(self, reason: str) -> None:
        """One violation settles it: stop observing so the rest of the run pays nothing."""
        global _ACTIVE
        self.violations.append(reason)
        if _ACTIVE is self:
            _ACTIVE = None

    def on_event(self, event: str, args: tuple[Any, ...]) -> None:
        if event == "open":
            path = self._path(args[0])
            if path is None or self._excluded(path):
                return
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else 0
            writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or bool(
                isinstance(flags, int) and flags & _WRITE_FLAGS
            )
            if writes:
                if not self._scratch(path):
                    self.violate(f"write:{path}")
            elif _under(path, self.expiring_roots) and not _under(path, self.immutable_roots):
                self.violate(f"expiring-cache:{path}")
            else:
                self.reads.add(path)
        elif event in ("os.listdir", "os.scandir"):
            path = self._path(args[0] if args else ".") if args else os.getcwd()
            if path is not None and not self._excluded(path):
                self.listed.add(path)
        elif event == "subprocess.Popen":
            argv = args[1] if len(args) > 1 else None
            if not _allowed_subprocess(argv):
                self.violate(f"subprocess:{argv!r}"[:200])
        elif event in _WRITE_EVENTS:
            path = self._path(args[0]) if args else None
            if path is None or not (self._excluded(path) or self._scratch(path)):
                self.violate(f"{event}:{path}")
        elif event in _VIOLATION_EVENTS:
            self.violate(event)

    def on_probe(self, value: Any) -> None:
        path = self._path(value)
        if path is not None and not self._excluded(path):
            self.probed.add(path)


def _allowed_subprocess(argv: Any) -> bool:
    if not isinstance(argv, (list, tuple)) or len(argv) < 2:
        return False
    program = os.path.basename(os.fsdecode(argv[0]))
    if program not in {"git", "git.exe"}:
        return False
    return os.fsdecode(argv[1]) in _ALLOWED_GIT_SUBCOMMANDS


_ACTIVE: _Recorder | None = None
_HOOK_INSTALLED = False


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    recorder = _ACTIVE
    if recorder is not None:
        recorder.on_event(event, args)


def _probing(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def probe(path: Any, *args: Any, **kwargs: Any) -> Any:
        recorder = _ACTIVE
        if recorder is not None and not kwargs.get("dir_fd"):
            recorder.on_probe(path)
        return original(path, *args, **kwargs)

    return probe


class _RecordingEnviron(os._Environ):  # type: ignore[name-defined,misc]
    def __getitem__(self, key: str) -> str:
        recorder = _ACTIVE
        if recorder is not None:
            recorder.env.add(key)
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        recorder = _ACTIVE
        if recorder is not None and isinstance(key, str):
            recorder.env.add(key)
        return super().__contains__(key)

    def __iter__(self):
        recorder = _ACTIVE
        if recorder is not None:
            recorder.env_all = True
        return super().__iter__()


class _Tee(io.TextIOBase):
    def __init__(self, stream: Any, sink: list[tuple[int, str]], channel: int) -> None:
        self._stream = stream
        self._sink = sink
        self._channel = channel

    def write(self, text: str) -> int:
        self._sink.append((self._channel, text))
        return self._stream.write(text)

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    def isatty(self) -> bool:
        return self._stream.isatty()

    def fileno(self) -> int:
        return self._stream.fileno()

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._stream.encoding

    @property
    def errors(self) -> str | None:  # type: ignore[override]
        return self._stream.errors


class _Recording:
    """Context of one recorded full run."""

    def __init__(
        self,
        key: dict[str, Any],
        stamp: Path,
        policy: str | None,
        started: float,
        project_root: Path,
    ) -> None:
        self.key = key
        self.stamp = stamp
        self.policy = policy
        self.started = started
        self.output: list[tuple[int, str]] = []
        excluded = {os.path.abspath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)}
        excluded.add(str(Path(__file__).resolve().parents[1]))
        excluded.add(str(stamp.parent))
        excluded.update(_policy_cache_roots())
        expiring, immutable = _cache_roots()
        self.recorder = _Recorder(
            _with_realpaths(excluded),
            _with_realpaths({tempfile.gettempdir()}),
            _with_realpaths({str(project_root)}),
            _with_realpaths(expiring),
            _with_realpaths(immutable),
        )
        self._saved: dict[str, Any] = {}

    def __enter__(self) -> _Recording:
        global _ACTIVE, _HOOK_INSTALLED
        if not _HOOK_INSTALLED:
            sys.addaudithook(_audit_hook)
            _HOOK_INSTALLED = True
        self._saved = {
            "stat": os.stat,
            "lstat": os.lstat,
            "readlink": os.readlink,
            "environ_class": os.environ.__class__,
            "stdout": sys.stdout,
            "stderr": sys.stderr,
        }
        os.stat = _probing(os.stat)
        os.lstat = _probing(os.lstat)
        os.readlink = _probing(os.readlink)
        os.environ.__class__ = _RecordingEnviron
        sys.stdout = _Tee(sys.stdout, self.output, 1)
        sys.stderr = _Tee(sys.stderr, self.output, 2)
        _ACTIVE = self.recorder
        self._canary()
        return self

    def _canary(self) -> None:
        """Prove the probe hooks see this interpreter's stat calls, or record nothing."""
        canary = os.path.join(os.getcwd(), f".apm-fast-path-canary-{os.getpid()}")
        seen = []
        for probe in (
            os.path.exists,
            os.path.isdir,
            os.path.lexists,
            os.path.realpath,
            lambda p: Path(p).exists(),
            lambda p: Path(p).is_file(),
            lambda p: Path(p).resolve(),
        ):
            self.recorder.probed.discard(canary)
            probe(canary)
            seen.append(canary in self.recorder.probed)
        self.recorder.probed.discard(canary)
        if not all(seen):
            self.recorder.violate("instrumentation-gap")

    def __exit__(self, *exc: object) -> None:
        global _ACTIVE
        _ACTIVE = None
        os.stat = self._saved["stat"]
        os.lstat = self._saved["lstat"]
        os.readlink = self._saved["readlink"]
        os.environ.__class__ = self._saved["environ_class"]
        sys.stdout = self._saved["stdout"]
        sys.stderr = self._saved["stderr"]

    def save(self, project_root: Path) -> bool:
        """Persist the stamp when the recorded run qualifies; return whether it did."""
        recorder = self.recorder
        if recorder.violations or self.policy is None:
            return False
        text = "".join(chunk for _, chunk in self.output)
        if len(_SUMMARY.findall(text)) != 1:
            return False
        if policy_fingerprint(project_root) != self.policy:
            return False
        output = [
            [channel, _SUMMARY.sub(_SUMMARY_PLACEHOLDER, chunk)] for channel, chunk in self.output
        ]
        stamp = {
            "key": self.key,
            "code": _code_identity(),
            "policy": self.policy,
            "env": _env_digest(None if recorder.env_all else sorted(recorder.env)),
            "env_names": None if recorder.env_all else sorted(recorder.env),
            "reads": {path: _file_digest(path) for path in sorted(recorder.reads)},
            "listed": {path: _listing(path) for path in sorted(recorder.listed)},
            "probed": {path: _probe(path) for path in sorted(recorder.probed)},
            "output": output,
        }
        try:
            self.stamp.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.stamp.parent, prefix=".stamp-")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(stamp, handle)
            os.replace(tmp, self.stamp)
        except OSError:
            return False
        return True


def _with_realpaths(roots: set[str]) -> tuple[str, ...]:
    paths = {os.path.abspath(root) for root in roots}
    paths.update(os.path.realpath(root) for root in list(paths))
    return tuple(sorted(paths))


def _cache_roots() -> tuple[set[str], set[str]]:
    """(expiring cache roots, content-addressed roots inside them)."""
    from apm_cli.cache.paths import GIT_CHECKOUTS_BUCKET, GIT_DB_BUCKET, get_cache_root
    from apm_cli.core.scope import get_apm_home

    root = str(get_cache_root(ensure=False))
    expiring = {root, str(get_apm_home() / "cache")}
    immutable = {os.path.join(root, GIT_DB_BUCKET), os.path.join(root, GIT_CHECKOUTS_BUCKET)}
    return expiring, immutable


def _policy_cache_roots() -> set[str]:
    """Policy caches are re-evaluated live on replay, so their bytes are not inputs."""
    try:
        from apm_cli.cache.paths import get_cache_root

        root = get_cache_root(ensure=False)
    except Exception:
        return set()
    return {os.path.abspath(os.path.join(root, "policy_v1"))}


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def _stamp_mismatch(
    stamp: dict[str, Any],
    key: dict[str, Any],
    policy: Callable[[], str | None],
    project_root: Path,
) -> str | None:
    """Return why *stamp* does not prove this run a no-op, or ``None`` when it does."""
    if stamp.get("key") != key:
        return "invocation"
    if stamp.get("code") != _code_identity():
        return "apm version"
    if stamp.get("env") != _env_digest(stamp.get("env_names")):
        return "environment"
    for path, digest in stamp.get("reads", {}).items():
        if _file_digest(path) != digest:
            return f"content {path}"
    for path, entries in stamp.get("listed", {}).items():
        if _listing(path) != entries:
            return f"listing {path}"
    for path, entry in stamp.get("probed", {}).items():
        if _probe(path) != entry:
            return f"path {path}"
    current = policy()
    if current is None or current != stamp.get("policy"):
        return "org policy"
    if not deployed_hashes_intact(project_root):
        return "deployed file hash"
    return None


def _in_background(compute: Callable[[], str | None]) -> Callable[[], str | None]:
    """Start *compute* on a thread (policy discovery waits on git); return its joiner."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = compute()
        except Exception:
            box["value"] = None

    thread = threading.Thread(target=target, name="apm-fast-path-policy", daemon=True)
    thread.start()

    def join() -> str | None:
        thread.join()
        return box.get("value")

    return join


def _replay(stamp: dict[str, Any], started: float) -> None:
    elapsed = time.perf_counter() - started
    summary = _SUMMARY_TEMPLATE.format(elapsed=elapsed)
    for channel, chunk in stamp["output"]:
        stream = sys.stdout if channel == 1 else sys.stderr
        stream.write(chunk.replace(_SUMMARY_PLACEHOLDER, summary))
    sys.stdout.flush()
    sys.stderr.flush()


def _load(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def run_with_fast_path(
    options: dict[str, Any], run: Callable[[], Any], project_root: Path | None = None
) -> Any:
    """Replay a verified no-op, or run *run* fully while recording its inputs."""
    started = time.perf_counter()
    if not eligible(options):
        return run()
    root = project_root or Path.cwd()
    try:
        key = _invocation_key(sys.argv[1:])
        stamp_path = _stamp_path(key)
    except Exception:
        return run()
    if not (root / "apm.lock.yaml").is_file():
        return run()  # a first install is never a no-op
    trace = os.environ.get(_DISABLE_ENV, "").strip().lower() == "trace"
    policy = _in_background(lambda: policy_fingerprint(root))
    stamp = _load(stamp_path)
    reason = "no stamp"
    if stamp is not None:
        try:
            reason = _stamp_mismatch(stamp, key, policy, root)
        except Exception as error:
            reason = f"error {type(error).__name__}"
        if reason is None:
            _replay(stamp, started)
            if trace:
                sys.stderr.write("[i] install fast path: replayed a verified no-op\n")
            return None
    if trace:
        sys.stderr.write(f"[i] install fast path: full run ({reason})\n")
    recording = _Recording(key, stamp_path, policy(), started, root)
    with recording:
        result = run()
    saved = recording.save(root)
    if trace:
        detail = "recorded" if saved else f"not recorded {recording.recorder.violations[:3]}"
        sys.stderr.write(f"[i] install fast path: {detail}\n")
    return result


def fast_path(command: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate the ``install`` click callback with the no-op fast path."""

    @functools.wraps(command)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        return run_with_fast_path(kwargs, lambda: command(*args, **kwargs))

    return wrapped
