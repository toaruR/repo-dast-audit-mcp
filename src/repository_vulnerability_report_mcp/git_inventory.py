"""Controlled Git inventory and race-aware, read-only file access."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from typing import Callable, Mapping

from .config import Limits
from .target import CanonicalTarget, TargetError, _is_reparse_point, canonical_target, is_contained


class InventoryError(RuntimeError):
    """A stable failure from the controlled Git inventory boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class InventorySkip:
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class TrackedInventory:
    target: CanonicalTarget
    head: str | None
    paths: tuple[str, ...]
    skipped: tuple[InventorySkip, ...] = ()


@dataclass(frozen=True, slots=True)
class FileRead:
    path: str
    status: str
    reason: str | None = None
    text: str | None = None
    sha256: str | None = None
    size: int = 0


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def git_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the fixed environment permitted for controlled Git commands."""
    source = os.environ if environment is None else environment
    result = {key: value for key, value in source.items() if not key.upper().startswith("GIT_")}
    result.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_EDITOR": "true",
    })
    return result


def _run_git(
    executable: Path | str,
    root: Path,
    args: list[str],
    *,
    timeout_seconds: float,
    runner: Runner = subprocess.run,
) -> bytes:
    command = [str(executable), "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root), *args]
    # Git only honors safe.directory from protected configuration. Supply one
    # non-persistent, exact canonical target through Git's command environment;
    # user/global configuration remains ignored.
    environment = git_environment()
    environment.update({
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": root.as_posix(),
    })
    try:
        completed = runner(command, cwd=root, env=environment, shell=False, check=False,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout_seconds)
    except FileNotFoundError as exc:
        raise InventoryError("E_GIT_UNAVAILABLE", "controlled Git executable is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise InventoryError("E_INVENTORY", "controlled Git command timed out") from exc
    except OSError as exc:
        raise InventoryError("E_INVENTORY", "controlled Git command could not run") from exc
    if completed.returncode != 0:
        raise InventoryError("E_NOT_GIT", "root is not an accessible Git repository")
    return completed.stdout


def _decode_toplevel(value: bytes) -> Path:
    try:
        text = value.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise InventoryError("E_ROOT", "Git returned an invalid repository top-level") from exc
    if not text or "\x00" in text:
        raise InventoryError("E_ROOT", "Git returned an invalid repository top-level")
    return Path(text)


def _validate_relative(raw: bytes) -> str | InventorySkip:
    if not raw:
        return InventorySkip("", "EMPTY_PATH")
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return InventorySkip("", "INVALID_PATH_ENCODING")
    path = Path(value)
    if "\x00" in value or path.is_absolute() or value.startswith(("/", "\\")):
        return InventorySkip(value, "UNSAFE_PATH")
    if any(part in {"", ".", ".."} for part in path.parts) or any(":" in part for part in path.parts):
        return InventorySkip(value, "UNSAFE_PATH")
    return value.replace("\\", "/")


def inventory_tracked_files(
    root: str | Path,
    *,
    git_path: Path | str = "git",
    cache_dir: Path | None = None,
    limits: Limits | None = None,
    runner: Runner = subprocess.run,
) -> TrackedInventory:
    """Return sorted, validated paths from one fixed ``git ls-files -z`` call."""
    target = canonical_target(root, cache_dir=cache_dir)
    active_limits = limits or Limits()
    timeout = active_limits.git_ms / 1000
    top = _decode_toplevel(_run_git(git_path, target.root, ["rev-parse", "--show-toplevel"], timeout_seconds=timeout, runner=runner))
    try:
        git_target = canonical_target(top, cache_dir=cache_dir)
    except TargetError as exc:
        raise InventoryError(exc.code, str(exc)) from exc
    if os.path.normcase(os.fspath(git_target.root)) != os.path.normcase(os.fspath(target.root)):
        raise InventoryError("E_ROOT", "root must be the canonical Git top-level")
    # A valid repository can have an unborn branch.  ``rev-parse HEAD`` exits
    # non-zero there, but the canonical top-level check above has already
    # established repository identity. Preserve the known missing HEAD.
    try:
        head = _run_git(git_path, target.root, ["rev-parse", "HEAD"], timeout_seconds=timeout, runner=runner).strip()
    except InventoryError as exc:
        if exc.code != "E_NOT_GIT":
            raise
        head_text = None
    else:
        if not head or b"\x00" in head:
            raise InventoryError("E_INVENTORY", "Git returned an invalid HEAD")
        try:
            head_text = head.decode("ascii")
        except UnicodeDecodeError as exc:
            raise InventoryError("E_INVENTORY", "Git returned an invalid HEAD") from exc
    raw_inventory = _run_git(git_path, target.root, ["ls-files", "-z", "--cached"], timeout_seconds=timeout, runner=runner)
    if len(raw_inventory) > active_limits.inventory_bytes or (raw_inventory and not raw_inventory.endswith(b"\x00")):
        raise InventoryError("E_INVENTORY", "Git returned malformed or oversized inventory")
    paths: list[str] = []
    skipped: list[InventorySkip] = []
    for raw in raw_inventory[:-1].split(b"\x00") if raw_inventory else ():
        item = _validate_relative(raw)
        if isinstance(item, InventorySkip):
            skipped.append(item)
        else:
            paths.append(item)
    if len(paths) > active_limits.files:
        paths = paths[:active_limits.files]
        skipped.append(InventorySkip("", "FILE_LIMIT"))
    if not paths and not skipped:
        # An empty tracked set is evidence of incomplete applicability, never a
        # basis for a downstream "clean repository" claim.
        skipped.append(InventorySkip("", "EMPTY_INVENTORY"))
    return TrackedInventory(target, head_text, tuple(sorted(set(paths), key=lambda path: path.encode("utf-8"))), tuple(skipped))


def _identity(path: Path) -> tuple[int, int, int, int]:
    details = path.stat(follow_symlinks=False)
    return details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns


def read_tracked_text(target: CanonicalTarget, relative_path: str, *, max_bytes: int) -> FileRead:
    """Read one validated file, returning an explicit result for every omission."""
    item = _validate_relative(relative_path.encode("utf-8", "strict"))
    if isinstance(item, InventorySkip):
        return FileRead(relative_path, "skipped", item.reason)
    candidate = target.root / item
    try:
        before_final = candidate.resolve(strict=True)
        if not is_contained(before_final, target.root) or _is_reparse_point(candidate):
            return FileRead(item, "skipped", "REPARSE_POINT")
        before = _identity(candidate)
        if before[2] > max_bytes:
            return FileRead(item, "skipped", "FILE_LIMIT", size=before[2])
        with candidate.open("rb") as source:
            payload = source.read(max_bytes + 1)
        after_final = candidate.resolve(strict=True)
        after = _identity(candidate)
    except (OSError, RuntimeError):
        return FileRead(item, "skipped", "UNREADABLE")
    if not is_contained(after_final, target.root) or before_final != after_final or before != after or len(payload) > max_bytes:
        return FileRead(item, "partial", "FILE_CHANGED")
    if b"\x00" in payload:
        return FileRead(item, "skipped", "BINARY", size=len(payload))
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return FileRead(item, "skipped", "INVALID_ENCODING", size=len(payload))
    return FileRead(item, "read", text=text, sha256=sha256(payload).hexdigest(), size=len(payload))
