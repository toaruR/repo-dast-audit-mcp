"""Validation of untrusted repository roots before any target read."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import stat


class TargetError(ValueError):
    """A stable, non-sensitive target validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CanonicalTarget:
    """An existing, non-reparse directory represented by its final path."""

    root: Path


def _is_reparse_point(path: Path) -> bool:
    """Return whether *path* is a symlink or Windows reparse point."""
    try:
        attributes = path.lstat().st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return path.is_symlink() or bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _parts_from_anchor(path: Path) -> tuple[Path, ...]:
    """Yield each existing lexical component, including the drive/root anchor."""
    anchor = Path(path.anchor)
    current = anchor
    values: list[Path] = []
    for part in path.parts[1:]:
        current = current / part
        values.append(current)
    return tuple(values)


def is_contained(path: Path, root: Path) -> bool:
    """Whether two already-canonical paths have a strict containment relation."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def canonical_target(root: str | Path, *, cache_dir: Path | None = None) -> CanonicalTarget:
    """Validate an absolute, lexical, non-reparse target directory.

    Git top-level confirmation belongs to :mod:`git_inventory`, because it is
    obtained through the same controlled Git runner as the inventory itself.
    """
    if not isinstance(root, (str, Path)):
        raise TargetError("E_ROOT", "root must be an absolute path")
    candidate = Path(root)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise TargetError("E_ROOT", "root must be an absolute path without traversal")
    try:
        if not candidate.exists() or not candidate.is_dir():
            raise TargetError("E_ROOT", "root does not name an accessible directory")
        for component in _parts_from_anchor(candidate):
            if _is_reparse_point(component):
                raise TargetError("E_ROOT", "root must not traverse a symlink or reparse point")
        resolved = candidate.resolve(strict=True)
    except PermissionError as exc:
        raise TargetError("E_ROOT", "root is inaccessible") from exc
    except OSError as exc:
        raise TargetError("E_ROOT", "root cannot be resolved") from exc
    if os.path.normcase(os.fspath(candidate)) != os.path.normcase(os.fspath(resolved)):
        raise TargetError("E_ROOT", "root must already be canonical")
    if cache_dir is not None:
        try:
            cache = cache_dir.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TargetError("E_ROOT", "cache path cannot be resolved") from exc
        if is_contained(cache, resolved):
            raise TargetError("E_ROOT", "root must not contain the server cache")
    return CanonicalTarget(resolved)
