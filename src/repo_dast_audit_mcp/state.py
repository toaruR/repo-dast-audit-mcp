"""Schema-checked, integer-only durable scan state."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping
import uuid


SCHEMA_VERSION = 1
ACTIVE_STATES = frozenset(("queued", "running"))
TERMINAL_STATES = frozenset(("completed", "partial", "cancelled", "interrupted", "failed"))
ALL_STATES = ACTIVE_STATES | TERMINAL_STATES


class StateError(ValueError):
    """Raised when an untrusted durable state record is malformed."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def progress(*, files_total: int, files_completed: int, bytes_limit: int, bytes_read: int,
             analyzers_completed: int = 0, findings_emitted: int = 0) -> dict[str, int]:
    """Build the exact integer progress representation used in reports and state."""
    values = (files_total, files_completed, bytes_limit, bytes_read, analyzers_completed, findings_emitted)
    if any(type(value) is not int or value < 0 for value in values):
        raise StateError("progress values must be non-negative integers")
    if files_completed > files_total or bytes_read > bytes_limit:
        raise StateError("progress exceeds configured limit")
    return {
        "files_total": files_total,
        "files_completed": files_completed,
        "bytes_limit": bytes_limit,
        "bytes_read": bytes_read,
        "analyzers_completed": analyzers_completed,
        "findings_emitted": findings_emitted,
        "progress_percent": (files_completed * 100 // files_total) if files_total else 100,
    }


def new_state(*, scan_id: str, root_fingerprint: str, limits: Mapping[str, int],
              options: Mapping[str, Any] | None = None, head: str | None = None,
              now: str | None = None) -> dict[str, Any]:
    """Create the first server-owned state.  Raw roots are deliberately absent."""
    timestamp = now or utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "revision": 1,
        "state": "queued",
        "root_fingerprint": root_fingerprint,
        "head": head,
        "options": dict(options or {}),
        "created_at": timestamp,
        "updated_at": timestamp,
        "deadline_at": None,
        "limits": dict(limits),
        "progress": progress(files_total=0, files_completed=0, bytes_limit=int(limits["total_bytes"]), bytes_read=0),
        "analyzer_statuses": {},
        "cancellation_requested_at": None,
        "cancel_observed_at": None,
        "cancel_latency_ms": None,
        "terminal_reason": None,
        "report_sha256": None,
    }


def validate_state(value: Any) -> dict[str, Any]:
    """Return a defensive copy after strict shape and lifecycle validation."""
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise StateError("unsupported state schema")
    required = {
        "schema_version", "scan_id", "revision", "state", "root_fingerprint", "head", "options", "created_at",
        "updated_at", "deadline_at", "limits", "progress", "analyzer_statuses", "cancellation_requested_at",
        "cancel_observed_at", "cancel_latency_ms", "terminal_reason", "report_sha256",
    }
    if set(value) - required - {"audit"} or not required.issubset(value):
        raise StateError("invalid state fields")
    try:
        uuid.UUID(value["scan_id"])
    except (TypeError, ValueError, AttributeError) as exc:
        raise StateError("invalid scan id") from exc
    if type(value["revision"]) is not int or value["revision"] < 1 or value["state"] not in ALL_STATES:
        raise StateError("invalid revision or lifecycle state")
    if not isinstance(value["root_fingerprint"], str) or len(value["root_fingerprint"]) != 64:
        raise StateError("invalid root fingerprint")
    if value["head"] is not None and (not isinstance(value["head"], str) or len(value["head"]) not in (40, 64)):
        raise StateError("invalid Git HEAD")
    if not isinstance(value["limits"], dict) or not isinstance(value["analyzer_statuses"], dict):
        raise StateError("invalid limits or analyzer statuses")
    p = value["progress"]
    if not isinstance(p, dict):
        raise StateError("invalid progress")
    progress_fields = (
        "files_total", "files_completed", "bytes_limit", "bytes_read", "analyzers_completed", "findings_emitted"
    )
    progress_values: dict[str, int] = {}
    for key in progress_fields:
        item = p.get(key)
        if type(item) is not int:
            raise StateError("invalid progress")
        progress_values[key] = item
    expected = progress(**progress_values)
    if p != expected:
        raise StateError("progress is not round-trippable")
    for key in ("cancellation_requested_at", "cancel_observed_at"):
        if value[key] is not None and not isinstance(value[key], str):
            raise StateError("invalid cancellation timestamp")
    if value["cancel_latency_ms"] is not None and (type(value["cancel_latency_ms"]) is not int or value["cancel_latency_ms"] < 0):
        raise StateError("invalid cancellation latency")
    if value["state"] in TERMINAL_STATES and value["terminal_reason"] is None:
        raise StateError("terminal state lacks reason")
    return deepcopy(value)


def revise(record: Mapping[str, Any], *, now: str | None = None, **changes: Any) -> dict[str, Any]:
    """Create the next immutable revision, enforcing the small lifecycle graph."""
    result = validate_state(dict(record))
    previous = result["state"]
    next_state = changes.get("state", previous)
    if previous in TERMINAL_STATES or (previous == "queued" and next_state not in {"queued", "running", *TERMINAL_STATES}) or (previous == "running" and next_state not in {"running", *TERMINAL_STATES}):
        raise StateError("invalid state transition")
    result.update(changes)
    result["revision"] += 1
    result["updated_at"] = now or utc_now()
    return validate_state(result)


def request_cancellation(state: Mapping[str, Any], *, accepted_at: str | None = None) -> dict[str, Any]:
    """Persist the first explicit cancellation request; repeated requests are idempotent."""
    checked = validate_state(dict(state))
    if checked["cancellation_requested_at"] is not None or checked["state"] in TERMINAL_STATES:
        return checked
    return revise(checked, cancellation_requested_at=accepted_at or utc_now())


def observe_cancellation(state: Mapping[str, Any], *, observed_at: str, latency_ms: int) -> dict[str, Any]:
    """Attach bounded cancellation evidence before committing a cancelled result."""
    if type(latency_ms) is not int or latency_ms < 0:
        raise StateError("invalid cancellation latency")
    checked = validate_state(dict(state))
    if checked["cancellation_requested_at"] is None:
        raise StateError("cancellation was not requested")
    return revise(checked, cancel_observed_at=observed_at, cancel_latency_ms=latency_ms,
                  state="cancelled", terminal_reason="CANCELLED")
