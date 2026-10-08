"""Server-owned atomic storage for durable scan generations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
from typing import Any, Mapping
import uuid

from .state import ACTIVE_STATES, StateError, TERMINAL_STATES, new_state, revise, validate_state


class StorageError(RuntimeError):
    code = "E_STORAGE"


class ScanNotFoundError(LookupError):
    code = "E_NOT_FOUND"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ScanStore:
    """Private cache layout; callers only address server-issued UUID scan IDs."""

    def __init__(self, cache_dir: Path, *, hmac_key: bytes | None = None) -> None:
        self.cache_dir = Path(cache_dir)
        self.records_dir = self.cache_dir / "records"
        try:
            self.records_dir.mkdir(parents=True, exist_ok=True)
            self._key = hmac_key or self._load_or_create_key()
        except OSError as exc:
            raise StorageError("cannot initialize server-owned storage") from exc
        if not isinstance(self._key, bytes) or len(self._key) < 16:
            raise StorageError("invalid storage HMAC key")

    def _load_or_create_key(self) -> bytes:
        key_path = self.cache_dir / ".root-hmac-key"
        if key_path.exists():
            return key_path.read_bytes()
        key = secrets.token_bytes(32)
        self._atomic_bytes(key_path, key)
        return key

    def root_fingerprint(self, root: str | Path) -> str:
        canonical_root = str(Path(root).resolve(strict=False))
        return hmac.new(self._key, canonical_root.encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self, *, root: str | Path, limits: Mapping[str, int], scan_id: str | None = None,
               options: Mapping[str, Any] | None = None, head: str | None = None) -> dict[str, Any]:
        identifier = scan_id or str(uuid.uuid4())
        try:
            uuid.UUID(identifier)
        except (ValueError, TypeError, AttributeError) as exc:
            raise StorageError("server scan id is invalid") from exc
        record_dir = self._record_dir(identifier)
        if record_dir.exists():
            raise StorageError("scan id already exists")
        state = new_state(scan_id=identifier, root_fingerprint=self.root_fingerprint(root), limits=limits,
                          options=options, head=head)
        self.commit(state)
        return state

    def commit(self, state: Mapping[str, Any], *, report_json: bytes | str | None = None,
               report_markdown: bytes | str | None = None) -> dict[str, Any]:
        """Commit a generation, then atomically replace the only public pointer."""
        try:
            checked = validate_state(dict(state))
            record_dir = self._record_dir(checked["scan_id"])
            generation = record_dir / "generations" / str(checked["revision"])
            if generation.exists():
                raise StorageError("generation already exists")
            json_bytes = self._as_bytes(report_json)
            markdown_bytes = self._as_bytes(report_markdown)
            if (json_bytes is None) != (markdown_bytes is None):
                raise StorageError("report generation must include JSON and Markdown")
            if json_bytes is not None:
                checked["report_sha256"] = hashlib.sha256(json_bytes).hexdigest()
            if checked["state"] in TERMINAL_STATES and json_bytes is None:
                raise StorageError("terminal generation requires a report")
            checked = self._sign_state(checked, self._previous_audit(record_dir))
            generation.mkdir(parents=True, exist_ok=False)
            self._atomic_bytes(generation / "state.json", _canonical(checked))
            if json_bytes is not None:
                self._atomic_bytes(generation / "report.json", json_bytes)
                self._atomic_bytes(generation / "report.md", markdown_bytes or b"")
            pointer = {"schema_version": 1, "revision": checked["revision"]}
            pointer["hmac"] = self._mac(pointer)
            self._atomic_bytes(record_dir / "current.json", _canonical(pointer))
            return checked
        except (OSError, StateError, ValueError) as exc:
            if isinstance(exc, StorageError):
                raise
            raise StorageError("could not atomically persist scan generation") from exc

    def load(self, scan_id: str) -> tuple[dict[str, Any], bytes | None, bytes | None]:
        record_dir = self._record_dir_checked(scan_id)
        try:
            pointer = json.loads((record_dir / "current.json").read_text(encoding="utf-8"))
            if not isinstance(pointer, dict) or pointer.get("schema_version") != 1 or not self._verify_mac(pointer):
                raise StorageError("invalid current generation pointer")
            revision = pointer.get("revision")
            if type(revision) is not int or revision < 1:
                raise StorageError("invalid current generation pointer")
            generation = record_dir / "generations" / str(revision)
            state = validate_state(json.loads((generation / "state.json").read_text(encoding="utf-8")))
            if state["scan_id"] != scan_id or state["revision"] != revision or not self._verify_state(state):
                raise StorageError("invalid state audit")
            report_path, markdown_path = generation / "report.json", generation / "report.md"
            has_report = report_path.exists() or markdown_path.exists()
            if has_report != (report_path.exists() and markdown_path.exists()):
                raise StorageError("incomplete report generation")
            report = report_path.read_bytes() if has_report else None
            markdown = markdown_path.read_bytes() if has_report else None
            if report is not None and state["report_sha256"] != hashlib.sha256(report).hexdigest():
                raise StorageError("report hash mismatch")
            if state["state"] in TERMINAL_STATES and report is None:
                raise StorageError("terminal generation lacks report")
            return state, report, markdown
        except StorageError:
            self._quarantine(record_dir)
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateError, ValueError) as exc:
            self._quarantine(record_dir)
            raise StorageError("invalid durable scan generation") from exc

    def recover(self) -> list[dict[str, Any]]:
        """Repair valid active records only; corrupt records remain E_STORAGE failures."""
        repaired: list[dict[str, Any]] = []
        for record_dir in self.records_dir.iterdir():
            if not record_dir.is_dir() or record_dir.name.startswith("quarantine-"):
                continue
            try:
                state, report, markdown = self.load(record_dir.name)
                if state["state"] in ACTIVE_STATES:
                    repaired_state = revise(state, state="interrupted", terminal_reason="PROCESS_RESTART")
                    from .config import Limits
                    from .report import build_report
                    from .render import render_report
                    value = json.loads(report) if report else {}
                    if not isinstance(value, dict) or "uncertainty" not in value:
                        value = build_report(repaired_state, (), limits=Limits())
                    value.update(state="interrupted", revision=repaired_state["revision"], progress=repaired_state["progress"])
                    value["uncertainty"].append({"check": "recovery@1", "status": "partial", "reason": "PROCESS_RESTART"})
                    report, markdown = render_report(value, limits=Limits())
                    repaired.append(self.commit(repaired_state, report_json=report, report_markdown=markdown))
            except StorageError:
                # The public lookup for this ID deliberately remains E_STORAGE, not absent.
                continue
        return repaired

    def _record_dir(self, scan_id: str) -> Path:
        return self.records_dir / scan_id

    def _record_dir_checked(self, scan_id: str) -> Path:
        try:
            uuid.UUID(scan_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ScanNotFoundError("unknown scan") from exc
        path = self._record_dir(scan_id)
        if not path.is_dir():
            raise ScanNotFoundError("unknown scan")
        return path

    def _previous_audit(self, record_dir: Path) -> str | None:
        pointer = record_dir / "current.json"
        if not pointer.exists():
            return None
        old, _, _ = self.load(record_dir.name)
        return old["audit"]["hmac"]

    def _sign_state(self, state: dict[str, Any], previous: str | None) -> dict[str, Any]:
        result = dict(state)
        result.pop("audit", None)
        result["audit"] = {"previous": previous}
        result["audit"]["hmac"] = self._mac(result)
        return result

    def _verify_state(self, state: Mapping[str, Any]) -> bool:
        audit = state.get("audit")
        if not isinstance(audit, dict) or set(audit) != {"previous", "hmac"} or not isinstance(audit["hmac"], str):
            return False
        probe = dict(state)
        probe["audit"] = {"previous": audit["previous"]}
        return hmac.compare_digest(audit["hmac"], self._mac(probe))

    def _verify_mac(self, value: Mapping[str, Any]) -> bool:
        signature = value.get("hmac")
        return isinstance(signature, str) and hmac.compare_digest(signature, self._mac(value))

    def _mac(self, value: Mapping[str, Any]) -> str:
        clean = dict(value)
        if isinstance(clean.get("audit"), dict):
            clean["audit"] = dict(clean["audit"])
            clean["audit"].pop("hmac", None)
        clean.pop("hmac", None)
        return hmac.new(self._key, _canonical(clean), hashlib.sha256).hexdigest()

    @staticmethod
    def _as_bytes(value: bytes | str | None) -> bytes | None:
        if value is None:
            return None
        return value if isinstance(value, bytes) else value.encode("utf-8")

    @staticmethod
    def _atomic_bytes(path: Path, data: bytes) -> None:
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    def _quarantine(self, record_dir: Path) -> None:
        # Retain evidence for operators while ensuring the corrupt record cannot look missing.
        try:
            target = record_dir.with_name("quarantine-" + record_dir.name)
            if not target.exists():
                shutil.copytree(record_dir, target)
        except OSError:
            pass


DurableScanStore = ScanStore
