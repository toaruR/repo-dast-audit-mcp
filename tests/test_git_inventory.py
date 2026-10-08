from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from repo_dast_audit_mcp.git_inventory import (
    InventoryError,
    git_environment,
    inventory_tracked_files,
    read_tracked_text,
)
from repo_dast_audit_mcp.target import canonical_target


class GitInventoryTests(unittest.TestCase):
    def test_runner_uses_fixed_arguments_and_sanitized_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            calls: list[tuple[list[str], dict[str, str], bool]] = []

            def runner(command, **kwargs):
                calls.append((command, kwargs["env"], kwargs["shell"]))
                tail = command[-2:]
                output = (str(root) + "\n").encode() if tail == ["rev-parse", "--show-toplevel"] else b"a" * 40 + b"\n" if tail == ["rev-parse", "HEAD"] else b"src/a.py\x00"
                return subprocess.CompletedProcess(command, 0, output, b"")

            result = inventory_tracked_files(root, runner=runner)
            self.assertEqual(result.paths, ("src/a.py",))
            self.assertTrue(all(call[0][1:5] == ["--no-optional-locks", "-c", "core.fsmonitor=false", "-C"] for call in calls))
            self.assertTrue(all(call[2] is False for call in calls))
            self.assertTrue(all("GIT_DIR" not in call[1] for call in calls))

    def test_non_toplevel_and_malformed_inventory_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()

            def non_toplevel(command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, (str(root.parent) + "\n").encode(), b"")

            with self.assertRaisesRegex(InventoryError, "top-level"):
                inventory_tracked_files(root, runner=non_toplevel)

            def malformed(command, **_kwargs):
                tail = command[-2:]
                payload = (str(root) + "\n").encode() if tail == ["rev-parse", "--show-toplevel"] else b"abc\n" if tail == ["rev-parse", "HEAD"] else b"unsafe"
                return subprocess.CompletedProcess(command, 0, payload, b"")

            with self.assertRaisesRegex(InventoryError, "malformed"):
                inventory_tracked_files(root, runner=malformed)

    def test_unsafe_paths_and_file_read_outcomes_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "good.txt").write_text("text", encoding="utf-8")
            (root / "binary.dat").write_bytes(b"a\x00b")
            target = canonical_target(root)
            self.assertEqual(read_tracked_text(target, "good.txt", max_bytes=10).status, "read")
            self.assertEqual(read_tracked_text(target, "binary.dat", max_bytes=10).reason, "BINARY")
            self.assertEqual(read_tracked_text(target, "../outside", max_bytes=10).reason, "UNSAFE_PATH")

    def test_empty_tracked_inventory_is_explicit_partial_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()

            def runner(command, **_kwargs):
                tail = command[-2:]
                payload = (str(root) + "\n").encode() if tail == ["rev-parse", "--show-toplevel"] else b"abc\n" if tail == ["rev-parse", "HEAD"] else b""
                return subprocess.CompletedProcess(command, 0, payload, b"")

            result = inventory_tracked_files(root, runner=runner)
            self.assertEqual(result.paths, ())
            self.assertEqual(result.skipped[0].reason, "EMPTY_INVENTORY")

    def test_unborn_head_is_known_missing_inventory_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()

            def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                tail = command[-3:]
                if tail[-2:] == ["rev-parse", "--show-toplevel"]:
                    return subprocess.CompletedProcess(command, 0, (str(root) + "\n").encode(), b"")
                if tail[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(command, 128, b"", b"Needed a single revision")
                return subprocess.CompletedProcess(command, 0, b"", b"")

            result = inventory_tracked_files(root, runner=runner)
        self.assertIsNone(result.head)
        self.assertEqual(result.paths, ())
        self.assertEqual(result.skipped[0].reason, "EMPTY_INVENTORY")

    def test_environment_removes_untrusted_git_overrides(self) -> None:
        environment = git_environment({"GIT_DIR": "bad", "GIT_CONFIG_GLOBAL": "bad", "PATH": "safe"})
        self.assertEqual(environment["PATH"], "safe")
        self.assertNotEqual(environment["GIT_CONFIG_GLOBAL"], "bad")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")


if __name__ == "__main__":
    unittest.main()
