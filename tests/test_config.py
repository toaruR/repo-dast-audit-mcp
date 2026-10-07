from __future__ import annotations

import unittest
from pathlib import Path
import subprocess
import sys

from repository_vulnerability_report_mcp.config import (
    ConfigurationError,
    LIMIT_BOUNDS,
    Limits,
    OSV_ORIGIN,
    ServerConfig,
    require_cpython_312,
)


class LimitsTests(unittest.TestCase):
    def test_documented_resource_limits_are_fixed_defaults(self) -> None:
        limits = Limits()
        self.assertEqual(limits.files, 5_000)
        self.assertEqual(limits.file_bytes, 1_048_576)
        self.assertEqual(limits.total_bytes, 52_428_800)
        self.assertEqual(limits.wall_ms, 60_000)
        self.assertEqual(limits.findings, 1_000)
        self.assertEqual(limits.json_bytes, 2_097_152)
        self.assertEqual(limits.markdown_bytes, 1_572_864)

    def test_invalid_limits_fail_instead_of_clamping(self) -> None:
        for name, (_lower, upper) in LIMIT_BOUNDS.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(ConfigurationError, name):
                    Limits(**{name: upper + 1})


class ServerConfigTests(unittest.TestCase):
    def test_server_owned_configuration_rejects_invalid_values(self) -> None:
        with self.assertRaises(ConfigurationError):
            ServerConfig(cache_dir=Path("relative-cache"))
        with self.assertRaises(ConfigurationError):
            ServerConfig(cache_dir=Path("C:/cache"), osv_origin="https://example.invalid")
        with self.assertRaises(ConfigurationError):
            ServerConfig(cache_dir=Path("C:/cache"), dependency_advisories="false")  # type: ignore[arg-type]

    def test_osv_origin_is_fixed(self) -> None:
        self.assertEqual(OSV_ORIGIN, "https://api.osv.dev/v1/query")


class RuntimeTests(unittest.TestCase):
    def test_test_runtime_is_cpython_312(self) -> None:
        self.assertEqual(sys.implementation.name, "cpython")
        self.assertEqual(sys.version_info[:2], (3, 12))

    def test_cpython_312_is_accepted(self) -> None:
        require_cpython_312("cpython", (3, 12))

    def test_other_runtime_or_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "CPython 3.12"):
            require_cpython_312("cpython", (3, 11))
        with self.assertRaisesRegex(ConfigurationError, "CPython 3.12"):
            require_cpython_312("pypy", (3, 12))


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_rejects_any_runtime_other_than_the_bundled_one(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(root / "tools" / "bootstrap-python.ps1"),
                "-Create",
                "-PythonPath",
                r"C:\not-the-bundled-runtime\python.exe",
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PythonPath must be the bundled CPython 3.12 runtime", result.stderr)


if __name__ == "__main__":
    unittest.main()
