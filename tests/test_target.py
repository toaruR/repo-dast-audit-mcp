from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from repository_vulnerability_report_mcp.target import TargetError, canonical_target


class TargetTests(unittest.TestCase):
    def test_rejects_relative_traversal_missing_and_cache_containing_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            with self.assertRaisesRegex(TargetError, "traversal"):
                canonical_target(base / "child" / "..")
            with self.assertRaisesRegex(TargetError, "accessible"):
                canonical_target(base / "missing")
            cache = base / "cache"
            cache.mkdir()
            with self.assertRaisesRegex(TargetError, "cache"):
                canonical_target(base, cache_dir=cache)

    def test_accepts_an_existing_canonical_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(canonical_target(root).root, root)


if __name__ == "__main__":
    unittest.main()
