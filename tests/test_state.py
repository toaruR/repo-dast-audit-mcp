from __future__ import annotations

import unittest
import uuid

from repo_dast_audit_mcp.state import StateError, new_state, observe_cancellation, progress, request_cancellation, validate_state


class StateTests(unittest.TestCase):
    def test_progress_round_trips_exact_integer_values(self) -> None:
        value = progress(files_total=50, files_completed=49, bytes_limit=52_428_800, bytes_read=52_428_799)
        self.assertEqual(value["progress_percent"], 98)
        state = new_state(scan_id=str(uuid.uuid4()), root_fingerprint="a" * 64, limits={"total_bytes": 52_428_800})
        state["progress"] = value
        self.assertEqual(validate_state(state)["progress"], value)

    def test_cancellation_has_accepted_observed_and_latency_evidence(self) -> None:
        state = new_state(scan_id=str(uuid.uuid4()), root_fingerprint="a" * 64, limits={"total_bytes": 1})
        requested = request_cancellation(state, accepted_at="2026-01-01T00:00:00+00:00")
        cancelled = observe_cancellation(requested, observed_at="2026-01-01T00:00:00.010+00:00", latency_ms=10)
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertEqual(cancelled["cancel_latency_ms"], 10)
        with self.assertRaises(StateError):
            observe_cancellation(state, observed_at="x", latency_ms=0)
