from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from incident_comms.pipeline import build_incident_packet, check_draft, load_demo_dataset
from incident_comms.generator import _classify_generation_error


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_demo_dataset(ROOT)
        cls.packet = build_incident_packet(cls.dataset, "identified")

    def test_packet_contains_expected_metadata(self) -> None:
        self.assertIn("api-gateway", self.packet.title.lower())
        self.assertEqual(self.packet.severity, "SEV-2")
        self.assertIn("cloudwatch_logs.json", self.packet.raw_sources)
        self.assertGreater(self.packet.source_snapshot["logs_count"], 0)

    def test_eval_checks_flag_internal_details(self) -> None:
        draft = "We identified the issue in rds-prod-main after rollback of PR #12345."
        checks = check_draft(self.packet, draft, "identified")
        leakage = next(check for check in checks if check.name == "Leakage")
        self.assertFalse(leakage.passed)

    def test_eval_checks_allow_safe_draft(self) -> None:
        draft = (
            "Between January 15, 2025 at 14:23 UTC and January 15, 2025 at 15:00 UTC, Abnormal experienced an issue affecting the customer-facing API. "
            "Customers may have experienced slower responses or intermittent request timeouts while mitigation was in progress. "
            "We have identified the issue and will share another update as recovery progresses.\n\n"
            "Jan 15, 06:23 - 07:00 PST"
        )
        checks = check_draft(self.packet, draft, "identified")
        self.assertTrue(all(check.passed for check in checks))

    def test_support_email_is_allowed_for_resolved_messages(self) -> None:
        resolved_packet = build_incident_packet(self.dataset, "resolved")
        draft = (
            "Between January 15, 2025 at 14:23 UTC and January 15, 2025 at 16:45 UTC, Abnormal experienced an issue affecting the customer-facing API. "
            "Service performance has been restored and remained stable through monitoring. "
            "If you continue to experience issues, please contact support at support@abnormalsecurity.com.\n\n"
            "Jan 15, 06:23 - 08:45 PST"
        )
        checks = check_draft(resolved_packet, draft, "resolved")
        leakage = next(check for check in checks if check.name == "Leakage")
        self.assertTrue(leakage.passed)

    def test_generation_error_classifier_detects_low_credits(self) -> None:
        code, message = _classify_generation_error(
            Exception("Your credit balance is too low to access the Anthropic API. Please purchase credits.")
        )
        self.assertEqual(code, "insufficient_credits")
        self.assertIn("enough credits", message)

    def test_generation_error_classifier_detects_connection_errors(self) -> None:
        code, message = _classify_generation_error(Exception("Connection error."))
        self.assertEqual(code, "connection_error")
        self.assertIn("could not reach Anthropic", message)


if __name__ == "__main__":
    unittest.main()
