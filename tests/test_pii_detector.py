"""Unit tests for PII Detector and Redactor."""

import os
import sys
import unittest

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
plugin_root = os.path.join(repo_root, "AGY-Plugin")
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
from src.pii_guard.checksums import (
    passport_in_validate,
    upi_validate,
    verhoeff_generate,
    voter_id_validate,
)
from src.pii_guard.detector import PIIDetector
from src.pii_guard.entities import PIISeverity


class TestPIIDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PIIDetector()
        self.valid_aadh = "2345 6789 012" + verhoeff_generate("23456789012")

    def test_clean_text(self):
        report = self.detector.scan("Please review the standard architecture diagram for Cloud SQL.")
        self.assertFalse(report.contains_pii)
        self.assertEqual(report.total_matches, 0)
        self.assertFalse(report.blocked_by_policy)

    def test_pan_and_aadhaar_detection(self):
        text = f"Customer PAN is ABCPE1234F and Aadhaar is {self.valid_aadh}."
        report = self.detector.scan(text, action_mode="BLOCK")
        self.assertTrue(report.contains_pii)
        self.assertEqual(report.total_matches, 2)
        self.assertTrue(report.blocked_by_policy)
        self.assertEqual(report.highest_severity, PIISeverity.CRITICAL)

        # Check redacted text preserves context
        self.assertIn("ABXXXXX34F", report.redacted_text)
        self.assertIn("XXXX-XXXX-", report.redacted_text)
        self.assertNotIn("ABCPE1234F", report.redacted_text)

    def test_banking_and_upi_detection(self):
        text = "Send settlement of INR 50,000 to Account No: 123456789012 at IFSC HDFC0001234 or UPI rahul.finance@okaxis."
        report = self.detector.scan(text, action_mode="BLOCK")
        self.assertTrue(report.contains_pii)
        self.assertGreaterEqual(report.total_matches, 3)

        entity_types = [m.entity_type for m in report.matches]
        self.assertIn("BANK_ACCOUNT_IN", entity_types)
        self.assertIn("IFSC", entity_types)
        self.assertIn("UPI_VPA", entity_types)

    def test_card_and_cvv_detection(self):
        text = "Card details for processing: 4532015112830366 CVV: 789 Exp: 12/28"
        report = self.detector.scan(text, action_mode="BLOCK")
        self.assertTrue(report.contains_pii)
        self.assertTrue(report.blocked_by_policy)
        self.assertEqual(report.highest_severity, PIISeverity.CRITICAL)

    def test_action_mode_mask(self):
        text = "User phone number is +91 9876543210."
        report = self.detector.scan(text, action_mode="MASK")
        self.assertTrue(report.contains_pii)
        self.assertFalse(report.blocked_by_policy)  # MASK mode does not hard block
        self.assertIn("+91-XXXXX-3210", report.redacted_text)

    def test_no_false_positives_on_emails_or_git_urls(self):
        text = (
            "Contact developer@gmail.com or admin@company.co.in; "
            "clone git@github.com:kintumiku/nandi.git or user@sbi.co.in."
        )
        report = self.detector.scan(text, action_mode="BLOCK")
        self.assertFalse(report.contains_pii)
        self.assertEqual(report.total_matches, 0)
        self.assertFalse(upi_validate("developer@gmail"))
        self.assertFalse(upi_validate("git@github"))
        self.assertTrue(upi_validate("rahul.sharma@okicici"))
        self.assertTrue(upi_validate("merchant_01@ybl"))

    def test_no_false_positives_on_lowercase_git_shas_for_passport(self):
        text = "Merged commit a1234567 and b9876543 into main branch."
        report = self.detector.scan(text, action_mode="BLOCK")
        self.assertFalse(report.contains_pii)
        self.assertEqual(report.total_matches, 0)
        self.assertFalse(passport_in_validate("a1234567"))
        self.assertTrue(passport_in_validate("J1234567"))

        pos_report = self.detector.scan("Passenger Passport: J1234567", action_mode="BLOCK")
        self.assertTrue(pos_report.contains_pii)
        self.assertEqual([m.entity_type for m in pos_report.matches], ["PASSPORT_IN"])

    def test_no_false_positives_on_ticket_ids_for_voter_id(self):
        text = "Resolved tickets BUG1234567, REQ0000001, ERR7654321, CVE2024001, and SHA1234567."
        report = self.detector.scan(text, action_mode="BLOCK")
        self.assertFalse(report.contains_pii)
        self.assertEqual(report.total_matches, 0)
        self.assertFalse(voter_id_validate("BUG1234567"))
        self.assertFalse(voter_id_validate("SJK0000000"))
        self.assertFalse(voter_id_validate("SJK1111111"))
        self.assertTrue(voter_id_validate("SJK1234567"))

        pos_report = self.detector.scan("Voter EPIC card: SJK1234567", action_mode="BLOCK")
        self.assertTrue(pos_report.contains_pii)
        self.assertEqual([m.entity_type for m in pos_report.matches], ["VOTER_ID_IN"])


if __name__ == "__main__":
    unittest.main()
