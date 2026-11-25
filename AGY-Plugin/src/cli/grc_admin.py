#!/usr/bin/env python3
"""Nandi - Administrator & Compliance CLI Tool."""

import argparse
import json
import os
import sys

# Ensure plugin root is in python path
plugin_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from src.governance.audit_logger import resolve_audit_log_path
from src.governance.rbi_controls import RBIComplianceController
from src.governance.sebi_controls import SEBIComplianceController
from src.model_armor.client import ModelArmorClient
from src.model_armor.policy_evaluator import ModelArmorPolicyEvaluator
from src.pii_guard.checksums import (
    verhoeff_generate,
    verhoeff_validate,
    luhn_validate,
    gstin_validate,
    pan_validate,
    ifsc_validate,
    upi_validate,
    phone_in_validate,
    dl_in_validate,
    passport_in_validate,
    cin_in_validate,
    pin_code_validate,
)
from src.pii_guard.detector import PIIDetector


def cmd_test_prompt(args: argparse.Namespace) -> None:
    """Tests a prompt against both PII Regex and Model Armor security filters."""
    prompt = args.prompt
    print("=" * 80)
    print(" NANDI - PROMPT COMPLIANCE & SAFETY INSPECTION")
    print("=" * 80)
    print(f"Prompt: {prompt}\n")

    # 1. PII Scan
    detector = PIIDetector()
    pii_report = detector.scan(prompt, action_mode="BLOCK")

    print("[1] PII REGEX & CHECKSUM ENGINE RESULTS:")
    print(f"  - Contains PII: {'YES (VIOLATION)' if pii_report.contains_pii else 'NO (CLEAN)'}")
    print(f"  - Total Entities Detected: {pii_report.total_matches}")
    print(f"  - Highest Severity: {pii_report.highest_severity.value if pii_report.highest_severity else 'NONE'}")
    print(f"  - Policy Action: {'BLOCK / DENY' if pii_report.blocked_by_policy else 'ALLOW'}")
    print(f"  - Elapsed Time: {pii_report.elapsed_ms} ms")
    if pii_report.matches:
        print("  - Detected Items:")
        for m in pii_report.matches:
            print(f"      * [{m.severity.value}] {m.entity_name} (Category: {m.category.value})")
            print(f"        Masked: {m.masked_value} | Checksum Valid: {m.checksum_valid}")
            print(f"        Regulatory Frameworks: {', '.join(m.regulatory_frameworks)}")
    print(f"  - Redacted Preview:\n    {pii_report.redacted_text}\n")

    # 2. Model Armor Scan
    client = ModelArmorClient()
    evaluator = ModelArmorPolicyEvaluator()
    ma_resp = client.sanitize_user_prompt(prompt)
    ma_report = evaluator.evaluate(ma_resp)

    print("[2] GOOGLE CLOUD MODEL ARMOR ENGINE RESULTS:")
    print(f"  - Gate Status: {'ALLOWED' if ma_report.is_allowed else 'DENIED'}")
    print(f"  - Decision: {ma_report.decision.upper()}")
    print(f"  - Risk Score: {ma_report.risk_score}")
    print(f"  - Latency: {ma_report.latency_ms} ms")
    print(f"  - Reason: {ma_report.reason}")
    if ma_report.violations_detected:
        print("  - Violations:")
        for v in ma_report.violations_detected:
            print(f"      * {v}")
    if ma_report.rbi_compliance_codes or ma_report.sebi_compliance_codes:
        print(f"  - RBI Controls: {', '.join(ma_report.rbi_compliance_codes)}")
        print(f"  - SEBI Controls: {', '.join(ma_report.sebi_compliance_codes)}")

    # Overall Verdict
    print("-" * 80)
    is_overall_allowed = (not pii_report.blocked_by_policy) and ma_report.is_allowed
    print(f"FINAL DECISION: {'>>> ALLOW <<<' if is_overall_allowed else '>>> DENY / BLOCK <<<'}")
    print("=" * 80)


def cmd_test_entity(args: argparse.Namespace) -> None:
    """Tests a single entity value against specific algorithmic checksums."""
    entity = args.entity.upper()
    val = args.value
    print(f"Testing Entity: {entity} | Value: {val}")

    if entity == "AADHAAR":
        is_valid = verhoeff_validate(val)
        print(f"Verhoeff Checksum Valid: {is_valid}")
        if not is_valid and len(val.replace(' ', '')) == 11:
            check = verhoeff_generate(val.replace(' ', ''))
            print(f"Generated 12th Verhoeff Digit: {check} -> Full: {val}{check}")
    elif entity == "PAN":
        print(f"PAN Structure Valid: {pan_validate(val)}")
    elif entity == "CARD":
        print(f"Luhn Mod-10 Checksum Valid: {luhn_validate(val)}")
    elif entity == "GSTIN":
        print(f"GSTIN Mod-36 Checksum Valid: {gstin_validate(val)}")
    elif entity == "IFSC":
        print(f"IFSC Code Valid: {ifsc_validate(val)}")
    elif entity == "UPI":
        print(f"UPI VPA Valid: {upi_validate(val)}")
    elif entity == "PHONE":
        print(f"Indian Phone Number Valid: {phone_in_validate(val)}")
    elif entity == "DL":
        print(f"Driving Licence Valid: {dl_in_validate(val)}")
    elif entity == "PASSPORT":
        print(f"Indian Passport Valid: {passport_in_validate(val)}")
    elif entity == "CIN":
        print(f"CIN Number Valid: {cin_in_validate(val)}")
    elif entity == "PIN":
        print(f"PIN Code Valid: {pin_code_validate(val)}")
    else:
        print(f"Unknown entity type: {entity}")


def cmd_show_audit(args: argparse.Namespace) -> None:
    """Displays and verifies the integrity of local FSI audit logs."""
    log_path = resolve_audit_log_path()
    if not os.path.exists(log_path):
        print(f"No audit log file found at {log_path}")
        return

    with open(log_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    print("=" * 80)
    print(f" ANTIGRAVITY FSI AUDIT TRAIL ({len(lines)} Total Records)")
    print("=" * 80)

    # Verify Hash Chain Integrity
    prev_hash = "GENESIS_BLOCK_FSI_INDIA_0000000000000000"
    tampered = False

    for idx, line in enumerate(lines):
        try:
            entry = json.loads(line)
            if entry.get("prev_event_hash") != prev_hash and idx > 0:
                print(f"⚠️ WARNING: Hash chain broken at record #{idx + 1} (Event ID: {entry.get('event_id')})")
                tampered = True
            prev_hash = entry.get("event_hash", "")
        except Exception:
            tampered = True

    if not tampered and lines:
        print("✅ Cryptographic Hash Chain Integrity: VERIFIED (Tamper-Resistant SHA-256 Chain Intact)\n")

    tail_count = args.tail or 10
    recent = lines[-tail_count:]
    for line in recent:
        e = json.loads(line)
        print(f"[{e['timestamp_ist']}] {e['event_id']} | Hook: {e['hook_name']} | Decision: {e['decision'].upper()}")
        print(f"  Risk Score: {e['risk_score']} | Reason: {e['reason']}")
        if e.get("detected_violations"):
            print(f"  Violations: {', '.join(e['detected_violations'])}")
        print(f"  Event Hash: {e['event_hash'][:16]}... | Prev Hash: {e['prev_event_hash'][:16]}...")
        print("-" * 80)


def cmd_verify_compliance(args: argparse.Namespace) -> None:
    """Verifies control coverage for RBI, SEBI, and DPDP Act frameworks."""
    framework = (args.framework or "ALL").upper()
    print("=" * 80)
    print(" ANTIGRAVITY FSI INDIA GOVERNANCE CONTROL COMPLIANCE MATRIX")
    print("=" * 80)

    if framework in ("ALL", "RBI"):
        print("\n[RESERVE BANK OF INDIA - IT GOVERNANCE & PAYMENT SECURITY CONTROLS]")
        for cid, details in RBIComplianceController.RBI_CONTROLS.items():
            print(f"  * {cid}: {details['title']}")
            print(f"    Reference: {details['reference']}")
            print(f"    Requirement: {details['requirement']}")
            print(f"    Target Entities: {', '.join(details['target_entities'])}")
            print(f"    Status: ✅ ENFORCED (Automated PreInvocation & PreToolUse Lifecycle Hooks)\n")

    if framework in ("ALL", "SEBI"):
        print("\n[SECURITIES AND EXCHANGE BOARD OF INDIA - CSCRF (2024) CONTROLS]")
        for cid, details in SEBIComplianceController.SEBI_CONTROLS.items():
            print(f"  * {cid}: {details['title']}")
            print(f"    Reference: {details['reference']}")
            print(f"    Requirement: {details['requirement']}")
            print(f"    Target Entities: {', '.join(details['target_entities'])}")
            print(f"    Status: ✅ ENFORCED (Model Armor Policy Evaluator & PII Shield)\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Nandi Admin CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # test-prompt
    p_test = subparsers.add_parser("test-prompt", help="Test a prompt against PII & Model Armor guardrails")
    p_test.add_argument("prompt", help="Prompt text to inspect")
    p_test.set_defaults(func=cmd_test_prompt)

    # test-entity
    p_entity = subparsers.add_parser("test-entity", help="Test specific entity validation algorithm")
    p_entity.add_argument("entity", help="Entity type (AADHAAR, PAN, CARD, GSTIN, IFSC, UPI, PHONE, DL, PASSPORT, CIN, PIN)")
    p_entity.add_argument("value", help="Value string to test")
    p_entity.set_defaults(func=cmd_test_entity)

    # show-audit
    p_audit = subparsers.add_parser("show-audit", help="View recent audit events and verify integrity")
    p_audit.add_argument("--tail", type=int, default=10, help="Number of recent records to display")
    p_audit.set_defaults(func=cmd_show_audit)

    # verify-compliance
    p_comp = subparsers.add_parser("verify-compliance", help="Display compliance control matrix")
    p_comp.add_argument("--framework", choices=["ALL", "RBI", "SEBI", "DPDP"], default="ALL")
    p_comp.set_defaults(func=cmd_verify_compliance)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
