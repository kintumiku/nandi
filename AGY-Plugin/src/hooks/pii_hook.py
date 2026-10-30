#!/usr/bin/env python3
"""Antigravity Lifecycle Hook: Indian PII Regex & Algorithmic Guard."""

import os
import sys

# Ensure plugin root is in python path
plugin_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from src.governance.audit_logger import FSIAuditLogger
from src.hooks.hook_base import AntigravityHookBase
from src.pii_guard.detector import PIIDetector


def main() -> None:
    hook = AntigravityHookBase(hook_name="fsi-pii-guard")
    detector = PIIDetector()
    audit_logger = FSIAuditLogger()
    event_type = hook.get_event_type()

    # 1. PostInvocation Handling
    if event_type == "post_invocation":
        is_blocked, _ = hook.is_turn_blocked()
        if is_blocked:
            hook.clear_turn_blocked()
            hook.reply_post_invocation(terminate=True)
        else:
            hook.reply_post_invocation(terminate=False)
        return

    # 2. PreToolUse Defense-in-Depth Gate
    if event_type == "pre_tool_use" or hook.tool_call:
        is_blocked, block_reason = hook.is_turn_blocked()
        if is_blocked:
            hook.reply_deny(f"🚫 [PII Guard Gate] Execution denied: Turn flagged for security policy violation ({block_reason})")
            return

        extraction = hook.extract_scan_target()
        if extraction.action == "BLOCK_POLICY":
            hook.reply_deny(f"🚫 [RBI & SEBI Governance Block] {extraction.block_reason}")
            return
        if extraction.action in ("SKIP_CACHED", "NO_ACTIONABLE_TEXT") or not extraction.text_to_scan.strip():
            hook.reply_allow("No actionable text in tool arguments")
            return
        text_to_scan, source = extraction.text_to_scan, extraction.source

        report = detector.scan(text_to_scan, action_mode="BLOCK")
        if report.contains_pii and report.blocked_by_policy:
            masked_list = [m.to_dict() for m in report.matches]
            violations = [f"{m.entity_name} ({m.masked_value})" for m in report.matches]

            audit_logger.log_event(
                hook_name="fsi-pii-guard",
                event_type="PRE_TOOL_USE",
                decision="deny",
                reason=report.violation_summary,
                risk_score=0.90 if report.highest_severity and report.highest_severity.value == "CRITICAL" else 0.70,
                conversation_id=hook.conversation_id,
                step_idx=hook.step_idx,
                detected_violations=violations,
                masked_entities=masked_list,
                regulatory_frameworks=["RBI_MD_IT_2023", "SEBI_CSCRF_2024", "DPDP_ACT_2023"],
                caller_metadata={"source": source, "tool_name": hook.tool_name},
            )
            deny_reason = f"🚫 [RBI & SEBI Governance Block] {report.violation_summary}"
            hook.reply_deny(deny_reason)
            return

        hook.reply_allow("Clean: No sensitive Indian PII detected")
        return

    # 3. PreInvocation Handling
    extraction = hook.extract_scan_target()
    if extraction.action == "BLOCK_POLICY":
        hook.reply_block_pre_invocation(f"🚫 [RBI & SEBI Governance Block] {extraction.block_reason}")
        return
    if extraction.action in ("SKIP_CACHED", "NO_ACTIONABLE_TEXT") or not extraction.text_to_scan.strip():
        hook.reply_pre_invocation()
        return
    text_to_scan, source = extraction.text_to_scan, extraction.source

    report = detector.scan(text_to_scan, action_mode="BLOCK")
    if report.contains_pii and report.blocked_by_policy:
        masked_list = [m.to_dict() for m in report.matches]
        violations = [f"{m.entity_name} ({m.masked_value})" for m in report.matches]

        audit_logger.log_event(
            hook_name="fsi-pii-guard",
            event_type="PRE_INVOCATION",
            decision="deny",
            reason=report.violation_summary,
            risk_score=0.90 if report.highest_severity and report.highest_severity.value == "CRITICAL" else 0.70,
            conversation_id=hook.conversation_id,
            step_idx=hook.step_idx,
            detected_violations=violations,
            masked_entities=masked_list,
            regulatory_frameworks=["RBI_MD_IT_2023", "SEBI_CSCRF_2024", "DPDP_ACT_2023"],
            caller_metadata={"source": source},
        )
        deny_reason = f"🚫 [RBI & SEBI Governance Block] {report.violation_summary}"
        hook.reply_block_pre_invocation(deny_reason)
        return

    hook.reply_pre_invocation()


if __name__ == "__main__":
    main()
