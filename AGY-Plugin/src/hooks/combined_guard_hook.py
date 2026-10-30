#!/usr/bin/env python3
"""Antigravity Lifecycle Hook: Unified PII & Model Armor Security Pipeline."""

import os
import sys

plugin_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from src.governance.audit_logger import FSIAuditLogger
from src.hooks.hook_base import AntigravityHookBase
from src.model_armor.client import ModelArmorClient
from src.model_armor.policy_evaluator import ModelArmorPolicyEvaluator
from src.pii_guard.detector import PIIDetector


def main() -> None:
    hook = AntigravityHookBase(hook_name="fsi-unified-guard")
    detector = PIIDetector()
    client = ModelArmorClient()
    evaluator = ModelArmorPolicyEvaluator()
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
            hook.reply_deny(f"🛡️ [Unified Gate] Execution denied: Turn flagged for security policy violation ({block_reason})")
            return

        extraction = hook.extract_scan_target()
        if extraction.action == "BLOCK_POLICY":
            hook.reply_deny(f"🛡️ [Unified Security Gate] {extraction.block_reason}")
            return
        if extraction.action in ("SKIP_CACHED", "NO_ACTIONABLE_TEXT") or not extraction.text_to_scan.strip():
            hook.reply_allow("No actionable text in tool arguments")
            return
        text_to_scan, source = extraction.text_to_scan, extraction.source

        # Phase 1: Tool Args Regex Check
        pii_report = detector.scan(text_to_scan, action_mode="BLOCK")
        if pii_report.contains_pii and pii_report.blocked_by_policy:
            masked_list = [m.to_dict() for m in pii_report.matches]
            violations = [f"{m.entity_name} ({m.masked_value})" for m in pii_report.matches]
            audit_logger.log_event(
                hook_name="fsi-unified-guard",
                event_type="PRE_TOOL_USE",
                decision="deny",
                reason=pii_report.violation_summary,
                risk_score=0.90 if pii_report.highest_severity and pii_report.highest_severity.value == "CRITICAL" else 0.70,
                conversation_id=hook.conversation_id,
                step_idx=hook.step_idx,
                detected_violations=violations,
                masked_entities=masked_list,
                regulatory_frameworks=["RBI_MD_IT_2023", "SEBI_CSCRF_2024", "DPDP_ACT_2023"],
                caller_metadata={"source": source, "tool_name": hook.tool_name, "stage": "pii_regex"},
            )
            deny_reason = f"🚫 [RBI & SEBI Governance Block] {pii_report.violation_summary}"
            hook.reply_deny(deny_reason)
            return

        # Phase 2: Tool Args Model Armor Check
        eval_report = hook.evaluate_model_armor(client, evaluator, text_to_scan)
        if not eval_report.is_allowed:
            audit_logger.log_event(
                hook_name="fsi-unified-guard",
                event_type="PRE_TOOL_USE",
                decision=eval_report.decision,
                reason=eval_report.reason,
                risk_score=eval_report.risk_score,
                conversation_id=hook.conversation_id,
                step_idx=hook.step_idx,
                detected_violations=eval_report.violations_detected,
                regulatory_frameworks=eval_report.rbi_compliance_codes + eval_report.sebi_compliance_codes,
                caller_metadata={"source": source, "tool_name": hook.tool_name, "latency_ms": eval_report.latency_ms, "stage": "model_armor"},
            )
            deny_reason = f"🛡️ [Model Armor Security Gate] {eval_report.reason}"
            if eval_report.decision == "force_ask":
                hook.reply_force_ask(deny_reason)
            else:
                hook.reply_deny(deny_reason)
            return

        hook.reply_allow("All FSI GRC Security & Safety Gates Passed")
        return

    # 3. PreInvocation Handling
    extraction = hook.extract_scan_target()
    if extraction.action == "BLOCK_POLICY":
        hook.reply_block_pre_invocation(f"🛡️ [Unified Security Gate] {extraction.block_reason}")
        return
    if extraction.action in ("SKIP_CACHED", "NO_ACTIONABLE_TEXT") or not extraction.text_to_scan.strip():
        hook.reply_pre_invocation()
        return
    text_to_scan, source = extraction.text_to_scan, extraction.source

    # Phase 1: Fast-Path Regex & Algorithmic Checksum PII Inspection (<1ms)
    pii_report = detector.scan(text_to_scan, action_mode="BLOCK")
    if pii_report.contains_pii and pii_report.blocked_by_policy:
        masked_list = [m.to_dict() for m in pii_report.matches]
        violations = [f"{m.entity_name} ({m.masked_value})" for m in pii_report.matches]

        audit_logger.log_event(
            hook_name="fsi-unified-guard",
            event_type="PRE_INVOCATION",
            decision="deny",
            reason=pii_report.violation_summary,
            risk_score=0.90 if pii_report.highest_severity and pii_report.highest_severity.value == "CRITICAL" else 0.70,
            conversation_id=hook.conversation_id,
            step_idx=hook.step_idx,
            detected_violations=violations,
            masked_entities=masked_list,
            regulatory_frameworks=["RBI_MD_IT_2023", "SEBI_CSCRF_2024", "DPDP_ACT_2023"],
            caller_metadata={"source": source, "stage": "pii_regex"},
        )
        deny_reason = f"🚫 [RBI & SEBI Governance Block] {pii_report.violation_summary}"
        hook.reply_block_pre_invocation(deny_reason)
        return

    # Phase 2: Deep Model Armor Security & AI Safety Inspection
    eval_report = hook.evaluate_model_armor(client, evaluator, text_to_scan)

    if not eval_report.is_allowed:
        audit_logger.log_event(
            hook_name="fsi-unified-guard",
            event_type="PRE_INVOCATION",
            decision=eval_report.decision,
            reason=eval_report.reason,
            risk_score=eval_report.risk_score,
            conversation_id=hook.conversation_id,
            step_idx=hook.step_idx,
            detected_violations=eval_report.violations_detected,
            regulatory_frameworks=eval_report.rbi_compliance_codes + eval_report.sebi_compliance_codes,
            caller_metadata={"source": source, "latency_ms": eval_report.latency_ms, "stage": "model_armor"},
        )
        deny_reason = f"🛡️ [Model Armor Security Gate] {eval_report.reason}"
        hook.reply_block_pre_invocation(deny_reason)
        return

    hook.reply_pre_invocation()


if __name__ == "__main__":
    main()
