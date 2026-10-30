#!/usr/bin/env python3
"""Antigravity Lifecycle Hook: Google Cloud Model Armor Guard."""

import os
import sys

# Ensure plugin root is in python path
plugin_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)

from src.governance.audit_logger import FSIAuditLogger
from src.hooks.hook_base import AntigravityHookBase
from src.model_armor.client import ModelArmorClient
from src.model_armor.policy_evaluator import ModelArmorPolicyEvaluator


def main() -> None:
    hook = AntigravityHookBase(hook_name="fsi-model-armor-guard")
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
            hook.reply_deny(f"🛡️ [Model Armor Gate] Execution denied: Turn flagged for security policy violation ({block_reason})")
            return

        extraction = hook.extract_scan_target()
        if extraction.action == "BLOCK_POLICY":
            hook.reply_deny(f"🛡️ [Model Armor Security Gate] {extraction.block_reason}")
            return
        if extraction.action in ("SKIP_CACHED", "NO_ACTIONABLE_TEXT") or not extraction.text_to_scan.strip():
            hook.reply_allow("No actionable text in tool arguments")
            return

        # Scan tool arguments via Model Armor
        text_to_scan, source = extraction.text_to_scan, extraction.source
        eval_report = hook.evaluate_model_armor(client, evaluator, text_to_scan)

        if not eval_report.is_allowed:
            audit_logger.log_event(
                hook_name="fsi-model-armor-guard",
                event_type="PRE_TOOL_USE",
                decision=eval_report.decision,
                reason=eval_report.reason,
                risk_score=eval_report.risk_score,
                conversation_id=hook.conversation_id,
                step_idx=hook.step_idx,
                detected_violations=eval_report.violations_detected,
                regulatory_frameworks=eval_report.rbi_compliance_codes + eval_report.sebi_compliance_codes,
                caller_metadata={"source": source, "tool_name": hook.tool_name, "latency_ms": eval_report.latency_ms},
            )
            deny_reason = f"🛡️ [Model Armor Security Gate] {eval_report.reason}"
            if eval_report.decision == "force_ask":
                hook.reply_force_ask(deny_reason)
            else:
                hook.reply_deny(deny_reason)
            return

        hook.reply_allow(eval_report.reason)
        return

    # 3. PreInvocation Handling
    extraction = hook.extract_scan_target()
    if extraction.action == "BLOCK_POLICY":
        hook.reply_block_pre_invocation(f"🛡️ [Model Armor Security Gate] {extraction.block_reason}")
        return
    if extraction.action in ("SKIP_CACHED", "NO_ACTIONABLE_TEXT") or not extraction.text_to_scan.strip():
        hook.reply_pre_invocation()
        return

    # Call Model Armor Sanitize API
    text_to_scan, source = extraction.text_to_scan, extraction.source
    eval_report = hook.evaluate_model_armor(client, evaluator, text_to_scan)

    if not eval_report.is_allowed:
        audit_logger.log_event(
            hook_name="fsi-model-armor-guard",
            event_type="PRE_INVOCATION",
            decision=eval_report.decision,
            reason=eval_report.reason,
            risk_score=eval_report.risk_score,
            conversation_id=hook.conversation_id,
            step_idx=hook.step_idx,
            detected_violations=eval_report.violations_detected,
            regulatory_frameworks=eval_report.rbi_compliance_codes + eval_report.sebi_compliance_codes,
            caller_metadata={"source": source, "latency_ms": eval_report.latency_ms},
        )
        deny_reason = f"🛡️ [Model Armor Security Gate] {eval_report.reason}"
        hook.reply_block_pre_invocation(deny_reason)
        return

    hook.reply_pre_invocation()


if __name__ == "__main__":
    main()
