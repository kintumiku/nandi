"""Model Armor Policy Evaluation and Decision Engine for India FSI Compliance."""

import dataclasses
from enum import Enum
from typing import Any, Dict, List

from src.model_armor.client import ModelArmorResponse


class FilterType(str, Enum):
    PI_AND_JAILBREAK = "pi_and_jailbreak"
    RESPONSIBLE_AI = "rai"
    MALICIOUS_URIS = "malicious_uris"
    CSAM = "csam"
    SENSITIVE_DATA = "sdp"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CONFIDENCE_LEVEL_UNSPECIFIED = "CONFIDENCE_LEVEL_UNSPECIFIED"

    def is_at_or_above(self, threshold: str) -> bool:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "CONFIDENCE_LEVEL_UNSPECIFIED": 0}
        thresh_val = threshold.upper().replace("_AND_ABOVE", "")
        return order.get(self.value, 0) >= order.get(thresh_val, 1)


@dataclasses.dataclass
class ModelArmorEvaluationReport:
    """Evaluation outcome of Model Armor checks mapped to RBI/SEBI standards."""
    is_allowed: bool
    decision: str  # "allow", "deny", "force_ask"
    reason: str
    risk_score: float
    violations_detected: List[str]
    filter_details: Dict[str, Any]
    rbi_compliance_codes: List[str]
    sebi_compliance_codes: List[str]
    latency_ms: float
    is_clean: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_allowed": self.is_allowed,
            "decision": self.decision,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "violations_detected": self.violations_detected,
            "filter_details": self.filter_details,
            "rbi_compliance_codes": self.rbi_compliance_codes,
            "sebi_compliance_codes": self.sebi_compliance_codes,
            "latency_ms": self.latency_ms,
            "is_clean": self.is_clean,
        }


class ModelArmorPolicyEvaluator:
    """Evaluates Model Armor filter responses against FSI governance thresholds."""

    def __init__(
        self,
        action_on_match: str = "BLOCK",
        pi_jb_threshold: str = "LOW_AND_ABOVE",
        rai_threshold: str = "MEDIUM_AND_ABOVE",
    ):
        self.action_on_match = action_on_match.upper()
        self.pi_jb_threshold = pi_jb_threshold
        self.rai_threshold = rai_threshold

    def evaluate(self, response: ModelArmorResponse) -> ModelArmorEvaluationReport:
        """Evaluates Model Armor API response against FSI security policies."""
        violations: List[str] = []
        rbi_codes: List[str] = []
        sebi_codes: List[str] = []
        risk_score = 0.0

        if not response.success or response.invocation_result == "FAILURE":
            err_msg = response.error_message or "Authentication or Model Armor API call failed."
            violations.append(f"Fail-Closed Security Gate: {err_msg}")
            rbi_codes.append("RBI-ITG-SEC-01")
            sebi_codes.append("SEBI-CSCRF-AI-01")
            risk_score = 1.0
            reason = (
                f"Model Armor Security Gate Denied Prompt (Fail-Closed Policy): {err_msg} "
                f"Prompt blocked from propagating to backend model. Regulatory Mandates Triggered: {', '.join(sorted(set(rbi_codes + sebi_codes)))}."
            )
            return ModelArmorEvaluationReport(
                is_allowed=False,
                decision="deny",
                reason=reason,
                risk_score=1.0,
                violations_detected=violations,
                filter_details={},
                rbi_compliance_codes=sorted(list(set(rbi_codes))),
                sebi_compliance_codes=sorted(list(set(sebi_codes))),
                latency_ms=response.latency_ms,
            )

        filter_res = response.filter_results or {}

        # 1. Evaluate Prompt Injection & Jailbreak
        pi_jb_wrapper = filter_res.get("pi_and_jailbreak", {})
        pi_jb = pi_jb_wrapper.get("piAndJailbreakFilterResult") or pi_jb_wrapper.get("pi_and_jailbreak_filter_result", {})
        pi_jb_match = pi_jb.get("matchState") or pi_jb.get("match_state")
        if pi_jb_match == "MATCH_FOUND":
            conf_str = pi_jb.get("confidenceLevel") or pi_jb.get("confidence_level", "HIGH")
            conf = ConfidenceLevel(conf_str) if conf_str in ConfidenceLevel.__members__ else ConfidenceLevel.HIGH
            if conf.is_at_or_above(self.pi_jb_threshold):
                score = pi_jb.get("score", 0.95)
                risk_score = max(risk_score, score)
                violations.append(f"Prompt Injection / Jailbreak Attack Detected (Confidence: {conf_str}, Score: {score})")
                rbi_codes.append("RBI-ITG-SEC-02")
                sebi_codes.append("SEBI-CSCRF-AI-01")

        # 2. Evaluate Responsible AI (RAI)
        rai_wrapper = filter_res.get("rai", {})
        rai = rai_wrapper.get("raiFilterResult") or rai_wrapper.get("rai_filter_result", {})
        rai_match = rai.get("matchState") or rai.get("match_state")
        if rai_match == "MATCH_FOUND":
            type_results = rai.get("raiFilterTypeResults") or rai.get("rai_filter_type_results", {})
            for cat, details in type_results.items():
                cat_match = details.get("matchState") or details.get("match_state")
                if cat_match == "MATCH_FOUND" or cat_match is None:
                    conf_str = details.get("confidenceLevel") or details.get("confidence_level", "LOW")
                    conf = ConfidenceLevel(conf_str) if conf_str in ConfidenceLevel.__members__ else ConfidenceLevel.LOW
                    if conf.is_at_or_above(self.rai_threshold):
                        risk_score = max(risk_score, 0.85)
                        violations.append(f"Responsible AI Safety Breach: {cat} (Confidence: {conf_str})")
                        rbi_codes.append("RBI-ITG-SEC-02")
                        sebi_codes.append("SEBI-CSCRF-AI-01")

        # 3. Evaluate Sensitive Data Protection (SDP)
        sdp_wrapper = filter_res.get("sdp", {})
        sdp = sdp_wrapper.get("sdpFilterResult") or sdp_wrapper.get("sdp_filter_result", {})
        inspect = sdp.get("inspectResult") or sdp.get("inspect_result", {})
        sdp_match = inspect.get("matchState") or inspect.get("match_state")
        if sdp_match == "MATCH_FOUND":
            findings = inspect.get("findings", [])
            types_found = []
            for f in findings:
                itype = f.get("infoType") or f.get("info_type")
                if itype and itype not in types_found:
                    types_found.append(itype)
            types_str = ", ".join(types_found) if types_found else "FSI Regulatory PII"
            risk_score = max(risk_score, 0.90)
            violations.append(f"Sensitive Data Protection Breach: Detected {types_str}")
            rbi_codes.append("RBI-ITG-SEC-01")
            rbi_codes.append("DPDP-2023-SEC-08")
            sebi_codes.append("SEBI-CSCRF-AI-01")

        # 4. Evaluate Malicious URIs
        mal_uris_wrapper = filter_res.get("malicious_uris", {})
        mal_uris = mal_uris_wrapper.get("maliciousUriFilterResult") or mal_uris_wrapper.get("malicious_uri_filter_result", {})
        mal_match = mal_uris.get("matchState") or mal_uris.get("match_state")
        if mal_match == "MATCH_FOUND":
            matched = mal_uris.get("matchedUris") or mal_uris.get("matched_uris", [])
            risk_score = max(risk_score, 0.95)
            violations.append(f"Malicious / Phishing URI Detected: {', '.join(matched) if matched else 'Unsafe URL'}")
            rbi_codes.append("RBI-ITG-SEC-02")
            sebi_codes.append("SEBI-CSCRF-NET-03")

        # 5. Evaluate CSAM
        csam_wrapper = filter_res.get("csam", {})
        csam = csam_wrapper.get("csamFilterFilterResult") or csam_wrapper.get("csam_filter_filter_result", {})
        csam_match = csam.get("matchState") or csam.get("match_state")
        if csam_match == "MATCH_FOUND":
            risk_score = 1.0
            violations.append("CSAM Content Policy Violation Detected")
            rbi_codes.append("RBI-ITG-SEC-01")
            sebi_codes.append("SEBI-CSCRF-AI-01")

        # 6. Fallback if overall MATCH_FOUND but specific filter detail unparsed
        if response.filter_match_state == "MATCH_FOUND" and not violations:
            risk_score = max(risk_score, 0.90)
            violations.append("Model Armor Security Filter Triggered (MATCH_FOUND)")
            rbi_codes.append("RBI-ITG-SEC-02")
            sebi_codes.append("SEBI-CSCRF-AI-01")

        # 7. Determine Decision
        has_violations = len(violations) > 0 or response.filter_match_state == "MATCH_FOUND"

        if has_violations:
            is_clean = False
            if self.action_on_match == "BLOCK":
                decision = "deny"
                is_allowed = False
            elif self.action_on_match == "FORCE_ASK":
                decision = "force_ask"
                is_allowed = False
            else:
                decision = "allow"
                is_allowed = True

            reason = (
                f"Model Armor Security Gate Denied Prompt: {'; '.join(violations)}. "
                f"Regulatory Mandates Triggered: {', '.join(sorted(set(rbi_codes + sebi_codes)))}. Risk Score: {round(risk_score, 2)}."
            )
        else:
            is_clean = response.invocation_result == "SUCCESS"
            decision = "allow"
            is_allowed = True
            reason = "Model Armor Security Gate Passed: No adversarial, toxic, or malicious indicators found."

        return ModelArmorEvaluationReport(
            is_allowed=is_allowed,
            decision=decision,
            reason=reason,
            risk_score=round(risk_score, 2),
            violations_detected=violations,
            filter_details=filter_res,
            rbi_compliance_codes=sorted(list(set(rbi_codes))),
            sebi_compliance_codes=sorted(list(set(sebi_codes))),
            latency_ms=response.latency_ms,
            is_clean=is_clean,
        )
