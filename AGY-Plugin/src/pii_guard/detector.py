"""PII Detection Engine with Regex and Algorithmic Checksum Validation."""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set

from src.pii_guard.checksums import (
    verhoeff_validate,
    luhn_validate,
    gstin_validate,
    pan_validate,
    ifsc_validate,
    upi_validate,
    phone_in_validate,
    dl_in_validate,
    passport_in_validate,
    voter_id_validate,
    cin_in_validate,
    pin_code_validate,
)
from src.pii_guard.entities import (
    PIICategory,
    PIISeverity,
    PIIMatch,
    PIIDetectionReport,
)
from src.pii_guard.redactor import PIIRedactor


class PIIDetector:
    """High-performance, regex and algorithmic PII scanner for Indian FSI compliance."""

    def __init__(
        self,
        patterns_config_path: Optional[str] = None,
        min_severity_to_block: str = "HIGH",
        strict_checksums: bool = True,
        allowed_entities: Optional[List[str]] = None,
    ):
        self.min_severity_to_block = PIISeverity(min_severity_to_block)
        self.strict_checksums = strict_checksums
        self.allowed_entities: Set[str] = set(allowed_entities or [])
        self.entities_config: Dict[str, Any] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}

        if not patterns_config_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            patterns_config_path = os.path.join(base_dir, "config", "pii_patterns.json")

        self.patterns_config_path = patterns_config_path
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Loads and pre-compiles regex patterns from JSON definition file."""
        if not os.path.exists(self.patterns_config_path):
            raise FileNotFoundError(f"PII patterns file not found: {self.patterns_config_path}")

        with open(self.patterns_config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.entities_config = data.get("entities", {})
        for entity_key, cfg in self.entities_config.items():
            pattern_str = cfg.get("regex")
            if pattern_str:
                self.compiled_patterns[entity_key] = re.compile(pattern_str)

    def _validate_checksum(self, entity_key: str, raw_value: str) -> bool:
        """Applies mathematical or algorithmic validation based on entity type."""
        if not self.strict_checksums:
            return True

        algo = self.entities_config.get(entity_key, {}).get("checksum_algorithm", "none")

        if algo == "verhoeff":
            return verhoeff_validate(raw_value)
        elif algo == "luhn":
            return luhn_validate(raw_value)
        elif algo == "gstin_mod36":
            return gstin_validate(raw_value)
        elif algo == "pan_structure":
            return pan_validate(raw_value)
        elif algo == "ifsc_structure":
            return ifsc_validate(raw_value)
        elif algo == "upi_handle_validation":
            return upi_validate(raw_value)
        elif algo == "phone_in_validation":
            return phone_in_validate(raw_value)
        elif algo == "dl_in_structure":
            return dl_in_validate(raw_value)
        elif algo == "passport_in_structure":
            return passport_in_validate(raw_value)
        elif algo == "voter_id_structure":
            return voter_id_validate(raw_value)
        elif algo == "cin_structure":
            return cin_in_validate(raw_value)
        elif algo == "pin_code_validation":
            return pin_code_validate(raw_value)
        elif algo == "contextual_digits":
            digits = re.sub(r"\D", "", raw_value)
            return 9 <= len(digits) <= 18
        elif algo == "none":
            return True

        return True

    def scan(self, text: str, action_mode: str = "BLOCK") -> PIIDetectionReport:
        """Scans input text for all configured Indian PII entities.

        Args:
            text: Raw input prompt, user input, or tool parameter text.
            action_mode: Enforcement action (BLOCK, MASK, WARN, AUDIT).

        Returns:
            PIIDetectionReport with complete detection breakdown and redacted text.
        """
        start_time = time.perf_counter()
        if not text:
            return PIIDetectionReport(
                contains_pii=False,
                matches=[],
                total_matches=0,
                highest_severity=None,
                blocked_by_policy=False,
                violation_summary="No text provided",
                redacted_text="",
                scanned_length=0,
                elapsed_ms=0.0,
            )

        raw_matches: List[PIIMatch] = []

        for entity_key, regex in self.compiled_patterns.items():
            if entity_key in self.allowed_entities:
                continue

            entity_meta = self.entities_config.get(entity_key, {})
            name = entity_meta.get("name", entity_key)
            category = PIICategory(entity_meta.get("category", "NATIONAL_ID"))
            severity = PIISeverity(entity_meta.get("severity", "HIGH"))
            frameworks = entity_meta.get("regulatory_frameworks", [])

            # Contextual entities where capture group 1 contains the actual sensitive value
            contextual_entities = {"BANK_ACCOUNT_IN", "CARD_CVV", "MICR", "PIN_CODE_IN"}

            for match in regex.finditer(text):
                if entity_key in contextual_entities and match.groups() and match.group(1):
                    val = match.group(1)
                    start, end = match.start(1), match.end(1)
                else:
                    val = match.group(0)
                    start, end = match.start(0), match.end(0)

                # Algorithmic validation
                is_valid = self._validate_checksum(entity_key, val)
                if not is_valid:
                    continue

                temp_match = PIIMatch(
                    entity_type=entity_key,
                    entity_name=name,
                    category=category,
                    severity=severity,
                    raw_value=val,
                    masked_value="",
                    start_index=start,
                    end_index=end,
                    confidence=0.98 if is_valid else 0.70,
                    checksum_valid=is_valid,
                    regulatory_frameworks=frameworks,
                )
                temp_match.masked_value = PIIRedactor.mask_match(temp_match)
                raw_matches.append(temp_match)

        deduped_matches = self._resolve_overlaps(raw_matches)

        contains_pii = len(deduped_matches) > 0
        highest_severity: Optional[PIISeverity] = None
        for m in deduped_matches:
            if highest_severity is None or m.severity > highest_severity:
                highest_severity = m.severity

        blocked_by_policy = False
        if contains_pii and action_mode == "BLOCK":
            if highest_severity and highest_severity >= self.min_severity_to_block:
                blocked_by_policy = True

        if contains_pii:
            entity_counts: Dict[str, int] = {}
            for m in deduped_matches:
                entity_counts[m.entity_name] = entity_counts.get(m.entity_name, 0) + 1
            breakdown = ", ".join([f"{k}: {v}" for k, v in entity_counts.items()])
            violation_summary = (
                f"RBI/SEBI Compliance Alert: Detected {len(deduped_matches)} sensitive PII item(s) "
                f"({breakdown}). Highest Severity: {highest_severity.value if highest_severity else 'NONE'}."
            )
        else:
            violation_summary = "Clean: No sensitive Indian PII detected."

        redacted_text = PIIRedactor.redact_text(text, deduped_matches) if contains_pii else text
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return PIIDetectionReport(
            contains_pii=contains_pii,
            matches=deduped_matches,
            total_matches=len(deduped_matches),
            highest_severity=highest_severity,
            blocked_by_policy=blocked_by_policy,
            violation_summary=violation_summary,
            redacted_text=redacted_text,
            scanned_length=len(text),
            elapsed_ms=round(elapsed_ms, 2),
        )

    def _resolve_overlaps(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Resolves overlapping matches by keeping the longest and highest severity span."""
        if not matches:
            return []

        sorted_m = sorted(
            matches,
            key=lambda m: (
                m.start_index,
                -(m.end_index - m.start_index),
                -({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(m.severity.value, 0)),
            ),
        )

        resolved: List[PIIMatch] = []
        last_end = -1

        for m in sorted_m:
            if m.start_index >= last_end:
                resolved.append(m)
                last_end = m.end_index
            else:
                prev = resolved[-1]
                prev_len = prev.end_index - prev.start_index
                curr_len = m.end_index - m.start_index

                if m.severity > prev.severity or (m.severity == prev.severity and curr_len > prev_len):
                    resolved.pop()
                    resolved.append(m)
                    last_end = m.end_index

        return resolved
