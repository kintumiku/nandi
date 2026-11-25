"""Unit tests for Audit Logger, Hash Chaining, and Control Mappings."""

import argparse
import functools
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
plugin_root = os.path.join(repo_root, "AGY-Plugin")
if plugin_root not in sys.path:
    sys.path.insert(0, plugin_root)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
from src.cli import grc_admin
from src.governance.audit_logger import FSIAuditLogger
from src.governance.rbi_controls import RBIComplianceController
from src.governance.sebi_controls import SEBIComplianceController


def _fail_program_files_makedirs(orig_makedirs, path, exist_ok=False):
    if path.endswith(os.path.join("AGY-Plugin", "logs")):
        raise PermissionError("Access is denied")
    return orig_makedirs(path, exist_ok=exist_ok)


def _hide_default_log(default_log, orig_exists, path):
    if os.path.abspath(path) == os.path.abspath(default_log):
        return False
    return orig_exists(path)


class TestGovernance(unittest.TestCase):

    def test_audit_hash_chain_integrity(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            logger = FSIAuditLogger(log_file_path=tmp_path, emit_to_stderr=False)
            
            # Log 3 events
            e1 = logger.log_event("hook_1", "PRE_INVOCATION", "allow", "Clean prompt", 0.0, "conv-1")
            e2 = logger.log_event("hook_2", "PRE_TOOL_USE", "deny", "PII Aadhaar detected", 0.9, "conv-1")
            e3 = logger.log_event("hook_3", "PRE_INVOCATION", "deny", "Jailbreak blocked", 0.95, "conv-1")

            self.assertEqual(e2.prev_event_hash, e1.event_hash)
            self.assertEqual(e3.prev_event_hash, e2.event_hash)

            # Re-instantiate logger and verify recovery
            logger2 = FSIAuditLogger(log_file_path=tmp_path, emit_to_stderr=False)
            self.assertEqual(logger2.last_hash, e3.event_hash)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_rbi_control_mapping(self):
        violations = ["Aadhaar Number (UIDAI) (XXXX-XXXX-1234)", "Card CVV ([REDACTED_CVV])"]
        controls = RBIComplianceController.map_violations_to_controls(violations)
        self.assertIn("RBI-ITG-SEC-01", controls)
        self.assertIn("RBI-DPSC-03", controls)

    def test_sebi_control_mapping(self):
        violations = ["Prompt Injection Attack", "Permanent Account Number (PAN)"]
        controls = SEBIComplianceController.map_violations_to_controls(violations)
        self.assertIn("SEBI-CSCRF-AI-01", controls)
        self.assertIn("SEBI-CSCRF-DP-02", controls)

    def test_audit_logger_localappdata_fallback_when_install_dir_readonly(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            local_appdata = os.path.join(tmp_dir, "LocalAppData")
            with patch.dict(
                os.environ,
                {"FSI_AUDIT_LOG_PATH": "", "LOCALAPPDATA": local_appdata},
                clear=False,
            ):
                makedirs_stub = functools.partial(_fail_program_files_makedirs, os.makedirs)
                with patch("os.makedirs", side_effect=makedirs_stub):
                    logger = FSIAuditLogger(emit_to_stderr=False)
                self.assertEqual(
                    logger.log_file_path,
                    os.path.join(local_appdata, "Nandi", "logs", "fsi_audit.log"),
                )
                logger.log_event("test", "PRE_INVOCATION", "deny", "Audit test", 0.95, "conv-audit")
                self.assertTrue(os.path.exists(logger.log_file_path))

    def test_cmd_show_audit_uses_fsi_audit_log_path_env(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_log = os.path.join(tmp_dir, "custom_fsi_audit.log")
            logger = FSIAuditLogger(log_file_path=env_log, emit_to_stderr=False)
            logger.log_event("model_armor", "PRE_INVOCATION", "deny", "Blocked", 0.95, "conv-env")

            buf = io.StringIO()
            with patch.dict(os.environ, {"FSI_AUDIT_LOG_PATH": env_log}, clear=False):
                with redirect_stdout(buf):
                    grc_admin.cmd_show_audit(argparse.Namespace(tail=5))
            output = buf.getvalue()
            self.assertIn("VERIFIED", output)
            self.assertIn("model_armor", output)

    def test_cmd_show_audit_falls_back_to_localappdata_without_creating_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            local_appdata = os.path.join(tmp_dir, "LocalAppData")
            expected_log = os.path.join(local_appdata, "Nandi", "logs", "fsi_audit.log")
            default_log = os.path.join(plugin_root, "logs", "fsi_audit.log")
            orig_exists = os.path.exists
            exists_stub = functools.partial(_hide_default_log, default_log, orig_exists)

            with patch.dict(
                os.environ,
                {"FSI_AUDIT_LOG_PATH": "", "LOCALAPPDATA": local_appdata},
                clear=False,
            ):
                buf_missing = io.StringIO()
                with patch("os.path.exists", side_effect=exists_stub):
                    with redirect_stdout(buf_missing):
                        grc_admin.cmd_show_audit(argparse.Namespace(tail=5))
                self.assertIn(f"No audit log file found at {expected_log}", buf_missing.getvalue())
                self.assertFalse(orig_exists(expected_log))

                logger = FSIAuditLogger(log_file_path=expected_log, emit_to_stderr=False)
                logger.log_event("model_armor", "PRE_INVOCATION", "allow", "Clean", 0.0, "conv-local")

                buf_found = io.StringIO()
                with patch("os.path.exists", side_effect=exists_stub):
                    with redirect_stdout(buf_found):
                        grc_admin.cmd_show_audit(argparse.Namespace(tail=5))
                self.assertIn("VERIFIED", buf_found.getvalue())


if __name__ == "__main__":
    unittest.main()
