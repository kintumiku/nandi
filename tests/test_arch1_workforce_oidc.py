"""Unit tests for Architecture 1 (WorkforceOIDC) Windows MDM channel."""

import os
import shlex
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(REPO_ROOT, "AGY-Plugin", "bin")


class TestArch1WorkforceOidc(unittest.TestCase):

    def test_workforce_oidc_channel_and_idp_helper_contracts(self):
        with open(os.path.join(BIN_DIR, "get-idp-oidc-token.ps1"), "r", encoding="utf-8-sig") as f:
            idp_text = f.read()
        with open(os.path.join(BIN_DIR, "channels", "install-workforceoidc.ps1"), "r", encoding="utf-8-sig") as f:
            install_mod = f.read()
        with open(os.path.join(BIN_DIR, "channels", "sync-workforceoidc.ps1"), "r", encoding="utf-8-sig") as f:
            sync_mod = f.read()

        self.assertIn("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE", idp_text)
        self.assertIn("Get-ClampedExpirationEpoch", idp_text)
        self.assertIn("[System.IO.File]::Replace($TmpPath, $TargetPath, $null)", idp_text)

        self.assertIn(r"$ProjectNumber -notmatch '^\d+$'", install_mod)
        self.assertIn("timeout_millis = 10000", install_mod)
        self.assertNotIn("timeout_millis = 30000", install_mod)
        self.assertIn("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", install_mod)
        self.assertIn("S-1-5-4", install_mod)
        self.assertIn("Nandi-User-WIF-Sync", install_mod)
        self.assertIn("%LOCALAPPDATA%\\Nandi\\cache\\access_token", install_mod)
        self.assertNotIn("CorpAuth", install_mod)
        self.assertNotIn("get-idp-oidc-token.exe", install_mod)

        default_cmd = (
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass"
            " -File C:/ProgramData/Nandi/bin/get-idp-oidc-token.ps1"
        )
        self.assertEqual(shlex.split(default_cmd), default_cmd.split())

        self.assertIn("cred-config.template.json", sync_mod)
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS", sync_mod)
        self.assertIn("GCP_ACCESS_TOKEN_FILE", sync_mod)
        self.assertIn("Invoke-PythonTokenRefresh", sync_mod)
        self.assertNotIn("service_account_impersonation_url", sync_mod)


if __name__ == "__main__":
    unittest.main()
