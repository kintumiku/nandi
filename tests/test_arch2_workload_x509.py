"""Unit tests for Architecture 2 (WorkloadX509 Options 2A & 2B) Windows MDM channel."""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(REPO_ROOT, "AGY-Plugin", "bin")


class TestArch2WorkloadX509(unittest.TestCase):

    def test_workload_x509_channel_and_mtls_helper_contracts(self):
        with open(os.path.join(BIN_DIR, "mtls-sts-common.ps1"), "r", encoding="utf-8-sig") as f:
            mtls_text = f.read()
        with open(os.path.join(BIN_DIR, "refresh-mtls-system.ps1"), "r", encoding="utf-8-sig") as f:
            refresh_text = f.read()
        with open(os.path.join(BIN_DIR, "channels", "install-workloadx509.ps1"), "r", encoding="utf-8-sig") as f:
            install_mod = f.read()
        with open(os.path.join(BIN_DIR, "channels", "sync-workloadx509user.ps1"), "r", encoding="utf-8-sig") as f:
            sync_mod = f.read()

        self.assertIn("StoreLocation]::CurrentUser", mtls_text)
        self.assertIn("StoreLocation]::LocalMachine", mtls_text)
        self.assertIn("sts.mtls.googleapis.com", mtls_text)
        self.assertIn("1.3.6.1.5.5.7.3.2", mtls_text)
        self.assertIn("IssuerName.RawData", mtls_text)
        self.assertIn("function Invoke-RestPost", mtls_text)
        self.assertIn('-ContentType "application/x-www-form-urlencoded"', mtls_text)
        for form_field in (
            "grant_type=",
            "&audience=",
            "&scope=",
            "&requested_token_type=",
            "&subject_token_type=",
            "&subject_token=",
        ):
            self.assertIn(f'"{form_field}"', mtls_text)
        self.assertIn("ToBase64String($SelectedCert.RawData)", mtls_text)
        self.assertNotIn('"subjectTokenType"', mtls_text)

        self.assertIn("function Invoke-Icacls", refresh_text)
        self.assertIn(". $MtlsCommonPath", refresh_text)
        self.assertIn("-TrustChainPath $TrustChainPath", refresh_text)
        self.assertIn("refresh_adc_token.py", refresh_text)
        self.assertNotIn("$env:TEMP", refresh_text)
        self.assertNotIn("WriteAllText", refresh_text)

        self.assertIn("NT AUTHORITY\\SYSTEM", install_mod)
        self.assertIn("service_account_impersonation_url", install_mod)
        self.assertIn("refresh-mtls-system.ps1", install_mod)
        self.assertIn("& $RefreshScript @InitialRefreshArgs", install_mod)
        self.assertIn("WorkloadX509User", install_mod)
        self.assertIn("Nandi-User-mTLS-Sync", install_mod)
        location_ref = re.search(r"certificate_config_location = \(\$(\w+) -replace", install_mod)
        self.assertIsNotNone(location_ref)
        self.assertEqual(location_ref.group(1), "CertConfigPath")
        self.assertIn('$CertConfigPath = Join-Path $PrivateCertsDir "certificate_config.json"', install_mod)
        for cert_config_key in ("cert_configs", "cert_path", "key_path"):
            self.assertIn(f"{cert_config_key} = ", install_mod)

        sync_non_comment = "\n".join(
            line for line in sync_mod.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertIn("CurrentUser", sync_mod)
        self.assertIn(". $MtlsCommonPath", sync_mod)
        self.assertIn("-TrustChainPath $TrustChainPath", sync_mod)
        self.assertNotIn("service_account_impersonation_url", sync_non_comment)


if __name__ == "__main__":
    unittest.main()
