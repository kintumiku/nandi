# Nandi - Operator & Developer User Guide

## 1. Overview

**Nandi** automatically activates when installed in your Antigravity environment. It inspects all user prompts before they reach the model (`PreInvocation`), and inspects all tool executions (`PreToolUse`), guaranteeing strict compliance with Indian financial regulations.

---

## 2. Directory Structure

```
nandi/
├── AGY-Plugin/                 # Antigravity IDE plugin (Installed into IDE)
│   ├── bin/                    # Plugin installer automation
│   │   ├── install-nandi.sh    # 5-step installer (Linux / macOS)
│   │   ├── install-nandi.ps1   # 5-step installer (Windows PowerShell)
│   │   ├── install-nandi.cmd   # Windows CMD launcher
│   │   └── install-nandi.bat   # Windows Command Prompt launcher
│   ├── plugin.json             # Antigravity plugin manifest
│   ├── hooks.json              # Lifecycle hook bindings (PreInvocation, PreToolUse)
│   ├── config/                 # PII regex patterns, Model Armor thresholds, RBI/SEBI policies
│   │   ├── config.yaml
│   │   ├── model_armor_policy.json
│   │   ├── pii_patterns.json
│   │   ├── rbi_compliance.yaml
│   │   └── sebi_compliance.yaml
│   ├── rules/                  # Always-on workspace rules (RBI & SEBI guidelines)
│   ├── skills/                 # In-session skills (fsi-compliance-audit, model-armor-diagnostics)
│   ├── logs/                   # Local tamper-evident audit logs (fsi_audit.log)
│   └── src/                    # Core Python engine (zero mandatory external dependencies)
│       ├── cli/                # Admin CLI (grc_admin.py)
│       ├── governance/         # Audit logger, RBI & SEBI compliance controllers
│       ├── hooks/              # Antigravity lifecycle hook executables
│       ├── model_armor/        # Model Armor REST client and policy evaluator
│       └── pii_guard/          # Regex & Checksum PII engine (Verhoeff, Luhn, Mod 36)
├── GCP/                        # Server infrastructure (External to IDE plugin)
│   ├── bin/                    # Setup automation
│   │   ├── setup-model-armor.sh   # Automated setup (Linux / macOS)
│   │   ├── setup-model-armor.ps1  # Automated setup (Windows PowerShell)
│   │   ├── setup-model-armor.cmd  # Windows CMD launcher
│   │   └── setup-model-armor.bat  # Windows Command Prompt launcher
│   ├── terraform/              # Production Terraform templates (Model Armor, DLP, Logging)
│   ├── generated_model_armor_template.json # Standalone REST API payload
│   └── MODEL_ARMOR_SETUP.md    # GCP deployment and IAM guide
├── tests/                      # 40 automated unit and end-to-end test suites
└── docs/                       # Complete compliance & architectural documentation
```

---

## 3. CLI Administration & Diagnostics

### Test a Prompt against Guardrails
```bash
python3 AGY-Plugin/src/cli/grc_admin.py test-prompt "Please check KYC for customer Aadhaar 2345 6789 0124 and PAN ABCPE1234F"
```

### Validate a Specific Entity Algorithm
```bash
# Validate Aadhaar Verhoeff checksum
python3 AGY-Plugin/src/cli/grc_admin.py test-entity AADHAAR "2345 6789 0124"

# Validate Income Tax PAN
python3 AGY-Plugin/src/cli/grc_admin.py test-entity PAN "ABCPE1234F"

# Validate GSTIN Mod 36
python3 AGY-Plugin/src/cli/grc_admin.py test-entity GSTIN "27AADCS1234F1Z5"
```

### Inspect Tamper-Resistant Audit Log
```bash
python3 AGY-Plugin/src/cli/grc_admin.py show-audit --tail 15
```

### Verify Regulatory Compliance Coverage
```bash
python3 AGY-Plugin/src/cli/grc_admin.py verify-compliance --framework ALL
```

---

## 4. Running Test Suites

Execute the comprehensive test runner:
```bash
python3 tests/run_all_tests.py
```

---

## 5. Enterprise Windows MDM Rollout (Intune / SCCM)

For zero-touch enterprise rollouts on Windows laptops without developer-side installation or `gcloud`, download **`nandi-enterprise-mdm-windows.zip`** from the release assets (or use `AGY-Plugin/bin/` from a repository checkout):

1. **Build the offline bundle** on an admin workstation:
   ```powershell
   .\AGY-Plugin\bin\build-offline-bundle.ps1 -OutputDir .\nandi-mdm-bundle
   ```

   - **Architecture 1 (`-AuthMode WorkforceOIDC`)**: Workforce Identity Federation via silent corporate SSO (`S-1-5-4` user-session refresh task via `sync-user-nandi.ps1` writing `%LOCALAPPDATA%\Nandi\cache\access_token`). Stages `get-idp-oidc-token.ps1` under `C:\ProgramData\Nandi\bin` by default; pass `-IdpTokenFile` or `-IdpTokenExecutable` when an existing company SSO agent provides tokens directly.

2. **Corporate TLS Inspection Proxy Root CA**:
   - By default, `install-enterprise-windows.ps1` merges `Cert:\LocalMachine\Root` with `certifi` into `C:\ProgramData\Nandi\certs\combined-ca-bundle.pem` and sets `caCertPath`, `REQUESTS_CA_BUNDLE`, and `SSL_CERT_FILE`.
   - Pass `-CustomCaPemPath .\corp-root-ca.pem` to merge an explicit Root CA PEM file instead.

3. **Deploy as `SYSTEM` via Intune or SCCM** using `install-enterprise-windows.ps1` with one of the installed credential channels:
   - **Architecture 2, Option 2A (`-AuthMode WorkloadX509 -ServiceAccountEmail <sa>`)**: Machine X.509 certificate + service account impersonation (`NT AUTHORITY\SYSTEM` refresh task via `refresh-mtls-system.ps1` writing `C:\ProgramData\Nandi\cache\access_token`). Uses `Cert:\LocalMachine\My` natively via `mtls-sts-common.ps1` by default, or pass `-MachineCertPath` and `-MachineKeyPath` (outside `C:\ProgramData\Nandi` and `C:\Program Files\Nandi`) for PEM mode.
   - **Architecture 2, Option 2B (`-AuthMode WorkloadX509`, omitting `-ServiceAccountEmail`)**: Direct per-user X.509 Workload Identity Federation against `Cert:\CurrentUser\My` (`S-1-5-4` user-session task via `sync-user-nandi.ps1 -AuthMode WorkloadX509User` writing `%LOCALAPPDATA%\Nandi\cache\access_token`).
   - Architecture 2 requires `-WorkloadAudience` (and `-IssuingCaCert .\corp-pki-issuing.crt` when staging `inter.crt` in `build-offline-bundle.ps1`).


