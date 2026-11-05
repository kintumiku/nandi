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
│       ├── file_guard/         # Pre-read file slice, notebook cell, and multimodal media scanner
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
├── tests/                      # 68 automated unit and end-to-end test suites
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
