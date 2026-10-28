# Google Cloud Model Armor Setup & Configuration Guide

This guide describes how to configure Google Cloud Model Armor in your Google Cloud project in the `asia-south1` (Mumbai) region for production deployment.

## 1. Automated Setup via Shell Script (Quickest & Recommended)

An end-to-end setup script is provided at [`GCP/bin/setup-model-armor.sh`](./bin/setup-model-armor.sh) that automates:
1. Preflight tool & authentication checks (`gcloud`, `curl`, `python3`, OAuth token).
2. Service API enablement (`modelarmor.googleapis.com`, `dlp.googleapis.com`, `logging.googleapis.com`).
3. IAM RBAC role configuration (`roles/modelarmor.user`, `roles/modelarmor.viewer`).
4. Model Armor template creation and synchronization via Regional Endpoints (`modelarmor.asia-south1.rep.googleapis.com`).
5. Live test prompt sanitization validation (`:sanitizeUserPrompt`) with connectivity verification payload.

### Running the Setup Script:
```bash
# Automated setup (requires --project-id):
./GCP/bin/setup-model-armor.sh --project-id your-gcp-project-id --region asia-south1
```

---

## 2. Automated Setup via Terraform

A complete, production-ready Terraform module is provided in [`terraform/`](./terraform/) that automatically configures:
- Model Armor API and template resources in domestic Indian regions (`asia-south1` or `asia-south2`).
- Dedicated Antigravity Agent Service Account with `roles/modelarmor.user` and `roles/logging.logWriter`.
- Cloud DLP inspection template for Indian financial and identity infoTypes (Aadhaar, PAN, GSTIN, Cards).
- 7-Year Cloud Audit Log Bucket and Sink conforming to RBI IT Governance (2023, Para 22) and SEBI CSCRF (2024, Rule 8.4).

### Terraform Quickstart:
```bash
cd GCP/terraform
cp terraform.tfvars.example terraform.tfvars
# Set your project_id and region in terraform.tfvars
terraform init
terraform apply
```

---

## 3. Manual Architecture & IAM Requirements

Model Armor provides real-time sanitization and filtering for LLMs.

### Required IAM Roles
Assign the following roles to the developer service account or identity:
```bash
# Model Armor User role for sanitizing user prompts and model responses
gcloud projects add-iam-policy-binding YOUR_GCP_PROJECT_ID \
    --member="serviceAccount:antigravity-fsi-sa@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/modelarmor.user"

# Model Armor Viewer role for inspecting templates and floor settings
gcloud projects add-iam-policy-binding YOUR_GCP_PROJECT_ID \
    --member="serviceAccount:antigravity-fsi-sa@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/modelarmor.viewer"
```

---

## 2. Enabling APIs & Creating Model Armor Template

### Enable Model Armor API
```bash
gcloud services enable modelarmor.googleapis.com --project=YOUR_GCP_PROJECT_ID
```

### Create Template via REST / gcloud
Create the FSI compliance template in `asia-south1` using the Regional Endpoint (REP):
```bash
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json; charset=utf-8" \
  -H "X-Goog-User-Project: YOUR_GCP_PROJECT_ID" \
  "https://modelarmor.asia-south1.rep.googleapis.com/v1/projects/YOUR_GCP_PROJECT_ID/locations/asia-south1/templates?templateId=Nandi-compliance-template" \
  -d '{
    "filter_config": {
      "pi_and_jailbreak_filter_settings": {
        "filter_enforcement": "ENABLED",
        "confidence_level": "LOW_AND_ABOVE"
      },
      "rai_settings": {
        "rai_filters": [
          { "filter_type": "HATE_SPEECH", "confidence_level": "MEDIUM_AND_ABOVE" },
          { "filter_type": "HARASSMENT", "confidence_level": "MEDIUM_AND_ABOVE" },
          { "filter_type": "SEXUALLY_EXPLICIT", "confidence_level": "MEDIUM_AND_ABOVE" },
          { "filter_type": "DANGEROUS", "confidence_level": "MEDIUM_AND_ABOVE" }
        ]
      },
      "sdp_settings": {
        "basic_config": {
          "filter_enforcement": "ENABLED"
        }
      }
    },
    "template_metadata": {
      "custom_prompt_safety_error_message": "Prompt blocked by FSI Model Armor security policy.",
      "log_sanitize_operations": true,
      "log_template_operations": true,
      "filter_version_selector": {
        "alias": "FILTER_VERSION_ALIAS_STABLE"
      }
    }
  }'
```

---

## 3. Testing Sanitization Endpoint

Invoke the regional endpoint to test real-time prompt sanitization:
```bash
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json; charset=utf-8" \
  -H "X-Goog-User-Project: YOUR_GCP_PROJECT_ID" \
  "https://modelarmor.asia-south1.rep.googleapis.com/v1/projects/YOUR_GCP_PROJECT_ID/locations/asia-south1/templates/Nandi-compliance-template:sanitizeUserPrompt" \
  -d '{
    "user_prompt_data": {
      "text": "Verify Google Cloud Model Armor connectivity and FSI template guardrails."
    },
    "multi_language_detection_metadata": {
      "enable_multi_language_detection": true
    }
  }'
```

### Expected Response:
```json
{
  "sanitization_result": {
    "filter_match_state": "NO_MATCH_FOUND",
    "filter_results": {
      "pi_and_jailbreak": {
        "pi_and_jailbreak_filter_result": {
          "match_state": "NO_MATCH_FOUND"
        }
      }
    },
    "invocation_result": "SUCCESS"
  }
}
```
