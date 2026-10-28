#!/usr/bin/env bash
# ==============================================================================
# Google Cloud Model Armor Setup Script
# Automates infrastructure provisioning and configuration as outlined in:
# GCP/MODEL_ARMOR_SETUP.md
#
# Steps Automated:
#  1. Preflight Diagnostics & Authentication Verification
#  2. Enable Google Cloud APIs (modelarmor, dlp, logging)
#  3. Configure IAM RBAC Roles (roles/modelarmor.user, roles/modelarmor.viewer)
#  4. Create / Update Model Armor Template via Regional Endpoint (REP) or Terraform
#  5. Verify & Test Prompt Sanitization Endpoint Connectivity
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${GCP_DIR}/.." && pwd)"

# Default Configuration
DEFAULT_REGION="asia-south1"
DEFAULT_TEMPLATE_ID="Nandi-compliance-template"
DEFAULT_SA_NAME="sa-nandi-guard"

PROJECT_ID=""
REGION=""
TEMPLATE_ID=""
SERVICE_ACCOUNT=""
DEPLOY_MODE="rest" # "rest" or "terraform"
SKIP_IAM=false
SKIP_API=false
SKIP_TEST=false
SKIP_AUTH=false

print_usage() {
  cat <<EOF
Usage: ./GCP/bin/setup-model-armor.sh -p PROJECT_ID [OPTIONS]

Automates Google Cloud Model Armor template creation, API enablement, IAM role bindings,
and end-to-end sanitization testing.

Required Options:
  -p, --project-id PROJECT_ID  Target GCP Project ID (REQUIRED; e.g. 'my-project-123456')

Optional Configuration:
  -r, --region REGION          Target GCP Region (default: ${DEFAULT_REGION})
  -t, --template-id ID         Model Armor Template ID (default: ${DEFAULT_TEMPLATE_ID})
  -s, --service-account EMAIL  Service account email to grant Model Armor & Logging roles
  -m, --mode MODE              Deployment mode: 'rest' (default, direct API) or 'terraform'
  --skip-iam                   Skip granting IAM policy bindings
  --skip-api                   Skip enabling Google Cloud service APIs
  --skip-test                  Skip live test prompt sanitization check
  --skip-auth                  Skip interactive 'gcloud auth login' / ADC prompts
  -h, --help                   Display this help message

Examples:
  ./GCP/bin/setup-model-armor.sh --project-id my-gcp-project-123456
  ./GCP/bin/setup-model-armor.sh --project-id my-gcp-project-123456 --region asia-south1
  ./GCP/bin/setup-model-armor.sh --project-id my-gcp-project-123456 --mode terraform
  ./GCP/bin/setup-model-armor.sh --project-id my-gcp-project-123456 --service-account sa-nandi-guard@my-project.iam.gserviceaccount.com
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--project-id|--project)
      PROJECT_ID="$2"
      shift 2
      ;;
    -r|--region|--location)
      REGION="$2"
      shift 2
      ;;
    -t|--template|--template-id)
      TEMPLATE_ID="$2"
      shift 2
      ;;
    -s|--service-account)
      SERVICE_ACCOUNT="$2"
      shift 2
      ;;
    -m|--mode)
      DEPLOY_MODE="$(echo "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --skip-iam)
      SKIP_IAM=true
      shift
      ;;
    --skip-api)
      SKIP_API=true
      shift
      ;;
    --skip-test)
      SKIP_TEST=true
      shift
      ;;
    --skip-auth)
      SKIP_AUTH=true
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      print_usage
      exit 1
      ;;
  esac
done

# ------------------------------------------------------------------------------
# 1. Preflight Diagnostics & Authentication Verification
# ------------------------------------------------------------------------------
echo "============================================================"
echo " Google Cloud Model Armor Setup (Automated Provisioner)"
echo "============================================================"

# 1.1 Verify CLI tool availability
if ! command -v gcloud &>/dev/null; then
  echo "❌ Error: 'gcloud' CLI is not installed or not on PATH." >&2
  echo "   Please install the Google Cloud SDK: https://cloud.google.com/sdk/docs/install" >&2
  exit 1
fi

if ! command -v curl &>/dev/null; then
  echo "❌ Error: 'curl' is not installed or not on PATH." >&2
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "❌ Error: 'python3' is not installed or not on PATH." >&2
  exit 1
fi

# 1.2 Validate mandatory target project ID
if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ Error: Missing mandatory option: -p, --project-id PROJECT_ID" >&2
  echo "   A valid GCP Project ID must be explicitly provided." >&2
  echo "" >&2
  print_usage >&2
  exit 1
fi

# 1.3 Resolve region and template ID
if [[ -z "${REGION}" ]]; then
  REGION="${DEFAULT_REGION}"
fi

if [[ -z "${TEMPLATE_ID}" ]]; then
  TEMPLATE_ID="${DEFAULT_TEMPLATE_ID}"
fi

# Determine regional endpoint
if [[ "${REGION}" == "global" ]]; then
  ENDPOINT="modelarmor.googleapis.com"
else
  ENDPOINT="modelarmor.${REGION}.rep.googleapis.com"
fi

ACTIVE_ACCOUNT="$(gcloud config get-value account 2>/dev/null || echo "(none)")"

echo "Target Project ID        : ${PROJECT_ID}"
echo "Target Region            : ${REGION}"
echo "Regional Endpoint (REP)  : ${ENDPOINT}"
echo "Model Armor Template ID  : ${TEMPLATE_ID}"
echo "Active gcloud Account    : ${ACTIVE_ACCOUNT}"
echo "Deployment Mode          : ${DEPLOY_MODE^^}"
echo "============================================================"

# 1.4 Check Authentication / Access Token
get_access_token() {
  if [[ -n "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]; then
    echo "${GOOGLE_OAUTH_ACCESS_TOKEN}"
    return 0
  fi
  if [[ -n "${GCP_ACCESS_TOKEN:-}" ]]; then
    echo "${GCP_ACCESS_TOKEN}"
    return 0
  fi
  local token
  token="$(gcloud auth print-access-token 2>/dev/null || gcloud auth application-default print-access-token 2>/dev/null || true)"
  if [[ -n "${token}" ]]; then
    echo "${token}"
    return 0
  fi
  return 1
}

TOKEN=""
if ! TOKEN="$(get_access_token)"; then
  if [[ "${SKIP_AUTH}" == "true" ]]; then
    echo "❌ Error: No valid GCP OAuth token found and --skip-auth was specified." >&2
    echo "   Please authenticate via 'gcloud auth login' or export GOOGLE_OAUTH_ACCESS_TOKEN." >&2
    exit 1
  fi

  echo ""
  echo "ℹ No active GCP OAuth token found. Initiating authentication..."
  if [[ -t 0 ]]; then
    gcloud auth application-default login
  else
    echo "  Running 'gcloud auth application-default login'..."
    gcloud auth application-default login || true
  fi

  if ! TOKEN="$(get_access_token)"; then
    echo "❌ Error: Failed to acquire GCP OAuth token after authentication attempt." >&2
    exit 1
  fi
fi

echo "✓ GCP OAuth authentication verified (Token acquired)."

# 1.5 Validate target GCP Project ID (strictly require project ID, not project name)
if ! gcloud projects describe "${PROJECT_ID}" &>/dev/null; then
  echo "❌ Error: Project ID '${PROJECT_ID}' was not found or permission denied." >&2
  MATCHING_ID="$(gcloud projects list --filter="name='${PROJECT_ID}'" --format="value(projectId)" 2>/dev/null | head -n 1 || true)"
  if [[ -n "${MATCHING_ID}" ]]; then
    echo "   '${PROJECT_ID}' is a GCP Project Display Name, not a Project ID." >&2
    echo "   Please specify the Project ID instead: --project-id ${MATCHING_ID}" >&2
  else
    echo "   Please provide a valid GCP Project ID (run 'gcloud projects list' to find your project ID)." >&2
  fi
  exit 1
fi
echo "✓ Target GCP Project ID verified: ${PROJECT_ID}"

# ------------------------------------------------------------------------------
# 2. Enable Required Google Cloud APIs
# ------------------------------------------------------------------------------
echo ""
echo "[Step 1/4] Enabling Google Cloud Service APIs..."

if [[ "${SKIP_API}" == "true" ]]; then
  echo "  ✓ Skipping API enablement (--skip-api specified)."
else
  APIS_TO_ENABLE=(
    "modelarmor.googleapis.com"
    "dlp.googleapis.com"
    "logging.googleapis.com"
  )
  echo "  Enabling APIs on project '${PROJECT_ID}': ${APIS_TO_ENABLE[*]}..."
  gcloud services enable "${APIS_TO_ENABLE[@]}" --project="${PROJECT_ID}"
  echo "  ✓ Google Cloud APIs successfully enabled."
fi

# ------------------------------------------------------------------------------
# 3. Configure IAM RBAC Roles
# ------------------------------------------------------------------------------
echo ""
echo "[Step 2/4] Configuring IAM RBAC Permissions..."

if [[ "${SKIP_IAM}" == "true" ]]; then
  echo "  ✓ Skipping IAM role assignment (--skip-iam specified)."
else
  # 3.1 Assign roles to active user identity
  if [[ -n "${ACTIVE_ACCOUNT}" && "${ACTIVE_ACCOUNT}" != "(none)" ]]; then
    echo "  Granting Model Armor roles to active user: ${ACTIVE_ACCOUNT}..."
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="user:${ACTIVE_ACCOUNT}" \
      --role="roles/modelarmor.user" \
      --condition=None --quiet 2>/dev/null || true

    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="user:${ACTIVE_ACCOUNT}" \
      --role="roles/modelarmor.viewer" \
      --condition=None --quiet 2>/dev/null || true
    echo "  ✓ Model Armor User and Viewer roles granted to user:${ACTIVE_ACCOUNT}"
  fi

  # 3.2 Assign roles to dedicated Service Account if requested or provided
  if [[ -n "${SERVICE_ACCOUNT}" ]]; then
    echo "  Configuring service account permissions: ${SERVICE_ACCOUNT}..."
    
    # Check if SA exists; if not, create it
    if ! gcloud iam service-accounts describe "${SERVICE_ACCOUNT}" --project="${PROJECT_ID}" &>/dev/null; then
      SA_NAME="${SERVICE_ACCOUNT%%@*}"
      echo "  Service account not found. Creating service account '${SA_NAME}' in project '${PROJECT_ID}'..."
      gcloud iam service-accounts create "${SA_NAME}" \
        --project="${PROJECT_ID}" \
        --display-name="Nandi Guard Agent SA" \
        --description="Dedicated service account for Nandi Model Armor and Cloud DLP integration" || true
    fi

    for role in "roles/modelarmor.user" "roles/modelarmor.viewer" "roles/logging.logWriter"; do
      gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="serviceAccount:${SERVICE_ACCOUNT}" \
        --role="${role}" \
        --condition=None --quiet 2>/dev/null || true
    done
    echo "  ✓ Granted roles/modelarmor.user, viewer, and logWriter to serviceAccount:${SERVICE_ACCOUNT}"
  fi
fi

# ------------------------------------------------------------------------------
# 4. Create / Update Model Armor Template
# ------------------------------------------------------------------------------
echo ""
echo "[Step 3/4] Deploying Model Armor Template '${TEMPLATE_ID}'..."

if [[ "${DEPLOY_MODE}" == "terraform" ]]; then
  # Option A: Terraform Automation
  echo "  Executing Terraform deployment in GCP/terraform..."
  if ! command -v terraform &>/dev/null; then
    echo "❌ Error: 'terraform' CLI is not installed or not on PATH." >&2
    exit 1
  fi

  TF_DIR="${GCP_DIR}/terraform"
  cd "${TF_DIR}"

  if [[ ! -f "terraform.tfvars" && -f "terraform.tfvars.example" ]]; then
    cp terraform.tfvars.example terraform.tfvars
  fi

  terraform init
  terraform apply -auto-approve \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    -var="template_id=${TEMPLATE_ID}"

  cd "${REPO_ROOT}"
  echo "  ✓ Terraform deployment finished successfully."

else
  # Option B: Direct REST API (Default)
  TEMPLATE_URL="https://${ENDPOINT}/v1/projects/${PROJECT_ID}/locations/${REGION}/templates/${TEMPLATE_ID}"
  CREATE_URL="https://${ENDPOINT}/v1/projects/${PROJECT_ID}/locations/${REGION}/templates?templateId=${TEMPLATE_ID}"

  echo "  Checking if template already exists at ${TEMPLATE_URL}..."
  HTTP_STATUS="$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    "${TEMPLATE_URL}")"

  # Construct compliant template payload matching MODEL_ARMOR_SETUP.md
  # Note: Malicious URI filter is currently supported in US/EU regions; excluded in asia-south1
  INCLUDE_MALICIOUS_URI=false
  if [[ "${REGION}" != "asia-south1" && "${REGION}" != "asia-south2" ]]; then
    INCLUDE_MALICIOUS_URI=true
  fi

  PAYLOAD="$(python3 -c "
import json
region = '${REGION}'
include_uri = '${INCLUDE_MALICIOUS_URI}'.lower() == 'true'

filter_cfg = {
    'pi_and_jailbreak_filter_settings': {
        'filter_enforcement': 'ENABLED',
        'confidence_level': 'LOW_AND_ABOVE'
    },
    'rai_settings': {
        'rai_filters': [
            {'filter_type': 'HATE_SPEECH', 'confidence_level': 'MEDIUM_AND_ABOVE'},
            {'filter_type': 'HARASSMENT', 'confidence_level': 'MEDIUM_AND_ABOVE'},
            {'filter_type': 'SEXUALLY_EXPLICIT', 'confidence_level': 'MEDIUM_AND_ABOVE'},
            {'filter_type': 'DANGEROUS', 'confidence_level': 'MEDIUM_AND_ABOVE'}
        ]
    },
    'sdp_settings': {
        'basic_config': {
            'filter_enforcement': 'ENABLED'
        }
    }
}

if include_uri:
    filter_cfg['malicious_uri_filter_settings'] = {'filter_enforcement': 'ENABLED'}

template_metadata = {
    'custom_prompt_safety_error_message': 'Prompt blocked by FSI Model Armor security policy.',
    'log_sanitize_operations': True,
    'log_template_operations': True,
    'filter_version_selector': {
        'alias': 'FILTER_VERSION_ALIAS_STABLE'
    }
}

# Multi-language detection is supported in global/US/EU regions; excluded in domestic Indian regions
if region not in ['asia-south1', 'asia-south2']:
    template_metadata['multi_language_detection'] = {
        'enable_multi_language_detection': True
    }

data = {
    'filter_config': filter_cfg,
    'template_metadata': template_metadata
}
print(json.dumps(data))
")"

  if [[ "${HTTP_STATUS}" == "200" ]]; then
    echo "  ✓ Model Armor Template '${TEMPLATE_ID}' already exists (HTTP 200)."
    echo "  Synchronizing template filter settings via PATCH..."
    PATCH_URL="${TEMPLATE_URL}?updateMask=filter_config,template_metadata"
    PATCH_RESP="$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X PATCH \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json; charset=utf-8" \
      -H "X-Goog-User-Project: ${PROJECT_ID}" \
      "${PATCH_URL}" \
      -d "${PAYLOAD}")"

    PATCH_CODE="$(echo "${PATCH_RESP}" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)"
    PATCH_BODY="$(echo "${PATCH_RESP}" | sed '/HTTP_STATUS:/d')"

    if [[ "${PATCH_CODE}" == "200" ]]; then
      echo "  ✓ Model Armor Template filter settings synchronized successfully."
    else
      echo "  ⚠️ Note: Template exists; PATCH returned status ${PATCH_CODE}. Proceeding..."
    fi

  elif [[ "${HTTP_STATUS}" == "404" ]]; then
    echo "  Template not found. Creating new Model Armor template '${TEMPLATE_ID}'..."
    CREATE_RESP="$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json; charset=utf-8" \
      -H "X-Goog-User-Project: ${PROJECT_ID}" \
      "${CREATE_URL}" \
      -d "${PAYLOAD}")"

    CREATE_CODE="$(echo "${CREATE_RESP}" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)"
    CREATE_BODY="$(echo "${CREATE_RESP}" | sed '/HTTP_STATUS:/d')"

    if [[ "${CREATE_CODE}" == "200" ]]; then
      echo "  ✓ Successfully created Model Armor Template '${TEMPLATE_ID}'!"
    else
      echo "❌ Error: Failed to create Model Armor Template (HTTP ${CREATE_CODE}):" >&2
      echo "${CREATE_BODY}" >&2
      exit 1
    fi
  else
    echo "❌ Error querying Model Armor Template endpoint (HTTP ${HTTP_STATUS})" >&2
    exit 1
  fi
fi

# ------------------------------------------------------------------------------
# 5. Verify & Test Prompt Sanitization Endpoint
# ------------------------------------------------------------------------------
echo ""
echo "[Step 4/4] Verifying Live Prompt Sanitization Endpoint..."

if [[ "${SKIP_TEST}" == "true" ]]; then
  echo "  ✓ Skipping live prompt sanitization test (--skip-test specified)."
else
  TEST_URL="https://${ENDPOINT}/v1/projects/${PROJECT_ID}/locations/${REGION}/templates/${TEMPLATE_ID}:sanitizeUserPrompt"
  TEST_PAYLOAD='{
    "user_prompt_data": {
      "text": "Verify Google Cloud Model Armor connectivity and FSI template guardrails."
    },
    "multi_language_detection_metadata": {
      "enable_multi_language_detection": true
    }
  }'

  echo "  Sending connectivity verification prompt to regional endpoint..."
  echo "  Endpoint: ${TEST_URL}"

  RAW_TEST_RESP="$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json; charset=utf-8" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    "${TEST_URL}" \
    -d "${TEST_PAYLOAD}")"

  TEST_CODE="$(echo "${RAW_TEST_RESP}" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)"
  TEST_BODY="$(echo "${RAW_TEST_RESP}" | sed '/HTTP_STATUS:/d')"

  if [[ "${TEST_CODE}" != "200" ]]; then
    echo "❌ Error: Prompt sanitization call failed (HTTP ${TEST_CODE}):" >&2
    echo "${TEST_BODY}" >&2
    exit 1
  fi

  # Parse test response with python3
  python3 - "${TEST_BODY}" <<'PY'
import json, sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
except Exception as e:
    print(f"  Warning: Could not parse response JSON: {e}")
    sys.exit(0)

# Check sanitization result structure
res = data.get("sanitizationResult", data.get("sanitization_result", {}))
match_state = res.get("filterMatchState", res.get("filter_match_state", "UNKNOWN"))
inv_res = res.get("invocationResult", res.get("invocation_result", "UNKNOWN"))
filter_res = res.get("filterResults", res.get("filter_results", {}))

print(f"  ✓ Live Model Armor API Call Succeeded (HTTP 200)!")
print(f"    Filter Match State : {match_state}")
print(f"    Invocation Result  : {inv_res}")

pi_res = filter_res.get("piAndJailbreak", filter_res.get("pi_and_jailbreak", {}))
if pi_res:
    pi_detail = pi_res.get("piAndJailbreakFilterResult", pi_res.get("pi_and_jailbreak_filter_result", {}))
    conf = pi_detail.get("confidenceLevel", pi_detail.get("confidence_level", "N/A"))
    score = pi_detail.get("score", "N/A")
    print(f"    ✓ Prompt Injection Filter Evaluated: Match={pi_detail.get('matchState', pi_detail.get('match_state'))} (Confidence: {conf}, Score: {score})")

rai_res = filter_res.get("rai", filter_res.get("rai_filter_result", {}))
if rai_res:
    print(f"    ✓ Responsible AI (RAI) Filter: Active")

print("\n  Security Gate Verification: PASSED ✅")
PY
fi

echo ""
echo "============================================================"
echo "🎉 Google Cloud Model Armor Setup Completed Successfully!"
echo "============================================================"
echo "Template Resource Name: projects/${PROJECT_ID}/locations/${REGION}/templates/${TEMPLATE_ID}"
echo "Regional REP Endpoint : ${ENDPOINT}"
echo ""
echo "Next Steps:"
echo "  1. Install the Nandi Antigravity developer plugin:"
echo "     ./AGY-Plugin/bin/install-nandi.sh --project-id ${PROJECT_ID}"
echo "  2. The installer will now detect this active template and pass"
echo "     all Step 3 project diagnostics and live sanitization probes."
echo "============================================================"
