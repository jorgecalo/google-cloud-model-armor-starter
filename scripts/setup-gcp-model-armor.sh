#!/usr/bin/env bash
# ============================================================================
# [GitHub File 1/5]: scripts/setup-gcp-model-armor.sh
# Purpose: Enable Model Armor APIs and grant least-privilege IAM roles
# ============================================================================
set -euo pipefail

export PROJECT_ID="${PROJECT_ID:-your-gcp-project-id}"
export APP_SA="${APP_SA:-your-app-sa@${PROJECT_ID}.iam.gserviceaccount.com}"

echo "Enabling Google Cloud Model Armor, Vertex AI, and Cloud Logging APIs in ${PROJECT_ID}..."
gcloud services enable \
    modelarmor.googleapis.com \
    aiplatform.googleapis.com \
    logging.googleapis.com \
    --project="${PROJECT_ID}"

echo "Granting least-privilege roles/modelarmor.user to ${APP_SA}..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${APP_SA}" \
    --role="roles/modelarmor.user"

echo "Done!"
