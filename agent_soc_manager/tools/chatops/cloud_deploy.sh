#!/bin/bash
# Deploy ChatOps Webhook Handler to Google Cloud Functions

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Configuration
FUNCTION_NAME="chatops-webhook-handler"
REGION=${GCP_LOCATION:-us-central1}
PROJECT_ID=${GCP_PROJECT_ID}
RUNTIME="python310"
ENTRY_POINT="app" # We'll need to wrap the FastAPI app for GCF
SA_EMAIL="${CHRONICLE_SERVICE_ACCOUNT_EMAIL}" # Use existing SA if possible

# Ensure project and region are set
if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT_ID not set"
    exit 1
fi

echo "Deploying $FUNCTION_NAME to $REGION in project $PROJECT_ID..."

# Use gcloud if available
gcloud functions deploy $FUNCTION_NAME \
    --project=$PROJECT_ID \
    --region=$REGION \
    --runtime=$RUNTIME \
    --trigger-http \
    --allow-unauthenticated \
    --entry-point=$ENTRY_POINT \
    --set-env-vars "CHRONICLE_CHATOPS_SECRET=$CHRONICLE_CHATOPS_SECRET,AGENT_ENGINE_RESOURCE_NAME=$AGENT_ENGINE_RESOURCE_NAME,GCP_PROJECT_ID=$GCP_PROJECT_ID,GCP_LOCATION=$GCP_LOCATION" \
    --service-account=$SA_EMAIL \
    --source=soc_agent/tools/chatops/
