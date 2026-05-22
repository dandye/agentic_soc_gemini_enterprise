#!/bin/bash
# Deploy ChatOps Webhook Handler to Google Cloud Run

# Load environment variables from .env
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Configuration
SERVICE_NAME="chatops-webhook"
REGION=${GCP_LOCATION:-us-central1}
PROJECT_ID=${GCP_PROJECT_ID}

# Ensure project and region are set
if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT_ID not set"
    exit 1
fi

echo "Deploying $SERVICE_NAME to $REGION in project $PROJECT_ID..."

# Use gcloud if available
# We use --source=. so gcloud builds the container automatically using the Dockerfile
gcloud run deploy $SERVICE_NAME \
    --project=$PROJECT_ID \
    --region=$REGION \
    --source=soc_agent/tools/chatops/ \
    --allow-unauthenticated \
    --set-env-vars "CHRONICLE_CHATOPS_SECRET=$CHRONICLE_CHATOPS_SECRET,AGENT_ENGINE_RESOURCE_NAME=$AGENT_ENGINE_RESOURCE_NAME,GCP_PROJECT_ID=$GCP_PROJECT_ID,GCP_LOCATION=$GCP_LOCATION"
