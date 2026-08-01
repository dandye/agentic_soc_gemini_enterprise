#!/bin/bash
# Deploy ChatOps Chat App Handler to Google Cloud Run
#
# Prefer the managed path, which resolves GCP_PROJECT_NUMBER and validates
# configuration first:
#     python manage.py chatops deploy-app
# This script is the minimal equivalent for CI or manual use.

# Load environment variables from .env
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Configuration
SERVICE_NAME="chatops-chat-app"
REGION=${GCP_LOCATION:-us-central1}
PROJECT_ID=${GCP_PROJECT_ID}

# Ensure project and region are set
if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT_ID not set"
    exit 1
fi

# The handler fails closed without a real secret (security.py); catch the
# misconfiguration here instead of shipping a broken service.
if [ -z "$CHRONICLE_CHATOPS_SECRET" ]; then
    echo "ERROR: CHRONICLE_CHATOPS_SECRET not set (empty secret would disable HMAC integrity)"
    exit 1
fi

echo "Deploying $SERVICE_NAME to $REGION in project $PROJECT_ID..."

# Use gcloud if available
# We use --source=. so gcloud builds the container automatically using the Dockerfile
gcloud run deploy $SERVICE_NAME \
    --project=$PROJECT_ID \
    --region=$REGION \
    --source=agent_soc_manager/tools/chatops/ \
    --allow-unauthenticated \
    --set-env-vars "CHRONICLE_CHATOPS_SECRET=$CHRONICLE_CHATOPS_SECRET,AGENT_ENGINE_RESOURCE_NAME=$AGENT_ENGINE_RESOURCE_NAME,GCP_PROJECT_ID=$GCP_PROJECT_ID,GCP_LOCATION=$GCP_LOCATION,GCP_PROJECT_NUMBER=$GCP_PROJECT_NUMBER,CHATOPS_SERVICE_URL=$CHATOPS_SERVICE_URL,CHATOPS_TASKS_QUEUE=${CHATOPS_TASKS_QUEUE:-chatops-actions},CHATOPS_TASKS_LOCATION=${CHATOPS_TASKS_LOCATION:-$REGION},CHATOPS_INVOKER_SA=$CHATOPS_INVOKER_SA"
