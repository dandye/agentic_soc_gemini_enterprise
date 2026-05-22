#!/bin/zsh
# helper script for podman testing

# 1. Build the image
PODMAN="/opt/podman/bin/podman"
echo "Building ChatOps Handler Image..."
$PODMAN build -t chatops-handler -f agent_soc_manager/tools/chatops/Dockerfile .

# 2. Run the container with environment variables
# Note: Use your actual GCP credentials if you want to test the Agent Engine query
echo "Launching Container on port 8080..."
$PODMAN run -it --rm \
  -p 8080:8080 \
  -e CHRONICLE_CHATOPS_SECRET="${CHRONICLE_CHATOPS_SECRET:-test-secret-12345678901234567890123456789012}" \
  -e GCP_PROJECT_ID="${GCP_PROJECT_ID:-secops-demo-env}" \
  -e GCP_LOCATION="${GCP_LOCATION:-us}" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/service-account.json \
  -e CONTAINER_HOST="unix:///var/folders/10/zdr6bd2j0334mx042_6dt1n8015qrb/T/podman/podman-machine-default-api.sock" \
  -v "${SECOPS_SA_PATH:-/Users/dandye/.ssh/secops-demo-env-a0f61702b7b4.json}:/app/service-account.json:ro" \
  chatops-handler
