#!/bin/zsh
# helper script for local python testing of the webhook

# 1. Load your local .env
if [ -f .env ]; then
  source .env
fi

# 2. Set necessary environment variables for the handler
export PORT=8080
export CHRONICLE_CHATOPS_SECRET="${CHRONICLE_CHATOPS_SECRET:-test-secret-12345678901234567890123456789012}"
export GCP_PROJECT_ID="${GCP_PROJECT_ID:-secops-demo-env}"
export GCP_LOCATION="${GCP_LOCATION:-us}"
# Ensure PYTHONPATH is set so imports work
export PYTHONPATH=$PYTHONPATH:$(pwd)

echo "Starting Webhook Handler locally on http://localhost:8080 ..."
echo "Press Ctrl+C to stop."

# 3. Run the handler
venv/bin/python soc_agent/tools/chatops/webhook_handler.py
