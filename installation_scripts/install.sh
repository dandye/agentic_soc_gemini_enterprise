#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting MCP server installation..."

# Install MCP server packages from local directories
# These directories are copied via extra_packages in the deployment
pip install -e /code/mcp-security/server/gti
pip install -e /code/mcp-security/server/secops
pip install -e /code/mcp-security/server/secops-soar
pip install -e /code/mcp-security/server/scc

echo "MCP server packages installed successfully"
