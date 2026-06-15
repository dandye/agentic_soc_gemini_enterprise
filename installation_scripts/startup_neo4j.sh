#!/bin/bash
# Startup script to provision Neo4j under Podman on GCE

echo "Updating system packages..."
apt-get update

echo "Installing Podman..."
apt-get install -y podman

echo "Creating Neo4j directory structure..."
mkdir -p /var/lib/neo4j/data /var/lib/neo4j/logs
chmod -R 777 /var/lib/neo4j

echo "Launching Neo4j container via Podman..."
podman run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/y7r_Ne04j_S0c_gRaph_sEcur3! \
  -v /var/lib/neo4j/data:/data:Z \
  -v /var/lib/neo4j/logs:/logs:Z \
  docker.io/library/neo4j:5.20.0-community

echo "Neo4j container startup sequence triggered."
