#!/bin/bash
# Startup script to provision Neo4j under Podman on GCE

echo "Updating system packages..."
apt-get update

echo "Installing Podman..."
apt-get install -y podman

echo "Creating Neo4j directory structure..."
mkdir -p /var/lib/neo4j/data /var/lib/neo4j/logs
# Official neo4j image runs as uid/gid 7474; scope permissions to that user
# instead of world-writable (chmod 777 let any local process modify the DB).
chown -R 7474:7474 /var/lib/neo4j
chmod -R 750 /var/lib/neo4j

echo "Retrieving Neo4j password from GCE metadata server..."
NEO4J_PASSWORD=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/neo4j-password" -H "Metadata-Flavor: Google")

if [ -z "$NEO4J_PASSWORD" ]; then
  echo "Error: Neo4j password not found in GCE metadata. Exiting."
  exit 1
fi

echo "Launching Neo4j container via Podman..."
podman run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
  -v /var/lib/neo4j/data:/data:Z \
  -v /var/lib/neo4j/logs:/logs:Z \
  docker.io/library/neo4j:5.20.0-community

echo "Neo4j container startup sequence triggered."
