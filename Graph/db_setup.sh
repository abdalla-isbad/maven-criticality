#!/usr/bin/env bash
set -euo pipefail

DB_NAME="neo4j"
NEO4J_VERSION="5.26.2"
NEO4J_PASSWORD="password"
ZENODO_URL="https://zenodo.org/records/16814371/files/neo4j.dump?download=1"
DUMP_FILE="neo4j.dump"

VOL_DATA="neo4j_data"
VOL_LOGS="neo4j_logs"
VOL_IMPORT="neo4j_import"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }

if [ ! -f "$DUMP_FILE" ]; then
  echo "[INFO] Downloading dump…"
  curl -L "$ZENODO_URL" -o "$DUMP_FILE"
fi

echo "[INFO] Loading dump into volume…"
docker run --rm \
  -v ${VOL_DATA}:/data \
  -v "$(pwd)":/backup \
  neo4j:${NEO4J_VERSION} \
  /var/lib/neo4j/bin/neo4j-admin database load ${DB_NAME} \
  --from-path=/backup --overwrite-destination=true

echo "[INFO] Starting server…"
docker rm -f neo4j >/dev/null 2>&1 || true
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/${NEO4J_PASSWORD} \
  -e NEO4J_PLUGINS='["apoc","graph-data-science"]' \
  -v ${VOL_DATA}:/data \
  -v ${VOL_LOGS}:/logs \
  -v ${VOL_IMPORT}:/import \
  neo4j:${NEO4J_VERSION}

echo "[INFO] Done. Open http://localhost:7474 (neo4j / ${NEO4J_PASSWORD})"

