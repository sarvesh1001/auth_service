#!/bin/bash
set -e

ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-elasticsearch}"
ELASTICSEARCH_URL="http://${ELASTICSEARCH_HOST}:9200"

echo "⏳ Waiting for Elasticsearch at ${ELASTICSEARCH_URL}..."

until curl -s -u "elastic:${ELASTICSEARCH_PASSWORD}" "${ELASTICSEARCH_URL}/_cluster/health" > /dev/null; do
  sleep 2
done
echo "✅ Elasticsearch is healthy."

# Set kibana_system password
echo "🔑 Setting kibana_system password..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -u "elastic:${ELASTICSEARCH_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -d "{\"password\": \"${KIBANA_SYSTEM_PASSWORD}\"}" \
  "${ELASTICSEARCH_URL}/_security/user/kibana_system/_password")

if [ "$RESPONSE" -eq 200 ]; then
  echo "✅ kibana_system password set successfully."
else
  echo "⚠️ Password may already be set or user exists. Response code: $RESPONSE"
fi

# Create dedicated user for Kibana import
echo "🔑 Creating kibana_import user..."
IMPORT_USER="${KIBANA_IMPORT_USER:-kibana_import}"
IMPORT_PASSWORD="${KIBANA_IMPORT_PASSWORD:-ImportSecure2026}"
curl -X POST -u "elastic:${ELASTICSEARCH_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"${IMPORT_PASSWORD}\",\"roles\":[\"kibana_admin\"]}" \
  "${ELASTICSEARCH_URL}/_security/user/${IMPORT_USER}" || echo "User may already exist."

echo "✅ Elasticsearch init completed."