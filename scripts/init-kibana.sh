#!/bin/bash
set -e

KIBANA_HOST="${KIBANA_URL:-http://kibana:5601}"
IMPORT_FILE="/kibana-export/export.ndjson"

KIBANA_USER="${KIBANA_USER:-kibana_system}"
KIBANA_PASSWORD="${KIBANA_PASSWORD:-ElsticSecure2026}"

echo "⏳ Waiting for Kibana at $KIBANA_HOST..."
until curl -s "${KIBANA_HOST}/api/status" | grep -q '"overall":{"level":"available"'; do
  sleep 2
done
echo "✅ Kibana is ready."

if [ -f "$IMPORT_FILE" ]; then
  echo "📥 Importing saved objects..."
  curl -X POST "${KIBANA_HOST}/api/saved_objects/_import?overwrite=true" \
    -u "${KIBANA_USER}:${KIBANA_PASSWORD}" \
    -H "kbn-xsrf: true" \
    --form file="@${IMPORT_FILE}"
  echo "✅ Kibana import completed."
else
  echo "⚠️ No export.ndjson found – skipping import."
fi