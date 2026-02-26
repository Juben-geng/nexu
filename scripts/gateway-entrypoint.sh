#!/bin/sh
set -e

CONFIG_PATH="/etc/openclaw/config.json"
MAX_RETRIES=30
RETRY_INTERVAL=2

: "${NEXU_API_URL:?NEXU_API_URL is required}"
: "${POOL_ID:?POOL_ID is required}"
: "${GATEWAY_TOKEN:?GATEWAY_TOKEN is required}"

# Fetch config from Nexu API with retries
echo "Fetching config from ${NEXU_API_URL}/api/internal/pools/${POOL_ID}/config ..."
attempt=0
while [ "$attempt" -lt "$MAX_RETRIES" ]; do
  status=$(curl -s -o "$CONFIG_PATH" -w "%{http_code}" \
    -H "Authorization: Bearer ${GATEWAY_TOKEN}" \
    "${NEXU_API_URL}/api/internal/pools/${POOL_ID}/config")

  if [ "$status" = "200" ]; then
    echo "Config fetched successfully."
    break
  fi

  attempt=$((attempt + 1))
  echo "Attempt ${attempt}/${MAX_RETRIES} failed (HTTP ${status}). Retrying in ${RETRY_INTERVAL}s..."
  sleep "$RETRY_INTERVAL"
done

if [ "$attempt" -ge "$MAX_RETRIES" ]; then
  echo "ERROR: Failed to fetch config after ${MAX_RETRIES} attempts."
  exit 1
fi

# Register Pod IP with Nexu API
POD_IP="${POD_IP:-$(hostname -i)}"
echo "Registering Pod IP ${POD_IP} for pool ${POOL_ID}..."
reg_status=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PATCH \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${GATEWAY_TOKEN}" \
  -d "{\"podIp\":\"${POD_IP}\",\"status\":\"active\"}" \
  "${NEXU_API_URL}/api/internal/pools/${POOL_ID}")

if [ "$reg_status" = "200" ]; then
  echo "Pod IP registered successfully."
else
  echo "WARNING: Pod IP registration returned HTTP ${reg_status} (non-fatal)."
fi

# Set config path and start gateway
export OPENCLAW_CONFIG_PATH="$CONFIG_PATH"
echo "Starting OpenClaw gateway on port 18789..."
exec openclaw gateway run --bind lan --port 18789 --allow-unconfigured
