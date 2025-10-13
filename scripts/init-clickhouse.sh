#!/bin/bash
set -e

echo "🔧 Starting ClickHouse initialization..."

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-9000}"
CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"

# Application user (from .env)
CLICKHOUSE_APP_USER="${CLICKHOUSE_USER:-auth_svc_user}"
CLICKHOUSE_APP_PASSWORD="${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD not set}"

# Wait for ClickHouse to be ready
echo "⏳ Waiting for ClickHouse to be ready..."
for i in $(seq 1 30); do
  if clickhouse-client --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --query "SELECT 1" 2>/dev/null; then
    echo "✅ ClickHouse is ready!"
    break
  fi
  echo "   Attempt $i/30..."
  sleep 2
done

# Create database and tables
echo "🏗️ Creating database and tables..."
clickhouse-client --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --multiquery << EOL
CREATE DATABASE IF NOT EXISTS auth_analytics;

CREATE TABLE IF NOT EXISTS auth_analytics.auth_events (
    event_date Date,
    event_time DateTime64(3),
    user_id UUID,
    event_type String,
    device_id String,
    ip_address String,
    risk_score UInt8,
    session_id UUID,
    processing_time_ms UInt32,
    region String,
    app_version String,
    country_code String,
    user_agent String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, event_type, user_id, device_id)
SETTINGS index_granularity=8192;

CREATE TABLE IF NOT EXISTS auth_analytics.user_behavior (
    event_date Date,
    user_id UUID,
    login_count UInt32,
    failed_attempts UInt32,
    devices Array(String),
    locations Array(String),
    avg_session_minutes Float32,
    last_seen Date,
    total_sessions UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, user_id)
SETTINGS index_granularity=8192;

CREATE TABLE IF NOT EXISTS auth_analytics.fraud_signals (
    detection_time DateTime64(3),
    user_id UUID,
    signal_type String,
    confidence Float32,
    factors Array(String),
    action_taken String,
    severity UInt8
) ENGINE = MergeTree()
ORDER BY (detection_time, signal_type, user_id)
SETTINGS index_granularity=8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.daily_active_users
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date) AS
SELECT event_date, uniqState(user_id) AS active_users
FROM auth_analytics.auth_events
WHERE event_type = 'login_success'
GROUP BY event_date;

CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.user_login_patterns
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (user_id, event_date) AS
SELECT
    user_id,
    event_date,
    count() AS total_logins,
    countIf(event_type = 'login_failed') AS failed_logins,
    uniq(device_id) AS unique_devices,
    uniq(ip_address) AS unique_locations,
    avg(risk_score) AS avg_risk_score
FROM auth_analytics.auth_events
GROUP BY user_id, event_date;

CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.hourly_activity
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, hour) AS
SELECT
    event_date,
    toHour(event_time) AS hour,
    uniqState(user_id) AS active_users,
    countState() AS total_events,
    countIfState(event_type = 'login_success') AS success_logins,
    countIfState(event_type = 'login_failed') AS failed_logins
FROM auth_analytics.auth_events
GROUP BY event_date, hour;

ALTER TABLE auth_analytics.auth_events MODIFY TTL event_date + INTERVAL 90 DAY;
ALTER TABLE auth_analytics.user_behavior MODIFY TTL event_date + INTERVAL 365 DAY;
ALTER TABLE auth_analytics.fraud_signals MODIFY TTL toDateTime(detection_time) + INTERVAL 30 DAY;

SHOW TABLES FROM auth_analytics;
EOL

echo "✅ ClickHouse initialization completed successfully!"
exit 0