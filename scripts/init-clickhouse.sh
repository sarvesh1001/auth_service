#!/bin/bash
# ============================================================
# File: scripts/init-clickhouse.sh
# Purpose: Initializes ClickHouse database, tables, and views
# for Auth Service + Kafka Log Event Analytics
# ============================================================

set -e

echo "🔧 Starting ClickHouse initialization..."

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-9000}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

# Build connection string
AUTH_STR=""
if [ -n "$CLICKHOUSE_USER" ]; then
    AUTH_STR="--user $CLICKHOUSE_USER"
    if [ -n "$CLICKHOUSE_PASSWORD" ]; then
        AUTH_STR="$AUTH_STR --password $CLICKHOUSE_PASSWORD"
    fi
fi

# Wait for ClickHouse to be ready with retry logic
echo "⏳ Waiting for ClickHouse to be ready at $CLICKHOUSE_HOST:$CLICKHOUSE_PORT..."
MAX_ATTEMPTS=30
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    if clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --query "SELECT 1" 2>/dev/null; then
        echo "✅ ClickHouse is ready!"
        break
    fi

    echo "   Attempt $ATTEMPT/$MAX_ATTEMPTS..."
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
        echo "❌ Failed to connect to ClickHouse after $MAX_ATTEMPTS attempts"
        exit 1
    fi

    sleep 2
    ATTEMPT=$((ATTEMPT + 1))
done

# Create database and tables
echo "🏗️ Creating database and tables..."
clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --multiquery <<'EOL'

-- ========================================================================
-- DATABASE SETUP
-- ========================================================================

CREATE DATABASE IF NOT EXISTS auth_analytics;

-- ========================================================================
-- KAFKA LOG EVENT TABLES - SIMPLIFIED TO MATCH ACTUAL USAGE
-- ========================================================================

CREATE TABLE IF NOT EXISTS auth_analytics.otp_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    user_id String,
    phone_number String,
    status String,
    attempt_number UInt32,
    attempts_left UInt32,
    error_code Nullable(String),
    error_message Nullable(String),
    ip_address Nullable(String),
    device_id Nullable(String),
    purpose Nullable(String),
    otp_provider Nullable(String),
    duration_ms UInt64,
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id, status)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS auth_analytics.mpin_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    user_id String,
    status String,
    attempts UInt32,
    attempts_left UInt32,
    is_locked UInt8,
    error_code Nullable(String),
    error_message Nullable(String),
    device_id Nullable(String),
    device_trust Nullable(String),
    failure_reason Nullable(String),
    duration_ms UInt64,
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id, status)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS auth_analytics.security_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    user_id String,
    event_category String,
    severity String,
    ip_address String,
    device_id String,
    action String,
    risk_score Float64,
    reason Nullable(String),
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, user_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS auth_analytics.admin_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    admin_id String,
    admin_role String,
    target_user_id Nullable(String),
    action String,
    resource_type String,
    resource_id Nullable(String),
    status String,
    error_code Nullable(String),
    duration_ms UInt64,
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, admin_id, action)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS auth_analytics.session_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    user_id String,
    session_id String,
    status String,
    device_id String,
    ip_address String,
    session_type String,
    ttl_seconds UInt64,
    error_code Nullable(String),
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id, session_id)
TTL timestamp + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS auth_analytics.user_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    user_id String,
    action String,
    phone_number Nullable(String),
    status String,
    device_id Nullable(String),
    error_code Nullable(String),
    duration_ms UInt64,
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id, action)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS auth_analytics.device_events;

CREATE TABLE IF NOT EXISTS auth_analytics.device_events (
    event_id      String,
    event_type    String,
    timestamp     DateTime,
    user_id       String,
    device_id     String,
    action        String,
    status        String,
    bind_token    Nullable(String),
    error_code    Nullable(String),
    error_message Nullable(String),
    ip_address    Nullable(String),
    session_id    Nullable(String),
    duration_ms   UInt64,
    environment   String,
    version       String,
    message       String,
    service_name  String
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_id)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
EOL

echo "✅ Base tables created successfully!"
echo "📊 Creating materialized views..."

clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --multiquery <<'EOL'

-- ✅ SIMPLIFIED: Device events daily summary (no trust analytics since we don't have that data)
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.device_events_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, action, status)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    action,
    status,
    count() AS total_events,
    uniq(device_id) AS unique_devices,
    uniq(user_id) AS unique_users,
    avg(duration_ms) AS avg_duration_ms
FROM auth_analytics.device_events
GROUP BY event_date, action, status;

-- ✅ Device binding success rate
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.device_binding_analytics
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, action)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    action,
    count() AS total_attempts,
    countIf(status = 'success') AS success_count,
    countIf(status = 'failed') AS failure_count,
    uniq(user_id) AS unique_users
FROM auth_analytics.device_events
WHERE action IN ('bind', 'unbind', 'validate')
GROUP BY event_date, action;

-- ✅ IP-based device analytics
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.device_ip_analytics
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, ip_address, action)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    ip_address,
    action,
    status,
    count() AS total_events,
    uniq(user_id) AS unique_users,
    uniq(device_id) AS unique_devices
FROM auth_analytics.device_events
WHERE ip_address != ''
GROUP BY event_date, ip_address, action, status;

EOL

echo "✅ Materialized views created successfully!"
echo ""
echo "📋 Final table count:"
clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --query "
SELECT 
    name as table_name,
    engine
FROM system.tables 
WHERE database = 'auth_analytics'
ORDER BY engine, name
"

echo ""
echo "🎉 ClickHouse initialization completed successfully!"