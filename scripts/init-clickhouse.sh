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
-- LEGACY AUTH TABLES
-- ========================================================================

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
TTL event_date + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

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
TTL event_date + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS auth_analytics.fraud_signals (
    detection_time DateTime,
    user_id UUID,
    signal_type String,
    confidence Float32,
    factors Array(String),
    action_taken String,
    severity UInt8
) ENGINE = MergeTree()
ORDER BY (detection_time, signal_type, user_id)
PARTITION BY toYYYYMM(detection_time)
TTL detection_time + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ========================================================================
-- KAFKA LOG EVENT TABLES
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

CREATE TABLE IF NOT EXISTS auth_analytics.device_events (
    event_id String,
    event_type String,
    timestamp DateTime,
    user_id String,
    device_id String,
    device_fingerprint String,
    device_type Nullable(String),
    device_os Nullable(String),
    device_browser Nullable(String),
    device_manufacturer Nullable(String),
    device_model Nullable(String),
    action String,
    status String,
    trust_level String,
    ip_address Nullable(String),
    location Nullable(String),
    user_agent Nullable(String),
    is_trusted UInt8,
    trust_expiry DateTime NULL,
    error_code Nullable(String),
    error_message Nullable(String),
    duration_ms UInt64,
    environment String,
    version String,
    message String,
    service_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id, device_id, action)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

EOL

echo "✅ Base tables created successfully!"
echo "📊 Creating materialized views..."

clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --multiquery <<'EOL'

-- (all other materialized views same as before...)

-- ✅ FIXED: Device Trust Analytics View (nullable key error fixed)
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.device_trust_analytics
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, device_type, trust_level)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    device_type,
    trust_level,
    count() AS total_events,
    countIf(action = 'trusted') AS trust_actions,
    countIf(action = 'untrusted') AS untrust_actions,
    countIf(is_trusted = 1) AS currently_trusted,
    uniq(device_id) AS unique_devices
FROM auth_analytics.device_events
GROUP BY event_date, device_type, trust_level;

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
