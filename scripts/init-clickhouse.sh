#!/bin/bash
# ============================================================
# File: scripts/init-clickhouse.sh
# Purpose: Initializes ClickHouse database for Time-Series Analytics only
# ✅ OPTIMIZED: Only time-series events (Device, MPIN, OTP, Security)
# ✅ FIXED: Removed UNION from materialized views (not supported)
# ✅ FIXED: Corrected port variable, improved timeout handling
# ✅ FIXED: Corrected system.tables query for ClickHouse 24.8
# ============================================================

set -e

echo "🔧 Starting ClickHouse initialization for time-series analytics..."

# Use environment variables with proper defaults
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-9000}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

echo "📋 Connection details: $CLICKHOUSE_HOST:$CLICKHOUSE_PORT (user: $CLICKHOUSE_USER)"

# Build connection string
AUTH_STR=""
if [ -n "$CLICKHOUSE_USER" ]; then
    AUTH_STR="--user $CLICKHOUSE_USER"
    if [ -n "$CLICKHOUSE_PASSWORD" ]; then
        AUTH_STR="$AUTH_STR --password $CLICKHOUSE_PASSWORD"
    fi
fi

# Wait for ClickHouse to be ready with improved retry logic
echo "⏳ Waiting for ClickHouse to be ready at $CLICKHOUSE_HOST:$CLICKHOUSE_PORT..."
MAX_ATTEMPTS=60
ATTEMPT=1
RETRY_INTERVAL=2

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    if clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --query "SELECT 1" 2>/dev/null; then
        echo "✅ ClickHouse is ready!"
        break
    fi

    ELAPSED=$((ATTEMPT * RETRY_INTERVAL))
    echo "   Attempt $ATTEMPT/$MAX_ATTEMPTS (${ELAPSED}s elapsed)..."
    
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
        echo ""
        echo "❌ Failed to connect to ClickHouse after $MAX_ATTEMPTS attempts"
        echo "🔍 Troubleshooting:"
        echo "   • Check ClickHouse logs: docker logs clickhouse-dev"
        echo "   • Verify host/port: $CLICKHOUSE_HOST:$CLICKHOUSE_PORT"
        exit 1
    fi

    sleep $RETRY_INTERVAL
    ATTEMPT=$((ATTEMPT + 1))
done

# Create database and tables
echo "🏗️ Creating database and time-series tables..."
clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --multiquery <<'EOL'

-- ========================================================================
-- DATABASE SETUP
-- ========================================================================

CREATE DATABASE IF NOT EXISTS auth_analytics;

-- ========================================================================
-- TIME-SERIES EVENT TABLES (ClickHouse Only)
-- ✅ OPTIMIZED: Only time-series events for analytics
-- ========================================================================

-- 📊 Device Events - Device metrics, binding trends
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
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, user_id, device_id)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- 🔐 MPIN Events - Authentication patterns, success rates
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

-- 📱 OTP Events - Delivery metrics, verification trends
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

-- 🛡️ Security Events - Real-time fraud detection
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

EOL

echo "✅ Time-series tables created successfully!"
echo "📊 Creating analytics views..."

clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --multiquery <<'EOL'

-- ========================================================================
-- ANALYTICS VIEWS FOR TIME-SERIES DATA
-- ✅ FIXED: Removed UNION (not supported in materialized views)
-- ========================================================================

-- 📊 Device Analytics - Daily aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.device_events_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, action, status)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    'device' AS event_type,
    action,
    status,
    count() AS total_events,
    uniq(device_id) AS unique_devices,
    uniq(user_id) AS unique_users,
    avg(duration_ms) AS avg_duration_ms
FROM auth_analytics.device_events
GROUP BY event_date, action, status;

-- 🔐 MPIN Analytics - Daily aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.mpin_events_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, status)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    'mpin' AS event_type,
    status,
    count() AS total_attempts,
    countIf(status = 'success') AS success_count,
    countIf(status = 'failed') AS failure_count,
    avg(duration_ms) AS avg_duration_ms,
    uniq(user_id) AS unique_users
FROM auth_analytics.mpin_events
GROUP BY event_date, status;

-- 📱 OTP Analytics - Daily aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.otp_events_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, status, purpose)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    'otp' AS event_type,
    status,
    purpose,
    count() AS total_events,
    countIf(status = 'success') AS success_count,
    countIf(status = 'failed') AS failure_count,
    avg(duration_ms) AS avg_duration_ms,
    uniq(user_id) AS unique_users
FROM auth_analytics.otp_events
GROUP BY event_date, status, purpose;

-- 🛡️ Security Analytics - Daily aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS auth_analytics.security_events_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, severity, event_category)
SETTINGS allow_nullable_key = 1 AS
SELECT
    toDate(timestamp) AS event_date,
    'security' AS event_type,
    severity,
    event_category,
    count() AS total_events,
    avg(risk_score) AS avg_risk_score,
    uniq(user_id) AS affected_users,
    uniq(ip_address) AS unique_ips
FROM auth_analytics.security_events
GROUP BY event_date, severity, event_category;

-- ========================================================================
-- UTILITY VIEWS FOR CROSS-EVENT QUERIES (NOT MATERIALIZED)
-- ✅ Use regular views for UNION queries
-- ========================================================================

-- 📈 Cross-Event Analytics (Regular View - NOT materialized)
CREATE VIEW IF NOT EXISTS auth_analytics.all_events_daily AS
SELECT
    event_date,
    event_type,
    total_events,
    unique_users,
    unique_devices
FROM (
    SELECT
        event_date,
        event_type,
        sum(total_events) AS total_events,
        sum(unique_users) AS unique_users,
        sum(unique_devices) AS unique_devices
    FROM auth_analytics.device_events_daily
    GROUP BY event_date, event_type
    
    UNION ALL
    
    SELECT
        event_date,
        event_type,
        sum(total_attempts) AS total_events,
        sum(unique_users) AS unique_users,
        0 AS unique_devices
    FROM auth_analytics.mpin_events_daily
    GROUP BY event_date, event_type
    
    UNION ALL
    
    SELECT
        event_date,
        event_type,
        sum(total_events) AS total_events,
        sum(unique_users) AS unique_users,
        0 AS unique_devices
    FROM auth_analytics.otp_events_daily
    GROUP BY event_date, event_type
    
    UNION ALL
    
    SELECT
        event_date,
        event_type,
        sum(total_events) AS total_events,
        sum(affected_users) AS unique_users,
        0 AS unique_devices
    FROM auth_analytics.security_events_daily
    GROUP BY event_date, event_type
);

-- 📊 Hourly Aggregation View (Regular View)
CREATE VIEW IF NOT EXISTS auth_analytics.events_hourly AS
SELECT
    toStartOfHour(timestamp) AS hour,
    event_type,
    count() AS total_events,
    uniq(user_id) AS unique_users,
    avg(duration_ms) AS avg_duration_ms
FROM (
    SELECT timestamp, 'device' AS event_type, user_id, duration_ms FROM auth_analytics.device_events
    UNION ALL
    SELECT timestamp, 'mpin' AS event_type, user_id, duration_ms FROM auth_analytics.mpin_events
    UNION ALL
    SELECT timestamp, 'otp' AS event_type, user_id, duration_ms FROM auth_analytics.otp_events
    UNION ALL
    SELECT timestamp, 'security' AS event_type, user_id, 0 AS duration_ms FROM auth_analytics.security_events
)
GROUP BY hour, event_type;

EOL

echo "✅ Analytics views created successfully!"
echo ""
echo "📋 Verifying tables and views..."
clickhouse-client $AUTH_STR --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --query "
SELECT 
    name as object_name,
    engine
FROM system.tables 
WHERE database = 'auth_analytics'
ORDER BY engine, name
"

echo ""
echo "🎉 ClickHouse time-series analytics initialization completed successfully!"
echo ""
echo "✅ Summary:"
echo "   • Device, MPIN, OTP, Security event tables created"
echo "   • Materialized views created for daily aggregations:"
echo "     - device_events_daily"
echo "     - mpin_events_daily"
echo "     - otp_events_daily"
echo "     - security_events_daily"
echo "   • Regular views for cross-event analytics:"
echo "     - all_events_daily"
echo "     - events_hourly"
echo "   • 30-day TTL for most events, 90-day for security events"
echo ""
echo "📝 Sample Queries:"
echo "   clickhouse-client -u auth_svc_user -p <password> << 'SQL'"
echo "   SELECT * FROM auth_analytics.device_events_daily LIMIT 10;"
echo "   SELECT event_date, event_type, total_events FROM auth_analytics.all_events_daily WHERE event_date = today();"
echo "   SQL"
