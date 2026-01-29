#!/bin/bash
# ===============================================
# File: scripts/init-kafka-topics.sh
# Purpose: Automatically create all required Kafka topics for optimized event distribution
# ===============================================

set -e

echo "🔧 Starting Kafka topics initialization..."

# Configuration from environment or defaults
KAFKA_HOST="${KAFKA_HOST:-kafka}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
KAFKA_BOOTSTRAP_SERVER="${KAFKA_BOOTSTRAP_SERVER:-$KAFKA_HOST:$KAFKA_PORT}"

# Validate configuration
if [ -z "$KAFKA_BOOTSTRAP_SERVER" ]; then
    echo "❌ KAFKA_BOOTSTRAP_SERVER not set"
    exit 1
fi

# Wait for Kafka to become healthy
echo "⏳ Waiting for Kafka to be ready at $KAFKA_BOOTSTRAP_SERVER..."
MAX_ATTEMPTS=30
ATTEMPT=1
while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    if timeout 10s kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" --list > /dev/null 2>&1; then
        echo "✅ Kafka is ready!"
        break
    fi

    echo "   Attempt $ATTEMPT/$MAX_ATTEMPTS..."
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
        echo "❌ Failed to connect to Kafka after $MAX_ATTEMPTS attempts"
        exit 1
    fi

    sleep 2
    ATTEMPT=$((ATTEMPT + 1))
done

# -----------------------------------------------
# SAFE Topic Creation With No Set -e Kill
# -----------------------------------------------
create_topic() {
    set +e  # prevent set -e from killing script inside this function

    local topic=$1
    local partitions=${2:-3}
    local replication_factor=${3:-1}
    local retention_ms=${4:-2592000000}
    local compression=${5:-gzip}

    echo "📝 Creating topic: $topic (partitions=$partitions, retention=${retention_ms}ms)"

    # Check if topic exists
    if timeout 10s kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" --list 2>/dev/null | grep -q "^${topic}$"; then
        echo "   ✅ Topic already exists, skipping"
        set -e
        return 0
    fi

    local retry=0
    local max_retries=3
    
    while [ $retry -lt $max_retries ]; do
        timeout 15s kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" \
            --create \
            --topic "$topic" \
            --partitions "$partitions" \
            --replication-factor "$replication_factor" \
            --config "retention.ms=$retention_ms" \
            --config "compression.type=$compression" \
            --config "cleanup.policy=delete" \
            --config "segment.ms=86400000" \
            --config "min.insync.replicas=1" \
            --config "retention.bytes=-1" \
            --config "max.message.bytes=1048588"

        if [ $? -eq 0 ]; then
            echo "   ✅ Created successfully"
            set -e
            return 0
        fi

        retry=$((retry + 1))
        echo "   ⚠️  Attempt $retry failed, retrying..."
        sleep 3
    done

    echo "   ❌ Failed to create topic $topic after $max_retries attempts"
    set -e
    return 1
}

echo ""
echo "🚀 Creating Kafka topics with optimized event distribution..."
echo ""

# -----------------------------------------------
# Topic definitions
# -----------------------------------------------
declare -A TOPIC_CONFIGS=(
    ["admin-events"]="3 1 15552000000 gzip"
    ["user-events"]="3 1 2592000000 gzip"
    ["session-events"]="3 1 604800000 gzip"
    ["audit-logs"]="3 1 2592000000 gzip"  
    ["device-events"]="3 1 2592000000 gzip"
    ["mpin-events"]="3 1 2592000000 gzip"
    ["otp-events"]="3 1 604800000 gzip"
    ["attendance.events"]="3 1 2592000000 gzip"  # 30 days retention
    ["security-events"]="3 1 7776000000 gzip"
)

FAILED_TOPICS=()

# Create topics
for topic in "${!TOPIC_CONFIGS[@]}"; do
    config=(${TOPIC_CONFIGS[$topic]})
    if ! create_topic "$topic" "${config[0]}" "${config[1]}" "${config[2]}" "${config[3]}"; then
        FAILED_TOPICS+=("$topic")
    fi
    echo ""
done

echo "📊 Verifying topics..."
echo ""

TOPICS=$(timeout 10s kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" --list 2>/dev/null)

ALL_SUCCESS=true

echo "🔍 Elasticsearch Topics:"
for topic in "admin-events" "user-events" "session-events"; do
    if echo "$TOPICS" | grep -q "^${topic}$"; then
        echo "   ✅ $topic"
    else
        echo "   ❌ $topic - MISSING"
        ALL_SUCCESS=false
    fi
done

echo ""
echo "📊 ClickHouse Topics:"
for topic in "device-events" "mpin-events" "otp-events"; do
    if echo "$TOPICS" | grep -q "^${topic}$"; then
        echo "   ✅ $topic"
    else
        echo "   ❌ $topic - MISSING"
        ALL_SUCCESS=false
    fi
done

echo ""
echo "🔄 Dual-Purpose Topics:"
for topic in "security-events"; do
    if echo "$TOPICS" | grep -q "^${topic}$"; then
        echo "   ✅ $topic"
    else
        echo "   ❌ $topic - MISSING"
        ALL_SUCCESS=false
    fi
done

echo ""

# ---------------------------------------------------
# Final Result
# ---------------------------------------------------
if [ "$ALL_SUCCESS" = "true" ]; then
    echo "🎉 All Kafka topics created successfully!"
    exit 0
fi

echo "❌ Some topics failed to create: ${FAILED_TOPICS[*]}"
exit 1
