#!/bin/bash
# ===============================================
# File: scripts/init-kafka-topics.sh
# Purpose: Create only the Kafka topics actually used
#          after consolidating all academic events
#          into "academics-events" and adding inventory.
# ===============================================

set -e

echo "🔧 Starting Kafka topics initialization..."

# -----------------------------------------------
# Configuration
# -----------------------------------------------
KAFKA_HOST="${KAFKA_HOST:-kafka}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
KAFKA_BOOTSTRAP_SERVER="${KAFKA_BOOTSTRAP_SERVER:-$KAFKA_HOST:$KAFKA_PORT}"

if [ -z "$KAFKA_BOOTSTRAP_SERVER" ]; then
    echo "❌ KAFKA_BOOTSTRAP_SERVER not set"
    exit 1
fi

# -----------------------------------------------
# Wait for Kafka
# -----------------------------------------------
echo "⏳ Waiting for Kafka at $KAFKA_BOOTSTRAP_SERVER..."
MAX_ATTEMPTS=30
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    if timeout 10s kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" --list > /dev/null 2>&1; then
        echo "✅ Kafka is ready!"
        break
    fi

    echo "   Attempt $ATTEMPT/$MAX_ATTEMPTS..."
    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
        echo "❌ Kafka not reachable"
        exit 1
    fi

    sleep 2
    ATTEMPT=$((ATTEMPT + 1))
done

# -----------------------------------------------
# Topic creation helper
# -----------------------------------------------
create_topic() {
    set +e

    local topic=$1
    local partitions=${2:-3}
    local replication_factor=${3:-1}
    local retention_ms=${4:-2592000000}
    local compression=${5:-gzip}

    echo "📝 Creating topic: $topic"

    if kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" --list | grep -q "^${topic}$"; then
        echo "   ✅ Already exists"
        set -e
        return 0
    fi

    kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" \
        --create \
        --topic "$topic" \
        --partitions "$partitions" \
        --replication-factor "$replication_factor" \
        --config "retention.ms=$retention_ms" \
        --config "compression.type=$compression" \
        --config "cleanup.policy=delete" \
        --config "segment.ms=86400000" \
        --config "min.insync.replicas=1"

    if [ $? -eq 0 ]; then
        echo "   ✅ Created"
    else
        echo "   ❌ Failed"
    fi

    set -e
}

echo ""
echo "🚀 Creating Kafka topics..."
echo ""

# -----------------------------------------------
# Topic definitions – only what's actually used
# -----------------------------------------------
declare -A TOPIC_CONFIGS=(

    # Core platform events (used by ES & ClickHouse consumers)
    ["admin-events"]="3 1 15552000000 gzip"
    ["user-events"]="3 1 2592000000 gzip"
    ["session-events"]="3 1 604800000 gzip"

    # Single unified topic for ALL academic events
    ["academics-events"]="3 1 2592000000 gzip"

    # Accounting module (separate, not part of academics)
    ["accounting-events"]="3 1 2592000000 gzip"

    # Inventory module (new)
    ["inventory-events"]="3 1 2592000000 gzip"

    # Time‑series / analytics events (consumed by ClickHouse)
    ["device-events"]="3 1 2592000000 gzip"
    ["mpin-events"]="3 1 2592000000 gzip"
    ["otp-events"]="3 1 604800000 gzip"

    # Security audit (consumed by both ES and ClickHouse)
    ["security-events"]="3 1 7776000000 gzip"

    # Audit logs (optional, can be removed if not used)
    ["audit-logs"]="3 1 2592000000 gzip"

    # Dead Letter Queues
    ["academics-events.dlq"]="3 1 604800000 gzip"
    ["accounting-events.dlq"]="3 1 604800000 gzip"
    ["inventory-events.dlq"]="3 1 604800000 gzip"
)

FAILED_TOPICS=()

# -----------------------------------------------
# Create topics
# -----------------------------------------------
for topic in "${!TOPIC_CONFIGS[@]}"; do
    config=(${TOPIC_CONFIGS[$topic]})
    if ! create_topic "$topic" "${config[0]}" "${config[1]}" "${config[2]}" "${config[3]}"; then
        FAILED_TOPICS+=("$topic")
    fi
    echo ""
done

# -----------------------------------------------
# Verification
# -----------------------------------------------
echo "📊 Verifying topics..."
echo ""

TOPICS=$(kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP_SERVER" --list)

ALL_SUCCESS=true

check_topic() {
    if echo "$TOPICS" | grep -q "^$1$"; then
        echo "   ✅ $1"
    else
        echo "   ❌ $1"
        ALL_SUCCESS=false
    fi
}

echo "🔍 Core Topics:"
check_topic "admin-events"
check_topic "user-events"
check_topic "session-events"

echo ""
echo "🎓 Unified Academics:"
check_topic "academics-events"

echo ""
echo "📊 Accounting:"
check_topic "accounting-events"

echo ""
echo "📦 Inventory:"
check_topic "inventory-events"

echo ""
echo "📈 Time‑Series / Analytics:"
for t in "device-events" "mpin-events" "otp-events" "security-events" "audit-logs"; do check_topic $t; done

echo ""
echo "⚠️ DLQ Topics:"
check_topic "academics-events.dlq"
check_topic "accounting-events.dlq"
check_topic "inventory-events.dlq"

echo ""

# -----------------------------------------------
# Final Result
# -----------------------------------------------
if [ "$ALL_SUCCESS" = true ]; then
    echo "🎉 All Kafka topics created successfully!"
    exit 0
fi

echo "❌ Some topics failed: ${FAILED_TOPICS[*]}"
exit 1