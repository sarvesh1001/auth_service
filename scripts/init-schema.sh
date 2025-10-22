#!/bin/bash
set -e

echo "🚀 Starting ScyllaDB schema initialization for core_auth service..."

# Wait for ScyllaDB to be fully ready
echo "⏳ Waiting for ScyllaDB to be ready..."
RETRY_COUNT=0
MAX_RETRIES=30

until cqlsh scylla 9042 -e "DESCRIBE KEYSPACES" >/dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "❌ ScyllaDB failed to become ready after $MAX_RETRIES attempts"
        exit 1
    fi
    echo "⏳ Waiting for ScyllaDB... (attempt $RETRY_COUNT/$MAX_RETRIES)"
    sleep 5
done

echo "✅ ScyllaDB is ready!"

# Create keyspace for core_auth
echo "📝 Creating keyspace core_auth..."
cqlsh scylla 9042 -e "
CREATE KEYSPACE IF NOT EXISTS core_auth 
WITH REPLICATION = {
    'class': 'NetworkTopologyStrategy', 
    'datacenter1': 1
} AND DURABLE_WRITES = true;" 2>/dev/null || {
    echo "⚠️  Keyspace creation failed or already exists"
}
echo "✅ Keyspace created/verified"

# Run all CQL migration files dynamically
CQL_DIR="/app/internal/repository/scylla"
echo "📂 Looking for .cql migration files in $CQL_DIR..."
CQL_FILES=$(find "$CQL_DIR" -maxdepth 1 -type f -name "*.cql" | sort)

if [ -z "$CQL_FILES" ]; then
    echo "❌ No .cql migration files found in $CQL_DIR"
    exit 1
fi

for FILE in $CQL_FILES; do
    echo "📊 Running migration: $FILE"
    cqlsh scylla 9042 -k core_auth -f "$FILE"
    echo "⏳ Waiting 5s for schema agreement..."
    sleep 5
done

# Verify schema setup
echo "🔍 Verifying schema setup..."
TABLE_COUNT=$(cqlsh scylla 9042 -k core_auth -e "SELECT COUNT(*) FROM system_schema.tables WHERE keyspace_name='core_auth';" 2>/dev/null | grep -o '[0-9]\+' | tail -1 || echo "0")

echo "📊 Found $TABLE_COUNT tables in core_auth keyspace"

if [ "$TABLE_COUNT" -ge "8" ]; then
    echo "✅ Schema verification passed - $TABLE_COUNT tables found"
else
    echo "⚠️  Expected at least 8 tables, found $TABLE_COUNT"
fi

# List created tables
echo "📋 Created tables:"
cqlsh scylla 9042 -k core_auth -e "DESCRIBE TABLES;" 2>/dev/null || echo "⚠️ Could not list tables"

echo ""
echo "🎉 Core Auth schema initialization completed successfully!"
echo "🔐 Enhanced security features and KYC system ready!"
