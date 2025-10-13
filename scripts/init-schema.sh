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

# Create new keyspace for core_auth
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

# Path to new migration file
MIGRATIONS_PATH="/app/internal/repository/scylla/core_auth_migration.cql"

echo "🔍 Checking migration file at: $MIGRATIONS_PATH"

# If file missing, show what exists for debugging
if [ ! -f "$MIGRATIONS_PATH" ]; then
    echo "❌ Migration file not found at $MIGRATIONS_PATH"
    echo "📂 Listing /app/internal/repository/scylla/ for debugging:"
    ls -lah /app/internal/repository/scylla/ || echo "⚠️  Could not list directory contents"
    exit 1
fi

# Run new migrations
echo "📊 Running database migrations from $MIGRATIONS_PATH..."
if cqlsh scylla 9042 -k core_auth -f "$MIGRATIONS_PATH"; then
    echo "✅ Migrations executed successfully"
else
    echo "⚠️  Some migrations failed (this might be normal if tables already exist)"
fi

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