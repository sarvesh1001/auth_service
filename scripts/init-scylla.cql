-- Initialize ScyllaDB with secure user and keyspace
CREATE KEYSPACE IF NOT EXISTS auth_service 
WITH replication = {
    'class': 'NetworkTopologyStrategy', 
    'replication_factor': 3
} AND durable_writes = true;

CREATE ROLE IF NOT EXISTS auth_admin WITH PASSWORD = '${SCYLLA_PASSWORD}' AND LOGIN = true AND SUPERUSER = false;
GRANT ALL PERMISSIONS ON KEYSPACE auth_service TO auth_admin;

-- Create application user with limited permissions
CREATE ROLE IF NOT EXISTS auth_app WITH PASSWORD = '${SCYLLA_PASSWORD}' AND LOGIN = true AND SUPERUSER = false;
GRANT SELECT, MODIFY ON KEYSPACE auth_service TO auth_app;