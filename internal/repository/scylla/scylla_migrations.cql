-- ScyllaDB Schema for Auth Service (500M+ Users Scale)
-- Optimized for high performance with proper partitioning strategies

-- ================== KEYSPACE CREATION ==================
-- Create keyspace with NetworkTopologyStrategy for production
-- Adjust replication factor based on cluster size
-- CREATE KEYSPACE IF NOT EXISTS auth_service 
-- WITH REPLICATION = {
--   'class': 'NetworkTopologyStrategy',
--   'datacenter1': 3
-- } AND DURABLE_WRITES = true;

-- USE auth_service;

-- ================== USERS TABLE ==================
-- Partition by phone_number for even distribution across nodes
-- Secondary index on user_id for fast lookups
CREATE TABLE IF NOT EXISTS users (
    phone_number text,          -- Partition key - ensures even distribution
    user_id uuid,               -- Clustering key for uniqueness
    country_code text,
    device_id text,
    mpin_hash text,
    is_verified boolean,
    is_active boolean,
    last_login_at timestamp,
    created_at timestamp,
    updated_at timestamp,
    last_login_ip text,
    last_login_city text,
    PRIMARY KEY (phone_number, user_id)
) WITH CLUSTERING ORDER BY (user_id ASC)
  AND comment = 'User accounts with phone as partition key for even distribution'
  AND compaction = {
    'class': 'LeveledCompactionStrategy',
    'sstable_size_in_mb': 160
  }
  AND compression = {
    'sstable_compression': 'LZ4Compressor'
  };

-- Secondary index on user_id for reverse lookups
CREATE INDEX IF NOT EXISTS idx_users_user_id ON users (user_id);
CREATE INDEX IF NOT EXISTS idx_users_device_id ON users (device_id);
CREATE INDEX IF NOT EXISTS idx_users_active ON users (is_active);

-- ================== USERS BY ID TABLE ==================
-- Materialized view for fast user_id lookups
-- This eliminates the need for secondary index performance issues
CREATE TABLE IF NOT EXISTS users_by_id (
    user_id uuid,
    phone_number text,
    country_code text,
    device_id text,
    mpin_hash text,
    is_verified boolean,
    is_active boolean,
    last_login_at timestamp,
    created_at timestamp,
    updated_at timestamp,
    last_login_ip text,
    last_login_city text,
    PRIMARY KEY (user_id)
) WITH comment = 'Users indexed by user_id for fast lookups'
  AND compaction = {
    'class': 'LeveledCompactionStrategy',
    'sstable_size_in_mb': 160
  }
  AND compression = {
    'sstable_compression': 'LZ4Compressor'
  };

-- ================== OTP TABLE ==================
-- Partition by phone_number with time-based clustering for TTL
-- Short TTL for automatic cleanup
CREATE TABLE IF NOT EXISTS otps (
    phone_number text,          -- Partition key
    otp_id uuid,               -- Clustering key
    otp_hash text,
    expires_at timestamp,
    attempt_count int,
    is_used boolean,
    device_id text,
    created_at timestamp,
    PRIMARY KEY (phone_number, otp_id)
) WITH CLUSTERING ORDER BY (otp_id DESC)
  AND comment = 'OTP storage with automatic expiry'
  AND default_time_to_live = 900  -- 15 minutes TTL
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'MINUTES',
    'compaction_window_size': 30
  }
  AND compression = {
    'sstable_compression': 'LZ4Compressor'
  };

-- Index for cleanup operations
CREATE INDEX IF NOT EXISTS idx_otps_expires_at ON otps (expires_at);

-- ================== MPIN TABLE ==================
-- Partition by user_id for direct access
CREATE TABLE IF NOT EXISTS mpins (
    user_id uuid,
    mpin_hash text,
    last_changed timestamp,
    is_blocked boolean,
    retry_count int,
    updated_at timestamp,
    PRIMARY KEY (user_id)
) WITH comment = 'MPIN storage per user'
  AND compaction = {
    'class': 'LeveledCompactionStrategy',
    'sstable_size_in_mb': 160
  }
  AND compression = {
    'sstable_compression': 'LZ4Compressor'
  };

-- ================== DEVICE SESSIONS TABLE ==================
-- Partition by user_id with session_id as clustering key
-- Allows multiple sessions per user with efficient queries
CREATE TABLE IF NOT EXISTS device_sessions (
    user_id uuid,              -- Partition key
    session_id uuid,           -- Clustering key
    device_id text,
    is_active boolean,
    auth_token text,
    created_at timestamp,
    last_accessed timestamp,
    revoked_reason text,
    PRIMARY KEY (user_id, session_id)
) WITH CLUSTERING ORDER BY (session_id DESC)
  AND comment = 'Device sessions per user'
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'DAYS',
    'compaction_window_size': 7
  }
  AND compression = {
    'sstable_compression': 'LZ4Compressor'
  };

-- Index for session management queries
CREATE INDEX IF NOT EXISTS idx_device_sessions_active ON device_sessions (is_active);
CREATE INDEX IF NOT EXISTS idx_device_sessions_device_id ON device_sessions (device_id);

-- ================== SESSIONS BY ID TABLE ==================
-- Fast session lookup by session_id
CREATE TABLE IF NOT EXISTS sessions_by_id (
    session_id uuid,
    user_id uuid,
    device_id text,
    is_active boolean,
    auth_token text,
    created_at timestamp,
    last_accessed timestamp,
    revoked_reason text,
    PRIMARY KEY (session_id)
) WITH comment = 'Sessions indexed by session_id for fast lookups'
  AND compaction = {
    'class': 'LeveledCompactionStrategy',
    'sstable_size_in_mb': 160
  }
  AND compression = {
    'sstable_compression': 'LZ4Compressor'
  };

-- ================== AUDIT TABLES FOR COMPLIANCE ==================
-- Login attempts audit table
CREATE TABLE IF NOT EXISTS login_attempts (
    phone_number text,
    attempt_id uuid,
    ip_address text,
    user_agent text,
    success boolean,
    failure_reason text,
    device_id text,
    location text,
    attempted_at timestamp,
    PRIMARY KEY (phone_number, attempted_at, attempt_id)
) WITH CLUSTERING ORDER BY (attempted_at DESC)
  AND comment = 'Login attempts audit trail'
  AND default_time_to_live = 7776000  -- 90 days
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'DAYS',
    'compaction_window_size': 1
  };

-- User activity audit
CREATE TABLE IF NOT EXISTS user_activity (
    user_id uuid,
    activity_id uuid,
    activity_type text,        -- LOGIN, LOGOUT, OTP_REQUEST, MPIN_CHANGE, etc.
    ip_address text,
    device_id text,
    metadata map<text, text>,  -- Additional contextual data
    created_at timestamp,
    PRIMARY KEY (user_id, created_at, activity_id)
) WITH CLUSTERING ORDER BY (created_at DESC)
  AND comment = 'User activity audit trail'
  AND default_time_to_live = 31536000  -- 1 year
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'DAYS',
    'compaction_window_size': 7
  };

-- ================== PERFORMANCE OPTIMIZATION TABLES ==================
-- Phone number to user_id mapping for fast reverse lookups
CREATE TABLE IF NOT EXISTS phone_to_user (
    phone_number text,
    user_id uuid,
    PRIMARY KEY (phone_number)
) WITH comment = 'Fast phone to user_id mapping'
  AND compaction = {
    'class': 'LeveledCompactionStrategy'
  };

-- Active sessions counter per user (for session limits)
CREATE TABLE IF NOT EXISTS user_session_count (
    user_id uuid,
    active_sessions counter,
    PRIMARY KEY (user_id)
) WITH comment = 'Track active session count per user';

-- ================== RATE LIMITING TABLES ==================
-- Rate limiting buckets
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key text,           -- e.g., "otp:+919876543210", "login:192.168.1.1"
    window_start timestamp,    -- Rate limit window start
    request_count counter,
    PRIMARY KEY (bucket_key, window_start)
) WITH CLUSTERING ORDER BY (window_start DESC)
  AND comment = 'Rate limiting buckets'
  AND default_time_to_live = 3600  -- 1 hour
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'MINUTES',
    'compaction_window_size': 60
  };

-- ================== ADDITIONAL INDEXES ==================
-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_users_country_active ON users (country_code, is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_device_active ON device_sessions (device_id, is_active);

-- Time-based indexes for cleanup operations
CREATE INDEX IF NOT EXISTS idx_device_sessions_last_accessed ON device_sessions (last_accessed);
CREATE INDEX IF NOT EXISTS idx_otps_created_at ON otps (created_at);

-- Security indexes
CREATE INDEX IF NOT EXISTS idx_mpins_blocked ON mpins (is_blocked);
CREATE INDEX IF NOT EXISTS idx_users_verification ON users (is_verified);
