-- =========================================================
-- CORE AUTH BASE TABLES (Scylla-Compatible)
-- =========================================================

-- ===============================
-- Keyspace
-- ===============================
CREATE KEYSPACE IF NOT EXISTS core_auth WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'datacenter1': 3
} AND DURABLE_WRITES = true;

USE core_auth;

-- ===============================
-- USERS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS users (
    user_bucket int,
    user_id uuid,
    phone_hash text,
    phone_encrypted blob,
    phone_key_id uuid,
    phone_encrypted_dek text,
    device_id text,
    device_fingerprint text,
    kyc_status text,
    kyc_level text,
    kyc_verified_at timestamp,
    kyc_verified_by uuid,
    profile_service_id uuid,
    is_verified boolean,
    is_blocked boolean,
    is_banned boolean,
    banned_by uuid,
    banned_reason text,
    banned_at timestamp,
    created_at timestamp,
    last_login timestamp,
    updated_at timestamp,
    consent_agreed boolean,
    consent_version text,
    data_region text,
    PRIMARY KEY ((user_bucket), user_id)
) WITH compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': 1,
    'compaction_window_unit': 'DAYS'
} AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- PHONE TO USER TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS phone_to_user (
    phone_hash text,
    user_bucket int,
    user_id uuid,
    created_at timestamp,
    PRIMARY KEY (phone_hash)
) WITH compaction = {'class': 'LeveledCompactionStrategy'}
AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- OTP VERIFICATIONS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS otp_verifications (
    phone_hash text,
    purpose text,
    time_bucket bigint,
    created_at timestamp,
    otp_hash text,
    otp_salt text,
    hash_algorithm text,
    pepper_version int,
    attempts int,
    expires_at timestamp,
    ip_address inet,
    provider_used text,
    PRIMARY KEY ((phone_hash, purpose, time_bucket), created_at)
) WITH CLUSTERING ORDER BY (created_at DESC)
AND default_time_to_live = 300
AND gc_grace_seconds = 3600
AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': 1,
    'compaction_window_unit': 'HOURS'
};

-- ===============================
-- USER ACTIVE DEVICE TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS user_active_device (
    user_id uuid,
    device_id text,
    session_id uuid,
    bound_at timestamp,
    bind_token text,
    PRIMARY KEY (user_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ===============================
-- ACTIVE SESSIONS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS active_sessions (
    user_id uuid,
    session_token text,
    device_id text,
    device_fingerprint text,
    kyc_verified boolean,
    created_at timestamp,
    last_activity timestamp,
    expires_at timestamp,
    ip_address inet,
    encryption_key blob,
    PRIMARY KEY (user_id)
) WITH default_time_to_live = 2592000;

-- ===============================
-- ADMIN USERS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id uuid PRIMARY KEY,
    username text,
    role_level text,
    permissions set<text>,
    password_hash text,
    mfa_secret text,
    mfa_type text,
    is_active boolean,
    failed_attempts int,
    ip_whitelist set<text>,
    data_access_scope text,
    created_by uuid,
    created_at timestamp
);

-- ===============================
-- ADMIN SESSIONS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS admin_sessions (
    admin_id uuid,
    session_token text,
    role_level text,
    permissions set<text>,
    mfa_verified boolean,
    created_at timestamp,
    last_activity timestamp,
    expires_at timestamp,
    ip_address inet,
    PRIMARY KEY (admin_id)
) WITH default_time_to_live = 28800;

-- ===============================
-- RATE LIMITS TABLE (WITHOUT COUNTER)
-- ===============================
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket int,
    identifier text,
    window_type text,
    time_window bigint,
    last_attempt timestamp,
    PRIMARY KEY ((bucket, identifier, window_type), time_window)
);

-- ===============================
-- RATE LIMITS COUNTER TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS rate_limits_attempts (
    bucket int,
    identifier text,
    window_type text,
    time_window bigint,
    attempts counter,
    PRIMARY KEY ((bucket, identifier, window_type), time_window)
);

-- ===============================
-- SECURITY EVENTS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS security_events (
    event_bucket int,
    user_id uuid,
    event_date text,
    event_time timestamp,
    event_type text,
    device_id text,
    ip_address inet,
    risk_score int,
    session_id uuid,
    details text,
    cdc_processed boolean,
    PRIMARY KEY ((event_bucket, event_date), event_time, user_id, event_type)
) WITH default_time_to_live = 4320000
AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': 1,
    'compaction_window_unit': 'DAYS'
};

-- ===============================
-- MPIN CREDENTIALS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS mpin_credentials (
    user_id uuid PRIMARY KEY,
    mpin_hash text,
    mpin_salt text,
    pepper_version int,
    hash_algorithm text,
    device_id text,
    last_changed timestamp,
    failed_attempts int,
    is_locked boolean,
    locked_until timestamp
) WITH compression = {'sstable_compression': 'LZ4Compressor'}
AND compaction = {'class': 'LeveledCompactionStrategy'}
AND gc_grace_seconds = 86400
AND caching = {'keys': 'ALL', 'rows_per_partition': 'ALL'}
AND comment = 'Stores user MPIN credentials with device binding';

-- ===============================
-- DEVICE TRUST LEVELS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS device_trust_levels (
    user_id uuid,
    device_id text,
    trust_status text,
    first_successful_login timestamp,
    last_login timestamp,
    ip_address inet,
    user_agent text,
    is_blocked boolean,
    PRIMARY KEY (user_id, device_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ===============================
-- USER DATA DELETIONS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS user_data_deletions (
    deletion_id uuid,
    user_id uuid,
    device_id text,
    reason text,
    deleted_at timestamp,
    data_wiped_categories set<text>,
    deleted_by uuid,
    PRIMARY KEY (deletion_id, user_id)
) WITH default_time_to_live = 7776000
AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- USER DEVICE BINDING HISTORY TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS user_device_binding_history (
    user_id uuid,
    bound_at timestamp,
    device_id text,
    session_id uuid,
    bind_token text,
    action text,
    action_timestamp timestamp,
    PRIMARY KEY ((user_id), action_timestamp, bound_at)
) WITH CLUSTERING ORDER BY (action_timestamp DESC, bound_at DESC)
AND compaction = {'class': 'TimeWindowCompactionStrategy', 'compaction_window_size': '7', 'compaction_window_unit': 'DAYS'}
AND default_time_to_live = 7776000
AND compression = {'sstable_compression': 'LZ4Compressor'}
AND comment = 'Audit trail for device binding and unbinding events with 90-day retention';
