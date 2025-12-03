-- =========================================================
-- CORE AUTH BASE TABLES (Scylla-Compatible, Final Minimal)
-- PostgreSQL now owns: users, companies, departments, roles, permissions
-- Scylla handles: OTPs, sessions, rate limits, device trust, MPIN, admin, audit
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
    device_id text,
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
-- RATE LIMITS TABLES
-- ===============================
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket int,
    identifier text,
    window_type text,
    time_window bigint,
    last_attempt timestamp,
    PRIMARY KEY ((bucket, identifier, window_type), time_window)
);

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
AND gc_grace_seconds = 86400;

-- ===============================
-- DEVICE TRUST LEVELS
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
    device_fingerprint text,
    os_version text,
    app_version text,
    last_ip_subnet text,
    last_location_hash text,
    device_model text,
    risk_score int,
    PRIMARY KEY (user_id, device_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ===============================
-- USER DATA DELETIONS
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
) WITH default_time_to_live = 3888000
AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- USER DEVICE BINDING HISTORY
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
AND default_time_to_live = 3888000;

-- ===============================
-- ACTIVE SESSIONS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS active_sessions (
    user_id uuid PRIMARY KEY,
    session_token text,
    device_id text,
    device_fingerprint text,
    kyc_verified boolean,
    created_at timestamp,
    last_activity timestamp,
    expires_at timestamp,
    ip_address inet,
    encryption_key blob,
    session_type text
) WITH default_time_to_live = 2592000
AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- ADMIN USERS TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id uuid PRIMARY KEY,
    phone_hash text,
    phone_encrypted blob,
    phone_key_id uuid,
    phone_encrypted_dek text,
    admin_role_level text,
    admin_permissions list<text>,
    admin_created_at timestamp,
    admin_created_by uuid,
    admin_updated_at timestamp,
    is_active boolean,
    data_access_scope list<text>,
    ip_whitelist set<text>,
    failed_login_attempts int,
    last_login timestamp
) WITH compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- ADMIN SESSIONS
-- ===============================
CREATE TABLE IF NOT EXISTS admin_sessions (
    admin_id uuid PRIMARY KEY,
    session_token text,
    role_level text,
    permissions set<text>,
    mfa_verified boolean,
    created_at timestamp,
    last_activity timestamp,
    expires_at timestamp,
    ip_address inet
) WITH default_time_to_live = 28800;

-- ===============================
-- ADMIN AUDIT LOG
-- ===============================
CREATE TABLE IF NOT EXISTS admin_audit_log (
    audit_bucket int,
    audit_id uuid,
    admin_id uuid,
    action_date text,
    action_time timestamp,
    action_type text,
    resource_type text,
    resource_id uuid,
    operation_status text,
    changes text,
    ip_address inet,
    old_values text,
    new_values text,
    error_message text,
    PRIMARY KEY ((audit_bucket, action_date), action_time, audit_id, admin_id)
) WITH CLUSTERING ORDER BY (action_time DESC, audit_id DESC, admin_id ASC)
AND default_time_to_live = 3888000
AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': 1,
    'compaction_window_unit': 'DAYS'
};

-- ===============================
-- PEPPER STORE
-- ===============================
CREATE TABLE IF NOT EXISTS pepper_store (
    version int PRIMARY KEY,
    pepper text,
    created_at timestamp,
    is_active boolean
) WITH compression = {'sstable_compression': 'LZ4Compressor'};

-- ===============================
-- ADMIN MPIN + DEVICE TRUST + HISTORY
-- ===============================
CREATE TABLE IF NOT EXISTS admin_mpin_credentials (
    admin_id uuid PRIMARY KEY,
    mpin_hash text,
    mpin_salt text,
    pepper_version int,
    hash_algorithm text,
    device_id text,
    last_changed timestamp,
    failed_attempts int,
    is_locked boolean,
    locked_until timestamp
);

CREATE TABLE IF NOT EXISTS admin_device_trust_levels (
    admin_id uuid,
    device_id text,
    trust_status text,
    first_successful_login timestamp,
    last_login timestamp,
    ip_address inet,
    user_agent text,
    is_blocked boolean,
    device_fingerprint text,
    os_version text,
    app_version text,
    last_ip_subnet text,
    last_location_hash text,
    device_model text,
    risk_score int,
    PRIMARY KEY (admin_id, device_id)
);

CREATE TABLE IF NOT EXISTS admin_device_binding_history (
    admin_id uuid,
    device_id text,
    session_id uuid,
    bound_at timestamp,
    bind_token text,
    action text,
    PRIMARY KEY (admin_id, bound_at)
) WITH CLUSTERING ORDER BY (bound_at DESC);

CREATE TABLE IF NOT EXISTS admin_data_deletions (
    deletion_id uuid,
    admin_id uuid,
    device_id text,
    reason text,
    deleted_at timestamp,
    data_wiped_categories set<text>,
    deleted_by uuid,
    PRIMARY KEY (deletion_id, admin_id)
);

CREATE TABLE IF NOT EXISTS admin_active_device (
    admin_id uuid PRIMARY KEY,
    device_id text,
    session_id uuid,
    bound_at timestamp,
    bind_token text
);
    
CREATE TABLE IF NOT EXISTS user_active_device (
    user_id uuid PRIMARY KEY,
    device_id text,
    session_id uuid,
    bound_at timestamp,
    bind_token text
);