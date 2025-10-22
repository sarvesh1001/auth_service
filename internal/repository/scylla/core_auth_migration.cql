-- =========================================================
-- CORE AUTH & OTP MIGRATION SCRIPT (Optimized & Fixed)
-- Keyspace: core_auth
-- =========================================================

-- 1. Create Keyspace
CREATE KEYSPACE IF NOT EXISTS core_auth WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'datacenter1': '3'
} AND DURABLE_WRITES = true;

USE core_auth;

-- ================== USERS TABLE ==================
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
    'compaction_window_size': '1',
    'compaction_window_unit': 'DAYS'
}
AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ================== PHONE TO USER TABLE ==================
CREATE TABLE IF NOT EXISTS phone_to_user (
    phone_hash text,
    user_bucket int,
    user_id uuid,
    created_at timestamp,
    PRIMARY KEY (phone_hash)
) WITH compaction = {'class': 'LeveledCompactionStrategy'}
AND compression = {'sstable_compression': 'LZ4Compressor'};

-- ================== USERS BY PHONE HASH VIEW ==================
CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_phone_hash AS
    SELECT user_bucket, user_id, phone_hash, is_blocked, kyc_status
    FROM users
    WHERE phone_hash IS NOT NULL AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY (phone_hash, user_bucket, user_id);

-- ================== OTP VERIFICATIONS TABLE ==================
-- FIXED: Added purpose to partition key for efficient querying
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
    'compaction_window_size': '1',
    'compaction_window_unit': 'HOURS'
};

-- ================== OTP BY PHONE MATERIALIZED VIEW ==================
-- FIXED: Updated to match new primary key structure
CREATE MATERIALIZED VIEW IF NOT EXISTS otp_by_phone AS
    SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, attempts, expires_at
    FROM otp_verifications
    WHERE phone_hash IS NOT NULL AND purpose IS NOT NULL AND time_bucket IS NOT NULL AND created_at IS NOT NULL
    PRIMARY KEY ((phone_hash), purpose, time_bucket, created_at)
    WITH CLUSTERING ORDER BY (purpose ASC, time_bucket DESC, created_at DESC);

-- ================== MPIN CREDENTIALS TABLE ==================
CREATE TABLE IF NOT EXISTS mpin_credentials (
    user_id uuid,
    mpin_hash text,
    mpin_salt text,
    pepper_version int,
    hash_algorithm text,
    device_id text,
    last_changed timestamp,
    failed_attempts int,
    is_locked boolean,
    locked_until timestamp,
    PRIMARY KEY (user_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ================== USER ACTIVE DEVICE TABLE ==================
CREATE TABLE IF NOT EXISTS user_active_device (
    user_id uuid,
    device_id text,
    session_id uuid,
    bound_at timestamp,
    bind_token text,
    PRIMARY KEY (user_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ================== ACTIVE SESSIONS TABLE ==================
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

CREATE MATERIALIZED VIEW IF NOT EXISTS sessions_by_token AS
    SELECT user_id, session_token, device_id, expires_at
    FROM active_sessions
    WHERE session_token IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY (session_token, user_id);

-- ================== ADMIN USERS & SESSIONS ==================
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

-- ================== RATE LIMITS TABLE ==================
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket int,
    identifier text,
    window_type text,
    time_window bigint,
    attempts counter,
    last_attempt timestamp,
    PRIMARY KEY ((bucket, identifier, window_type), time_window)
);

-- ================== SECURITY EVENTS TABLE ==================
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
    'compaction_window_size': '1',
    'compaction_window_unit': 'DAYS'
};

-- ================== ADMIN ROLES & INITIAL DATA ==================
CREATE TABLE IF NOT EXISTS admin_roles (
    role_level text PRIMARY KEY,
    role_name text,
    permissions set<text>,
    mfa_required boolean
);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('owner', 'System Owner', {'manage_employees','manage_super_employees','ban_employees','ban_users','system_config'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('super_employee', 'Supervisor', {'manage_employees','ban_users','verify_kyc'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('employee', 'Support Agent', {'verify_kyc','ban_users'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('support', 'Read Only Support', {'view_user_data'}, false);

-- ================== USERS BY KYC STATUS VIEW ==================
CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_kyc_status AS
    SELECT kyc_status, user_bucket, user_id
    FROM users
    WHERE kyc_status IS NOT NULL AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY ((kyc_status), user_bucket, user_id);

-- ================== BANNED_USERS VIEW ==================
CREATE MATERIALIZED VIEW IF NOT EXISTS banned_users AS
    SELECT is_banned, user_bucket, user_id, phone_hash, is_blocked
    FROM users
    WHERE is_banned = true AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY ((is_banned), user_bucket, user_id)
    WITH compaction = {
        'class': 'TimeWindowCompactionStrategy',
        'compaction_window_size': '1',
        'compaction_window_unit': 'DAYS'
    };
