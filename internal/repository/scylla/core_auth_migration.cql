-- =========================================================
-- CORE AUTH MIGRATION SCRIPT (Fixed & Optimized)
-- Migrates from auth_service to core_auth schema
-- =========================================================

-- Create new keyspace
CREATE KEYSPACE IF NOT EXISTS core_auth WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'datacenter1': '3'
} AND DURABLE_WRITES = true;

USE core_auth;

-- ================== USERS TABLE (NEW STRUCTURE) ==================
CREATE TABLE IF NOT EXISTS users (
    user_bucket int,              -- murmur3(user_id) % 1024 for better distribution
    user_id uuid,
    phone_hash text,              -- Hashed phone for lookup
    phone_encrypted blob,         -- Encrypted phone number
    phone_key_id uuid,            -- Key ID for decryption
    device_id text,
    device_fingerprint text,
    
    -- Enhanced KYC fields
    kyc_status text,
    kyc_level text,
    kyc_verified_at timestamp,
    kyc_verified_by uuid,
    
    -- Profile reference
    profile_service_id uuid,
    
    -- Account status
    is_verified boolean,
    is_blocked boolean,
    is_banned boolean,
    banned_by uuid,
    banned_reason text,
    banned_at timestamp,
    
    -- Timestamps
    created_at timestamp,
    last_login timestamp,
    updated_at timestamp,
    
    -- Compliance
    consent_agreed boolean,
    consent_version text,
    data_region text,
    
    PRIMARY KEY ((user_bucket), user_id)
) WITH compaction = { 
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': '1',
    'compaction_window_unit': 'DAYS'
} AND compression = {'sstable_compression': 'LZ4Compressor'};

-- Phone lookup materialized view (✅ fixed null filtering)
CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_phone_hash AS
    SELECT user_bucket, user_id, phone_hash, is_blocked, kyc_status
    FROM users
    WHERE phone_hash IS NOT NULL AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY (phone_hash, user_bucket, user_id);

-- ================== OTP TABLE (ENHANCED) ==================
CREATE TABLE IF NOT EXISTS otp_verifications (
    phone_hash text,
    time_bucket bigint,           -- floor(extract(epoch from now())/300) * 300
    created_at timestamp,
    otp_hash text,
    otp_salt text,                -- base64 encoded
    hash_algorithm text,          -- 'argon2id-v1'
    pepper_version int,
    purpose text,
    attempts int,
    expires_at timestamp,
    ip_address inet,
    provider_used text,
    PRIMARY KEY ((phone_hash, time_bucket), created_at)
) WITH default_time_to_live = 900
AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': '1', 
    'compaction_window_unit': 'HOURS'
};

-- ================== MPIN TABLE (ENHANCED SECURITY) ==================
CREATE TABLE IF NOT EXISTS mpin_credentials (
    user_id uuid,
    mpin_hash text,
    mpin_salt text,               -- base64 encoded
    pepper_version int,
    hash_algorithm text,          -- 'argon2id-v1'
    device_id text,
    last_changed timestamp,
    failed_attempts int,
    is_locked boolean,
    locked_until timestamp,
    PRIMARY KEY (user_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ================== DEVICE MANAGEMENT (NEW) ==================
CREATE TABLE IF NOT EXISTS user_active_device (
    user_id uuid,
    device_id text,
    session_id uuid,
    bound_at timestamp,
    bind_token text,              -- For idempotent retries
    PRIMARY KEY (user_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'};

-- ================== SESSIONS (ENHANCED) ==================
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

-- ================== ADMIN SYSTEM (NEW) ==================
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id uuid,
    username text,
    role_level text,              -- 'owner', 'super_employee', 'employee', 'support'
    permissions set<text>,
    password_hash text,
    mfa_secret text,
    mfa_type text,                -- 'totp', 'hardware', 'webauthn'
    is_active boolean,
    failed_attempts int,
    ip_whitelist set<text>,
    data_access_scope text,
    created_by uuid,
    created_at timestamp,
    PRIMARY KEY (admin_id)
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

-- ================== RATE LIMITING (ENHANCED) ==================
-- ⚙️ Removed default TTL (not allowed for counter tables)
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket int,                    -- murmur3(identifier) % 256
    identifier text,
    window_type text,              -- 'minute', 'hour', 'day'
    time_window bigint,
    attempts counter,
    last_attempt timestamp,
    PRIMARY KEY ((bucket, identifier, window_type, time_window))
);

-- ================== SECURITY EVENTS (NEW) ==================
-- ⚙️ Adjusted TTL to 50 days to stay below TWCS limit
CREATE TABLE IF NOT EXISTS security_events (
    event_bucket int,              -- murmur3(user_id) % 256
    user_id uuid,
    event_date text,               -- 'YYYY-MM-DD'
    event_time timestamp,
    event_type text,
    device_id text,
    ip_address inet,
    risk_score int,
    session_id uuid,
    details text,
    cdc_processed boolean,         -- For CDC tracking
    PRIMARY KEY ((event_bucket, event_date), event_time, user_id, event_type)
) WITH default_time_to_live = 4320000
AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_size': '1',
    'compaction_window_unit': 'DAYS'
};

-- ================== ADMIN ROLES (INITIAL DATA) ==================
CREATE TABLE IF NOT EXISTS admin_roles (
    role_level text PRIMARY KEY,
    role_name text,
    permissions set<text>,
    mfa_required boolean
);

-- ✅ Each insert separated to avoid SyntaxException
INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('owner', 'System Owner', {'manage_employees', 'manage_super_employees', 'ban_employees', 'ban_users', 'system_config'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('super_employee', 'Supervisor', {'manage_employees', 'ban_users', 'verify_kyc'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('employee', 'Support Agent', {'verify_kyc', 'ban_users'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required)
VALUES ('support', 'Read Only Support', {'view_user_data'}, false);
-- Users by KYC status (avoids filtering on base table)
CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_kyc_status AS
    SELECT 
        kyc_status,
        user_bucket,
        user_id
    FROM users
    WHERE kyc_status IS NOT NULL AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY ((kyc_status), user_bucket, user_id);
