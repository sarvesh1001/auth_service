USE core_auth;

-- USERS BY PHONE HASH
CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_phone_hash AS
    SELECT user_bucket, user_id, phone_hash, is_blocked, kyc_status
    FROM users
    WHERE phone_hash IS NOT NULL AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY (phone_hash, user_bucket, user_id);

-- OTP BY PHONE
CREATE MATERIALIZED VIEW IF NOT EXISTS otp_by_phone AS
    SELECT phone_hash, purpose, time_bucket, created_at, otp_hash, attempts, expires_at
    FROM otp_verifications
    WHERE phone_hash IS NOT NULL AND purpose IS NOT NULL AND time_bucket IS NOT NULL AND created_at IS NOT NULL
    PRIMARY KEY ((phone_hash), purpose, time_bucket, created_at)
    WITH CLUSTERING ORDER BY (purpose ASC, time_bucket DESC, created_at DESC);

-- SESSIONS BY TOKEN
CREATE MATERIALIZED VIEW IF NOT EXISTS sessions_by_token AS
    SELECT user_id, session_token, device_id, expires_at
    FROM active_sessions
    WHERE session_token IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY (session_token, user_id);

-- USERS BY KYC STATUS
CREATE MATERIALIZED VIEW IF NOT EXISTS users_by_kyc_status AS
    SELECT kyc_status, user_bucket, user_id
    FROM users
    WHERE kyc_status IS NOT NULL AND user_bucket IS NOT NULL AND user_id IS NOT NULL
    PRIMARY KEY ((kyc_status), user_bucket, user_id);

-- BANNED USERS
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

-- DEVICE BINDINGS BY DEVICE ID (FIXED)
CREATE MATERIALIZED VIEW IF NOT EXISTS device_bindings_by_device_id AS
    SELECT user_id, device_id, bound_at, bind_token, action_timestamp
    FROM user_device_binding_history
    WHERE device_id IS NOT NULL AND user_id IS NOT NULL AND action_timestamp IS NOT NULL AND bound_at IS NOT NULL
    PRIMARY KEY ((device_id), action_timestamp, bound_at, user_id)
    WITH CLUSTERING ORDER BY (action_timestamp DESC, bound_at DESC);
