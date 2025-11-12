USE core_auth;

-- =========================================================
-- USERS MATERIALIZED VIEWS
-- =========================================================

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

-- DEVICE BINDINGS BY DEVICE ID
CREATE MATERIALIZED VIEW IF NOT EXISTS device_bindings_by_device_id AS
    SELECT user_id, device_id, bound_at, bind_token, action_timestamp
    FROM user_device_binding_history
    WHERE device_id IS NOT NULL AND user_id IS NOT NULL AND action_timestamp IS NOT NULL AND bound_at IS NOT NULL
    PRIMARY KEY ((device_id), action_timestamp, bound_at, user_id)
    WITH CLUSTERING ORDER BY (action_timestamp DESC, bound_at DESC);


-- =========================================================
-- COMPANY MATERIALIZED VIEWS (FIXED)
-- =========================================================
-- =========================================================
-- COMPANY MATERIALIZED VIEWS (FIXED - ScyllaDB Compatible)
-- =========================================================

-- Companies by owner (user_id)
CREATE MATERIALIZED VIEW IF NOT EXISTS companies_by_owner AS
    SELECT company_id, company_name, owner_phone, owner_user_id,
           subscription_tier, is_active, created_at
    FROM companies 
    WHERE owner_user_id IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (owner_user_id, company_id);

-- Employees by user
CREATE MATERIALIZED VIEW IF NOT EXISTS employees_by_user AS
    SELECT company_id, user_id, employee_id, role_id, department_id, is_active
    FROM company_employees 
    WHERE user_id IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (user_id, company_id);

-- Companies by tier (main view)
CREATE MATERIALIZED VIEW IF NOT EXISTS companies_by_tier AS
    SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
           subscription_start_date, subscription_end_date, created_at
    FROM companies 
    WHERE subscription_tier IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (subscription_tier, company_id)
    WITH CLUSTERING ORDER BY (company_id ASC);

-- Companies by active/inactive status
CREATE MATERIALIZED VIEW IF NOT EXISTS companies_by_active_status AS
    SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
           subscription_start_date, subscription_end_date, created_at
    FROM companies
    WHERE is_active IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (is_active, company_id)
    WITH CLUSTERING ORDER BY (company_id ASC);

-- Companies by blocked status
CREATE MATERIALIZED VIEW IF NOT EXISTS companies_by_blocked_status AS
    SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
           subscription_start_date, subscription_end_date, created_at
    FROM companies
    WHERE is_blocked IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (is_blocked, company_id)
    WITH CLUSTERING ORDER BY (company_id ASC);

-- Companies by subscription end date
CREATE MATERIALIZED VIEW IF NOT EXISTS companies_by_subscription_date AS
    SELECT company_id, company_name, subscription_tier, is_active, is_blocked,
           subscription_start_date, subscription_end_date, created_at
    FROM companies 
    WHERE subscription_end_date IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (subscription_end_date, company_id)
    WITH CLUSTERING ORDER BY (company_id ASC);

-- Companies by creation date (for recent companies)
CREATE MATERIALIZED VIEW IF NOT EXISTS companies_by_created_date AS
    SELECT company_id, company_name, subscription_tier, is_active, created_at
    FROM companies
    WHERE created_at IS NOT NULL AND company_id IS NOT NULL
    PRIMARY KEY (created_at, company_id)
    WITH CLUSTERING ORDER BY (company_id ASC);

    