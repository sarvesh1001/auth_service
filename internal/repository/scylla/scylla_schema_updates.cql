-- ============================================
-- IP REPUTATION TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip_address inet PRIMARY KEY,
    risk_score int,
    total_requests bigint,
    failed_attempts bigint,
    malicious_flags int,
    first_seen timestamp,
    last_seen timestamp,
    country_code text,
    asn text,
    is_whitelisted boolean,
    is_blacklisted boolean,
    threat_types set<text>
) WITH default_time_to_live = 2592000; -- 30 days TTL

-- ============================================
-- BRUTE FORCE SCORES TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS brute_force_scores (
    identifier text, -- phone_hash:ip or phone_hash:purpose
    score int,
    factors set<text>,
    last_updated timestamp,
    expires_at timestamp,
    PRIMARY KEY (identifier)
) WITH default_time_to_live = 86400; -- 24 hours TTL

-- ============================================
-- SECURITY EVENTS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS security_events_enhanced (
    event_bucket int,
    event_date text,
    event_time timestamp,
    event_id uuid,
    event_type text,
    phone_hash text,
    ip_address inet,
    device_id text,
    risk_score int,
    action text,
    details text,
    PRIMARY KEY ((event_bucket, event_date), event_time, event_id)
) WITH CLUSTERING ORDER BY (event_time DESC)
AND default_time_to_live = 2592000; -- 30 days

-- ============================================
-- DAILY OTP LIMITS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS daily_otp_limits (
    phone_hash text,
    date text, -- YYYY-MM-DD
    total_sent int,
    total_failed int,
    last_sent_at timestamp,
    is_limit_exceeded boolean,
    PRIMARY KEY (phone_hash, date)
) WITH default_time_to_live = 172800; -- 48 hours TTL

-- ============================================
-- OTP REPLAY PROTECTION TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS otp_replay_protection (
    otp_hash text,
    phone_hash text,
    purpose text,
    used_at timestamp,
    expires_at timestamp,
    PRIMARY KEY ((otp_hash, phone_hash, purpose))
) WITH default_time_to_live = 600; -- 10 minutes TTL

-- ============================================
-- SMS PROVIDER LOGS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS sms_provider_logs (
    provider text,
    event_date text,
    event_time timestamp,
    attempt_id uuid,
    phone_number text,
    success boolean,
    error text,
    response_time int,
    PRIMARY KEY ((provider, event_date), event_time, attempt_id)
) WITH CLUSTERING ORDER BY (event_time DESC)
AND default_time_to_live = 604800; -- 7 days TTL

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_ip_reputation_risk ON ip_reputation (risk_score);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_blacklisted ON ip_reputation (is_blacklisted);
CREATE INDEX IF NOT EXISTS idx_security_events_phone ON security_events_enhanced (phone_hash);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events_enhanced (ip_address);