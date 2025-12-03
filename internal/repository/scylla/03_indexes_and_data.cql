USE core_auth;

-- =========================================================
-- INDEXES AND ADMIN ROLES
-- =========================================================

-- ===============================
-- MPIN INDEXES
-- ===============================
CREATE INDEX IF NOT EXISTS idx_mpin_locked ON mpin_credentials (is_locked);
CREATE INDEX IF NOT EXISTS idx_mpin_device ON mpin_credentials (device_id);

-- ===============================
-- ADMIN ROLES TABLE
-- ===============================
CREATE TABLE IF NOT EXISTS admin_roles (
    role_level text PRIMARY KEY,
    role_name text,
    permissions set<text>,
    mfa_required boolean
) WITH comment = 'Static admin role definitions for Scylla-based RBAC control.';

-- ===============================
-- INITIAL ROLE SEED DATA
-- ===============================
INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('owner', 'System Owner', {'manage_admins','system_config','manage_security','view_audit_logs'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('super_admin', 'Super Administrator', {'manage_admins','view_audit_logs','manage_trust','ban_users'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('moderator', 'Moderator', {'verify_kyc','ban_users','manage_sessions'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('support', 'Support Staff', {'view_user_data','view_sessions'}, false);

-- ===============================
-- SECONDARY INDEXES FOR ADMIN QUERIES
-- ===============================
CREATE INDEX IF NOT EXISTS admin_users_role_level_idx ON admin_users (admin_role_level);
CREATE INDEX IF NOT EXISTS admin_users_phone_hash_idx ON admin_users (phone_hash);
CREATE INDEX IF NOT EXISTS admin_users_is_active_idx ON admin_users (is_active);

-- ===============================
-- PEPPER STORE INDEX
-- ===============================
CREATE INDEX IF NOT EXISTS idx_pepper_store_is_active ON pepper_store (is_active);
CREATE INDEX IF NOT EXISTS ON otp_verifications (device_id);
