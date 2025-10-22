USE core_auth;

-- MPIN INDEXES
CREATE INDEX IF NOT EXISTS idx_mpin_locked ON mpin_credentials (is_locked);
CREATE INDEX IF NOT EXISTS idx_mpin_device ON mpin_credentials (device_id);

-- ADMIN ROLES TABLE
CREATE TABLE IF NOT EXISTS admin_roles (
    role_level text PRIMARY KEY,
    role_name text,
    permissions set<text>,
    mfa_required boolean
);

-- INSERT INITIAL ROLES
INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('owner', 'System Owner', {'manage_employees','manage_super_employees','ban_employees','ban_users','system_config'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('super_employee', 'Supervisor', {'manage_employees','ban_users','verify_kyc'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('employee', 'Support Agent', {'verify_kyc','ban_users'}, true);

INSERT INTO admin_roles (role_level, role_name, permissions, mfa_required) VALUES 
('support', 'Read Only Support', {'view_user_data'}, false);
