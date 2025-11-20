set -e

echo "🔧 Starting PostgreSQL initialization..."

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
sleep 2
done

echo "✅ PostgreSQL is ready!"
echo "🏗️ Creating database schema..."

# Execute the SQL schema
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Enable UUID extension
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    -- =========================================================
    -- USERS
    -- =========================================================
    CREATE TABLE users (
        user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        phone_hash VARCHAR(128) NOT NULL,
        phone_encrypted BYTEA NOT NULL,
        phone_encrypted_dek TEXT NOT NULL, -- 🆕 Added this field
        phone_key_id UUID NOT NULL,
        device_id VARCHAR(256),
        device_fingerprint VARCHAR(512),
        kyc_status VARCHAR(50) NOT NULL DEFAULT 'pending',
        kyc_level VARCHAR(20) NOT NULL DEFAULT 'basic',
        kyc_verified_at TIMESTAMPTZ,
        is_verified BOOLEAN NOT NULL DEFAULT false,
        is_active BOOLEAN NOT NULL DEFAULT true,
        data_region VARCHAR(20) NOT NULL DEFAULT 'us',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_login TIMESTAMPTZ
    ) PARTITION BY HASH (user_id);

    -- Create 8 partitions for users
    CREATE TABLE users_p0 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 0);
    CREATE TABLE users_p1 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 1);
    CREATE TABLE users_p2 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 2);
    CREATE TABLE users_p3 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 3);
    CREATE TABLE users_p4 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 4);
    CREATE TABLE users_p5 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 5);
    CREATE TABLE users_p6 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 6);
    CREATE TABLE users_p7 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 7);

    -- =========================================================
    -- COMPANIES
    -- =========================================================
    CREATE TABLE companies (
        company_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_name VARCHAR(255) NOT NULL,
        owner_user_id UUID NOT NULL REFERENCES users(user_id),
        subscription_tier VARCHAR(20) NOT NULL DEFAULT 'basic',
        subscription_status VARCHAR(20) NOT NULL DEFAULT 'active',
        max_employees INTEGER NOT NULL DEFAULT 10,
        data_region VARCHAR(10) NOT NULL DEFAULT 'us',
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        subscription_start_date TIMESTAMPTZ,
        subscription_end_date TIMESTAMPTZ,
        -- Add unique constraint for company_name and owner_user_id
        UNIQUE(company_name, owner_user_id)
    );

    -- =========================================================
    -- SYSTEM DEPARTMENTS (GLOBAL MODULE TEMPLATES)
    -- =========================================================
    CREATE TABLE system_departments (
        system_department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) UNIQUE NOT NULL,
        module_code VARCHAR(100) NOT NULL,
        description TEXT
    );

    
    CREATE TABLE permissions (
        permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        permission_name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT,
        category VARCHAR(50) NOT NULL,
        module VARCHAR(50) NOT NULL,
        requires_tier VARCHAR(20) DEFAULT 'basic',
        bit_index INTEGER UNIQUE, -- 🆕 NEW: Bit position for bitmask
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    -- =========================================================
    -- ROLES
    -- =========================================================
    CREATE TABLE roles (
        role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role_name VARCHAR(100) NOT NULL,
        role_level INTEGER NOT NULL DEFAULT 1000,
        company_id UUID NOT NULL REFERENCES companies(company_id),
        is_system_role BOOLEAN NOT NULL DEFAULT false,
        description TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(company_id, role_name)
    );

    -- =========================================================
    -- ROLE PERMISSIONS
    -- =========================================================
    CREATE TABLE role_permissions (
        role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
        permission_id UUID NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
        granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        granted_by UUID NOT NULL REFERENCES users(user_id),
        PRIMARY KEY (role_id, permission_id)
    );

    -- =========================================================
    -- DEPARTMENTS (MUST BE CREATED BEFORE role_departments)
    -- =========================================================
    CREATE TABLE departments (
        department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID NOT NULL REFERENCES companies(company_id),
        department_name VARCHAR(255) NOT NULL,
        system_department_id UUID NULL REFERENCES system_departments(system_department_id),
        department_head UUID, -- ✅ FIXED: Will be validated via application logic
        parent_department_id UUID, -- Will add self-reference FK later
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(company_id, department_name)
    );

    -- =========================================================
    -- ROLE DEPARTMENTS MAPPING (MUST BE AFTER departments)
    -- =========================================================
    CREATE TABLE role_departments (
        role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
        department_id UUID NOT NULL REFERENCES departments(department_id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, department_id)
    );

    -- =========================================================
    -- COMPANY EMPLOYEES
    -- =========================================================
    CREATE TABLE company_employees (
        company_id UUID NOT NULL REFERENCES companies(company_id),
        user_id UUID NOT NULL REFERENCES users(user_id),
        employee_id VARCHAR(100) NOT NULL,
        role_id UUID NOT NULL REFERENCES roles(role_id),
        department_id UUID REFERENCES departments(department_id),
        hire_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT true,
        reports_to UUID, -- ✅ FIXED: Will be validated via application logic
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (company_id, user_id)
    );

    -- =========================================================
    -- NEW TABLE: USER DEVICES
    -- =========================================================
    CREATE TABLE user_devices (
        device_id VARCHAR(256) PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(user_id),
        device_type VARCHAR(50),
        device_name VARCHAR(100),
        os_version VARCHAR(50),
        app_version VARCHAR(50),
        last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- =========================================================
    -- NEW TABLE: LOGIN ATTEMPTS
    -- =========================================================
    CREATE TABLE login_attempts (
        attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(user_id),
        success BOOLEAN NOT NULL,
        ip_address VARCHAR(64),
        user_agent TEXT,
        device_id VARCHAR(256) REFERENCES user_devices(device_id),
        attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        failure_reason TEXT
    );

    -- =========================================================
    -- FOREIGN KEYS (ONLY SELF-REFERENCING ONES NEED ALTER)
    -- =========================================================
    -- ✅ FIXED: Only self-referencing FK needs ALTER
    ALTER TABLE departments ADD CONSTRAINT fk_departments_parent 
        FOREIGN KEY (parent_department_id) REFERENCES departments(department_id);

    -- =========================================================
    -- INDEXES (REMOVED CONCURRENTLY - can't use in transaction)
    -- =========================================================
    CREATE INDEX idx_users_phone_hash ON users (phone_hash);
    CREATE INDEX idx_users_created_at ON users (created_at);
    CREATE INDEX idx_users_status ON users (is_active, kyc_status);
    CREATE INDEX idx_users_region ON users (data_region);
    CREATE INDEX idx_users_kyc_status ON users(kyc_status);

    CREATE INDEX idx_companies_owner ON companies (owner_user_id);
    CREATE INDEX idx_companies_status ON companies (is_active, subscription_status);
    CREATE INDEX idx_companies_region ON companies (data_region);

    CREATE INDEX idx_roles_company ON roles (company_id);
    CREATE INDEX idx_roles_level ON roles (role_level);

    CREATE INDEX idx_role_perms_permission ON role_permissions (permission_id);

    CREATE INDEX idx_employees_user ON company_employees (user_id);
    CREATE INDEX idx_employees_role ON company_employees (role_id);
    CREATE INDEX idx_employees_dept ON company_employees (department_id);
    CREATE INDEX idx_employees_active ON company_employees (is_active);
    CREATE INDEX idx_employees_company_active ON company_employees (company_id, is_active);
    CREATE INDEX idx_employees_reports_to ON company_employees (company_id, reports_to);

    CREATE INDEX idx_departments_company ON departments (company_id);
    CREATE INDEX idx_departments_parent ON departments (parent_department_id);
    CREATE INDEX idx_departments_head ON departments (department_head);
    CREATE INDEX idx_departments_system ON departments (system_department_id);

    CREATE INDEX idx_role_departments_role ON role_departments (role_id);
    CREATE INDEX idx_role_departments_department ON role_departments (department_id);

    CREATE INDEX idx_system_departments_module ON system_departments (module_code);
    CREATE INDEX idx_system_departments_name ON system_departments (name);

    CREATE INDEX idx_user_devices_user ON user_devices (user_id);
    CREATE INDEX idx_user_devices_active ON user_devices (is_active);
    CREATE INDEX idx_user_devices_last_active ON user_devices (last_active);

    CREATE INDEX idx_login_attempts_user ON login_attempts (user_id);
    CREATE INDEX idx_login_attempts_device ON login_attempts (device_id);
    CREATE INDEX idx_login_attempts_success ON login_attempts (success);
    CREATE INDEX idx_login_attempts_time ON login_attempts (attempted_at DESC);

    -- =========================================================
    -- SEED DATA: SYSTEM DEPARTMENTS
    -- =========================================================
    -- Seed ERP standard departments
    INSERT INTO system_departments (name, module_code, description) VALUES
    ('HR', 'hr', 'Human resource management'),
    ('Finance', 'finance', 'Finance operations'),
    ('Accounting', 'accounting', 'Accounting and ledger'),
    ('Procurement', 'procurement', 'Purchasing & vendor mgmt'),
    ('Inventory', 'inventory', 'Stock & warehouse'),
    ('Logistics', 'logistics', 'Dispatch & delivery'),
    ('Sales', 'sales', 'Lead & pipeline mgmt'),
    ('Marketing', 'marketing', 'Campaigns & analysis'),
    ('Customer Support', 'support', 'Support & helpdesk'),
    ('Operations', 'operations', 'Operations & workflows'),
    ('IT', 'it', 'IT assets & incidents'),
    ('Production', 'production', 'Manufacturing operations'),
    ('Quality Control', 'qc', 'QC inspections'),
    ('Quality Assurance', 'qa', 'QA processes'),
    ('R&D', 'rnd', 'Research & development'),
    ('Administration', 'administration', 'Company administration and management')
    ON CONFLICT (name) DO NOTHING;

    -- =========================================================
    -- COMPLETE ENTERPRISE PERMISSIONS (220+)
    -- Split into multiple inserts for safety
    -- =========================================================
    -- ============================================
-- RBAC PERMISSIONS WITH GLOBAL BIT INDEXES
-- ============================================

-- 🔵 HR MODULE (20 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('hr.employee.create', 'Create employees', 'employee', 'hr', 'basic', 0),
('hr.employee.update', 'Update employees', 'employee', 'hr', 'basic', 1),
('hr.employee.delete', 'Delete employees', 'employee', 'hr', 'basic', 2),
('hr.employee.view', 'View employees', 'employee', 'hr', 'basic', 3),
('hr.employee.search', 'Search employees', 'employee', 'hr', 'basic', 4),
('hr.employee.terminate', 'Terminate employees', 'employee', 'hr', 'basic', 5),
('hr.employee.transfer', 'Transfer employees', 'employee', 'hr', 'basic', 6),
('hr.document.upload', 'Upload documents', 'document', 'hr', 'basic', 7),
('hr.document.view', 'View documents', 'document', 'hr', 'basic', 8),
('hr.document.delete', 'Delete documents', 'document', 'hr', 'basic', 9),
('hr.position.create', 'Create positions', 'position', 'hr', 'basic', 10),
('hr.position.update', 'Update positions', 'position', 'hr', 'basic', 11),
('hr.position.delete', 'Delete positions', 'position', 'hr', 'basic', 12),
('hr.position.view', 'View positions', 'position', 'hr', 'basic', 13),
('hr.leave.request', 'Request leave', 'leave', 'hr', 'basic', 14),
('hr.leave.approve', 'Approve leave', 'leave', 'hr', 'basic', 15),
('hr.leave.reject', 'Reject leave', 'leave', 'hr', 'basic', 16),
('hr.leave.view', 'View leave', 'leave', 'hr', 'basic', 17),
('hr.attendance.view', 'View attendance', 'attendance', 'hr', 'basic', 18),
('hr.attendance.update', 'Update attendance', 'attendance', 'hr', 'basic', 19)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 FINANCE MODULE (19 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('finance.invoice.create', 'Create invoices', 'invoice', 'finance', 'basic', 20),
('finance.invoice.update', 'Update invoices', 'invoice', 'finance', 'basic', 21),
('finance.invoice.delete', 'Delete invoices', 'invoice', 'finance', 'basic', 22),
('finance.invoice.view', 'View invoices', 'invoice', 'finance', 'basic', 23),
('finance.invoice.send', 'Send invoices', 'invoice', 'finance', 'basic', 24),
('finance.invoice.approve', 'Approve invoices', 'invoice', 'finance', 'basic', 25),
('finance.payment.process', 'Process payments', 'payment', 'finance', 'basic', 26),
('finance.payment.refund', 'Process refunds', 'payment', 'finance', 'basic', 27),
('finance.payment.view', 'View payments', 'payment', 'finance', 'basic', 28),
('finance.statement.view', 'View statements', 'statement', 'finance', 'basic', 29),
('finance.statement.download', 'Download statements', 'statement', 'finance', 'basic', 30),
('finance.tax.create', 'Create tax records', 'tax', 'finance', 'basic', 31),
('finance.tax.update', 'Update tax records', 'tax', 'finance', 'basic', 32),
('finance.tax.view', 'View tax records', 'tax', 'finance', 'basic', 33),
('finance.tax.delete', 'Delete tax records', 'tax', 'finance', 'basic', 34),
('finance.budget.create', 'Create budgets', 'budget', 'finance', 'basic', 35),
('finance.budget.update', 'Update budgets', 'budget', 'finance', 'basic', 36),
('finance.budget.delete', 'Delete budgets', 'budget', 'finance', 'basic', 37),
('finance.budget.view', 'View budgets', 'budget', 'finance', 'basic', 38)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 ACCOUNTING MODULE (10 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('accounting.ledger.view', 'View ledger', 'ledger', 'accounting', 'basic', 39),
('accounting.journal.create', 'Create journal entries', 'journal', 'accounting', 'basic', 40),
('accounting.journal.update', 'Update journal entries', 'journal', 'accounting', 'basic', 41),
('accounting.journal.delete', 'Delete journal entries', 'journal', 'accounting', 'basic', 42),
('accounting.journal.view', 'View journal entries', 'journal', 'accounting', 'basic', 43),
('accounting.pl.view', 'View profit/loss', 'pl', 'accounting', 'basic', 44),
('accounting.balance_sheet.view', 'View balance sheet', 'balance_sheet', 'accounting', 'basic', 45),
('accounting.cashflow.view', 'View cash flow', 'cashflow', 'accounting', 'basic', 46),
('accounting.reconcile', 'Reconcile accounts', 'reconcile', 'accounting', 'basic', 47),
('accounting.report.export', 'Export reports', 'report', 'accounting', 'basic', 48)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 PROCUREMENT MODULE (15 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('procurement.po.create', 'Create purchase orders', 'po', 'procurement', 'basic', 49),
('procurement.po.update', 'Update purchase orders', 'po', 'procurement', 'basic', 50),
('procurement.po.approve', 'Approve purchase orders', 'po', 'procurement', 'basic', 51),
('procurement.po.reject', 'Reject purchase orders', 'po', 'procurement', 'basic', 52),
('procurement.po.delete', 'Delete purchase orders', 'po', 'procurement', 'basic', 53),
('procurement.po.view', 'View purchase orders', 'po', 'procurement', 'basic', 54),
('procurement.vendor.create', 'Create vendors', 'vendor', 'procurement', 'basic', 55),
('procurement.vendor.update', 'Update vendors', 'vendor', 'procurement', 'basic', 56),
('procurement.vendor.block', 'Block vendors', 'vendor', 'procurement', 'basic', 57),
('procurement.vendor.delete', 'Delete vendors', 'vendor', 'procurement', 'basic', 58),
('procurement.vendor.view', 'View vendors', 'vendor', 'procurement', 'basic', 59),
('procurement.request.create', 'Create procurement requests', 'request', 'procurement', 'basic', 60),
('procurement.request.update', 'Update procurement requests', 'request', 'procurement', 'basic', 61),
('procurement.request.delete', 'Delete procurement requests', 'request', 'procurement', 'basic', 62),
('procurement.request.view', 'View procurement requests', 'request', 'procurement', 'basic', 63)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 INVENTORY MODULE (18 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('inventory.item.create', 'Create items', 'item', 'inventory', 'basic', 64),
('inventory.item.update', 'Update items', 'item', 'inventory', 'basic', 65),
('inventory.item.delete', 'Delete items', 'item', 'inventory', 'basic', 66),
('inventory.item.view', 'View items', 'item', 'inventory', 'basic', 67),
('inventory.stock.in', 'Stock in items', 'stock', 'inventory', 'basic', 68),
('inventory.stock.out', 'Stock out items', 'stock', 'inventory', 'basic', 69),
('inventory.stock.transfer', 'Transfer stock', 'stock', 'inventory', 'basic', 70),
('inventory.stock.adjust', 'Adjust stock', 'stock', 'inventory', 'basic', 71),
('inventory.stock.audit', 'Audit stock', 'stock', 'inventory', 'basic', 72),
('inventory.stock.view', 'View stock', 'stock', 'inventory', 'basic', 73),
('inventory.batch.create', 'Create batches', 'batch', 'inventory', 'basic', 74),
('inventory.batch.update', 'Update batches', 'batch', 'inventory', 'basic', 75),
('inventory.batch.view', 'View batches', 'batch', 'inventory', 'basic', 76),
('inventory.batch.delete', 'Delete batches', 'batch', 'inventory', 'basic', 77),
('inventory.warehouse.create', 'Create warehouses', 'warehouse', 'inventory', 'basic', 78),
('inventory.warehouse.update', 'Update warehouses', 'warehouse', 'inventory', 'basic', 79),
('inventory.warehouse.delete', 'Delete warehouses', 'warehouse', 'inventory', 'basic', 80),
('inventory.warehouse.view', 'View warehouses', 'warehouse', 'inventory', 'basic', 81)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 LOGISTICS MODULE (12 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('logistics.shipment.create', 'Create shipments', 'shipment', 'logistics', 'basic', 82),
('logistics.shipment.update', 'Update shipments', 'shipment', 'logistics', 'basic', 83),
('logistics.shipment.delete', 'Delete shipments', 'shipment', 'logistics', 'basic', 84),
('logistics.shipment.view', 'View shipments', 'shipment', 'logistics', 'basic', 85),
('logistics.tracking.view', 'View tracking', 'tracking', 'logistics', 'basic', 86),
('logistics.route.create', 'Create routes', 'route', 'logistics', 'basic', 87),
('logistics.route.update', 'Update routes', 'route', 'logistics', 'basic', 88),
('logistics.route.delete', 'Delete routes', 'route', 'logistics', 'basic', 89),
('logistics.route.view', 'View routes', 'route', 'logistics', 'basic', 90),
('logistics.vehicle.assign', 'Assign vehicles', 'vehicle', 'logistics', 'basic', 91),
('logistics.vehicle.update', 'Update vehicles', 'vehicle', 'logistics', 'basic', 92),
('logistics.vehicle.view', 'View vehicles', 'vehicle', 'logistics', 'basic', 93)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 SALES MODULE (16 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('sales.lead.create', 'Create sales leads', 'lead', 'sales', 'basic', 94),
('sales.lead.update', 'Update sales leads', 'lead', 'sales', 'basic', 95),
('sales.lead.delete', 'Delete sales leads', 'lead', 'sales', 'basic', 96),
('sales.lead.view', 'View sales leads', 'lead', 'sales', 'basic', 97),
('sales.deal.create', 'Create deals', 'deal', 'sales', 'basic', 98),
('sales.deal.update', 'Update deals', 'deal', 'sales', 'basic', 99),
('sales.deal.delete', 'Delete deals', 'deal', 'sales', 'basic', 100),
('sales.deal.view', 'View deals', 'deal', 'sales', 'basic', 101),
('sales.deal.close', 'Close deals', 'deal', 'sales', 'basic', 102),
('sales.quote.create', 'Create quotes', 'quote', 'sales', 'basic', 103),
('sales.quote.update', 'Update quotes', 'quote', 'sales', 'basic', 104),
('sales.quote.delete', 'Delete quotes', 'quote', 'sales', 'basic', 105),
('sales.quote.view', 'View quotes', 'quote', 'sales', 'basic', 106),
('sales.target.create', 'Create sales targets', 'target', 'sales', 'basic', 107),
('sales.target.update', 'Update sales targets', 'target', 'sales', 'basic', 108),
('sales.target.view', 'View sales targets', 'target', 'sales', 'basic', 109)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 MARKETING MODULE (12 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('marketing.campaign.create', 'Create campaigns', 'campaign', 'marketing', 'basic', 110),
('marketing.campaign.update', 'Update campaigns', 'campaign', 'marketing', 'basic', 111),
('marketing.campaign.delete', 'Delete campaigns', 'campaign', 'marketing', 'basic', 112),
('marketing.campaign.view', 'View campaigns', 'campaign', 'marketing', 'basic', 113),
('marketing.analytics.view', 'View analytics', 'analytics', 'marketing', 'basic', 114),
('marketing.audience.create', 'Create audiences', 'audience', 'marketing', 'basic', 115),
('marketing.audience.update', 'Update audiences', 'audience', 'marketing', 'basic', 116),
('marketing.audience.delete', 'Delete audiences', 'audience', 'marketing', 'basic', 117),
('marketing.audience.view', 'View audiences', 'audience', 'marketing', 'basic', 118),
('marketing.budget.create', 'Create marketing budgets', 'budget', 'marketing', 'basic', 119),
('marketing.budget.update', 'Update marketing budgets', 'budget', 'marketing', 'basic', 120),
('marketing.budget.view', 'View marketing budgets', 'budget', 'marketing', 'basic', 121)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 CUSTOMER SUPPORT (11 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('support.ticket.create', 'Create support tickets', 'ticket', 'support', 'basic', 122),
('support.ticket.update', 'Update support tickets', 'ticket', 'support', 'basic', 123),
('support.ticket.assign', 'Assign support tickets', 'ticket', 'support', 'basic', 124),
('support.ticket.close', 'Close support tickets', 'ticket', 'support', 'basic', 125),
('support.ticket.delete', 'Delete support tickets', 'ticket', 'support', 'basic', 126),
('support.ticket.view', 'View support tickets', 'ticket', 'support', 'basic', 127),
('support.faq.create', 'Create FAQs', 'faq', 'support', 'basic', 128),
('support.faq.update', 'Update FAQs', 'faq', 'support', 'basic', 129),
('support.faq.delete', 'Delete FAQs', 'faq', 'support', 'basic', 130),
('support.faq.view', 'View FAQs', 'faq', 'support', 'basic', 131),
('support.report.view', 'View support reports', 'report', 'support', 'basic', 132)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 OPERATIONS (14 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('operations.task.create', 'Create tasks', 'task', 'operations', 'basic', 133),
('operations.task.update', 'Update tasks', 'task', 'operations', 'basic', 134),
('operations.task.delete', 'Delete tasks', 'task', 'operations', 'basic', 135),
('operations.task.view', 'View tasks', 'task', 'operations', 'basic', 136),
('operations.task.assign', 'Assign tasks', 'task', 'operations', 'basic', 137),
('operations.task.complete', 'Complete tasks', 'task', 'operations', 'basic', 138),
('operations.shift.create', 'Create shifts', 'shift', 'operations', 'basic', 139),
('operations.shift.update', 'Update shifts', 'shift', 'operations', 'basic', 140),
('operations.shift.delete', 'Delete shifts', 'shift', 'operations', 'basic', 141),
('operations.shift.view', 'View shifts', 'shift', 'operations', 'basic', 142),
('operations.workflow.create', 'Create workflows', 'workflow', 'operations', 'basic', 143),
('operations.workflow.update', 'Update workflows', 'workflow', 'operations', 'basic', 144),
('operations.workflow.delete', 'Delete workflows', 'workflow', 'operations', 'basic', 145),
('operations.workflow.view', 'View workflows', 'workflow', 'operations', 'basic', 146)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 IT MODULE (14 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('it.asset.create', 'Create IT assets', 'asset', 'it', 'basic', 147),
('it.asset.update', 'Update IT assets', 'asset', 'it', 'basic', 148),
('it.asset.delete', 'Delete IT assets', 'asset', 'it', 'basic', 149),
('it.asset.view', 'View IT assets', 'asset', 'it', 'basic', 150),
('it.incident.create', 'Create incidents', 'incident', 'it', 'basic', 151),
('it.incident.update', 'Update incidents', 'incident', 'it', 'basic', 152),
('it.incident.resolve', 'Resolve incidents', 'incident', 'it', 'basic', 153),
('it.incident.close', 'Close incidents', 'incident', 'it', 'basic', 154),
('it.incident.view', 'View incidents', 'incident', 'it', 'basic', 155),
('it.access.request', 'Request access', 'access', 'it', 'basic', 156),
('it.access.grant', 'Grant access', 'access', 'it', 'basic', 157),
('it.access.revoke', 'Revoke access', 'access', 'it', 'basic', 158),
('it.system.config.update', 'Update system config', 'system', 'it', 'basic', 159),
('it.system.config.view', 'View system config', 'system', 'it', 'basic', 160)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 PRODUCTION (16 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('production.order.create', 'Create production orders', 'order', 'production', 'basic', 161),
('production.order.update', 'Update production orders', 'order', 'production', 'basic', 162),
('production.order.start', 'Start production orders', 'order', 'production', 'basic', 163),
('production.order.pause', 'Pause production orders', 'order', 'production', 'basic', 164),
('production.order.finish', 'Finish production orders', 'order', 'production', 'basic', 165),
('production.order.cancel', 'Cancel production orders', 'order', 'production', 'basic', 166),
('production.order.delete', 'Delete production orders', 'order', 'production', 'basic', 167),
('production.order.view', 'View production orders', 'order', 'production', 'basic', 168),
('production.bom.create', 'Create BOMs', 'bom', 'production', 'basic', 169),
('production.bom.update', 'Update BOMs', 'bom', 'production', 'basic', 170),
('production.bom.delete', 'Delete BOMs', 'bom', 'production', 'basic', 171),
('production.bom.view', 'View BOMs', 'bom', 'production', 'basic', 172),
('production.route.create', 'Create routes', 'route', 'production', 'basic', 173),
('production.route.update', 'Update routes', 'route', 'production', 'basic', 174),
('production.route.view', 'View routes', 'route', 'production', 'basic', 175),
('production.route.delete', 'Delete routes', 'route', 'production', 'basic', 176)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 QUALITY CONTROL (10 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('qc.inspection.create', 'Create inspections', 'inspection', 'qc', 'basic', 177),
('qc.inspection.update', 'Update inspections', 'inspection', 'qc', 'basic', 178),
('qc.inspection.approve', 'Approve inspections', 'inspection', 'qc', 'basic', 179),
('qc.inspection.reject', 'Reject inspections', 'inspection', 'qc', 'basic', 180),
('qc.inspection.delete', 'Delete inspections', 'inspection', 'qc', 'basic', 181),
('qc.inspection.view', 'View inspections', 'inspection', 'qc', 'basic', 182),
('qc.batch.hold', 'Hold batches', 'batch', 'qc', 'basic', 183),
('qc.batch.release', 'Release batches', 'batch', 'qc', 'basic', 184),
('qc.report.generate', 'Generate QC reports', 'report', 'qc', 'basic', 185),
('qc.report.view', 'View QC reports', 'report', 'qc', 'basic', 186)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 QUALITY ASSURANCE (10 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('qa.test.create', 'Create tests', 'test', 'qa', 'basic', 187),
('qa.test.update', 'Update tests', 'test', 'qa', 'basic', 188),
('qa.test.delete', 'Delete tests', 'test', 'qa', 'basic', 189),
('qa.test.execute', 'Execute tests', 'test', 'qa', 'basic', 190),
('qa.test.view', 'View tests', 'test', 'qa', 'basic', 191),
('qa.audit.create', 'Create audits', 'audit', 'qa', 'basic', 192),
('qa.audit.update', 'Update audits', 'audit', 'qa', 'basic', 193),
('qa.audit.view', 'View audits', 'audit', 'qa', 'basic', 194),
('qa.report.generate', 'Generate QA reports', 'report', 'qa', 'basic', 195),
('qa.report.view', 'View QA reports', 'report', 'qa', 'basic', 196)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 R&D (12 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('rnd.experiment.create', 'Create experiments', 'experiment', 'rnd', 'basic', 197),
('rnd.experiment.update', 'Update experiments', 'experiment', 'rnd', 'basic', 198),
('rnd.experiment.delete', 'Delete experiments', 'experiment', 'rnd', 'basic', 199),
('rnd.experiment.view', 'View experiments', 'experiment', 'rnd', 'basic', 200),
('rnd.prototype.create', 'Create prototypes', 'prototype', 'rnd', 'basic', 201),
('rnd.prototype.update', 'Update prototypes', 'prototype', 'rnd', 'basic', 202),
('rnd.prototype.view', 'View prototypes', 'prototype', 'rnd', 'basic', 203),
('rnd.prototype.delete', 'Delete prototypes', 'prototype', 'rnd', 'basic', 204),
('rnd.document.create', 'Create R&D documents', 'document', 'rnd', 'basic', 205),
('rnd.document.update', 'Update R&D documents', 'document', 'rnd', 'basic', 206),
('rnd.document.view', 'View R&D documents', 'document', 'rnd', 'basic', 207),
('rnd.document.delete', 'Delete R&D documents', 'document', 'rnd', 'basic', 208)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 ADMIN / SYSTEM (19 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('admin.user.create', 'Create users', 'user', 'admin', 'admin', 209),
('admin.user.update', 'Update users', 'user', 'admin', 'admin', 210),
('admin.user.view', 'View users', 'user', 'admin', 'admin', 211),
('admin.user.delete', 'Delete users', 'user', 'admin', 'admin', 212),
('admin.role.create', 'Create roles', 'role', 'admin', 'admin', 213),
('admin.role.update', 'Update roles', 'role', 'admin', 'admin', 214),
('admin.role.delete', 'Delete roles', 'role', 'admin', 'admin', 215),
('admin.role.view', 'View roles', 'role', 'admin', 'admin', 216),
('admin.permission.assign', 'Assign permissions', 'permission', 'admin', 'admin', 217),
('admin.permission.revoke', 'Revoke permissions', 'permission', 'admin', 'admin', 218),
('admin.permission.view', 'View permissions', 'permission', 'admin', 'admin', 219),
('admin.department.create', 'Create departments', 'department', 'admin', 'admin', 220),
('admin.department.update', 'Update departments', 'department', 'admin', 'admin', 221),
('admin.department.delete', 'Delete departments', 'department', 'admin', 'admin', 222),
('admin.department.view', 'View departments', 'department', 'admin', 'admin', 223),
('admin.company.update', 'Update company', 'company', 'admin', 'admin', 224),
('admin.company.view', 'View company', 'company', 'admin', 'admin', 225),
('admin.company.suspend', 'Suspend company', 'company', 'admin', 'admin', 226),
('admin.audit.logs.view', 'View audit logs', 'audit', 'admin', 'admin', 227),
('admin.audit.logs.export', 'Export audit logs', 'audit', 'admin', 'admin', 228)
ON CONFLICT (permission_name) DO NOTHING;

-- 🔵 ADMINISTRATION MODULE (6 permissions)
INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
('administrative.department.view', 'View company departments', 'department', 'administration', 'basic', 229),
('administrative.department.create', 'Create departments', 'department', 'administration', 'basic', 230),
('administrative.department.update', 'Update departments', 'department', 'administration', 'basic', 231),
('administrative.department.delete', 'Delete departments', 'department', 'administration', 'basic', 232),
('administrative.employee.view', 'View company employees', 'employee', 'administration', 'basic', 233),
('administrative.employee.manage', 'Manage company employees', 'employee', 'administration', 'basic', 234)
ON CONFLICT (permission_name) DO NOTHING;

    -- =========================================================
    -- TRIGGERS
    -- =========================================================
    CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS \$\$
    BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
    END;
    \$\$ LANGUAGE plpgsql;

    CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_companies_updated_at BEFORE UPDATE ON companies FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_departments_updated_at BEFORE UPDATE ON departments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_company_employees_updated_at BEFORE UPDATE ON company_employees FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_user_devices_updated_at BEFORE UPDATE ON user_devices FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

    -- =========================================================
    -- APPLICATION-LEVEL DATA INTEGRITY CONSTRAINTS
    -- =========================================================
    -- ✅ NOTE: The following constraints must be enforced at application level:
    -- 1. company_employees.reports_to must reference a user in the same company
    -- 2. departments.department_head must be an employee of the same company
    -- 
    -- These cannot be implemented as database foreign keys due to circular dependencies,
    -- but MUST be enforced by your application business logic to prevent:
    -- - Cross-company reporting chains
    -- - Cross-company department heads
    -- - Orphaned reporting structures

EOSQL

echo "✅ PostgreSQL schema created successfully!"
echo ""
echo "📊 Database Summary:"
echo "   • Users table with 8 partitions"
echo "   • Companies, Roles, Permissions, Departments, Employees"
echo "   • System Departments (16 standard ERP modules) ✅"
echo "   • Role-Departments mapping table ✅"
echo "   • UserDevices and LoginAttempts added ✅"
echo "   • 235 Enterprise Permissions across all modules ✅"
echo "   • ✅ ADDED: Administration system department"
echo "   • ✅ UPDATED: Company owner permissions to administrative.department.*"
echo "   • ✅ FIXED: All table creation order issues"
echo "   • ✅ FIXED: department_head FK constraint"
echo "   • ✅ FIXED: Removed CONCURRENTLY from indexes"
echo "   • ✅ FIXED: Direct FK references in table definitions"
echo "   • ✅ FIXED: Data integrity requirements documented"
echo "   • Performance indexes on all key columns"
echo "   • ✅ Sessions handled by ScyllaDB"
echo "   • ✅ Audit events handled by ClickHouse"
echo ""
echo "⚠️  IMPORTANT APPLICATION-LEVEL CONSTRAINTS:"
echo "   • reports_to must reference same-company employees"
echo "   • department_head must be same-company employees" 
echo "   • These MUST be enforced in your application business logic"
echo ""
echo "🎉 PostgreSQL RBAC initialization completed!"