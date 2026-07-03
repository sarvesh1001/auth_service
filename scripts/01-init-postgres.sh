set -e
echo "🔧 Starting PostgreSQL initialization..."
echo "⏳ Waiting for PostgreSQL to be ready..."
until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
  sleep 2
done
echo "✅ PostgreSQL is ready!"
echo "🏗️ Creating database schema..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE SCHEMA IF NOT EXISTS leave;
CREATE SCHEMA IF NOT EXISTS payroll;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS attendance;
CREATE SCHEMA IF NOT EXISTS biometric;
CREATE SCHEMA IF NOT EXISTS outbox;
CREATE SCHEMA IF NOT EXISTS sales;
CREATE SCHEMA IF NOT EXISTS sales_analytics;
CREATE TABLE IF NOT EXISTS permissions (
    permission_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_name VARCHAR(100) NOT NULL UNIQUE,
    description     TEXT,
    category        VARCHAR(50) NOT NULL,
    module          VARCHAR(50) NOT NULL,
    scope           VARCHAR(20) NOT NULL DEFAULT 'user',
    requires_tier   VARCHAR(20) DEFAULT 'basic',
    bit_index       INTEGER UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS system_departments (
    system_department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 VARCHAR(255) UNIQUE NOT NULL,
    module_code          VARCHAR(100) NOT NULL,
    description          TEXT,
    bitmask              BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_roles (
    admin_role_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name       VARCHAR(100) NOT NULL,
    role_level      INTEGER NOT NULL DEFAULT 1000,
    role_type       INTEGER NOT NULL DEFAULT 1,
    is_system_role  BOOLEAN NOT NULL DEFAULT false,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(role_name),
    CONSTRAINT check_role_type CHECK (role_type IN (1, 2, 4)),
    CONSTRAINT unique_super_admin_role EXCLUDE USING btree (role_type WITH =) WHERE (role_type = 4)
);
CREATE TABLE IF NOT EXISTS admin_role_permissions (
    admin_role_id  UUID NOT NULL,
    permission_id  UUID NOT NULL,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by     UUID NOT NULL,
    PRIMARY KEY (admin_role_id, permission_id),
    CONSTRAINT fk_admin_role_perms_role FOREIGN KEY (admin_role_id) REFERENCES admin_roles(admin_role_id) ON DELETE CASCADE,
    CONSTRAINT fk_admin_role_perms_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS admin_role_departments (
    admin_role_id        UUID NOT NULL,
    system_department_id UUID NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (admin_role_id, system_department_id),
    CONSTRAINT fk_admin_role_departments_role FOREIGN KEY (admin_role_id) REFERENCES admin_roles(admin_role_id) ON DELETE CASCADE,
    CONSTRAINT fk_admin_role_departments_department FOREIGN KEY (system_department_id) REFERENCES system_departments(system_department_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash            VARCHAR(128) NOT NULL,
    phone_encrypted       BYTEA NOT NULL,
    phone_key_id          UUID NOT NULL,
    phone_encrypted_dek   TEXT NOT NULL,
    admin_role_id         UUID NOT NULL,
    role_type             INTEGER NOT NULL DEFAULT 1,
    reports_to            UUID REFERENCES admin_users(admin_id),
    admin_created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    admin_created_by      UUID,
    admin_updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active             BOOLEAN NOT NULL DEFAULT true,
    data_access_scope     TEXT[],
    ip_whitelist          TEXT[],
    failed_login_attempts INTEGER DEFAULT 0,
    last_login            TIMESTAMPTZ,
    username              VARCHAR(100) NOT NULL UNIQUE,
    full_name             VARCHAR(255),
    user_search_tsv       TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('simple', COALESCE(username, '')) ||
        to_tsvector('simple', COALESCE(full_name, ''))
    ) STORED,
    CONSTRAINT fk_admin_users_role FOREIGN KEY (admin_role_id) REFERENCES admin_roles(admin_role_id),
    CONSTRAINT check_admin_role_type CHECK (role_type IN (1, 2, 4)),
    CONSTRAINT unique_super_admin_user EXCLUDE USING btree (role_type WITH =) WHERE (role_type = 4)
);
CREATE TABLE IF NOT EXISTS users (
    user_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username         VARCHAR(100) NOT NULL,
    full_name        VARCHAR(255),
    user_search_tsv  TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('simple', COALESCE(username, '')) ||
        to_tsvector('simple', COALESCE(full_name, ''))
    ) STORED,
    phone_hash       VARCHAR(128) NOT NULL,
    phone_encrypted  BYTEA NOT NULL,
    phone_encrypted_dek TEXT NOT NULL,
    phone_key_id     UUID NOT NULL,
    device_id        VARCHAR(256),
    device_fingerprint VARCHAR(512),
    kyc_status       VARCHAR(50) NOT NULL DEFAULT 'pending',
    kyc_level        VARCHAR(20) NOT NULL DEFAULT 'basic',
    kyc_verified_at  TIMESTAMPTZ,
    is_verified      BOOLEAN NOT NULL DEFAULT false,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    data_region      VARCHAR(20) NOT NULL DEFAULT 'us',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login       TIMESTAMPTZ,
    CONSTRAINT unique_username UNIQUE (user_id, username)
) PARTITION BY HASH (user_id);
CREATE TABLE IF NOT EXISTS users_p0 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE IF NOT EXISTS users_p1 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE IF NOT EXISTS users_p2 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE IF NOT EXISTS users_p3 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE IF NOT EXISTS users_p4 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE IF NOT EXISTS users_p5 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE IF NOT EXISTS users_p6 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE IF NOT EXISTS users_p7 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 7);
CREATE TABLE IF NOT EXISTS companies (
    company_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_name            VARCHAR(255) NOT NULL,
    company_name_tsv        TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', company_name)) STORED,
    owner_user_id           UUID NOT NULL,
    subscription_tier       VARCHAR(20) NOT NULL DEFAULT 'basic',
    subscription_status     VARCHAR(20) NOT NULL DEFAULT 'active',
    max_employees           INTEGER NOT NULL DEFAULT 10,
    max_departments         INTEGER NOT NULL DEFAULT 5,
    data_region             VARCHAR(10) NOT NULL DEFAULT 'us',
    is_active               BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    subscription_start_date TIMESTAMPTZ,
    subscription_end_date   TIMESTAMPTZ,
    financial_year_start_month INT NOT NULL DEFAULT 4
        CHECK (financial_year_start_month BETWEEN 1 AND 12),
    UNIQUE(company_name, owner_user_id),
    CONSTRAINT fk_companies_owner FOREIGN KEY (owner_user_id) REFERENCES users(user_id),
    CONSTRAINT check_max_departments CHECK (max_departments > 0 AND max_departments <= 1000)
);
CREATE TABLE IF NOT EXISTS roles (
    role_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name       VARCHAR(100) NOT NULL,
    role_level      INTEGER NOT NULL DEFAULT 1000,
    company_id      UUID NOT NULL,
    is_system_role  BOOLEAN NOT NULL DEFAULT false,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, role_name),
    CONSTRAINT fk_roles_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       UUID NOT NULL,
    permission_id UUID NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by    UUID NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_perms_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_role_perms_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS departments (
    department_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    department_name      VARCHAR(255) NOT NULL,
    system_department_id UUID,
    parent_department_id UUID,
    is_active            BOOLEAN NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_departments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_departments_system FOREIGN KEY (system_department_id) REFERENCES system_departments(system_department_id),
    CONSTRAINT fk_departments_parent FOREIGN KEY (parent_department_id) REFERENCES departments(department_id)
);
CREATE TABLE IF NOT EXISTS role_departments (
    role_id       UUID NOT NULL,
    department_id UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, department_id),
    CONSTRAINT fk_role_departments_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_role_departments_department FOREIGN KEY (department_id) REFERENCES departments(department_id)
);
CREATE TABLE IF NOT EXISTS company_employees (
    company_id  UUID NOT NULL,
    user_id     UUID NOT NULL,
    employee_id VARCHAR(100) NOT NULL,
    role_id     UUID NOT NULL,
    hire_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active   BOOLEAN NOT NULL DEFAULT true,
    reports_to  UUID,
    position_id UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (company_id, user_id),
    CONSTRAINT fk_employees_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_employees_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_employees_role FOREIGN KEY (role_id) REFERENCES roles(role_id)
);
CREATE TABLE IF NOT EXISTS user_devices (
    device_id    VARCHAR(256) PRIMARY KEY,
    user_id      UUID NOT NULL,
    device_type  VARCHAR(50),
    device_name  VARCHAR(100),
    os_version   VARCHAR(50),
    app_version  VARCHAR(50),
    last_active  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active    BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user_devices_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL,
    success       BOOLEAN NOT NULL,
    ip_address    VARCHAR(64),
    user_agent    TEXT,
    device_id     VARCHAR(256),
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    failure_reason TEXT,
    CONSTRAINT fk_login_attempts_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_login_attempts_device FOREIGN KEY (device_id) REFERENCES user_devices(device_id)
);
CREATE TABLE IF NOT EXISTS employee_profiles (
    employee_profile_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL,
    company_id          UUID NOT NULL,
    date_of_birth       DATE,
    gender              VARCHAR(20),
    marital_status      VARCHAR(20),
    nationality         VARCHAR(50),
    employment_type     VARCHAR(30),
    employment_status   VARCHAR(30) NOT NULL DEFAULT 'active',
    probation_end_date  DATE,
    confirmation_date   DATE,
    job_title           VARCHAR(255),
    grade               VARCHAR(50),
    cost_center         VARCHAR(50),
    tax_id              VARCHAR(50),
    social_security_id  VARCHAR(50),
    email               VARCHAR(255),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (company_id, user_id),
    CONSTRAINT chk_employment_status CHECK (employment_status IN ('active','notice','terminated','on_hold')),
    CONSTRAINT fk_employee_profile_membership FOREIGN KEY (company_id, user_id)
        REFERENCES company_employees (company_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS employee_department_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL,
    company_id    UUID NOT NULL,
    department_id UUID NOT NULL,
    start_date    DATE NOT NULL,
    end_date      DATE,
    change_reason TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (department_id) REFERENCES departments(department_id)
);
CREATE TABLE IF NOT EXISTS employee_documents (
    document_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL,
    company_id          UUID NOT NULL,
    document_type       VARCHAR(50),
    document_name       VARCHAR(255),
    document_object_key TEXT NOT NULL,
    mime_type           VARCHAR(50),
    is_confidential     BOOLEAN DEFAULT false,
    uploaded_by         UUID,
    uploaded_at         TIMESTAMPTZ DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS positions (
    position_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    department_id        UUID NOT NULL,
    title                VARCHAR(255),
    is_open              BOOLEAN DEFAULT true,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    updated_at           TIMESTAMPTZ DEFAULT NOW(),
    is_schedulable       BOOLEAN NOT NULL DEFAULT true,
    attendance_required  BOOLEAN NOT NULL DEFAULT true,
    overtime_allowed     BOOLEAN NOT NULL DEFAULT false,
    work_center_code     VARCHAR(100),
    CONSTRAINT uniq_position_title_per_dept UNIQUE (company_id, department_id, title),
    FOREIGN KEY (department_id) REFERENCES departments(department_id)
);
CREATE TABLE IF NOT EXISTS employee_role_history (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL,
    role_id    UUID NOT NULL,
    start_date DATE,
    end_date   DATE,
    reason     TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);
CREATE TABLE IF NOT EXISTS employee_exit (
    exit_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL,
    company_id       UUID NOT NULL,
    exit_date        DATE NOT NULL,
    exit_reason      TEXT,
    eligible_for_rehire BOOLEAN DEFAULT false,
    exit_state       VARCHAR(20) NOT NULL DEFAULT 'scheduled',
    enforced_at      TIMESTAMPTZ,
    enforced_by      UUID,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT chk_exit_state CHECK (
        exit_state IN ('scheduled','effective','cancelled','rehired')
    ),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS leave.leave_type (
    leave_type_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    code                TEXT NOT NULL,
    name                TEXT NOT NULL,
    is_paid             BOOLEAN NOT NULL DEFAULT true,
    requires_approval   BOOLEAN NOT NULL DEFAULT true,
    accrual_method      TEXT NOT NULL,
    carry_forward_limit INT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_leave_type_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT uq_leave_type_company_code UNIQUE (company_id, code)
);
CREATE TABLE IF NOT EXISTS leave.leave_policy (
    policy_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id                  UUID NOT NULL,
    policy_name                 TEXT NOT NULL,
    applies_to_type             TEXT NOT NULL,
    applies_to_id               TEXT,
    applies_to_position_id      UUID,
    applies_to_work_center_code TEXT,
    priority                    INT NOT NULL DEFAULT 100,
    effective_from              DATE NOT NULL,
    effective_to                DATE,
    is_active                   BOOLEAN NOT NULL DEFAULT true,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_leave_policy_scope CHECK (applies_to_type IN ('position','work_center','org_unit','company')),
    CONSTRAINT fk_leave_policy_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_leave_policy_position FOREIGN KEY (applies_to_position_id) REFERENCES positions(position_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS leave.leave_policy_rule (
    policy_rule_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id            UUID NOT NULL,
    leave_type_id        UUID NOT NULL,
    total_days           INT NOT NULL,
    accrual_method       TEXT NOT NULL,
    carry_forward_limit  INT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_lpr_policy FOREIGN KEY (policy_id) REFERENCES leave.leave_policy(policy_id) ON DELETE CASCADE,
    CONSTRAINT fk_lpr_leave_type FOREIGN KEY (leave_type_id) REFERENCES leave.leave_type(leave_type_id) ON DELETE CASCADE,
    CONSTRAINT chk_lpr_accrual_method CHECK (accrual_method IN ('monthly','quarterly','yearly','none')),
    UNIQUE (policy_id, leave_type_id)
);
CREATE TABLE IF NOT EXISTS leave.leave_entitlement (
    entitlement_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    leave_type_id    UUID NOT NULL,
    policy_id        UUID,
    source           TEXT NOT NULL DEFAULT 'policy',
    total_days       INT NOT NULL,
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    position_id      UUID,
    work_center_code TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_leave_entitlement_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_leave_entitlement_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_leave_entitlement_type FOREIGN KEY (leave_type_id) REFERENCES leave.leave_type(leave_type_id),
    CONSTRAINT fk_leave_entitlement_policy FOREIGN KEY (policy_id) REFERENCES leave.leave_policy(policy_id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS leave.leave_accrual (
    accrual_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entitlement_id   UUID NOT NULL,
    accrual_date     DATE NOT NULL,
    days_accrued     INT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fractional_days  DECIMAL(10,4) DEFAULT 0.0,
    cumulative_balance DECIMAL(10,4) GENERATED ALWAYS AS (days_accrued::DECIMAL + fractional_days) STORED,
    CONSTRAINT fk_leave_accrual_entitlement FOREIGN KEY (entitlement_id) REFERENCES leave.leave_entitlement(entitlement_id) ON DELETE CASCADE,
    CONSTRAINT unique_entitlement_accrual_date UNIQUE (entitlement_id, accrual_date)
);
CREATE TABLE IF NOT EXISTS leave.leave_request (
    leave_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    leave_type_id    UUID NOT NULL,
    start_date       DATE NOT NULL,
    end_date         DATE NOT NULL,
    total_days       INT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    requested_by     UUID,
    approved_by      UUID,
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at      TIMESTAMPTZ,
    CONSTRAINT fk_leave_request_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_leave_request_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_leave_request_type FOREIGN KEY (leave_type_id) REFERENCES leave.leave_type(leave_type_id),
    CONSTRAINT check_status CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled'))
);
CREATE TABLE IF NOT EXISTS leave.leave_ledger (
    ledger_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entitlement_id   UUID NOT NULL,
    leave_request_id UUID,
    entry_type       TEXT NOT NULL,
    days             INT NOT NULL,
    entry_date       DATE NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_leave_ledger_entitlement FOREIGN KEY (entitlement_id) REFERENCES leave.leave_entitlement(entitlement_id) ON DELETE CASCADE,
    CONSTRAINT fk_leave_ledger_request FOREIGN KEY (leave_request_id) REFERENCES leave.leave_request(leave_request_id) ON DELETE SET NULL,
    CONSTRAINT check_entry_type CHECK (entry_type IN ('accrual', 'consumption', 'reversal'))
);
CREATE TABLE IF NOT EXISTS leave.leave_balance_snapshot (
    snapshot_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entitlement_id UUID NOT NULL,
    balance_days   INT NOT NULL,
    calculated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_lbs_entitlement FOREIGN KEY (entitlement_id) REFERENCES leave.leave_entitlement(entitlement_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS leave.leave_policy_resolution (
    resolution_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id    UUID NOT NULL,
    user_id       UUID NOT NULL,
    policy_id     UUID,
    resolved_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason        TEXT,
    metadata      JSONB,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS payroll.payroll_component (
    company_id        UUID,
    component_code    VARCHAR(50) NOT NULL,
    component_type    VARCHAR(40) NOT NULL
        CHECK (component_type IN ('earning','deduction')),
    description       TEXT,
    is_taxable        BOOLEAN NOT NULL DEFAULT false,
    is_system         BOOLEAN NOT NULL DEFAULT false,
    is_active         BOOLEAN NOT NULL DEFAULT true,
    contribution_side VARCHAR(20) DEFAULT 'none'
        CHECK (contribution_side IN ('employee','employer','none')),
    CONSTRAINT payroll_component_component_code_unique
        UNIQUE (component_code)
);
CREATE TABLE IF NOT EXISTS payroll.payroll_tax_profile (
    profile_name   VARCHAR(100) NOT NULL,
    country_code   VARCHAR(10) NOT NULL,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS payroll.attendance_rule (
    rule_id UUID NOT NULL,
    company_id UUID NOT NULL,
    rule_type VARCHAR(50) NOT NULL,
    calculation_type VARCHAR(50) NOT NULL,
    value NUMERIC(10,4) NOT NULL,
    based_on VARCHAR(50),
    threshold_minutes INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now() NOT NULL,
    created_by UUID,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    updated_by UUID,
    component_code VARCHAR(50),
    CONSTRAINT attendance_rule_pkey
        PRIMARY KEY (rule_id),
    CONSTRAINT fk_attendance_rule_company
        FOREIGN KEY (company_id)
        REFERENCES public.companies(company_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_attendance_rule_component
        FOREIGN KEY (component_code)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT fk_attendance_rule_created_by
        FOREIGN KEY (created_by)
        REFERENCES public.users(user_id),
    CONSTRAINT fk_attendance_rule_updated_by
        FOREIGN KEY (updated_by)
        REFERENCES public.users(user_id)
);
CREATE INDEX IF NOT EXISTS idx_attendance_rule_company
ON payroll.attendance_rule(company_id, is_active);
CREATE TABLE IF NOT EXISTS payroll.payroll_run (
    payroll_run_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    period_start     DATE NOT NULL,
    period_end       DATE NOT NULL,
    status           VARCHAR(20) NOT NULL CHECK (
        status IN ('draft','processing','executing','calculated','approved','paid','failed','partially_processed')
    ),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    total_employees  INT,
    processed_count  INT DEFAULT 0,
    failed_count     INT DEFAULT 0,
    last_processed_at TIMESTAMPTZ,
    CONSTRAINT fk_payroll_run_company FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS payroll.employee_fine (
    fine_id UUID NOT NULL,
    company_id UUID NOT NULL,
    user_id UUID NOT NULL,
    fine_amount NUMERIC(12,2) NOT NULL,
    reason TEXT NOT NULL,
    fine_date DATE NOT NULL,
    is_processed BOOLEAN DEFAULT false NOT NULL,
    payroll_run_id UUID,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now() NOT NULL,
    created_by UUID NOT NULL,
    component_code VARCHAR(50),
    CONSTRAINT employee_fine_pkey PRIMARY KEY (fine_id),
    CONSTRAINT fk_employee_fine_company
        FOREIGN KEY (company_id)
        REFERENCES public.companies(company_id),
    CONSTRAINT fk_employee_fine_user
        FOREIGN KEY (user_id)
        REFERENCES public.users(user_id),
    CONSTRAINT fk_employee_fine_created_by
        FOREIGN KEY (created_by)
        REFERENCES public.users(user_id),
    CONSTRAINT fk_employee_fine_payroll_run
        FOREIGN KEY (payroll_run_id)
        REFERENCES payroll.payroll_run(payroll_run_id),
    CONSTRAINT fk_employee_fine_component
        FOREIGN KEY (component_code)
        REFERENCES payroll.payroll_component(component_code)
);
CREATE INDEX IF NOT EXISTS idx_employee_fine_user
ON payroll.employee_fine(company_id, user_id, is_processed);
CREATE TABLE IF NOT EXISTS payroll.payroll_tax_rule (
    tax_rule_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_code   VARCHAR(50) NOT NULL,
    calculation_type VARCHAR(20) NOT NULL,
    rule_definition  JSONB,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS payroll.statutory_rule_set (
    rule_set_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL,
    country_code    VARCHAR(10) NOT NULL,
    version_label   VARCHAR(50) NOT NULL,
    effective_from  DATE NOT NULL,
    effective_to    DATE,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,
    UNIQUE(company_id, country_code, effective_from),
    CONSTRAINT fk_rule_set_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT no_overlapping_rulesets EXCLUDE USING gist (
        company_id WITH =,
        country_code WITH =,
        daterange(effective_from, COALESCE(effective_to, 'infinity'), '[]') WITH &&
    )
);
CREATE TABLE IF NOT EXISTS payroll.statutory_component_definition (
    company_id       UUID NOT NULL,
    statutory_code   VARCHAR(50) NOT NULL,
    description      TEXT,
    country_code     VARCHAR(10) NOT NULL,
    calculation_basis VARCHAR(30) NOT NULL
        CHECK (calculation_basis IN ('basic','gross','ctc','taxable_income')),
    has_employee_contribution BOOLEAN NOT NULL DEFAULT true,
    has_employer_contribution BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active        BOOLEAN NOT NULL DEFAULT true,
    deactivated_at   TIMESTAMPTZ,
    deactivated_by   UUID,
    PRIMARY KEY (company_id, statutory_code),
    CONSTRAINT fk_scd_company
        FOREIGN KEY (company_id)
        REFERENCES companies(company_id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payroll.statutory_component_mapping (
    mapping_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    statutory_code   VARCHAR(50) NOT NULL,
    component_code   VARCHAR(50) NOT NULL,
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    deactivated_at   TIMESTAMPTZ,
    deactivated_by   UUID,
    version          INT NOT NULL DEFAULT 1,
    rule_set_id      UUID,
    CONSTRAINT fk_scm_company
        FOREIGN KEY (company_id)
        REFERENCES public.companies(company_id),
    CONSTRAINT fk_scm_component
        FOREIGN KEY (component_code)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT fk_scm_ruleset
        FOREIGN KEY (rule_set_id)
        REFERENCES payroll.statutory_rule_set(rule_set_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_scm_definition
        FOREIGN KEY (company_id, statutory_code)
        REFERENCES payroll.statutory_component_definition(company_id, statutory_code)
        ON DELETE CASCADE,
    UNIQUE (company_id, statutory_code, component_code, effective_from)
);
CREATE TABLE IF NOT EXISTS payroll.statutory_contribution_rule (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id    UUID NOT NULL,
    rule_set_id   UUID NOT NULL,
    statutory_code VARCHAR(50) NOT NULL,
    contribution_side VARCHAR(20) NOT NULL
        CHECK (contribution_side IN ('employee','employer')),
    calculation_type VARCHAR(20) NOT NULL
        CHECK (calculation_type IN ('percentage','fixed','slab')),
    rate_value NUMERIC(10,4),
    wage_ceiling NUMERIC(14,2),
    min_threshold NUMERIC(14,2),
    effective_from DATE NOT NULL,
    effective_to   DATE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    deactivated_at TIMESTAMPTZ,
    deactivated_by UUID,
    CONSTRAINT fk_scr_company
        FOREIGN KEY (company_id)
        REFERENCES companies(company_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_scr_ruleset
        FOREIGN KEY (rule_set_id)
        REFERENCES payroll.statutory_rule_set(rule_set_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_scr_component
        FOREIGN KEY (company_id, statutory_code)
        REFERENCES payroll.statutory_component_definition(company_id, statutory_code)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payroll.company_tax_slab (
    slab_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    statutory_code VARCHAR(50) NOT NULL,
    min_income     NUMERIC(14,2) NOT NULL,
    max_income     NUMERIC(14,2),
    tax_percentage NUMERIC(5,2) NOT NULL,
    slab_order     INT NOT NULL DEFAULT 1,
    is_percentage  BOOLEAN NOT NULL DEFAULT true,
    effective_from DATE NOT NULL,
    effective_to   DATE,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    created_by     UUID,
    deactivated_at TIMESTAMPTZ,
    deactivated_by UUID,
    updated_at     TIMESTAMPTZ DEFAULT NOW(),
    updated_by     UUID,
    version        INT NOT NULL DEFAULT 1,
    rule_set_id    UUID NOT NULL,
    CONSTRAINT fk_tax_slab_company
        FOREIGN KEY (company_id)
        REFERENCES companies(company_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_tax_slab_ruleset
        FOREIGN KEY (rule_set_id)
        REFERENCES payroll.statutory_rule_set(rule_set_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_tax_slab_definition
        FOREIGN KEY (company_id, statutory_code)
        REFERENCES payroll.statutory_component_definition(company_id, statutory_code)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payroll.employee_statutory_profile (
    profile_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    statutory_code   VARCHAR(50) NOT NULL,
    opt_in           BOOLEAN NOT NULL DEFAULT true,
    special_category VARCHAR(50),
    regime           VARCHAR(20),
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    deactivated_at   TIMESTAMPTZ,
    deactivated_by   UUID,
    version          INT NOT NULL DEFAULT 1,
    rule_set_id      UUID,
    CONSTRAINT fk_esp_company
        FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_esp_user
        FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_esp_ruleset
        FOREIGN KEY (rule_set_id) REFERENCES payroll.statutory_rule_set(rule_set_id) ON DELETE CASCADE,
    CONSTRAINT fk_esp_definition
        FOREIGN KEY (company_id, statutory_code)
        REFERENCES payroll.statutory_component_definition(company_id, statutory_code)
        ON DELETE CASCADE,
    UNIQUE (company_id, user_id, statutory_code, effective_from),
    CONSTRAINT no_overlapping_statutory_profiles EXCLUDE USING gist (
        company_id WITH =,
        user_id WITH =,
        statutory_code WITH =,
        daterange(effective_from, COALESCE(effective_to, 'infinity'), '[]') WITH &&
    ) WHERE (is_active = true)
);
CREATE TABLE IF NOT EXISTS payroll.statutory_deduction_limit (
    limit_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  UUID NOT NULL,
    rule_set_id UUID NOT NULL,
    limit_code  VARCHAR(50) NOT NULL,
    limit_value NUMERIC(14,2) NOT NULL,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_limit_company
        FOREIGN KEY (company_id)
        REFERENCES companies(company_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_limit_ruleset
        FOREIGN KEY (rule_set_id)
        REFERENCES payroll.statutory_rule_set(rule_set_id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payroll.company_statutory_profile (
    profile_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id                  UUID NOT NULL,
    country_code                VARCHAR(10) NOT NULL,
    financial_year_start_month  INT NOT NULL DEFAULT 4,
    supports_multiple_regimes   BOOLEAN DEFAULT false,
    created_at                  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id),
    CONSTRAINT fk_stat_profile_company FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS payroll.salary_structure (
    salary_structure_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    structure_name      VARCHAR(150) NOT NULL,
    currency_code       VARCHAR(10) NOT NULL DEFAULT 'INR',
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    created_by          UUID,
    version             INT NOT NULL DEFAULT 1,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by          UUID,
    deactivated_at      TIMESTAMPTZ,
    deactivated_by      UUID,
    CONSTRAINT fk_salary_structure_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    UNIQUE(company_id, structure_name)
);
CREATE TABLE IF NOT EXISTS payroll.salary_structure_component (
    mapping_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    salary_structure_id  UUID NOT NULL,
    company_id           UUID NOT NULL,
    component_code       VARCHAR(50) NOT NULL,
    calculation_type     VARCHAR(20) NOT NULL
        CHECK (calculation_type IN ('fixed','percentage')),
    value                NUMERIC(12,4) NOT NULL,
    based_on_component   VARCHAR(50),
    sequence_order       INTEGER DEFAULT 1,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_structure_component
        UNIQUE (salary_structure_id, component_code),
    CONSTRAINT fk_ssc_structure
        FOREIGN KEY (salary_structure_id)
        REFERENCES payroll.salary_structure(salary_structure_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_ssc_component
        FOREIGN KEY (component_code)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT fk_ssc_based_on_component
        FOREIGN KEY (based_on_component)
        REFERENCES payroll.payroll_component(component_code)
);
CREATE TABLE IF NOT EXISTS payroll.employee_salary (
    employee_salary_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    user_id              UUID NOT NULL,
    salary_structure_id  UUID NOT NULL,
    monthly_ctc          NUMERIC(14,2) NOT NULL,
    effective_from       DATE NOT NULL,
    effective_to         DATE,
    is_active            BOOLEAN DEFAULT true,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    version              INT NOT NULL DEFAULT 1,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by           UUID,
    deactivated_at       TIMESTAMPTZ,
    deactivated_by       UUID,
    pay_type             VARCHAR(20) NOT NULL DEFAULT 'monthly' CHECK (pay_type IN ('monthly','daily_wage','hourly')),
    CONSTRAINT fk_emp_salary_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_emp_salary_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_emp_salary_structure FOREIGN KEY (salary_structure_id) REFERENCES payroll.salary_structure(salary_structure_id)
);
CREATE TABLE IF NOT EXISTS payroll.company_statutory_config (
    company_statutory_config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id                  UUID NOT NULL,
    effective_from              DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_to                DATE,
    is_active                   BOOLEAN NOT NULL DEFAULT true,
    deactivated_at              TIMESTAMPTZ,
    deactivated_by              UUID,
    created_by                  UUID,
    version                     INT NOT NULL DEFAULT 1,
    CONSTRAINT fk_csc_company FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS payroll.payroll_item (
    payroll_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payroll_run_id  UUID NOT NULL,
    user_id         UUID NOT NULL,
    payable_days    NUMERIC(5,2) NOT NULL,
    unpaid_days     NUMERIC(5,2) NOT NULL,
    gross_amount    NUMERIC(12,2) NOT NULL,
    net_amount      NUMERIC(12,2) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version         INT NOT NULL DEFAULT 1,
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_by      UUID,
    version_number  INT NOT NULL DEFAULT 1,
    is_superseded   BOOLEAN NOT NULL DEFAULT FALSE,
    superseded_at   TIMESTAMP NULL,
    superseded_by   UUID NULL,
    CONSTRAINT fk_payroll_item_run FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE,
    CONSTRAINT fk_payroll_item_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS payroll.payroll_ledger (
    ledger_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payroll_item_id UUID NOT NULL,
    company_id      UUID NOT NULL,
    component_code  VARCHAR(50) NOT NULL,
    amount          NUMERIC(12,2) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ledger_item
        FOREIGN KEY (payroll_item_id)
        REFERENCES payroll.payroll_item(payroll_item_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_ledger_component
        FOREIGN KEY (component_code)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT uq_payroll_ledger_item_component
        UNIQUE (payroll_item_id, component_code)
);
CREATE TABLE IF NOT EXISTS payroll.payroll_snapshot (
    snapshot_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payroll_run_id UUID NOT NULL,
    company_id     UUID NOT NULL,
    snapshot_type  VARCHAR(30) NOT NULL CHECK (snapshot_type IN ('run','item','salary','tax','statutory','employee_full_snapshot')),
    snapshot_data  JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     UUID NOT NULL,
    rule_set_id    UUID,
    rule_hash      TEXT,
    CONSTRAINT fk_snapshot_run FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payroll.payroll_period_lock (
    lock_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id    UUID NOT NULL,
    period_start  DATE NOT NULL,
    period_end    DATE NOT NULL,
    locked_by     UUID,
    locked_at     TIMESTAMPTZ DEFAULT NOW(),
    reason        TEXT,
    CONSTRAINT fk_period_lock_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    UNIQUE(company_id, period_start, period_end),
    CONSTRAINT no_overlap_payroll_period_lock EXCLUDE USING gist (
        company_id WITH =,
        daterange(period_start, period_end, '[]') WITH &&
    )
);
CREATE TABLE IF NOT EXISTS payroll.payroll_adjustment (
    adjustment_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL,
    user_id         UUID NOT NULL,
    component_code  VARCHAR(50) NOT NULL,
    amount          NUMERIC(12,2) NOT NULL,
    adjustment_type VARCHAR(20)
        CHECK (adjustment_type IN ('addition','deduction')),
    reason          TEXT,
    applicable_month DATE NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    created_by      UUID,
    CONSTRAINT fk_adjust_company
        FOREIGN KEY (company_id)
        REFERENCES public.companies(company_id),
    CONSTRAINT fk_adjust_component
        FOREIGN KEY (component_code)
        REFERENCES payroll.payroll_component(component_code)
);
CREATE TABLE IF NOT EXISTS payroll.payslip_template (
    template_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    template_name       VARCHAR(150),
    footer_declaration  TEXT,
    authorized_signatory VARCHAR(150),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_template_company FOREIGN KEY (company_id) REFERENCES companies(company_id)
);
CREATE TABLE IF NOT EXISTS payroll.employee_statutory_contribution (
    contribution_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    statutory_code   VARCHAR(50) NOT NULL,
    period_start     DATE NOT NULL,
    period_end       DATE NOT NULL,
    employee_amount  NUMERIC(12,2) NOT NULL,
    employer_amount  NUMERIC(12,2) NOT NULL,
    total_amount     NUMERIC(12,2) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_esc_definition
        FOREIGN KEY (company_id, statutory_code)
        REFERENCES payroll.statutory_component_definition(company_id, statutory_code)
        ON DELETE CASCADE,
    CONSTRAINT fk_esc_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id),
    CONSTRAINT uniq_employee_statutory_period
        UNIQUE (
            company_id,
            user_id,
            statutory_code,
            period_start,
            period_end
        )
);
CREATE TABLE IF NOT EXISTS user_avatars (
    avatar_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL,
    avatar_type       VARCHAR(20) NOT NULL DEFAULT 'uploaded',
    avatar_hash       VARCHAR(128),
    avatar_object_key TEXT NOT NULL,
    avatar_mime_type  VARCHAR(50),
    is_active         BOOLEAN NOT NULL DEFAULT true,
    is_primary        BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user_avatars_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT uq_user_primary_avatar UNIQUE (user_id, is_primary)
);
CREATE TABLE IF NOT EXISTS admin_avatars (
    avatar_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id          UUID NOT NULL,
    avatar_type       VARCHAR(20) NOT NULL DEFAULT 'uploaded',
    avatar_hash       VARCHAR(128),
    avatar_object_key TEXT NOT NULL,
    avatar_mime_type  VARCHAR(50),
    is_active         BOOLEAN NOT NULL DEFAULT true,
    is_primary        BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_admin_avatars_admin FOREIGN KEY (admin_id) REFERENCES admin_users(admin_id) ON DELETE CASCADE,
    CONSTRAINT uq_admin_primary_avatar UNIQUE (admin_id, is_primary)
);
CREATE TABLE IF NOT EXISTS audit.audit_logs (
    audit_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID,
    module       VARCHAR(50) NOT NULL,
    action       VARCHAR(100) NOT NULL,
    entity_type  VARCHAR(50) NOT NULL,
    entity_id    UUID,
    actor_type   VARCHAR(20) NOT NULL,
    actor_id     UUID,
    before_state JSONB,
    after_state  JSONB,
    metadata     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit.audit_logs_outbox (
    outbox_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id     UUID NOT NULL,
    operation    VARCHAR(10) NOT NULL,
    payload      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    error_message TEXT
);
CREATE TABLE IF NOT EXISTS audit.outbox_debounce (
    debounce_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    last_processed_id  UUID,
    last_processed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    batch_size         INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS org_units (
    org_unit_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    org_unit_type  VARCHAR(30) NOT NULL,
    name           VARCHAR(255) NOT NULL,
    description    TEXT,
    department_id  UUID,
    is_active      BOOLEAN DEFAULT true,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    updated_at     TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_org_units_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_org_units_department FOREIGN KEY (department_id) REFERENCES departments(department_id)
);
CREATE TABLE IF NOT EXISTS org_unit_members (
    org_unit_id    UUID NOT NULL,
    user_id        UUID NOT NULL,
    effective_from DATE NOT NULL,
    effective_to   DATE,
    PRIMARY KEY (org_unit_id, user_id, effective_from),
    CONSTRAINT fk_oum_org_unit FOREIGN KEY (org_unit_id) REFERENCES org_units(org_unit_id) ON DELETE CASCADE,
    CONSTRAINT fk_oum_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS org_unit_roles (
    org_unit_id    UUID NOT NULL,
    user_id        UUID NOT NULL,
    role           VARCHAR(30) NOT NULL,
    position_id    UUID,
    effective_from DATE NOT NULL,
    effective_to   DATE,
    PRIMARY KEY (org_unit_id, user_id, role, effective_from),
    CONSTRAINT fk_our_org_unit FOREIGN KEY (org_unit_id) REFERENCES org_units(org_unit_id) ON DELETE CASCADE,
    CONSTRAINT fk_our_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_our_position FOREIGN KEY (position_id) REFERENCES positions(position_id)
);
CREATE TABLE payroll.employee_bank_details (
    bank_detail_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(user_id),
    account_holder   VARCHAR(255) NOT NULL,
    account_number           TEXT NOT NULL,
    account_number_dek       TEXT NOT NULL,
    account_number_key_id    TEXT NOT NULL,
    ifsc_code                TEXT NOT NULL,
    ifsc_code_dek            TEXT NOT NULL,
    ifsc_code_key_id         TEXT NOT NULL,
    bank_name        VARCHAR(255),
    branch           VARCHAR(255),
    account_type     VARCHAR(20),
    is_active        BOOLEAN NOT NULL DEFAULT true,
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (company_id, user_id, effective_from)
);
CREATE TABLE IF NOT EXISTS payroll.payslip (
    payslip_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payroll_run_id   UUID NOT NULL REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(user_id),
    pdf_object_key   TEXT NOT NULL,
    generated_at     TIMESTAMPTZ DEFAULT NOW(),
    sent_at          TIMESTAMPTZ,
    CONSTRAINT uq_payslip_run_user UNIQUE (payroll_run_id, user_id)
);
CREATE TABLE IF NOT EXISTS payroll.employee_loan (
    loan_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES companies(company_id),
    user_id          UUID NOT NULL REFERENCES users(user_id),
    loan_type        VARCHAR(20) NOT NULL,
    principal_amount NUMERIC(14,2) NOT NULL,
    emi_amount       NUMERIC(14,2) NOT NULL,
    interest_rate    NUMERIC(5,2),
    total_emis       INT NOT NULL,
    emis_paid        INT NOT NULL DEFAULT 0,
    disbursed_at     DATE NOT NULL,
    first_emi_date   DATE NOT NULL,
    closure_date     DATE,
    status           VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    created_by       UUID REFERENCES users(user_id),
    component_code   VARCHAR(50),
    interest_type    VARCHAR(20) DEFAULT 'flat',
    tenure_months    INT,
    outstanding_balance NUMERIC(14,2),
    penalty_rate     NUMERIC(5,2) DEFAULT 0,
    allow_partial_payment BOOLEAN DEFAULT true,
    CONSTRAINT fk_employee_loan_component FOREIGN KEY (component_code) REFERENCES payroll.payroll_component(component_code)
);
CREATE TABLE IF NOT EXISTS payroll.emi_transaction (
    emi_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    loan_id          UUID NOT NULL REFERENCES payroll.employee_loan(loan_id) ON DELETE CASCADE,
    due_date         DATE NOT NULL,
    paid_date        DATE,
    amount           NUMERIC(14,2) NOT NULL,
    payroll_run_id   UUID REFERENCES payroll.payroll_run(payroll_run_id),
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    penalty_amount   NUMERIC(10,2) DEFAULT 0,
    paid_amount      NUMERIC(10,2),
    remaining_amount NUMERIC(10,2),
    payment_status   VARCHAR(20) DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS payroll.arrears (
    arrears_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    payroll_run_id   UUID,
    effective_from   DATE NOT NULL,
    effective_to     DATE NOT NULL,
    amount           NUMERIC(14,2) NOT NULL,
    reason           TEXT,
    processed        BOOLEAN DEFAULT false,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    component_code   VARCHAR(50),
    CONSTRAINT fk_arrears_component FOREIGN KEY (component_code) REFERENCES payroll.payroll_component(component_code)
);
CREATE TABLE IF NOT EXISTS payroll.tax_declaration_type (
    company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    type_code        VARCHAR(50) NOT NULL,
    description      TEXT,
    max_limit        NUMERIC(14,2),
    is_active        BOOLEAN DEFAULT true,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (company_id, type_code)
);
CREATE TABLE IF NOT EXISTS payroll.tax_declaration (
    declaration_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES companies(company_id),
    user_id          UUID NOT NULL REFERENCES users(user_id),
    financial_year   VARCHAR(9) NOT NULL,
    declaration_type VARCHAR(50) NOT NULL,
    amount           NUMERIC(14,2) NOT NULL,
    supporting_docs  TEXT[],
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    submitted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at      TIMESTAMPTZ,
    verified_by      UUID REFERENCES users(user_id),
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_tax_declaration_type FOREIGN KEY (company_id, declaration_type)
        REFERENCES payroll.tax_declaration_type(company_id, type_code)
);
CREATE TABLE IF NOT EXISTS payroll.company_payroll_settings (
    company_id                UUID PRIMARY KEY
        REFERENCES companies(company_id) ON DELETE CASCADE,
    default_fine_component    VARCHAR(50),
    default_arrears_component VARCHAR(50),
    default_loan_component    VARCHAR(50),
    default_basic_component   VARCHAR(50),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_default_fine_component
        FOREIGN KEY (default_fine_component)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT fk_default_arrears_component
        FOREIGN KEY (default_arrears_component)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT fk_default_loan_component
        FOREIGN KEY (default_loan_component)
        REFERENCES payroll.payroll_component(component_code),
    CONSTRAINT fk_default_basic_component
        FOREIGN KEY (default_basic_component)
        REFERENCES payroll.payroll_component(component_code)
);
CREATE TABLE IF NOT EXISTS payroll.payroll_job (
    job_id UUID PRIMARY KEY,
    company_id UUID NOT NULL,
    payroll_run_id UUID NOT NULL,
    status TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    priority INT DEFAULT 5,
    retry_count INT DEFAULT 0,
    max_retries INT DEFAULT 3,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    next_run_at TIMESTAMPTZ DEFAULT NOW(),
    locked_by TEXT,
    locked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payroll.loan_payment (
    payment_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    loan_id           UUID NOT NULL REFERENCES payroll.employee_loan(loan_id) ON DELETE CASCADE,
    emi_id            UUID REFERENCES payroll.emi_transaction(emi_id) ON DELETE SET NULL,
    amount            NUMERIC(14,2) NOT NULL CHECK (amount > 0),
    penalty           NUMERIC(14,2) DEFAULT 0 CHECK (penalty >= 0),
    paid_at           TIMESTAMPTZ NOT NULL,
    source            VARCHAR(20) NOT NULL CHECK (source IN ('payroll','manual','adjustment')),
    payroll_run_id    UUID REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_admin_users_search_tsv ON admin_users USING GIN (user_search_tsv);
CREATE INDEX IF NOT EXISTS idx_admin_users_username_trgm ON admin_users USING GIN (username gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_admin_users_fullname_trgm ON admin_users USING GIN (full_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users (admin_role_id) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_admin_users_role_type ON admin_users (role_type) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_admin_users_role_type_role ON admin_users (role_type, admin_role_id) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_admin_users_phone_hash ON admin_users (phone_hash);
CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users (username);
CREATE INDEX IF NOT EXISTS idx_admin_users_role_active_login ON admin_users (admin_role_id, is_active, last_login DESC);
CREATE INDEX IF NOT EXISTS idx_admin_roles_name ON admin_roles (role_name);
CREATE INDEX IF NOT EXISTS idx_admin_roles_level ON admin_roles (role_level);
CREATE INDEX IF NOT EXISTS idx_admin_roles_type ON admin_roles (role_type);
CREATE INDEX IF NOT EXISTS idx_admin_role_perms_role ON admin_role_permissions (admin_role_id);
CREATE INDEX IF NOT EXISTS idx_admin_role_perms_permission ON admin_role_permissions (permission_id);
CREATE INDEX IF NOT EXISTS idx_admin_role_departments_role ON admin_role_departments (admin_role_id);
CREATE INDEX IF NOT EXISTS idx_admin_role_departments_dept ON admin_role_departments (system_department_id);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions (permission_name);
CREATE INDEX IF NOT EXISTS idx_permissions_bit_index ON permissions (bit_index);
CREATE INDEX IF NOT EXISTS idx_permissions_module ON permissions (module);
CREATE INDEX IF NOT EXISTS idx_permissions_scope ON permissions (scope);
CREATE INDEX IF NOT EXISTS idx_system_departments_name ON system_departments (name);
CREATE INDEX IF NOT EXISTS idx_system_departments_module ON system_departments (module_code);
CREATE INDEX IF NOT EXISTS idx_system_departments_bitmask ON system_departments (bitmask);
CREATE INDEX IF NOT EXISTS idx_departments_company_active ON departments (company_id) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_departments_parent_active ON departments (parent_department_id) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_departments_company ON departments (company_id);
CREATE INDEX IF NOT EXISTS idx_departments_parent ON departments (parent_department_id);
CREATE INDEX IF NOT EXISTS idx_departments_system ON departments (system_department_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_departments_company_name_active ON departments (company_id, department_name) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_users_search_tsv ON users USING GIN (user_search_tsv);
CREATE INDEX IF NOT EXISTS idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_users_fullname_trgm ON users USING GIN (full_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_fullname ON users (full_name);
CREATE INDEX IF NOT EXISTS idx_users_name_search ON users (username, full_name);
CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users (phone_hash);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at);
CREATE INDEX IF NOT EXISTS idx_users_status ON users (is_active, kyc_status);
CREATE INDEX IF NOT EXISTS idx_users_region ON users (data_region);
CREATE INDEX IF NOT EXISTS idx_users_kyc_status ON users(kyc_status);
CREATE INDEX IF NOT EXISTS idx_companies_name_tsv ON companies USING GIN (company_name_tsv);
CREATE INDEX IF NOT EXISTS idx_companies_name_trgm ON companies USING GIN (company_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_companies_name ON companies (company_name);
CREATE INDEX IF NOT EXISTS idx_companies_owner_name ON companies (owner_user_id, company_name);
CREATE INDEX IF NOT EXISTS idx_companies_owner ON companies (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_companies_status ON companies (is_active, subscription_status);
CREATE INDEX IF NOT EXISTS idx_companies_region ON companies (data_region);
CREATE INDEX IF NOT EXISTS idx_roles_company ON roles (company_id);
CREATE INDEX IF NOT EXISTS idx_roles_level ON roles (role_level);
CREATE INDEX IF NOT EXISTS idx_role_perms_permission ON role_permissions (permission_id);
CREATE INDEX IF NOT EXISTS idx_employees_user ON company_employees (user_id);
CREATE INDEX IF NOT EXISTS idx_employees_role ON company_employees (role_id);
CREATE INDEX IF NOT EXISTS idx_employees_active ON company_employees (is_active);
CREATE INDEX IF NOT EXISTS idx_employees_company_active ON company_employees (company_id, is_active);
CREATE INDEX IF NOT EXISTS idx_employees_reports_to ON company_employees (company_id, reports_to);
CREATE INDEX IF NOT EXISTS idx_company_employees_position ON company_employees (position_id) WHERE position_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_role_departments_role ON role_departments (role_id);
CREATE INDEX IF NOT EXISTS idx_role_departments_department ON role_departments (department_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices (user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_active ON user_devices (is_active);
CREATE INDEX IF NOT EXISTS idx_user_devices_last_active ON user_devices (last_active);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts (user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_device ON login_attempts (device_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_success ON login_attempts (success);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts (attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_employee_profiles_user ON employee_profiles (user_id);
CREATE INDEX IF NOT EXISTS idx_employee_profiles_company ON employee_profiles (company_id);
CREATE INDEX IF NOT EXISTS idx_employee_profiles_employment_status ON employee_profiles (employment_status) WHERE employment_status = 'active';
CREATE INDEX IF NOT EXISTS idx_employee_department_history_user ON employee_department_history (user_id);
CREATE INDEX IF NOT EXISTS idx_employee_department_history_dept ON employee_department_history (department_id);
CREATE INDEX IF NOT EXISTS idx_employee_department_history_dates ON employee_department_history (start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_employee_documents_user ON employee_documents (user_id);
CREATE INDEX IF NOT EXISTS idx_employee_documents_company ON employee_documents (company_id);
CREATE INDEX IF NOT EXISTS idx_employee_documents_type ON employee_documents (document_type);
CREATE INDEX IF NOT EXISTS idx_positions_company ON positions (company_id);
CREATE INDEX IF NOT EXISTS idx_positions_department ON positions (department_id);
CREATE INDEX IF NOT EXISTS idx_positions_open ON positions (is_open) WHERE is_open = true;
CREATE INDEX IF NOT EXISTS idx_positions_work_center ON positions (company_id, work_center_code) WHERE work_center_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_employee_role_history_user ON employee_role_history (user_id);
CREATE INDEX IF NOT EXISTS idx_employee_role_history_role ON employee_role_history (role_id);
CREATE INDEX IF NOT EXISTS idx_employee_exit_user ON employee_exit (user_id);
CREATE INDEX IF NOT EXISTS idx_employee_exit_company ON employee_exit (company_id);
CREATE INDEX IF NOT EXISTS idx_employee_exit_date ON employee_exit (exit_date);
CREATE INDEX IF NOT EXISTS idx_leave_type_company ON leave.leave_type (company_id);
CREATE INDEX IF NOT EXISTS idx_leave_type_code ON leave.leave_type (code);
CREATE INDEX IF NOT EXISTS idx_leave_type_accrual_method ON leave.leave_type (accrual_method);
CREATE INDEX IF NOT EXISTS idx_leave_entitlement_company_user ON leave.leave_entitlement (company_id, user_id);
CREATE INDEX IF NOT EXISTS idx_leave_entitlement_user ON leave.leave_entitlement (user_id);
CREATE INDEX IF NOT EXISTS idx_leave_entitlement_leave_type ON leave.leave_entitlement (leave_type_id);
CREATE INDEX IF NOT EXISTS idx_leave_entitlement_dates ON leave.leave_entitlement (effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_leave_entitlement_current ON leave.leave_entitlement (user_id, leave_type_id) WHERE effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_leave_accrual_entitlement ON leave.leave_accrual (entitlement_id);
CREATE INDEX IF NOT EXISTS idx_leave_accrual_date ON leave.leave_accrual (accrual_date);
CREATE INDEX IF NOT EXISTS idx_leave_accrual_entitlement_date ON leave.leave_accrual (entitlement_id, accrual_date);
CREATE INDEX IF NOT EXISTS idx_leave_request_company_user ON leave.leave_request (company_id, user_id);
CREATE INDEX IF NOT EXISTS idx_leave_request_user ON leave.leave_request (user_id);
CREATE INDEX IF NOT EXISTS idx_leave_request_leave_type ON leave.leave_request (leave_type_id);
CREATE INDEX IF NOT EXISTS idx_leave_request_status ON leave.leave_request (status);
CREATE INDEX IF NOT EXISTS idx_leave_request_dates ON leave.leave_request (start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_leave_request_requested_at ON leave.leave_request (requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_leave_request_pending ON leave.leave_request (company_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_leave_request_approved_by ON leave.leave_request (approved_by) WHERE approved_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_leave_request_date_range ON leave.leave_request USING gist (daterange(start_date, end_date, '[]'));
CREATE INDEX IF NOT EXISTS idx_leave_ledger_entitlement ON leave.leave_ledger (entitlement_id);
CREATE INDEX IF NOT EXISTS idx_leave_ledger_request ON leave.leave_ledger (leave_request_id);
CREATE INDEX IF NOT EXISTS idx_leave_ledger_entry_date ON leave.leave_ledger (entry_date);
CREATE INDEX IF NOT EXISTS idx_leave_ledger_entry_type ON leave.leave_ledger (entry_type);
CREATE INDEX IF NOT EXISTS idx_leave_ledger_entitlement_date ON leave.leave_ledger (entitlement_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_leave_ledger_request_type ON leave.leave_ledger (leave_request_id, entry_type) WHERE leave_request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_leave_balance_snapshot_entitlement ON leave.leave_balance_snapshot (entitlement_id);
CREATE INDEX IF NOT EXISTS idx_payroll_run_company ON payroll.payroll_run (company_id);
CREATE INDEX IF NOT EXISTS idx_payroll_run_status ON payroll.payroll_run (status) WHERE status IN ('draft','calculated');
CREATE INDEX IF NOT EXISTS idx_payroll_run_period ON payroll.payroll_run (period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_payroll_run_created_at ON payroll.payroll_run (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payroll_item_user ON payroll.payroll_item (user_id);
CREATE INDEX IF NOT EXISTS idx_payroll_item_run ON payroll.payroll_item (payroll_run_id);
CREATE INDEX IF NOT EXISTS idx_payroll_item_created_at ON payroll.payroll_item (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payroll_component_type ON payroll.payroll_component (component_type);
CREATE INDEX IF NOT EXISTS idx_payroll_component_taxable ON payroll.payroll_component (is_taxable) WHERE is_taxable = true;
CREATE INDEX IF NOT EXISTS idx_payroll_component_system ON payroll.payroll_component (is_system) WHERE is_system = true;
CREATE INDEX IF NOT EXISTS idx_payroll_ledger_component ON payroll.payroll_ledger (component_code);
CREATE INDEX IF NOT EXISTS idx_payroll_ledger_created_at ON payroll.payroll_ledger (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payroll_ledger_item_component ON payroll.payroll_ledger (payroll_item_id, component_code);
CREATE INDEX IF NOT EXISTS idx_payroll_tax_profile_country ON payroll.payroll_tax_profile (country_code);
CREATE INDEX IF NOT EXISTS idx_payroll_tax_profile_active ON payroll.payroll_tax_profile (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_payroll_tax_profile_created_at ON payroll.payroll_tax_profile (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payroll_tax_rule_component ON payroll.payroll_tax_rule (component_code);
CREATE INDEX IF NOT EXISTS idx_payroll_tax_rule_type ON payroll.payroll_tax_rule (calculation_type);
CREATE INDEX IF NOT EXISTS idx_org_units_company ON org_units (company_id, org_unit_type) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_oum_user_active ON org_unit_members (user_id) WHERE effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_our_user_active ON org_unit_roles (user_id) WHERE effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_company_time ON audit.audit_logs (company_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_module_action ON audit.audit_logs (module, action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit.audit_logs (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_outbox_unprocessed ON audit.audit_logs_outbox (created_at) WHERE processed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_employee_active_department ON employee_department_history (user_id) WHERE end_date IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_employee_role_active ON employee_role_history (user_id) WHERE end_date IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_employee_exit_active ON employee_exit (company_id, user_id) WHERE exit_state IN ('scheduled','effective');
CREATE INDEX IF NOT EXISTS idx_user_avatars_user_active ON user_avatars (user_id) WHERE is_active = true AND is_primary = true;
CREATE INDEX IF NOT EXISTS idx_user_avatars_hash ON user_avatars (avatar_hash);
CREATE INDEX IF NOT EXISTS idx_admin_avatars_admin_active ON admin_avatars (admin_id) WHERE is_active = true AND is_primary = true;
CREATE INDEX IF NOT EXISTS idx_admin_avatars_hash ON admin_avatars (avatar_hash);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_entitlement_per_leave ON leave.leave_entitlement (company_id, user_id, leave_type_id, source) WHERE effective_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_leave_policy_scope_priority ON leave.leave_policy (company_id, applies_to_type, priority, is_active);
CREATE INDEX IF NOT EXISTS idx_payroll_snapshot_run ON payroll.payroll_snapshot(payroll_run_id);
CREATE INDEX IF NOT EXISTS idx_payroll_snapshot_company ON payroll.payroll_snapshot(company_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_leave_policy_position ON leave.leave_policy (company_id, applies_to_position_id) WHERE applies_to_type = 'position' AND is_active = true;
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_leave_policy_work_center ON leave.leave_policy (company_id, applies_to_work_center_code) WHERE applies_to_type = 'work_center' AND is_active = true;
CREATE INDEX IF NOT EXISTS idx_leave_policy_company_active ON leave.leave_policy (company_id, is_active);
CREATE INDEX IF NOT EXISTS idx_leave_policy_position ON leave.leave_policy (applies_to_position_id);
CREATE INDEX IF NOT EXISTS idx_leave_policy_work_center ON leave.leave_policy (applies_to_work_center_code);
CREATE INDEX IF NOT EXISTS idx_employee_salary_version ON payroll.employee_salary (employee_salary_id, version);
CREATE INDEX IF NOT EXISTS idx_employee_salary_range ON payroll.employee_salary USING GIST (daterange(effective_from, COALESCE(effective_to, 'infinity'), '[]'));
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_salary ON payroll.employee_salary (company_id, user_id) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_employee_salary_active_lookup ON payroll.employee_salary (company_id, user_id, effective_from) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_salary_structure_components_lookup ON payroll.salary_structure_component (salary_structure_id, sequence_order);
CREATE INDEX IF NOT EXISTS idx_salary_structure_version ON payroll.salary_structure (salary_structure_id, version);
CREATE INDEX IF NOT EXISTS idx_tax_slab_lookup ON payroll.company_tax_slab (company_id, statutory_code, effective_from);
CREATE INDEX IF NOT EXISTS idx_emp_stat_profile_lookup ON payroll.employee_statutory_profile (company_id, user_id, effective_from);
CREATE INDEX IF NOT EXISTS idx_payroll_period_lock_range ON payroll.payroll_period_lock USING GIST (company_id, daterange(period_start, period_end, '[]'));
CREATE INDEX IF NOT EXISTS idx_payroll_adjustment_lookup ON payroll.payroll_adjustment(company_id, user_id, applicable_month);
CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_item_run_user ON payroll.payroll_item(payroll_run_id, user_id) WHERE is_superseded = FALSE;
CREATE INDEX IF NOT EXISTS idx_emp_stat_profile_active_range ON payroll.employee_statutory_profile USING gist (company_id, user_id, statutory_code, daterange(effective_from, effective_to));
CREATE INDEX IF NOT EXISTS idx_payroll_period_lock_company_range ON payroll.payroll_period_lock (company_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_scr_lookup ON payroll.statutory_contribution_rule (company_id, statutory_code, contribution_side, effective_from);
CREATE INDEX IF NOT EXISTS idx_scr_ruleset ON payroll.statutory_contribution_rule (rule_set_id);
CREATE INDEX IF NOT EXISTS idx_scd_company ON payroll.statutory_component_definition (company_id);
CREATE INDEX IF NOT EXISTS idx_loan_payment_loan ON payroll.loan_payment(loan_id);
CREATE INDEX IF NOT EXISTS idx_loan_payment_emi ON payroll.loan_payment(emi_id);
CREATE INDEX IF NOT EXISTS idx_loan_payment_payroll_run ON payroll.loan_payment(payroll_run_id);
CREATE INDEX IF NOT EXISTS idx_loan_payment_paid_at ON payroll.loan_payment(paid_at);
CREATE INDEX IF NOT EXISTS idx_emi_loan_due_status ON payroll.emi_transaction (loan_id, due_date) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_emi_user_period ON payroll.emi_transaction (due_date) WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS uq_payroll_job_active_run ON payroll.payroll_job(payroll_run_id) WHERE status IN ('queued','processing');
CREATE INDEX IF NOT EXISTS idx_payroll_job_worker_poll ON payroll.payroll_job(status, next_run_at, priority DESC);
CREATE INDEX IF NOT EXISTS idx_payroll_item_run_active ON payroll.payroll_item(payroll_run_id) WHERE is_superseded = FALSE;
CREATE INDEX IF NOT EXISTS idx_payroll_ledger_item ON payroll.payroll_ledger(payroll_item_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_statutory_contribution_rule_active ON payroll.statutory_contribution_rule (company_id, statutory_code, contribution_side, effective_from, rule_set_id) WHERE is_active = true;
CREATE UNIQUE INDEX IF NOT EXISTS uq_company_tax_slab_active ON payroll.company_tax_slab (company_id, statutory_code, min_income, max_income, effective_from, rule_set_id) WHERE is_active = true;
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'admin_users' THEN
        NEW.admin_updated_at = NOW();
    ELSIF TG_TABLE_NAME = 'admin_roles' THEN
        NEW.updated_at = NOW();
    ELSE
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION update_admin_user_search_tsv()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.username IS DISTINCT FROM OLD.username OR NEW.full_name IS DISTINCT FROM OLD.full_name THEN
        NEW.user_search_tsv = to_tsvector('simple', COALESCE(NEW.username, '')) ||
                              to_tsvector('simple', COALESCE(NEW.full_name, ''));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION update_user_search_tsv()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.username IS DISTINCT FROM OLD.username OR NEW.full_name IS DISTINCT FROM OLD.full_name THEN
        NEW.user_search_tsv = to_tsvector('simple', COALESCE(NEW.username, '')) ||
                              to_tsvector('simple', COALESCE(NEW.full_name, ''));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION update_company_name_tsv()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.company_name IS DISTINCT FROM OLD.company_name THEN
        NEW.company_name_tsv = to_tsvector('simple', NEW.company_name);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION audit.audit_logs_outbox_trigger()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.audit_logs_outbox (audit_id, operation, payload)
    VALUES (
        NEW.audit_id,
        'INSERT',
        jsonb_build_object(
            'audit_id', NEW.audit_id,
            'company_id', NEW.company_id,
            'module', NEW.module,
            'action', NEW.action,
            'entity_type', NEW.entity_type,
            'entity_id', NEW.entity_id,
            'actor_type', NEW.actor_type,
            'actor_id', NEW.actor_id,
            'before_state', NEW.before_state,
            'after_state', NEW.after_state,
            'metadata', NEW.metadata,
            'created_at', NEW.created_at
        )
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION enforce_department_limit()
RETURNS TRIGGER AS $$
DECLARE
    current_dept_count INTEGER;
    max_dept_allowed INTEGER;
BEGIN
    PERFORM 1 FROM companies WHERE company_id = NEW.company_id FOR UPDATE;
    SELECT COUNT(*) INTO current_dept_count FROM departments WHERE company_id = NEW.company_id AND is_active = true;
    SELECT max_departments INTO max_dept_allowed FROM companies WHERE company_id = NEW.company_id;
    IF max_dept_allowed > 1000 THEN max_dept_allowed := 1000; END IF;
    IF TG_OP = 'INSERT' THEN
        IF current_dept_count >= max_dept_allowed THEN
            RAISE EXCEPTION 'Department limit exceeded (%)', max_dept_allowed USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.is_active = false AND NEW.is_active = true THEN
            IF current_dept_count >= max_dept_allowed THEN
                RAISE EXCEPTION 'Department limit exceeded (%)', max_dept_allowed USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION deactivate_child_departments(p_dept_id UUID)
RETURNS VOID AS $$
DECLARE
    child_id UUID;
BEGIN
    FOR child_id IN SELECT department_id FROM departments WHERE parent_department_id = p_dept_id AND is_active = true LOOP
        UPDATE departments SET is_active = false WHERE department_id = child_id;
        PERFORM deactivate_child_departments(child_id);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION cascade_department_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_active = true AND NEW.is_active = false THEN
        PERFORM deactivate_child_departments(OLD.department_id);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION prevent_child_on_inactive_parent()
RETURNS TRIGGER AS $$
DECLARE
    parent_active BOOLEAN;
BEGIN
    IF NEW.parent_department_id IS NOT NULL THEN
        SELECT is_active INTO parent_active FROM departments WHERE department_id = NEW.parent_department_id;
        IF parent_active IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'Cannot create or activate department under inactive or missing parent';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.is_active = false AND NEW.is_active = true AND NEW.parent_department_id IS NOT NULL THEN
        SELECT is_active INTO parent_active FROM departments WHERE department_id = NEW.parent_department_id;
        IF parent_active IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'Cannot activate department under inactive parent';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION enforce_unique_active_department_name()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_active = true THEN
        IF EXISTS (
            SELECT 1 FROM departments
            WHERE company_id = NEW.company_id AND department_name = NEW.department_name
              AND is_active = true AND department_id <> NEW.department_id
        ) THEN
            RAISE EXCEPTION 'Active department name already exists';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION prevent_department_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Hard delete of departments is not allowed';
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION enforce_employee_limit()
RETURNS TRIGGER AS $$
DECLARE
    active_count INTEGER;
    max_allowed INTEGER;
BEGIN
    IF (TG_OP = 'INSERT' AND NEW.is_active = true) OR (TG_OP = 'UPDATE' AND OLD.is_active = false AND NEW.is_active = true) THEN
        SELECT max_employees INTO max_allowed FROM companies WHERE company_id = NEW.company_id FOR UPDATE;
        SELECT COUNT(*) INTO active_count FROM company_employees WHERE company_id = NEW.company_id AND is_active = true;
        IF active_count + 1 > max_allowed THEN
            RAISE EXCEPTION 'Employee limit exceeded (%/%). Deactivate another employee.', active_count + 1, max_allowed;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_active_employee_count(p_company_id UUID)
RETURNS INTEGER AS $$
DECLARE total INTEGER;
BEGIN
    SELECT COUNT(*) INTO total FROM company_employees WHERE company_id = p_company_id AND is_active = true;
    RETURN total;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION prevent_position_in_inactive_department()
RETURNS TRIGGER AS $$
DECLARE
    dept_active BOOLEAN;
BEGIN
    SELECT is_active INTO dept_active FROM departments WHERE department_id = NEW.department_id;
    IF dept_active = false THEN
        RAISE EXCEPTION 'Cannot assign position to inactive department';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION close_positions_on_department_deactivate()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_active = true AND NEW.is_active = false THEN
        UPDATE positions SET is_open = false WHERE department_id = OLD.department_id AND is_open = true;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION sync_employee_department_on_position()
RETURNS TRIGGER AS $$
DECLARE
    new_department_id UUID;
BEGIN
    IF NEW.position_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT department_id INTO new_department_id FROM positions WHERE position_id = NEW.position_id;
    UPDATE employee_department_history SET end_date = CURRENT_DATE
    WHERE user_id = NEW.user_id AND company_id = NEW.company_id AND end_date IS NULL;
    INSERT INTO employee_department_history (user_id, company_id, department_id, start_date, change_reason)
    VALUES (NEW.user_id, NEW.company_id, new_department_id, CURRENT_DATE,
            CASE WHEN TG_OP = 'INSERT' THEN 'initial position assignment' ELSE 'position change' END);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION sync_employee_role_history()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE employee_role_history SET end_date = CURRENT_DATE WHERE user_id = NEW.user_id AND end_date IS NULL;
    INSERT INTO employee_role_history (user_id, role_id, start_date, reason)
    VALUES (NEW.user_id, NEW.role_id, CURRENT_DATE,
            CASE WHEN TG_OP = 'INSERT' THEN 'initial role assignment' ELSE 'role change' END);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION enforce_scheduled_employee_exits(
    p_effective_date DATE DEFAULT CURRENT_DATE,
    p_enforced_by UUID DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE affected_count INTEGER := 0;
BEGIN
    UPDATE employee_exit SET exit_state = 'effective', enforced_at = NOW(), enforced_by = p_enforced_by
    WHERE exit_state = 'scheduled' AND exit_date <= p_effective_date;
    GET DIAGNOSTICS affected_count = ROW_COUNT;
    UPDATE company_employees ce SET is_active = false
    FROM employee_exit ee WHERE ce.company_id = ee.company_id AND ce.user_id = ee.user_id AND ee.exit_state = 'effective' AND ce.is_active = true;
    UPDATE employee_profiles ep SET employment_status = 'terminated', updated_at = NOW()
    FROM employee_exit ee WHERE ep.company_id = ee.company_id AND ep.user_id = ee.user_id AND ee.exit_state = 'effective' AND ep.employment_status <> 'terminated';
    RETURN affected_count;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION mark_employee_rehired(
    p_company_id UUID,
    p_user_id UUID
)
RETURNS VOID AS $$
BEGIN
    UPDATE employee_exit SET exit_state = 'rehired' WHERE company_id = p_company_id AND user_id = p_user_id AND exit_state = 'effective';
    UPDATE company_employees SET is_active = true WHERE company_id = p_company_id AND user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION prevent_exit_for_inactive_employee()
RETURNS TRIGGER AS $$
DECLARE active_status BOOLEAN;
BEGIN
    SELECT is_active INTO active_status FROM company_employees WHERE company_id = NEW.company_id AND user_id = NEW.user_id;
    IF active_status IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Cannot create exit for inactive employee';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION search_admin_users(
    search_query_param TEXT DEFAULT NULL,
    role_type_filter_param INTEGER DEFAULT NULL,
    include_inactive_param BOOLEAN DEFAULT false,
    search_type_param TEXT DEFAULT 'autocomplete',
    limit_count_param INTEGER DEFAULT 50,
    offset_count_param INTEGER DEFAULT 0
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    role_name VARCHAR(100),
    admin_role_id UUID,
    role_type INTEGER,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ,
    admin_created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
BEGIN
    IF search_query_param = '' THEN
        search_query_param := NULL;
    END IF;
    IF search_query_param IS NULL THEN
        RETURN QUERY
        SELECT
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, au.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            1.0::FLOAT as relevance_score,
            'all'::TEXT as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        WHERE
            (role_type_filter_param IS NULL OR au.role_type = role_type_filter_param)
            AND (include_inactive_param OR au.is_active = true)
        ORDER BY ar.role_level DESC, au.username ASC
        LIMIT limit_count_param
        OFFSET offset_count_param;
    ELSIF search_type_param = 'autocomplete' OR LENGTH(search_query_param) < 3 THEN
        RETURN QUERY
        SELECT
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, au.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            GREATEST(
                COALESCE(similarity(au.username, search_query_param)::FLOAT, 0),
                COALESCE(similarity(au.full_name, search_query_param)::FLOAT, 0)
            ) as relevance_score,
            'autocomplete'::TEXT as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        WHERE
            (au.username ILIKE '%' || search_query_param || '%'
            OR au.full_name ILIKE '%' || search_query_param || '%')
            AND (role_type_filter_param IS NULL OR au.role_type = role_type_filter_param)
            AND (include_inactive_param OR au.is_active = true)
        ORDER BY relevance_score DESC, ar.role_level DESC, au.username ASC
        LIMIT limit_count_param
        OFFSET offset_count_param;
    ELSE
        RETURN QUERY
        SELECT
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, au.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            ts_rank(au.user_search_tsv, plainto_tsquery('simple', search_query_param))::FLOAT as relevance_score,
            'fulltext'::TEXT as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
        WHERE
            au.user_search_tsv @@ plainto_tsquery('simple', search_query_param)
            AND (role_type_filter_param IS NULL OR au.role_type = role_type_filter_param)
            AND (include_inactive_param OR au.is_active = true)
        ORDER BY relevance_score DESC, ar.role_level DESC, au.username ASC
        LIMIT limit_count_param
        OFFSET offset_count_param;
    END IF;
    RETURN;
END;
$$ LANGUAGE plpgsql STABLE;
CREATE OR REPLACE FUNCTION search_admin_users_by_role_type(
    role_type_param INTEGER,
    search_query TEXT DEFAULT NULL,
    search_type TEXT DEFAULT 'autocomplete',
    include_inactive BOOLEAN DEFAULT false,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    role_name VARCHAR(100),
    admin_role_id UUID,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ,
    admin_created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM search_admin_users(
        search_query,
        role_type_param,
        include_inactive,
        search_type,
        limit_count,
        offset_count
    );
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION search_admin_employees(
    search_query TEXT DEFAULT NULL,
    search_type TEXT DEFAULT 'autocomplete',
    include_inactive BOOLEAN DEFAULT false,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    role_name VARCHAR(100),
    admin_role_id UUID,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ,
    admin_created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM search_admin_users_by_role_type(
        1,
        search_query,
        search_type,
        include_inactive,
        limit_count,
        offset_count
    );
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION search_admin_managers(
    search_query TEXT DEFAULT NULL,
    search_type TEXT DEFAULT 'autocomplete',
    include_inactive BOOLEAN DEFAULT false,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    role_name VARCHAR(100),
    admin_role_id UUID,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ,
    admin_created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM search_admin_users_by_role_type(
        2,
        search_query,
        search_type,
        include_inactive,
        limit_count,
        offset_count
    );
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION search_super_admins(
    search_query TEXT DEFAULT NULL,
    search_type TEXT DEFAULT 'autocomplete',
    include_inactive BOOLEAN DEFAULT false,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    role_name VARCHAR(100),
    admin_role_id UUID,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ,
    admin_created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM search_admin_users_by_role_type(
        4,
        search_query,
        search_type,
        include_inactive,
        limit_count,
        offset_count
    );
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_admin_with_permissions(
    admin_id_param UUID
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    role_name VARCHAR(100),
    role_level INTEGER,
    role_type INTEGER,
    permissions JSONB,
    departments JSONB,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    WITH admin_perms AS (
        SELECT
            arp.admin_role_id,
            jsonb_agg(
                jsonb_build_object(
                    'permission_id', p.permission_id,
                    'permission_name', p.permission_name,
                    'description', p.description,
                    'category', p.category,
                    'module', p.module,
                    'scope', p.scope,
                    'bit_index', p.bit_index
                )
            ) as permissions
        FROM admin_role_permissions arp
        JOIN permissions p ON arp.permission_id = p.permission_id
        GROUP BY arp.admin_role_id
    ),
    admin_depts AS (
        SELECT
            ard.admin_role_id,
            jsonb_agg(
                jsonb_build_object(
                    'department_id', sd.system_department_id,
                    'name', sd.name,
                    'module_code', sd.module_code,
                    'description', sd.description,
                    'bitmask', sd.bitmask
                )
            ) as departments
        FROM admin_role_departments ard
        JOIN system_departments sd ON ard.system_department_id = sd.system_department_id
        GROUP BY ard.admin_role_id
    )
    SELECT
        au.admin_id,
        au.username,
        au.full_name,
        ar.role_name,
        ar.role_level,
        au.role_type,
        COALESCE(ap.permissions, '[]'::jsonb) as permissions,
        COALESCE(ad.departments, '[]'::jsonb) as departments,
        au.reports_to,
        ru.full_name as reports_to_name,
        au.is_active,
        au.last_login
    FROM admin_users au
    JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
    LEFT JOIN admin_perms ap ON ar.admin_role_id = ap.admin_role_id
    LEFT JOIN admin_depts ad ON ar.admin_role_id = ad.admin_role_id
    LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
    WHERE au.admin_id = admin_id_param;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION admin_has_permission(
    admin_id_param UUID,
    permission_name_param VARCHAR(100)
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM admin_users au
        JOIN admin_role_permissions arp ON au.admin_role_id = arp.admin_role_id
        JOIN permissions p ON arp.permission_id = p.permission_id
        WHERE au.admin_id = admin_id_param
        AND au.is_active = true
        AND p.permission_name = permission_name_param
    );
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION admin_has_department_access(
    admin_id_param UUID,
    department_bitmask BIGINT
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM admin_users au
        JOIN admin_role_departments ard ON au.admin_role_id = ard.admin_role_id
        JOIN system_departments sd ON ard.system_department_id = sd.system_department_id
        WHERE au.admin_id = admin_id_param
        AND au.is_active = true
        AND (sd.bitmask & department_bitmask) > 0
    );
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_admin_suggestions(
    prefix VARCHAR(100),
    role_type_filter INTEGER DEFAULT NULL,
    exclude_super_admin BOOLEAN DEFAULT true,
    limit_suggestions INTEGER DEFAULT 10
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    role_name VARCHAR(100),
    role_level INTEGER,
    role_type INTEGER,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    relevance FLOAT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        au.admin_id, au.username, au.full_name,
        ar.role_name, ar.role_level, au.role_type,
        au.reports_to, ru.full_name as reports_to_name,
        similarity(au.username, prefix)::FLOAT as relevance
    FROM admin_users au
    JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
    LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
    WHERE au.is_active = true
    AND (au.username ILIKE prefix || '%' OR au.full_name ILIKE prefix || '%')
    AND (role_type_filter IS NULL OR au.role_type = role_type_filter)
    AND (NOT exclude_super_admin OR au.role_type != 4)
    ORDER BY
        CASE
            WHEN au.username ILIKE prefix || '%' THEN 1
            WHEN au.full_name ILIKE prefix || '%' THEN 2
            ELSE 3
        END,
        similarity(au.username, prefix) DESC,
        ar.role_level DESC
    LIMIT limit_suggestions;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_admin_role_permissions(
    role_id_param UUID
) RETURNS TABLE(
    permission_id UUID,
    permission_name VARCHAR(100),
    description TEXT,
    category VARCHAR(50),
    module VARCHAR(50),
    scope VARCHAR(20),
    bit_index INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        p.permission_id,
        p.permission_name,
        p.description,
        p.category,
        p.module,
        p.scope,
        p.bit_index
    FROM admin_role_permissions arp
    JOIN permissions p ON arp.permission_id = p.permission_id
    WHERE arp.admin_role_id = role_id_param
    ORDER BY p.module, p.bit_index;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_admin_role_departments(
    role_id_param UUID
) RETURNS TABLE(
    department_id UUID,
    name VARCHAR(255),
    module_code VARCHAR(100),
    description TEXT,
    bitmask BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        sd.system_department_id,
        sd.name,
        sd.module_code,
        sd.description,
        sd.bitmask
    FROM admin_role_departments ard
    JOIN system_departments sd ON ard.system_department_id = sd.system_department_id
    WHERE ard.admin_role_id = role_id_param
    ORDER BY sd.bitmask;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION search_admin_users_with_departments(
    search_query TEXT DEFAULT NULL,
    role_type_filter INTEGER DEFAULT NULL,
    include_inactive BOOLEAN DEFAULT false,
    search_type TEXT DEFAULT 'autocomplete',
    department_ids UUID[] DEFAULT NULL,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    admin_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    role_name VARCHAR(100),
    admin_role_id UUID,
    role_type INTEGER,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    is_active BOOLEAN,
    last_login TIMESTAMPTZ,
    admin_created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
DECLARE
    base_query TEXT;
    where_clause TEXT := 'WHERE 1=1';
    query_params TEXT[];
    param_counter INTEGER := 1;
BEGIN
    IF department_ids IS NOT NULL AND array_length(department_ids, 1) > 0 THEN
        where_clause := where_clause || ' AND ard.system_department_id = ANY($' || param_counter || ')';
        query_params := array_append(query_params, array_to_string(department_ids, ','));
        param_counter := param_counter + 1;
    END IF;
    IF search_query IS NOT NULL AND search_query != '' THEN
        IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
            where_clause := where_clause || ' AND (au.username ILIKE $' || param_counter ||
                          ' OR au.full_name ILIKE $' || param_counter || ')';
            query_params := array_append(query_params, '%' || search_query || '%');
            param_counter := param_counter + 1;
        ELSE
            where_clause := where_clause || ' AND au.user_search_tsv @@ plainto_tsquery(''simple'', $' ||
                          param_counter || '::text)';
            query_params := array_append(query_params, search_query);
            param_counter := param_counter + 1;
        END IF;
    END IF;
    IF role_type_filter IS NOT NULL THEN
        where_clause := where_clause || ' AND au.role_type = $' || param_counter;
        query_params := array_append(query_params, role_type_filter::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF NOT include_inactive THEN
        where_clause := where_clause || ' AND au.is_active = true';
    END IF;
    base_query := '
        SELECT
            au.admin_id, au.username, au.full_name, au.phone_hash,
            ar.role_name, au.admin_role_id, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            au.is_active, au.last_login, au.admin_created_at,
            CASE
                WHEN $' || param_counter || '::text = '''' THEN 1.0
                ELSE ts_rank(au.user_search_tsv, plainto_tsquery(''simple'', $' || param_counter || '::text))
            END as relevance_score,
            CASE
                WHEN $' || param_counter || '::text = '''' THEN ''all''
                WHEN LENGTH($' || (param_counter - 1) || '::text) < 3 THEN ''autocomplete''
                ELSE ''fulltext''
            END as match_type
        FROM admin_users au
        JOIN admin_roles ar ON au.admin_role_id = ar.admin_role_id
        LEFT JOIN admin_users ru ON au.reports_to = ru.admin_id
    ';
    IF department_ids IS NOT NULL AND array_length(department_ids, 1) > 0 THEN
        base_query := base_query || '
            JOIN admin_role_departments ard ON au.admin_role_id = ard.admin_role_id
        ';
    END IF;
    base_query := base_query || where_clause || '
        ORDER BY relevance_score DESC, au.username ASC
        LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);
    query_params := array_append(query_params, COALESCE(search_query, ''));
    query_params := array_append(query_params, limit_count::TEXT);
    query_params := array_append(query_params, offset_count::TEXT);
    RETURN QUERY EXECUTE base_query USING query_params;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION user_search(
    search_query TEXT,
    search_type TEXT DEFAULT 'fulltext',
    filter_is_active BOOLEAN DEFAULT NULL,
    filter_kyc_status TEXT DEFAULT NULL,
    filter_data_region TEXT DEFAULT NULL,
    filter_is_verified BOOLEAN DEFAULT NULL,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    user_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    kyc_status VARCHAR(50),
    kyc_level VARCHAR(20),
    is_verified BOOLEAN,
    is_active BOOLEAN,
    data_region VARCHAR(20),
    created_at TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
DECLARE
    base_query TEXT;
    where_clause TEXT := '';
    query_params TEXT[];
    param_counter INTEGER := 1;
    filter_param_count INTEGER := 0;
    search_param_index INTEGER := 1;
BEGIN
    IF filter_is_active IS NOT NULL THEN
        where_clause := where_clause || ' AND is_active = $' || param_counter;
        query_params := array_append(query_params, filter_is_active::TEXT);
        param_counter := param_counter + 1;
        filter_param_count := filter_param_count + 1;
    END IF;
    IF filter_kyc_status IS NOT NULL THEN
        where_clause := where_clause || ' AND kyc_status = $' || param_counter;
        query_params := array_append(query_params, filter_kyc_status);
        param_counter := param_counter + 1;
        filter_param_count := filter_param_count + 1;
    END IF;
    IF filter_data_region IS NOT NULL THEN
        where_clause := where_clause || ' AND data_region = $' || param_counter;
        query_params := array_append(query_params, filter_data_region);
        param_counter := param_counter + 1;
        filter_param_count := filter_param_count + 1;
    END IF;
    IF filter_is_verified IS NOT NULL THEN
        where_clause := where_clause || ' AND is_verified = $' || param_counter;
        query_params := array_append(query_params, filter_is_verified::TEXT);
        param_counter := param_counter + 1;
        filter_param_count := filter_param_count + 1;
    END IF;
    IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
        base_query := '
            SELECT
                u.user_id,
                u.username,
                u.full_name,
                u.phone_hash,
                u.kyc_status,
                u.kyc_level,
                u.is_verified,
                u.is_active,
                u.data_region,
                u.created_at,
                u.last_login,
                GREATEST(
                    COALESCE(similarity(u.username, $' || param_counter || '), 0),
                    COALESCE(similarity(u.full_name, $' || param_counter || '), 0)
                )::FLOAT AS relevance_score,
                ''autocomplete'' AS match_type
            FROM users u
            WHERE 1=1 ' || where_clause ||
            ' AND (u.username ILIKE $' || (param_counter + 1) ||
            ' OR u.full_name ILIKE $' || (param_counter + 1) || ')
            ORDER BY relevance_score DESC, u.username ASC
            LIMIT $' || (param_counter + 2) || ' OFFSET $' || (param_counter + 3);
        query_params := array_append(query_params, search_query);
        query_params := array_append(query_params, '%' || search_query || '%');
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);
    ELSE
        base_query := '
            SELECT
                u.user_id,
                u.username,
                u.full_name,
                u.phone_hash,
                u.kyc_status,
                u.kyc_level,
                u.is_verified,
                u.is_active,
                u.data_region,
                u.created_at,
                u.last_login,
                ts_rank(
                    u.user_search_tsv,
                    plainto_tsquery(''simple'', $' || param_counter || '::text)
                )::FLOAT AS relevance_score,
                ''fulltext'' AS match_type
            FROM users u
            WHERE 1=1 ' || where_clause ||
            ' AND u.user_search_tsv @@ plainto_tsquery(''simple'', $' || param_counter || '::text)
            ORDER BY relevance_score DESC, u.username ASC
            LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);
        query_params := array_append(query_params, search_query);
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);
    END IF;
    RETURN QUERY EXECUTE base_query USING query_params;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Error in user_search: %', SQLERRM;
        RAISE NOTICE 'Query: %', base_query;
        RAISE NOTICE 'Params: %', query_params;
        RAISE;
END;
$$ LANGUAGE plpgsql STABLE;
CREATE OR REPLACE FUNCTION company_search(
    search_query TEXT,
    search_type TEXT DEFAULT 'fulltext',
    filter_owner_id UUID DEFAULT NULL,
    filter_is_active BOOLEAN DEFAULT NULL,
    filter_subscription_tier TEXT DEFAULT NULL,
    filter_data_region TEXT DEFAULT NULL,
    filter_subscription_status TEXT DEFAULT NULL,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    company_id UUID,
    company_name VARCHAR(255),
    owner_user_id UUID,
    subscription_tier VARCHAR(20),
    subscription_status VARCHAR(20),
    max_employees INTEGER,
    is_active BOOLEAN,
    data_region VARCHAR(10),
    created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
DECLARE
    base_query TEXT;
    where_clause TEXT := '';
    query_params TEXT[];
    param_counter INTEGER := 1;
    filter_param_count INTEGER := 0;
BEGIN
    IF filter_owner_id IS NOT NULL THEN
        where_clause := where_clause || ' AND owner_user_id = $' || param_counter;
        query_params := array_append(query_params, filter_owner_id::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_is_active IS NOT NULL THEN
        where_clause := where_clause || ' AND is_active = $' || param_counter;
        query_params := array_append(query_params, filter_is_active::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_subscription_tier IS NOT NULL THEN
        where_clause := where_clause || ' AND subscription_tier = $' || param_counter;
        query_params := array_append(query_params, filter_subscription_tier);
        param_counter := param_counter + 1;
    END IF;
    IF filter_data_region IS NOT NULL THEN
        where_clause := where_clause || ' AND data_region = $' || param_counter;
        query_params := array_append(query_params, filter_data_region);
        param_counter := param_counter + 1;
    END IF;
    IF filter_subscription_status IS NOT NULL THEN
        where_clause := where_clause || ' AND subscription_status = $' || param_counter;
        query_params := array_append(query_params, filter_subscription_status);
        param_counter := param_counter + 1;
    END IF;
    filter_param_count := param_counter - 1;
    IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
        base_query := '
            SELECT
                c.company_id,
                c.company_name,
                c.owner_user_id,
                c.subscription_tier,
                c.subscription_status,
                c.max_employees,
                c.is_active,
                c.data_region,
                c.created_at,
                similarity(c.company_name, $' || (filter_param_count + 1) || ')::FLOAT as relevance_score,
                ''autocomplete'' as match_type
            FROM companies c
            WHERE 1=1 ' || where_clause ||
            ' AND c.company_name ILIKE $' || (filter_param_count + 2) ||
            ' ORDER BY relevance_score DESC, c.company_name ASC
            LIMIT $' || (filter_param_count + 3) || ' OFFSET $' || (filter_param_count + 4);
        query_params := array_append(query_params, search_query);
        query_params := array_append(query_params, '%' || search_query || '%');
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);
    ELSE
        base_query := '
            SELECT
                c.company_id,
                c.company_name,
                c.owner_user_id,
                c.subscription_tier,
                c.subscription_status,
                c.max_employees,
                c.is_active,
                c.data_region,
                c.created_at,
                ts_rank(c.company_name_tsv, plainto_tsquery(''simple'', $' || (filter_param_count + 1) || '::text)) as relevance_score,
                ''fulltext'' as match_type
            FROM companies c
            WHERE 1=1 ' || where_clause ||
            ' AND c.company_name_tsv @@ plainto_tsquery(''simple'', $' || (filter_param_count + 1) || '::text)
            ORDER BY relevance_score DESC, c.company_name ASC
            LIMIT $' || (filter_param_count + 2) || ' OFFSET $' || (filter_param_count + 3);
        query_params := array_append(query_params, search_query);
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);
    END IF;
    RETURN QUERY EXECUTE base_query USING query_params;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION company_employee_search(
    search_query TEXT,
    company_id_param UUID,
    search_type TEXT DEFAULT 'fulltext',
    filter_role_id UUID DEFAULT NULL,
    filter_department_id UUID DEFAULT NULL,
    filter_is_active BOOLEAN DEFAULT NULL,
    filter_reports_to UUID DEFAULT NULL,
    filter_hire_date_from TIMESTAMPTZ DEFAULT NULL,
    filter_hire_date_to TIMESTAMPTZ DEFAULT NULL,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
) RETURNS TABLE(
    user_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    employee_id VARCHAR(100),
    role_id UUID,
    role_name VARCHAR(100),
    department_id UUID,
    department_name VARCHAR(255),
    hire_date TIMESTAMPTZ,
    is_active BOOLEAN,
    reports_to UUID,
    reports_to_name VARCHAR(255),
    created_at TIMESTAMPTZ,
    relevance_score FLOAT,
    match_type TEXT
) AS $$
DECLARE
    base_query TEXT;
    where_clause TEXT := '';
    query_params TEXT[];
    param_counter INTEGER := 1;
BEGIN
    query_params := array[]::text[];
    where_clause := where_clause || ' AND ce.company_id = $' || param_counter;
    query_params := array_append(query_params, company_id_param::TEXT);
    param_counter := param_counter + 1;
    IF filter_role_id IS NOT NULL THEN
        where_clause := where_clause || ' AND ce.role_id = $' || param_counter;
        query_params := array_append(query_params, filter_role_id::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_department_id IS NOT NULL THEN
        where_clause := where_clause || ' AND rd.department_id = $' || param_counter;
        query_params := array_append(query_params, filter_department_id::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_is_active IS NOT NULL THEN
        where_clause := where_clause || ' AND ce.is_active = $' || param_counter;
        query_params := array_append(query_params, filter_is_active::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_reports_to IS NOT NULL THEN
        where_clause := where_clause || ' AND ce.reports_to = $' || param_counter;
        query_params := array_append(query_params, filter_reports_to::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_hire_date_from IS NOT NULL THEN
        where_clause := where_clause || ' AND ce.hire_date >= $' || param_counter;
        query_params := array_append(query_params, filter_hire_date_from::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF filter_hire_date_to IS NOT NULL THEN
        where_clause := where_clause || ' AND ce.hire_date <= $' || param_counter;
        query_params := array_append(query_params, filter_hire_date_to::TEXT);
        param_counter := param_counter + 1;
    END IF;
    IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
        base_query := '
            SELECT
                u.user_id,
                u.username,
                u.full_name,
                u.phone_hash,
                ce.employee_id,
                ce.role_id,
                r.role_name,
                rd.department_id,
                d.department_name,
                ce.hire_date,
                ce.is_active,
                ce.reports_to,
                ru.username as reports_to_name,
                u.created_at,
                GREATEST(
                    COALESCE(similarity(u.username, $' || param_counter || '), 0),
                    COALESCE(similarity(u.full_name, $' || param_counter || '), 0),
                    COALESCE(similarity(ce.employee_id, $' || param_counter || '), 0)
                )::FLOAT as relevance_score,
                ''autocomplete'' as match_type
            FROM users u
            INNER JOIN company_employees ce ON u.user_id = ce.user_id
            INNER JOIN roles r ON ce.role_id = r.role_id
            INNER JOIN role_departments rd ON r.role_id = rd.role_id
            LEFT JOIN departments d ON rd.department_id = d.department_id
            LEFT JOIN users ru ON ce.reports_to = ru.user_id
            WHERE 1=1 ' || where_clause ||
            ' AND (u.username ILIKE $' || (param_counter + 1) ||
            ' OR u.full_name ILIKE $' || (param_counter + 1) ||
            ' OR ce.employee_id ILIKE $' || (param_counter + 1) || ')
            ORDER BY relevance_score DESC, ce.hire_date DESC
            LIMIT $' || (param_counter + 2) || ' OFFSET $' || (param_counter + 3);
        query_params := array_append(query_params, search_query);
        query_params := array_append(query_params, '%' || search_query || '%');
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);
    ELSE
        base_query := '
            SELECT
                u.user_id,
                u.username,
                u.full_name,
                u.phone_hash,
                ce.employee_id,
                ce.role_id,
                r.role_name,
                rd.department_id,
                d.department_name,
                ce.hire_date,
                ce.is_active,
                ce.reports_to,
                ru.username as reports_to_name,
                u.created_at,
                ts_rank(u.user_search_tsv, plainto_tsquery(''simple'', $' || param_counter || '::text)) as relevance_score,
                ''fulltext'' as match_type
            FROM users u
            INNER JOIN company_employees ce ON u.user_id = ce.user_id
            INNER JOIN roles r ON ce.role_id = r.role_id
            INNER JOIN role_departments rd ON r.role_id = rd.role_id
            LEFT JOIN departments d ON rd.department_id = d.department_id
            LEFT JOIN users ru ON ce.reports_to = ru.user_id
            WHERE 1=1 ' || where_clause ||
            ' AND u.user_search_tsv @@ plainto_tsquery(''simple'', $' || param_counter || '::text)
            ORDER BY relevance_score DESC, ce.hire_date DESC
            LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);
        query_params := array_append(query_params, search_query);
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);
    END IF;
    RETURN QUERY EXECUTE base_query USING query_params;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_company_employee_suggestions(
    company_id_param UUID,
    prefix VARCHAR(100),
    limit_suggestions INTEGER DEFAULT 10
) RETURNS TABLE(
    username VARCHAR(100),
    full_name VARCHAR(255),
    user_id UUID,
    employee_id VARCHAR(100),
    role_name VARCHAR(100)
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.username,
        u.full_name,
        u.user_id,
        ce.employee_id,
        r.role_name
    FROM users u
    INNER JOIN company_employees ce ON u.user_id = ce.user_id
    INNER JOIN roles r ON ce.role_id = r.role_id
    WHERE ce.company_id = company_id_param
    AND ce.is_active = true
    AND (u.username ILIKE prefix || '%'
         OR u.full_name ILIKE prefix || '%'
         OR ce.employee_id ILIKE prefix || '%')
    ORDER BY
        CASE
            WHEN u.username ILIKE prefix || '%' THEN 1
            WHEN u.full_name ILIKE prefix || '%' THEN 2
            WHEN ce.employee_id ILIKE prefix || '%' THEN 3
            ELSE 4
        END,
        u.username
    LIMIT limit_suggestions;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION find_company_employee_by_username(
    company_id_search UUID,
    username_search VARCHAR(100)
) RETURNS TABLE(
    user_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    employee_id VARCHAR(100),
    role_id UUID,
    role_name VARCHAR(100),
    department_id UUID,
    department_name VARCHAR(255),
    is_active BOOLEAN,
    hire_date TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.user_id,
        u.username,
        u.full_name,
        u.phone_hash,
        ce.employee_id,
        ce.role_id,
        r.role_name,
        rd.department_id,
        d.department_name,
        ce.is_active,
        ce.hire_date
    FROM users u
    INNER JOIN company_employees ce ON u.user_id = ce.user_id
    INNER JOIN roles r ON ce.role_id = r.role_id
    INNER JOIN role_departments rd ON r.role_id = rd.role_id
    LEFT JOIN departments d ON rd.department_id = d.department_id
    WHERE ce.company_id = company_id_search
    AND u.username = username_search
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION find_user_by_username(username_search VARCHAR(100))
RETURNS TABLE(
    user_id UUID,
    username VARCHAR(100),
    full_name VARCHAR(255),
    phone_hash VARCHAR(128),
    is_active BOOLEAN,
    created_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.user_id,
        u.username,
        u.full_name,
        u.phone_hash,
        u.is_active,
        u.created_at
    FROM users u
    WHERE u.username = username_search
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION find_companies_by_owner(
    owner_id UUID,
    name_filter VARCHAR(255) DEFAULT NULL
) RETURNS TABLE(
    company_id UUID,
    company_name VARCHAR(255),
    subscription_tier VARCHAR(20),
    subscription_status VARCHAR(20),
    is_active BOOLEAN,
    created_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.company_id,
        c.company_name,
        c.subscription_tier,
        c.subscription_status,
        c.is_active,
        c.created_at
    FROM companies c
    WHERE c.owner_user_id = owner_id
    AND (name_filter IS NULL OR c.company_name ILIKE '%' || name_filter || '%')
    ORDER BY c.created_at DESC;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_user_suggestions(
    prefix VARCHAR(100),
    limit_suggestions INTEGER DEFAULT 10
) RETURNS TABLE(
    username VARCHAR(100),
    full_name VARCHAR(255),
    user_id UUID
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.username,
        u.full_name,
        u.user_id
    FROM users u
    WHERE u.username ILIKE prefix || '%'
       OR u.full_name ILIKE prefix || '%'
    ORDER BY
        CASE
            WHEN u.username ILIKE prefix || '%' THEN 1
            WHEN u.full_name ILIKE prefix || '%' THEN 2
            ELSE 3
        END,
        u.username
    LIMIT limit_suggestions;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION get_company_suggestions(
    prefix VARCHAR(255),
    limit_suggestions INTEGER DEFAULT 10
) RETURNS TABLE(
    company_name VARCHAR(255),
    company_id UUID
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.company_name,
        c.company_id
    FROM companies c
    WHERE c.company_name ILIKE prefix || '%'
    ORDER BY c.company_name
    LIMIT limit_suggestions;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION leave.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION leave.calculate_fractional_accrual(
    p_total_days INTEGER,
    p_accrual_method TEXT,
    p_months_count INTEGER DEFAULT 1
) RETURNS DECIMAL(10,4) AS $$
DECLARE
    v_result DECIMAL(10,4);
BEGIN
    CASE p_accrual_method
        WHEN 'monthly' THEN
            v_result := p_total_days::DECIMAL / 12.0 * p_months_count;
        WHEN 'quarterly' THEN
            v_result := p_total_days::DECIMAL / 4.0 * (p_months_count / 3.0);
        WHEN 'yearly' THEN
            v_result := p_total_days::DECIMAL * (p_months_count / 12.0);
        ELSE
            v_result := 0.0;
    END CASE;
    RETURN ROUND(v_result, 4);
END;
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE OR REPLACE FUNCTION leave.get_user_effective_policy(
    p_company_id UUID,
    p_user_id UUID,
    p_as_of DATE DEFAULT CURRENT_DATE
) RETURNS TABLE (
    policy_id UUID,
    policy_name TEXT,
    applies_to_type TEXT,
    applies_to_id TEXT,
    priority INTEGER,
    effective_from DATE,
    effective_to DATE,
    rule_leave_type_id UUID,
    rule_total_days INTEGER,
    rule_accrual_method TEXT,
    rule_carry_forward_limit INTEGER
) AS $$
BEGIN
    RETURN QUERY
    WITH user_context AS (
        SELECT
            ce.position_id,
            p.work_center_code
        FROM company_employees ce
        LEFT JOIN positions p ON ce.position_id = p.position_id
        WHERE ce.company_id = p_company_id
        AND ce.user_id = p_user_id
        AND ce.is_active = true
    ),
    applicable_policies AS (
        SELECT
            lp.policy_id,
            lp.policy_name,
            lp.applies_to_type,
            lp.applies_to_id,
            lp.priority,
            lp.effective_from,
            lp.effective_to,
            lpr.leave_type_id as rule_leave_type_id,
            lpr.total_days as rule_total_days,
            lpr.accrual_method as rule_accrual_method,
            lpr.carry_forward_limit as rule_carry_forward_limit,
            CASE lp.applies_to_type
                WHEN 'position' THEN 1
                WHEN 'work_center' THEN 2
                WHEN 'company' THEN 3
                ELSE 4
            END as scope_rank
        FROM leave.leave_policy lp
        JOIN leave.leave_policy_rule lpr ON lp.policy_id = lpr.policy_id
        JOIN user_context uc ON 1=1
        WHERE lp.company_id = p_company_id
        AND lp.is_active = true
        AND lp.effective_from <= p_as_of
        AND (lp.effective_to IS NULL OR lp.effective_to >= p_as_of)
        AND (
            lp.applies_to_type = 'company'
            OR
            (lp.applies_to_type = 'position'
             AND lp.applies_to_position_id = uc.position_id)
            OR
            (lp.applies_to_type = 'work_center'
             AND lp.applies_to_work_center_code = uc.work_center_code)
        )
    )
    SELECT DISTINCT ON (ap.rule_leave_type_id)
        ap.policy_id,
        ap.policy_name,
        ap.applies_to_type,
        ap.applies_to_id,
        ap.priority,
        ap.effective_from,
        ap.effective_to,
        ap.rule_leave_type_id,
        ap.rule_total_days,
        ap.rule_accrual_method,
        ap.rule_carry_forward_limit
    FROM applicable_policies ap
    ORDER BY
        ap.rule_leave_type_id,
        ap.scope_rank ASC,
        ap.priority ASC,
        ap.effective_from DESC;
END;
$$ LANGUAGE plpgsql STABLE;
CREATE OR REPLACE FUNCTION leave.close_active_entitlements(
    p_company_id UUID,
    p_user_id UUID,
    p_policy_id UUID,
    p_effective_to DATE
)
RETURNS INTEGER AS $$
BEGIN
    UPDATE leave.leave_entitlement
    SET effective_to = p_effective_to
    WHERE company_id = p_company_id
      AND user_id = p_user_id
      AND policy_id = p_policy_id
      AND effective_to IS NULL;
    RETURN ROW_COUNT;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION prevent_structure_update_if_used()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM payroll.employee_salary
        WHERE salary_structure_id = OLD.salary_structure_id
    ) THEN
        RAISE EXCEPTION 'Cannot update salary structure % – already assigned to employees',
            OLD.salary_structure_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_logs_outbox_trigger
    AFTER INSERT ON audit.audit_logs FOR EACH ROW
    EXECUTE FUNCTION audit.audit_logs_outbox_trigger();
CREATE TRIGGER update_admin_user_search_tsv
    BEFORE UPDATE OF username, full_name ON admin_users FOR EACH ROW
    EXECUTE FUNCTION update_admin_user_search_tsv();
CREATE TRIGGER update_user_search_tsv
    BEFORE UPDATE OF username, full_name ON users FOR EACH ROW
    EXECUTE FUNCTION update_user_search_tsv();
CREATE TRIGGER update_company_name_tsv
    BEFORE UPDATE OF company_name ON companies FOR EACH ROW
    EXECUTE FUNCTION update_company_name_tsv();
CREATE TRIGGER update_admin_users_updated_at
    BEFORE UPDATE ON admin_users FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_companies_updated_at
    BEFORE UPDATE ON companies FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_departments_updated_at
    BEFORE UPDATE ON departments FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_company_employees_updated_at
    BEFORE UPDATE ON company_employees FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_user_devices_updated_at
    BEFORE UPDATE ON user_devices FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_admin_roles_updated_at
    BEFORE UPDATE ON admin_roles FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_employee_profiles_updated_at
    BEFORE UPDATE ON employee_profiles FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_leave_entitlement_updated_at
    BEFORE UPDATE ON leave.leave_entitlement FOR EACH ROW
    EXECUTE FUNCTION leave.update_updated_at_column();
CREATE TRIGGER update_leave_policy_updated_at
    BEFORE UPDATE ON leave.leave_policy FOR EACH ROW
    EXECUTE FUNCTION leave.update_updated_at_column();
CREATE TRIGGER update_leave_policy_rule_updated_at
    BEFORE UPDATE ON leave.leave_policy_rule FOR EACH ROW
    EXECUTE FUNCTION leave.update_updated_at_column();
CREATE TRIGGER trg_enforce_department_limit
    BEFORE INSERT OR UPDATE OF is_active ON departments FOR EACH ROW
    EXECUTE FUNCTION enforce_department_limit();
CREATE TRIGGER trg_no_department_delete
    BEFORE DELETE ON departments FOR EACH ROW
    EXECUTE FUNCTION prevent_department_delete();
CREATE TRIGGER trg_cascade_department_soft_delete
    BEFORE UPDATE OF is_active ON departments FOR EACH ROW
    EXECUTE FUNCTION cascade_department_soft_delete();
CREATE TRIGGER trg_prevent_child_on_inactive_parent
    BEFORE INSERT OR UPDATE OF parent_department_id ON departments FOR EACH ROW
    EXECUTE FUNCTION prevent_child_on_inactive_parent();
CREATE TRIGGER trg_unique_active_department_name
    BEFORE INSERT OR UPDATE OF department_name, is_active ON departments FOR EACH ROW
    EXECUTE FUNCTION enforce_unique_active_department_name();
CREATE TRIGGER trg_close_positions_on_department_deactivate
    BEFORE UPDATE OF is_active ON departments FOR EACH ROW
    EXECUTE FUNCTION close_positions_on_department_deactivate();
CREATE TRIGGER trg_prevent_position_in_inactive_department
    BEFORE INSERT OR UPDATE ON positions FOR EACH ROW
    EXECUTE FUNCTION prevent_position_in_inactive_department();
CREATE TRIGGER trg_enforce_employee_limit
    BEFORE INSERT OR UPDATE OF is_active ON company_employees FOR EACH ROW
    EXECUTE FUNCTION enforce_employee_limit();
CREATE TRIGGER trg_sync_department_on_position
    AFTER INSERT OR UPDATE OF position_id ON company_employees FOR EACH ROW
    EXECUTE FUNCTION sync_employee_department_on_position();
CREATE TRIGGER trg_sync_role_history
    AFTER INSERT OR UPDATE OF role_id ON company_employees FOR EACH ROW
    EXECUTE FUNCTION sync_employee_role_history();
CREATE TRIGGER trg_prevent_exit_for_inactive_employee
    BEFORE INSERT ON employee_exit FOR EACH ROW
    EXECUTE FUNCTION prevent_exit_for_inactive_employee();
CREATE TRIGGER trg_prevent_structure_update
    BEFORE UPDATE ON payroll.salary_structure FOR EACH ROW
    EXECUTE FUNCTION prevent_structure_update_if_used();
INSERT INTO payroll.payroll_component (
    company_id,
    component_code,
    component_type,
    description,
    is_taxable,
    is_system,
    is_active,
    contribution_side
) VALUES
(NULL,'BASIC','earning','Basic Salary',true,true,true,'employee'),
(NULL,'HRA','earning','House Rent Allowance',true,false,true,'employee'),
(NULL,'CONVEYANCE','earning','Conveyance Allowance',true,false,true,'employee'),
(NULL,'SPECIAL_ALLOWANCE','earning','Special Allowance',true,false,true,'employee'),
(NULL,'MEDICAL_ALLOWANCE','earning','Medical Allowance',true,false,true,'employee'),
(NULL,'LTA','earning','Leave Travel Allowance',true,false,true,'employee'),
(NULL,'BONUS','earning','Performance Bonus',true,false,true,'employee'),
(NULL,'COMMISSION','earning','Sales Commission',true,false,true,'employee'),
(NULL,'OVERTIME','earning','Overtime Pay',true,false,true,'employee'),
(NULL,'ARREARS','earning','Salary Arrears',true,false,true,'employee'),
(NULL,'SHIFT_ALLOWANCE','earning','Shift Allowance',true,false,true,'employee'),
(NULL,'FOOD_ALLOWANCE','earning','Meal / Food Allowance',true,false,true,'employee'),
(NULL,'OVERTIME_PAY','earning','Overtime Pay',true,true,true,'employee'),
(NULL,'LOAN_EMI','deduction','Loan EMI',false,false,true,'employee'),
(NULL,'ABSENT_DEDUCTION','deduction','Absent Deduction',false,true,true,'employee'),
(NULL,'MANUAL_FINE','deduction','Manual Fine',false,false,true,'employee'),
(NULL,'PF','deduction','Provident Fund (Employee)',false,false,true,'employee'),
(NULL,'ESI','deduction','Employee State Insurance',false,false,true,'employee'),
(NULL,'PT','deduction','Professional Tax',false,false,true,'employee'),
(NULL,'TDS','deduction','Income Tax (TDS)',false,false,true,'employee'),
(NULL,'LOP','deduction','Loss of Pay',false,true,true,'employee'),
(NULL,'ADVANCE','deduction','Salary Advance Recovery',false,false,true,'employee'),
(NULL,'LOAN_DEDUCTION','deduction','Loan Repayment Deduction',false,false,true,'employee'),
(NULL,'INSURANCE','deduction','Insurance Deduction',false,false,true,'employee'),
(NULL,'OTHER_DEDUCTION','deduction','Other Deduction',false,false,true,'employee'),
(NULL,'LATE_DEDUCTION','deduction','Late Attendance Deduction',false,true,true,'employee'),
(NULL,'PF_EMPLOYER','deduction','Employer Provident Fund',false,true,true,'employer'),
(NULL,'ESI_EMPLOYER','deduction','Employer ESI Contribution',false,true,true,'employer'),
(NULL,'GRATUITY','deduction','Gratuity Provision',false,true,true,'employer'),
(NULL,'BONUS_PROVISION','deduction','Bonus Provision',false,true,true,'employer')
ON CONFLICT DO NOTHING;
INSERT INTO system_departments (name, module_code, description, bitmask) VALUES
    ('HR', 'hr', 'Human resource management', 1 << 0),
    ('Finance', 'finance', 'Finance operations', 1 << 1),
    ('Accounting', 'accounting', 'Accounting and ledger', 1 << 2),
    ('Procurement', 'procurement', 'Purchasing & vendor mgmt', 1 << 3),
    ('Inventory', 'inventory', 'Stock & warehouse', 1 << 4),
    ('Logistics', 'logistics', 'Dispatch & delivery', 1 << 5),
    ('Sales', 'sales', 'Lead & pipeline mgmt', 1 << 6),
    ('Marketing', 'marketing', 'Campaigns & analysis', 1 << 7),
    ('Customer Support', 'support', 'Support & helpdesk', 1 << 8),
    ('Operations', 'operations', 'Operations & workflows', 1 << 9),
    ('IT', 'it', 'IT assets & incidents', 1 << 10),
    ('Production', 'production', 'Manufacturing operations', 1 << 11),
    ('Quality Control', 'qc', 'QC inspections', 1 << 12),
    ('Quality Assurance', 'qa', 'QA processes', 1 << 13),
    ('R&D', 'rnd', 'Research & development', 1 << 14),
    ('Administration', 'administration', 'Company administration and management', 1 << 15),
    ('Employee Management', 'employee_management', 'Employee management and administration', 1 << 16),
    ('Manager Management', 'manager_management', 'Manager oversight and coordination', 1 << 17),
    ('Company Management', 'company_management', 'Overall company management and strategy', 1 << 18),
    ('Super Admin Management', 'super_admin', 'Super Admin management and system control', 1 << 19),
    ('Attendance', 'attendance', 'Attendance and time tracking management', 1 << 20),
    ('Payroll', 'payroll', 'Payroll management and processing', 1 << 21),
    ('Academics', 'academics', 'Academic management system', 1 << 22)
ON CONFLICT (name) DO NOTHING;
INSERT INTO permissions (permission_name, description, category, module, scope, requires_tier, bit_index) VALUES
    ('hr.employee.create', 'Create employees', 'employee', 'hr', 'user', 'basic', 0),
    ('hr.employee.update', 'Update employees', 'employee', 'hr', 'user', 'basic', 1),
    ('hr.employee.delete', 'Delete employees', 'employee', 'hr', 'user', 'basic', 2),
    ('hr.employee.view', 'View employees', 'employee', 'hr', 'user', 'basic', 3),
    ('hr.employee.search', 'Search employees', 'employee', 'hr', 'user', 'basic', 4),
    ('hr.employee.terminate', 'Terminate employees', 'employee', 'hr', 'user', 'basic', 5),
    ('hr.employee.transfer', 'Transfer employees', 'employee', 'hr', 'user', 'basic', 6),
    ('hr.document.upload', 'Upload documents', 'document', 'hr', 'user', 'basic', 7),
    ('hr.document.view', 'View documents', 'document', 'hr', 'user', 'basic', 8),
    ('hr.document.delete', 'Delete documents', 'document', 'hr', 'user', 'basic', 9),
    ('hr.position.create', 'Create positions', 'position', 'hr', 'user', 'basic', 10),
    ('hr.position.update', 'Update positions', 'position', 'hr', 'user', 'basic', 11),
    ('hr.position.delete', 'Delete positions', 'position', 'hr', 'user', 'basic', 12),
    ('hr.position.view', 'View positions', 'position', 'hr', 'user', 'basic', 13),
    ('hr.leave.request', 'Request leave', 'leave', 'hr', 'user', 'basic', 14),
    ('hr.leave.approve', 'Approve leave', 'leave', 'hr', 'user', 'basic', 15),
    ('hr.leave.reject', 'Reject leave', 'leave', 'hr', 'user', 'basic', 16),
    ('hr.leave.view', 'View leave', 'leave', 'hr', 'user', 'basic', 17),
    ('hr.attendance.view', 'View attendance', 'attendance', 'hr', 'user', 'basic', 18),
    ('hr.attendance.update', 'Update attendance', 'attendance', 'hr', 'user', 'basic', 19),
    ('finance.invoice.create', 'Create invoices', 'invoice', 'finance', 'user', 'basic', 20),
    ('finance.invoice.update', 'Update invoices', 'invoice', 'finance', 'user', 'basic', 21),
    ('finance.invoice.delete', 'Delete invoices', 'invoice', 'finance', 'user', 'basic', 22),
    ('finance.invoice.view', 'View invoices', 'invoice', 'finance', 'user', 'basic', 23),
    ('finance.invoice.send', 'Send invoices', 'invoice', 'finance', 'user', 'basic', 24),
    ('finance.invoice.approve', 'Approve invoices', 'invoice', 'finance', 'user', 'basic', 25),
    ('finance.payment.process', 'Process payments', 'payment', 'finance', 'user', 'basic', 26),
    ('finance.payment.refund', 'Process refunds', 'payment', 'finance', 'user', 'basic', 27),
    ('finance.payment.view', 'View payments', 'payment', 'finance', 'user', 'basic', 28),
    ('finance.statement.view', 'View statements', 'statement', 'finance', 'user', 'basic', 29),
    ('finance.statement.download', 'Download statements', 'statement', 'finance', 'user', 'basic', 30),
    ('finance.tax.create', 'Create tax records', 'tax', 'finance', 'user', 'basic', 31),
    ('finance.tax.update', 'Update tax records', 'tax', 'finance', 'user', 'basic', 32),
    ('finance.tax.view', 'View tax records', 'tax', 'finance', 'user', 'basic', 33),
    ('finance.tax.delete', 'Delete tax records', 'tax', 'finance', 'user', 'basic', 34),
    ('finance.budget.create', 'Create budgets', 'budget', 'finance', 'user', 'basic', 35),
    ('finance.budget.update', 'Update budgets', 'budget', 'finance', 'user', 'basic', 36),
    ('finance.budget.delete', 'Delete budgets', 'budget', 'finance', 'user', 'basic', 37),
    ('finance.budget.view', 'View budgets', 'budget', 'finance', 'user', 'basic', 38),
    ('accounting.ledger.view', 'View ledger', 'ledger', 'accounting', 'user', 'basic', 39),
    ('accounting.journal.create', 'Create journal entries', 'journal', 'accounting', 'user', 'basic', 40),
    ('accounting.journal.update', 'Update journal entries', 'journal', 'accounting', 'user', 'basic', 41),
    ('accounting.journal.delete', 'Delete journal entries', 'journal', 'accounting', 'user', 'basic', 42),
    ('accounting.journal.view', 'View journal entries', 'journal', 'accounting', 'user', 'basic', 43),
    ('accounting.pl.view', 'View profit/loss', 'pl', 'accounting', 'user', 'basic', 44),
    ('accounting.balance_sheet.view', 'View balance sheet', 'balance_sheet', 'accounting', 'user', 'basic', 45),
    ('accounting.cashflow.view', 'View cash flow', 'cashflow', 'accounting', 'user', 'basic', 46),
    ('accounting.reconcile', 'Reconcile accounts', 'reconcile', 'accounting', 'user', 'basic', 47),
    ('accounting.report.export', 'Export reports', 'report', 'accounting', 'user', 'basic', 48),
    ('procurement.po.create', 'Create purchase orders', 'po', 'procurement', 'user', 'basic', 49),
    ('procurement.po.update', 'Update purchase orders', 'po', 'procurement', 'user', 'basic', 50),
    ('procurement.po.approve', 'Approve purchase orders', 'po', 'procurement', 'user', 'basic', 51),
    ('procurement.po.reject', 'Reject purchase orders', 'po', 'procurement', 'user', 'basic', 52),
    ('procurement.po.delete', 'Delete purchase orders', 'po', 'procurement', 'user', 'basic', 53),
    ('procurement.po.view', 'View purchase orders', 'po', 'procurement', 'user', 'basic', 54),
    ('procurement.vendor.create', 'Create vendors', 'vendor', 'procurement', 'user', 'basic', 55),
    ('procurement.vendor.update', 'Update vendors', 'vendor', 'procurement', 'user', 'basic', 56),
    ('procurement.vendor.block', 'Block vendors', 'vendor', 'procurement', 'user', 'basic', 57),
    ('procurement.vendor.delete', 'Delete vendors', 'vendor', 'procurement', 'user', 'basic', 58),
    ('procurement.vendor.view', 'View vendors', 'vendor', 'procurement', 'user', 'basic', 59),
    ('procurement.request.create', 'Create procurement requests', 'request', 'procurement', 'user', 'basic', 60),
    ('procurement.request.update', 'Update procurement requests', 'request', 'procurement', 'user', 'basic', 61),
    ('procurement.request.delete', 'Delete procurement requests', 'request', 'procurement', 'user', 'basic', 62),
    ('procurement.request.view', 'View procurement requests', 'request', 'procurement', 'user', 'basic', 63),
    ('inventory.item.create', 'Create items', 'item', 'inventory', 'user', 'basic', 64),
    ('inventory.item.update', 'Update items', 'item', 'inventory', 'user', 'basic', 65),
    ('inventory.item.delete', 'Delete items', 'item', 'inventory', 'user', 'basic', 66),
    ('inventory.item.view', 'View items', 'item', 'inventory', 'user', 'basic', 67),
    ('inventory.stock.in', 'Stock in items', 'stock', 'inventory', 'user', 'basic', 68),
    ('inventory.stock.out', 'Stock out items', 'stock', 'inventory', 'user', 'basic', 69),
    ('inventory.stock.transfer', 'Transfer stock', 'stock', 'inventory', 'user', 'basic', 70),
    ('inventory.stock.adjust', 'Adjust stock', 'stock', 'inventory', 'user', 'basic', 71),
    ('inventory.stock.audit', 'Audit stock', 'stock', 'inventory', 'user', 'basic', 72),
    ('inventory.stock.view', 'View stock', 'stock', 'inventory', 'user', 'basic', 73),
    ('inventory.batch.create', 'Create batches', 'batch', 'inventory', 'user', 'basic', 74),
    ('inventory.batch.update', 'Update batches', 'batch', 'inventory', 'user', 'basic', 75),
    ('inventory.batch.view', 'View batches', 'batch', 'inventory', 'user', 'basic', 76),
    ('inventory.batch.delete', 'Delete batches', 'batch', 'inventory', 'user', 'basic', 77),
    ('inventory.warehouse.create', 'Create warehouses', 'warehouse', 'inventory', 'user', 'basic', 78),
    ('inventory.warehouse.update', 'Update warehouses', 'warehouse', 'inventory', 'user', 'basic', 79),
    ('inventory.warehouse.delete', 'Delete warehouses', 'warehouse', 'inventory', 'user', 'basic', 80),
    ('inventory.warehouse.view', 'View warehouses', 'warehouse', 'inventory', 'user', 'basic', 81),
    ('logistics.shipment.create', 'Create shipments', 'shipment', 'logistics', 'user', 'basic', 82),
    ('logistics.shipment.update', 'Update shipments', 'shipment', 'logistics', 'user', 'basic', 83),
    ('logistics.shipment.delete', 'Delete shipments', 'shipment', 'logistics', 'user', 'basic', 84),
    ('logistics.shipment.view', 'View shipments', 'shipment', 'logistics', 'user', 'basic', 85),
    ('logistics.tracking.view', 'View tracking', 'tracking', 'logistics', 'user', 'basic', 86),
    ('logistics.route.create', 'Create routes', 'route', 'logistics', 'user', 'basic', 87),
    ('logistics.route.update', 'Update routes', 'route', 'logistics', 'user', 'basic', 88),
    ('logistics.route.delete', 'Delete routes', 'route', 'logistics', 'user', 'basic', 89),
    ('logistics.route.view', 'View routes', 'route', 'logistics', 'user', 'basic', 90),
    ('logistics.vehicle.assign', 'Assign vehicles', 'vehicle', 'logistics', 'user', 'basic', 91),
    ('logistics.vehicle.update', 'Update vehicles', 'vehicle', 'logistics', 'user', 'basic', 92),
    ('logistics.vehicle.view', 'View vehicles', 'vehicle', 'logistics', 'user', 'basic', 93),
    ('sales.lead.create', 'Create sales leads', 'lead', 'sales', 'user', 'basic', 94),
    ('sales.lead.update', 'Update sales leads', 'lead', 'sales', 'user', 'basic', 95),
    ('sales.lead.delete', 'Delete sales leads', 'lead', 'sales', 'user', 'basic', 96),
    ('sales.lead.view', 'View sales leads', 'lead', 'sales', 'user', 'basic', 97),
    ('sales.deal.create', 'Create deals', 'deal', 'sales', 'user', 'basic', 98),
    ('sales.deal.update', 'Update deals', 'deal', 'sales', 'user', 'basic', 99),
    ('sales.deal.delete', 'Delete deals', 'deal', 'sales', 'user', 'basic', 100),
    ('sales.deal.view', 'View deals', 'deal', 'sales', 'user', 'basic', 101),
    ('sales.deal.close', 'Close deals', 'deal', 'sales', 'user', 'basic', 102),
    ('sales.quote.create', 'Create quotes', 'quote', 'sales', 'user', 'basic', 103),
    ('sales.quote.update', 'Update quotes', 'quote', 'sales', 'user', 'basic', 104),
    ('sales.quote.delete', 'Delete quotes', 'quote', 'sales', 'user', 'basic', 105),
    ('sales.quote.view', 'View quotes', 'quote', 'sales', 'user', 'basic', 106),
    ('sales.target.create', 'Create sales targets', 'target', 'sales', 'user', 'basic', 107),
    ('sales.target.update', 'Update sales targets', 'target', 'sales', 'user', 'basic', 108),
    ('sales.target.view', 'View sales targets', 'target', 'sales', 'user', 'basic', 109),
    ('marketing.campaign.create', 'Create campaigns', 'campaign', 'marketing', 'user', 'basic', 110),
    ('marketing.campaign.update', 'Update campaigns', 'campaign', 'marketing', 'user', 'basic', 111),
    ('marketing.campaign.delete', 'Delete campaigns', 'campaign', 'marketing', 'user', 'basic', 112),
    ('marketing.campaign.view', 'View campaigns', 'campaign', 'marketing', 'user', 'basic', 113),
    ('marketing.analytics.view', 'View analytics', 'analytics', 'marketing', 'user', 'basic', 114),
    ('marketing.audience.create', 'Create audiences', 'audience', 'marketing', 'user', 'basic', 115),
    ('marketing.audience.update', 'Update audiences', 'audience', 'marketing', 'user', 'basic', 116),
    ('marketing.audience.delete', 'Delete audiences', 'audience', 'marketing', 'user', 'basic', 117),
    ('marketing.audience.view', 'View audiences', 'audience', 'marketing', 'user', 'basic', 118),
    ('marketing.budget.create', 'Create marketing budgets', 'budget', 'marketing', 'user', 'basic', 119),
    ('marketing.budget.update', 'Update marketing budgets', 'budget', 'marketing', 'user', 'basic', 120),
    ('marketing.budget.view', 'View marketing budgets', 'budget', 'marketing', 'user', 'basic', 121),
    ('support.ticket.create', 'Create support tickets', 'ticket', 'support', 'user', 'basic', 122),
    ('support.ticket.update', 'Update support tickets', 'ticket', 'support', 'user', 'basic', 123),
    ('support.ticket.assign', 'Assign support tickets', 'ticket', 'support', 'user', 'basic', 124),
    ('support.ticket.close', 'Close support tickets', 'ticket', 'support', 'user', 'basic', 125),
    ('support.ticket.delete', 'Delete support tickets', 'ticket', 'support', 'user', 'basic', 126),
    ('support.ticket.view', 'View support tickets', 'ticket', 'support', 'user', 'basic', 127),
    ('support.faq.create', 'Create FAQs', 'faq', 'support', 'user', 'basic', 128),
    ('support.faq.update', 'Update FAQs', 'faq', 'support', 'user', 'basic', 129),
    ('support.faq.delete', 'Delete FAQs', 'faq', 'support', 'user', 'basic', 130),
    ('support.faq.view', 'View FAQs', 'faq', 'support', 'user', 'basic', 131),
    ('support.report.view', 'View support reports', 'report', 'support', 'user', 'basic', 132),
    ('operations.task.create', 'Create tasks', 'task', 'operations', 'user', 'basic', 133),
    ('operations.task.update', 'Update tasks', 'task', 'operations', 'user', 'basic', 134),
    ('operations.task.delete', 'Delete tasks', 'task', 'operations', 'user', 'basic', 135),
    ('operations.task.view', 'View tasks', 'task', 'operations', 'user', 'basic', 136),
    ('operations.task.assign', 'Assign tasks', 'task', 'operations', 'user', 'basic', 137),
    ('operations.task.complete', 'Complete tasks', 'task', 'operations', 'user', 'basic', 138),
    ('operations.shift.create', 'Create shifts', 'shift', 'operations', 'user', 'basic', 139),
    ('operations.shift.update', 'Update shifts', 'shift', 'operations', 'user', 'basic', 140),
    ('operations.shift.delete', 'Delete shifts', 'shift', 'operations', 'user', 'basic', 141),
    ('operations.shift.view', 'View shifts', 'shift', 'operations', 'user', 'basic', 142),
    ('operations.workflow.create', 'Create workflows', 'workflow', 'operations', 'user', 'basic', 143),
    ('operations.workflow.update', 'Update workflows', 'workflow', 'operations', 'user', 'basic', 144),
    ('operations.workflow.delete', 'Delete workflows', 'workflow', 'operations', 'user', 'basic', 145),
    ('operations.workflow.view', 'View workflows', 'workflow', 'operations', 'user', 'basic', 146),
    ('it.asset.create', 'Create IT assets', 'asset', 'it', 'user', 'basic', 147),
    ('it.asset.update', 'Update IT assets', 'asset', 'it', 'user', 'basic', 148),
    ('it.asset.delete', 'Delete IT assets', 'asset', 'it', 'user', 'basic', 149),
    ('it.asset.view', 'View IT assets', 'asset', 'it', 'user', 'basic', 150),
    ('it.incident.create', 'Create incidents', 'incident', 'it', 'user', 'basic', 151),
    ('it.incident.update', 'Update incidents', 'incident', 'it', 'user', 'basic', 152),
    ('it.incident.resolve', 'Resolve incidents', 'incident', 'it', 'user', 'basic', 153),
    ('it.incident.close', 'Close incidents', 'incident', 'it', 'user', 'basic', 154),
    ('it.incident.view', 'View incidents', 'incident', 'it', 'user', 'basic', 155),
    ('it.access.request', 'Request access', 'access', 'it', 'user', 'basic', 156),
    ('it.access.grant', 'Grant access', 'access', 'it', 'user', 'basic', 157),
    ('it.access.revoke', 'Revoke access', 'access', 'it', 'user', 'basic', 158),
    ('it.system.config.update', 'Update system config', 'system', 'it', 'user', 'basic', 159),
    ('it.system.config.view', 'View system config', 'system', 'it', 'user', 'basic', 160),
    ('production.order.create', 'Create production orders', 'order', 'production', 'user', 'basic', 161),
    ('production.order.update', 'Update production orders', 'order', 'production', 'user', 'basic', 162),
    ('production.order.start', 'Start production orders', 'order', 'production', 'user', 'basic', 163),
    ('production.order.pause', 'Pause production orders', 'order', 'production', 'user', 'basic', 164),
    ('production.order.finish', 'Finish production orders', 'order', 'production', 'user', 'basic', 165),
    ('production.order.cancel', 'Cancel production orders', 'order', 'production', 'user', 'basic', 166),
    ('production.order.delete', 'Delete production orders', 'order', 'production', 'user', 'basic', 167),
    ('production.order.view', 'View production orders', 'order', 'production', 'user', 'basic', 168),
    ('production.bom.create', 'Create BOMs', 'bom', 'production', 'user', 'basic', 169),
    ('production.bom.update', 'Update BOMs', 'bom', 'production', 'user', 'basic', 170),
    ('production.bom.delete', 'Delete BOMs', 'bom', 'production', 'user', 'basic', 171),
    ('production.bom.view', 'View BOMs', 'bom', 'production', 'user', 'basic', 172),
    ('production.route.create', 'Create routes', 'route', 'production', 'user', 'basic', 173),
    ('production.route.update', 'Update routes', 'route', 'production', 'user', 'basic', 174),
    ('production.route.view', 'View routes', 'route', 'production', 'user', 'basic', 175),
    ('production.route.delete', 'Delete routes', 'route', 'production', 'user', 'basic', 176),
    ('qc.inspection.create', 'Create inspections', 'inspection', 'qc', 'user', 'basic', 177),
    ('qc.inspection.update', 'Update inspections', 'inspection', 'qc', 'user', 'basic', 178),
    ('qc.inspection.approve', 'Approve inspections', 'inspection', 'qc', 'user', 'basic', 179),
    ('qc.inspection.reject', 'Reject inspections', 'inspection', 'qc', 'user', 'basic', 180),
    ('qc.inspection.delete', 'Delete inspections', 'inspection', 'qc', 'user', 'basic', 181),
    ('qc.inspection.view', 'View inspections', 'inspection', 'qc', 'user', 'basic', 182),
    ('qc.batch.hold', 'Hold batches', 'batch', 'qc', 'user', 'basic', 183),
    ('qc.batch.release', 'Release batches', 'batch', 'qc', 'user', 'basic', 184),
    ('qc.report.generate', 'Generate QC reports', 'report', 'qc', 'user', 'basic', 185),
    ('qc.report.view', 'View QC reports', 'report', 'qc', 'user', 'basic', 186),
    ('qa.test.create', 'Create tests', 'test', 'qa', 'user', 'basic', 187),
    ('qa.test.update', 'Update tests', 'test', 'qa', 'user', 'basic', 188),
    ('qa.test.delete', 'Delete tests', 'test', 'qa', 'user', 'basic', 189),
    ('qa.test.execute', 'Execute tests', 'test', 'qa', 'user', 'basic', 190),
    ('qa.test.view', 'View tests', 'test', 'qa', 'user', 'basic', 191),
    ('qa.audit.create', 'Create audits', 'audit', 'qa', 'user', 'basic', 192),
    ('qa.audit.update', 'Update audits', 'audit', 'qa', 'user', 'basic', 193),
    ('qa.audit.view', 'View audits', 'audit', 'qa', 'user', 'basic', 194),
    ('qa.report.generate', 'Generate QA reports', 'report', 'qa', 'user', 'basic', 195),
    ('qa.report.view', 'View QA reports', 'report', 'qa', 'user', 'basic', 196),
    ('rnd.experiment.create', 'Create experiments', 'experiment', 'rnd', 'user', 'basic', 197),
    ('rnd.experiment.update', 'Update experiments', 'experiment', 'rnd', 'user', 'basic', 198),
    ('rnd.experiment.delete', 'Delete experiments', 'experiment', 'rnd', 'user', 'basic', 199),
    ('rnd.experiment.view', 'View experiments', 'experiment', 'rnd', 'user', 'basic', 200),
    ('rnd.prototype.create', 'Create prototypes', 'prototype', 'rnd', 'user', 'basic', 201),
    ('rnd.prototype.update', 'Update prototypes', 'prototype', 'rnd', 'user', 'basic', 202),
    ('rnd.prototype.view', 'View prototypes', 'prototype', 'rnd', 'user', 'basic', 203),
    ('rnd.prototype.delete', 'Delete prototypes', 'prototype', 'rnd', 'user', 'basic', 204),
    ('rnd.document.create', 'Create R&D documents', 'document', 'rnd', 'user', 'basic', 205),
    ('rnd.document.update', 'Update R&D documents', 'document', 'rnd', 'user', 'basic', 206),
    ('rnd.document.view', 'View R&D documents', 'document', 'rnd', 'user', 'basic', 207),
    ('rnd.document.delete', 'Delete R&D documents', 'document', 'rnd', 'user', 'basic', 208),
    ('administration.company.view', 'View company administration settings', 'company', 'administration', 'user', 'basic', 210),
    ('administration.company.update', 'Update company administration settings', 'company', 'administration', 'user', 'basic', 211),
    ('administration.policy.create', 'Create company policies', 'policy', 'administration', 'user', 'basic', 212),
    ('administration.policy.update', 'Update company policies', 'policy', 'administration', 'user', 'basic', 213),
    ('administration.policy.delete', 'Delete company policies', 'policy', 'administration', 'user', 'basic', 214),
    ('administration.policy.view', 'View company policies', 'policy', 'administration', 'user', 'basic', 215),
    ('administration.approval.create', 'Create approval workflows', 'approval', 'administration', 'user', 'basic', 216),
    ('administration.approval.update', 'Update approval workflows', 'approval', 'administration', 'user', 'basic', 217),
    ('administration.approval.delete', 'Delete approval workflows', 'approval', 'administration', 'user', 'basic', 218),
    ('administration.approval.view', 'View approval workflows', 'approval', 'administration', 'user', 'basic', 219),
    ('administration.audit.view', 'View company audit logs', 'audit', 'administration', 'user', 'basic', 220),
    ('administration.security.view', 'View company security settings', 'security', 'administration', 'user', 'basic', 221),
    ('administration.security.update', 'Update company security settings', 'security', 'administration', 'user', 'basic', 222),
    ('attendance.self.punch', 'Allow user to punch their own attendance (check-in/check-out)', 'attendance', 'attendance', 'user', 'basic', 223),
    ('attendance.team.punch', 'Allow manager/lead to punch attendance for team members', 'attendance', 'attendance', 'user', 'basic', 224),
    ('attendance.correct', 'Allow correction or adjustment of attendance records', 'attendance', 'attendance', 'user', 'basic', 225),
    ('attendance.configure', 'Configure attendance rules, sources, and policies', 'attendance', 'attendance', 'user', 'basic', 226),
    ('payroll.run.create', 'Create payroll runs', 'payroll', 'payroll', 'user', 'basic', 227),
    ('payroll.run.update', 'Update payroll runs', 'payroll', 'payroll', 'user', 'basic', 228),
    ('payroll.run.view', 'View payroll runs', 'payroll', 'payroll', 'user', 'basic', 229),
    ('payroll.run.delete', 'Delete payroll runs', 'payroll', 'payroll', 'user', 'basic', 230),
    ('payroll.run.approve', 'Approve payroll runs', 'payroll', 'payroll', 'user', 'basic', 231),
    ('payroll.run.process', 'Process payroll runs', 'payroll', 'payroll', 'user', 'basic', 232),
    ('payroll.component.manage', 'Manage payroll components', 'payroll', 'payroll', 'user', 'basic', 233),
    ('payroll.tax.manage', 'Manage tax rules and profiles', 'payroll', 'payroll', 'user', 'basic', 234),
    ('admin.employee.create', 'Create admin employees', 'employee', 'employee_management', 'admin', 'admin', 235),
    ('admin.employee.update', 'Update admin employees', 'employee', 'employee_management', 'admin', 'admin', 236),
    ('admin.employee.view', 'View admin employees', 'employee', 'employee_management', 'admin', 'admin', 237),
    ('admin.employee.delete', 'Delete admin employees', 'employee', 'employee_management', 'admin', 'admin', 238),
    ('admin.employee.assign', 'Assign admin employees to departments', 'employee', 'employee_management', 'admin', 'admin', 239),
    ('admin.manager.create', 'Create admin managers', 'manager', 'manager_management', 'admin', 'admin', 240),
    ('admin.manager.update', 'Update admin managers', 'manager', 'manager_management', 'admin', 'admin', 241),
    ('admin.manager.view', 'View admin managers', 'manager', 'manager_management', 'admin', 'admin', 242),
    ('admin.manager.delete', 'Delete admin managers', 'manager', 'manager_management', 'admin', 'admin', 243),
    ('admin.manager.assign', 'Assign admin managers to departments', 'manager', 'manager_management', 'admin', 'admin', 244),
    ('admin.company.create', 'Create companies', 'company', 'company_management', 'admin', 'admin', 245),
    ('admin.company.update', 'Update companies', 'company', 'company_management', 'admin', 'admin', 246),
    ('admin.company.view', 'View companies', 'company', 'company_management', 'admin', 'admin', 247),
    ('admin.company.delete', 'Delete companies', 'company', 'company_management', 'admin', 'admin', 248),
    ('admin.company.suspend', 'Suspend companies', 'company', 'company_management', 'admin', 'admin', 249),
    ('admin.super.manage_roles', 'Manage all admin roles', 'role', 'super_admin', 'admin', 'super_admin', 250),
    ('admin.super.manage_permissions', 'Manage all permissions', 'permission', 'super_admin', 'admin', 'super_admin', 251),
    ('admin.super.manage_departments', 'Manage all departments', 'department', 'super_admin', 'admin', 'super_admin', 252),
    ('admin.super.system_config', 'Configure system settings', 'system', 'super_admin', 'admin', 'super_admin', 253),
    ('admin.super.audit_logs', 'View audit logs', 'audit', 'super_admin', 'admin', 'super_admin', 254),
    ('academics.academic_year.read', 'View academic years', 'academics', 'academics', 'user', 'basic', 255),
    ('academics.academic_year.create', 'Create academic years', 'academics', 'academics', 'user', 'basic', 256),
    ('academics.academic_year.update', 'Update academic years', 'academics', 'academics', 'user', 'basic', 257),
    ('academics.academic_year.delete', 'Delete academic years', 'academics', 'academics', 'user', 'basic', 258),
    ('academics.academic_year.set_current', 'Set current academic year', 'academics', 'academics', 'user', 'basic', 259),
    ('academics.academic_year.bulk_create', 'Bulk create academic years', 'academics', 'academics', 'user', 'basic', 260),
    ('academics.academic_year.upsert', 'Upsert academic years', 'academics', 'academics', 'user', 'basic', 261),
    ('academics.admission.read', 'View admissions', 'academics', 'academics', 'user', 'basic', 262),
    ('academics.admission.create', 'Create admissions', 'academics', 'academics', 'user', 'basic', 263),
    ('academics.admission.update', 'Update admissions', 'academics', 'academics', 'user', 'basic', 264),
    ('academics.admission.delete', 'Delete admissions', 'academics', 'academics', 'user', 'basic', 265),
    ('academics.admission.update_status', 'Update admission status', 'academics', 'academics', 'user', 'basic', 266),
    ('academics.admission.bulk_create', 'Bulk create admissions', 'academics', 'academics', 'user', 'basic', 267),
    ('academics.assignment.read', 'View assignments', 'academics', 'academics', 'user', 'basic', 268),
    ('academics.assignment.create', 'Create assignments', 'academics', 'academics', 'user', 'basic', 269),
    ('academics.assignment.update', 'Update assignments', 'academics', 'academics', 'user', 'basic', 270),
    ('academics.assignment.delete', 'Delete assignments', 'academics', 'academics', 'user', 'basic', 271),
    ('academics.assignment.publish', 'Publish assignments', 'academics', 'academics', 'user', 'basic', 272),
    ('academics.assignment.bulk_create', 'Bulk create assignments', 'academics', 'academics', 'user', 'basic', 273),
    ('academics.attendance.mark', 'Mark student attendance', 'academics', 'academics', 'user', 'basic', 274),
    ('academics.attendance.bulk_mark', 'Bulk mark attendance', 'academics', 'academics', 'user', 'basic', 275),
    ('academics.attendance.read', 'View attendance records', 'academics', 'academics', 'user', 'basic', 276),
    ('academics.attendance.delete', 'Delete attendance record', 'academics', 'academics', 'user', 'basic', 277),
    ('academics.attendance.recalculate', 'Recalculate attendance summary', 'academics', 'academics', 'user', 'basic', 278),
    ('academics.attendance.manage_exemptions', 'Manage attendance exemptions', 'academics', 'academics', 'user', 'basic', 279),
    ('academics.course.read', 'View courses', 'academics', 'academics', 'user', 'basic', 280),
    ('academics.course.create', 'Create courses', 'academics', 'academics', 'user', 'basic', 281),
    ('academics.course.update', 'Update courses', 'academics', 'academics', 'user', 'basic', 282),
    ('academics.course.delete', 'Delete courses', 'academics', 'academics', 'user', 'basic', 283),
    ('academics.course.activate', 'Activate course', 'academics', 'academics', 'user', 'basic', 284),
    ('academics.course.deactivate', 'Deactivate course', 'academics', 'academics', 'user', 'basic', 285),
    ('academics.course.bulk_create', 'Bulk create courses', 'academics', 'academics', 'user', 'basic', 286),
    ('academics.curriculum.assign', 'Assign subject to course', 'academics', 'academics', 'user', 'basic', 287),
    ('academics.curriculum.bulk_assign', 'Bulk assign subjects', 'academics', 'academics', 'user', 'basic', 288),
    ('academics.curriculum.read', 'View curriculum', 'academics', 'academics', 'user', 'basic', 289),
    ('academics.curriculum.remove', 'Remove subject mapping', 'academics', 'academics', 'user', 'basic', 290),
    ('academics.curriculum.remove_all', 'Remove all mappings for course', 'academics', 'academics', 'user', 'basic', 291),
    ('academics.curriculum.validate', 'Validate curriculum', 'academics', 'academics', 'user', 'basic', 292),
    ('academics.enrollment.read', 'View enrollments', 'academics', 'academics', 'user', 'basic', 293),
    ('academics.enrollment.create', 'Create enrollment', 'academics', 'academics', 'user', 'basic', 294),
    ('academics.enrollment.update', 'Update enrollment', 'academics', 'academics', 'user', 'basic', 295),
    ('academics.enrollment.delete', 'Delete enrollment', 'academics', 'academics', 'user', 'basic', 296),
    ('academics.enrollment.bulk_create', 'Bulk enroll students', 'academics', 'academics', 'user', 'basic', 297),
    ('academics.enrollment.upsert', 'Upsert enrollment', 'academics', 'academics', 'user', 'basic', 298),
    ('academics.enrollment.transfer', 'Transfer section', 'academics', 'academics', 'user', 'basic', 299),
    ('academics.enrollment.bulk_transfer', 'Bulk transfer sections', 'academics', 'academics', 'user', 'basic', 300),
    ('academics.enrollment.swap', 'Swap sections', 'academics', 'academics', 'user', 'basic', 301),
    ('academics.enrollment.promote', 'Promote student', 'academics', 'academics', 'user', 'basic', 302),
    ('academics.enrollment.bulk_promote', 'Bulk promote students', 'academics', 'academics', 'user', 'basic', 303),
    ('academics.enrollment.promote_section', 'Promote whole section', 'academics', 'academics', 'user', 'basic', 304),
    ('academics.enrollment.graduate', 'Mark student as graduated', 'academics', 'academics', 'user', 'basic', 305),
    ('academics.enrollment.mark_alumni', 'Mark as alumni', 'academics', 'academics', 'user', 'basic', 306),
    ('academics.enrollment.bulk_update_status', 'Bulk update enrollment status', 'academics', 'academics', 'user', 'basic', 307),
    ('academics.enrollment.bulk_assign_roll_numbers', 'Bulk assign roll numbers', 'academics', 'academics', 'user', 'basic', 308),
    ('academics.enrollment.search', 'Search enrollments', 'academics', 'academics', 'user', 'basic', 309),
    ('academics.enrollment.update_status', 'Update enrollment status', 'academics', 'academics', 'user', 'basic', 310),
    ('academics.exam.read', 'View exams', 'academics', 'academics', 'user', 'basic', 311),
    ('academics.exam.create', 'Create exam', 'academics', 'academics', 'user', 'basic', 312),
    ('academics.exam.update', 'Update exam', 'academics', 'academics', 'user', 'basic', 313),
    ('academics.exam.delete', 'Delete exam', 'academics', 'academics', 'user', 'basic', 314),
    ('academics.exam.schedule.create', 'Create exam schedule', 'academics', 'academics', 'user', 'basic', 315),
    ('academics.exam.schedule.read', 'View exam schedules', 'academics', 'academics', 'user', 'basic', 316),
    ('academics.exam.schedule.update', 'Update exam schedule', 'academics', 'academics', 'user', 'basic', 317),
    ('academics.exam.schedule.delete', 'Delete exam schedule', 'academics', 'academics', 'user', 'basic', 318),
    ('academics.exam.result.create', 'Create exam result', 'academics', 'academics', 'user', 'basic', 319),
    ('academics.exam.result.bulk_create', 'Bulk create exam results', 'academics', 'academics', 'user', 'basic', 320),
    ('academics.exam.result.read', 'View exam results', 'academics', 'academics', 'user', 'basic', 321),
    ('academics.exam.result.update', 'Update exam result', 'academics', 'academics', 'user', 'basic', 322),
    ('academics.exam.result.delete', 'Delete exam result', 'academics', 'academics', 'user', 'basic', 323),
    ('academics.exam.grade.create', 'Create exam grade', 'academics', 'academics', 'user', 'basic', 324),
    ('academics.exam.grade.read', 'View exam grades', 'academics', 'academics', 'user', 'basic', 325),
    ('academics.exam.grade.update', 'Update exam grade', 'academics', 'academics', 'user', 'basic', 326),
    ('academics.exam.grade.delete', 'Delete exam grade', 'academics', 'academics', 'user', 'basic', 327),
    ('academics.fee.structure.create', 'Create fee structure', 'academics', 'academics', 'user', 'basic', 328),
    ('academics.fee.structure.read', 'View fee structures', 'academics', 'academics', 'user', 'basic', 329),
    ('academics.fee.structure.update', 'Update fee structure', 'academics', 'academics', 'user', 'basic', 330),
    ('academics.fee.structure.delete', 'Delete fee structure', 'academics', 'academics', 'user', 'basic', 331),
    ('academics.fee.invoice.create', 'Create fee invoice', 'academics', 'academics', 'user', 'basic', 332),
    ('academics.fee.invoice.read', 'View fee invoices', 'academics', 'academics', 'user', 'basic', 333),
    ('academics.fee.invoice.update', 'Update fee invoice', 'academics', 'academics', 'user', 'basic', 334),
    ('academics.fee.payment.create', 'Create fee payment', 'academics', 'academics', 'user', 'basic', 335),
    ('academics.fee.payment.read', 'View fee payments', 'academics', 'academics', 'user', 'basic', 336),
    ('academics.fee.discount.create', 'Create fee discount', 'academics', 'academics', 'user', 'basic', 337),
    ('academics.fee.discount.update', 'Update fee discount', 'academics', 'academics', 'user', 'basic', 338),
    ('academics.fee.discount.delete', 'Delete fee discount', 'academics', 'academics', 'user', 'basic', 339),
    ('academics.fee.penalty.create', 'Create fee penalty', 'academics', 'academics', 'user', 'basic', 340),
    ('academics.fee.penalty.update', 'Update fee penalty', 'academics', 'academics', 'user', 'basic', 341),
    ('academics.fee.receipt.generate', 'Generate fee receipt', 'academics', 'academics', 'user', 'basic', 342),
    ('academics.fee.receipt.read', 'View fee receipt', 'academics', 'academics', 'user', 'basic', 343),
    ('academics.grading.policy.create', 'Create grading policy', 'academics', 'academics', 'user', 'basic', 344),
    ('academics.grading.policy.read', 'View grading policies', 'academics', 'academics', 'user', 'basic', 345),
    ('academics.grading.policy.update', 'Update grading policy', 'academics', 'academics', 'user', 'basic', 346),
    ('academics.grading.policy.delete', 'Delete grading policy', 'academics', 'academics', 'user', 'basic', 347),
    ('academics.grading.boundary.create', 'Create grade boundary', 'academics', 'academics', 'user', 'basic', 348),
    ('academics.grading.boundary.bulk_create', 'Bulk create grade boundaries', 'academics', 'academics', 'user', 'basic', 349),
    ('academics.grading.boundary.read', 'View grade boundaries', 'academics', 'academics', 'user', 'basic', 350),
    ('academics.grading.boundary.update', 'Update grade boundary', 'academics', 'academics', 'user', 'basic', 351),
    ('academics.grading.boundary.delete', 'Delete grade boundary', 'academics', 'academics', 'user', 'basic', 352),
    ('academics.grading.boundary.delete_all', 'Delete all grade boundaries for policy', 'academics', 'academics', 'user', 'basic', 353),
    ('academics.guardian.create', 'Create guardian', 'academics', 'academics', 'user', 'basic', 354),
    ('academics.guardian.bulk_create', 'Bulk create guardians', 'academics', 'academics', 'user', 'basic', 355),
    ('academics.guardian.read', 'View guardians', 'academics', 'academics', 'user', 'basic', 356),
    ('academics.guardian.update', 'Update guardian', 'academics', 'academics', 'user', 'basic', 357),
    ('academics.guardian.delete', 'Delete guardian', 'academics', 'academics', 'user', 'basic', 358),
    ('academics.guardian.set_primary', 'Set primary guardian', 'academics', 'academics', 'user', 'basic', 359),
    ('academics.library.category.create', 'Create library category', 'academics', 'academics', 'user', 'basic', 360),
    ('academics.library.category.read', 'View library categories', 'academics', 'academics', 'user', 'basic', 361),
    ('academics.library.category.update', 'Update library category', 'academics', 'academics', 'user', 'basic', 362),
    ('academics.library.category.delete', 'Delete library category', 'academics', 'academics', 'user', 'basic', 363),
    ('academics.library.book.create', 'Create library book', 'academics', 'academics', 'user', 'basic', 364),
    ('academics.library.book.read', 'View library books', 'academics', 'academics', 'user', 'basic', 365),
    ('academics.library.book.update', 'Update library book', 'academics', 'academics', 'user', 'basic', 366),
    ('academics.library.book.delete', 'Delete library book', 'academics', 'academics', 'user', 'basic', 367),
    ('academics.library.copy.create', 'Create book copy', 'academics', 'academics', 'user', 'basic', 368),
    ('academics.library.copy.read', 'View book copies', 'academics', 'academics', 'user', 'basic', 369),
    ('academics.library.copy.update', 'Update book copy', 'academics', 'academics', 'user', 'basic', 370),
    ('academics.library.copy.delete', 'Delete book copy', 'academics', 'academics', 'user', 'basic', 371),
    ('academics.library.issue.create', 'Issue book', 'academics', 'academics', 'user', 'basic', 372),
    ('academics.library.issue.read', 'View book issues', 'academics', 'academics', 'user', 'basic', 373),
    ('academics.library.return.create', 'Return book', 'academics', 'academics', 'user', 'basic', 374),
    ('academics.library.fine.create', 'Create fine', 'academics', 'academics', 'user', 'basic', 375),
    ('academics.library.fine.update', 'Update fine payment', 'academics', 'academics', 'user', 'basic', 376),
    ('academics.library.fine.read', 'View fines', 'academics', 'academics', 'user', 'basic', 377),
    ('academics.notification.create', 'Create notification', 'academics', 'academics', 'user', 'basic', 378),
    ('academics.notification.read', 'View notifications', 'academics', 'academics', 'user', 'basic', 379),
    ('academics.notification.update', 'Update notification', 'academics', 'academics', 'user', 'basic', 380),
    ('academics.notification.delete', 'Delete notification', 'academics', 'academics', 'user', 'basic', 381),
    ('academics.room.create', 'Create room', 'academics', 'academics', 'user', 'basic', 382),
    ('academics.room.bulk_create', 'Bulk create rooms', 'academics', 'academics', 'user', 'basic', 383),
    ('academics.room.read', 'View rooms', 'academics', 'academics', 'user', 'basic', 384),
    ('academics.room.update', 'Update room', 'academics', 'academics', 'user', 'basic', 385),
    ('academics.room.delete', 'Delete room', 'academics', 'academics', 'user', 'basic', 386),
    ('academics.room.activate', 'Activate room', 'academics', 'academics', 'user', 'basic', 387),
    ('academics.room.deactivate', 'Deactivate room', 'academics', 'academics', 'user', 'basic', 388),
    ('academics.section.create', 'Create section', 'academics', 'academics', 'user', 'basic', 389),
    ('academics.section.bulk_create', 'Bulk create sections', 'academics', 'academics', 'user', 'basic', 390),
    ('academics.section.upsert', 'Upsert section', 'academics', 'academics', 'user', 'basic', 391),
    ('academics.section.read', 'View sections', 'academics', 'academics', 'user', 'basic', 392),
    ('academics.section.update', 'Update section', 'academics', 'academics', 'user', 'basic', 393),
    ('academics.section.delete', 'Delete section', 'academics', 'academics', 'user', 'basic', 394),
    ('student.create', 'Create student', 'academics', 'academics', 'user', 'basic', 395),
    ('student.bulk_create', 'Bulk create students', 'academics', 'academics', 'user', 'basic', 396),
    ('student.read', 'View student details', 'academics', 'academics', 'user', 'basic', 397),
    ('student.update', 'Update student', 'academics', 'academics', 'user', 'basic', 398),
    ('student.delete', 'Delete student', 'academics', 'academics', 'user', 'basic', 399),
    ('student.activate', 'Activate student', 'academics', 'academics', 'user', 'basic', 400),
    ('student.deactivate', 'Deactivate student', 'academics', 'academics', 'user', 'basic', 401),
    ('student.promote', 'Promote student', 'academics', 'academics', 'user', 'basic', 402),
    ('student.graduate', 'Graduate student', 'academics', 'academics', 'user', 'basic', 403),
    ('student.dropout', 'Mark student as dropout', 'academics', 'academics', 'user', 'basic', 404),
    ('student.bulk_promote', 'Bulk promote students', 'academics', 'academics', 'user', 'basic', 405),
    ('student.bulk_update_status', 'Bulk update student status', 'academics', 'academics', 'user', 'basic', 406),
    ('student.set_password', 'Set student password', 'academics', 'academics', 'user', 'basic', 407),
    ('student.reset_password', 'Reset student password', 'academics', 'academics', 'user', 'basic', 408),
    ('student.change_password', 'Change own password', 'academics', 'academics', 'user', 'basic', 409),
    ('subject.create', 'Create subject', 'academics', 'academics', 'user', 'basic', 410),
    ('subject.bulk_create', 'Bulk create subjects', 'academics', 'academics', 'user', 'basic', 411),
    ('subject.read', 'View subjects', 'academics', 'academics', 'user', 'basic', 412),
    ('subject.update', 'Update subject', 'academics', 'academics', 'user', 'basic', 413),
    ('subject.delete', 'Delete subject', 'academics', 'academics', 'user', 'basic', 414),
    ('subject.activate', 'Activate subject', 'academics', 'academics', 'user', 'basic', 415),
    ('subject.deactivate', 'Deactivate subject', 'academics', 'academics', 'user', 'basic', 416),
    ('submission.create', 'Create submission', 'academics', 'academics', 'user', 'basic', 417),
    ('submission.read', 'View submissions', 'academics', 'academics', 'user', 'basic', 418),
    ('submission.update', 'Update submission', 'academics', 'academics', 'user', 'basic', 419),
    ('submission.delete', 'Delete submission', 'academics', 'academics', 'user', 'basic', 420),
    ('submission.grade', 'Grade submission', 'academics', 'academics', 'user', 'basic', 421),
    ('submission.comment', 'Comment on submission', 'academics', 'academics', 'user', 'basic', 422),
    ('teacher.create', 'Create teacher', 'academics', 'academics', 'user', 'basic', 423),
    ('teacher.bulk_create', 'Bulk create teachers', 'academics', 'academics', 'user', 'basic', 424),
    ('teacher.read', 'View teacher details', 'academics', 'academics', 'user', 'basic', 425),
    ('teacher.update', 'Update teacher', 'academics', 'academics', 'user', 'basic', 426),
    ('teacher.update_status', 'Update teacher status', 'academics', 'academics', 'user', 'basic', 427),
    ('teacher.delete', 'Delete teacher', 'academics', 'academics', 'user', 'basic', 428),
    ('teacher.bulk_update_status', 'Bulk update teacher status', 'academics', 'academics', 'user', 'basic', 429),
    ('teacher.manage_subjects', 'Manage teacher subjects', 'academics', 'academics', 'user', 'basic', 430),
    ('teacher.manage_sections', 'Manage teacher sections', 'academics', 'academics', 'user', 'basic', 431),
    ('teacher.manage_preferences', 'Manage teacher schedule preferences', 'academics', 'academics', 'user', 'basic', 432),
    ('term.create', 'Create term', 'academics', 'academics', 'user', 'basic', 433),
    ('term.bulk_create', 'Bulk create terms', 'academics', 'academics', 'user', 'basic', 434),
    ('term.read', 'View terms', 'academics', 'academics', 'user', 'basic', 435),
    ('term.update', 'Update term', 'academics', 'academics', 'user', 'basic', 436),
    ('term.delete', 'Delete term', 'academics', 'academics', 'user', 'basic', 437),
    ('term.set_current', 'Set current term', 'academics', 'academics', 'user', 'basic', 438),
    ('timetable.create', 'Create timetable', 'academics', 'academics', 'user', 'basic', 439),
    ('timetable.read', 'View timetables', 'academics', 'academics', 'user', 'basic', 440),
    ('timetable.update', 'Update timetable', 'academics', 'academics', 'user', 'basic', 441),
    ('timetable.delete', 'Delete timetable', 'academics', 'academics', 'user', 'basic', 442),
    ('timetable.manage_slots', 'Manage timetable slots', 'academics', 'academics', 'user', 'basic', 443),
    ('timetable.manage_entries', 'Manage timetable entries', 'academics', 'academics', 'user', 'basic', 444),
    ('timetable.manage_changes', 'Manage timetable changes', 'academics', 'academics', 'user', 'basic', 445),
    ('transport.route.create', 'Create transport route', 'academics', 'academics', 'user', 'basic', 446),
    ('transport.route.read', 'View transport routes', 'academics', 'academics', 'user', 'basic', 447),
    ('transport.route.update', 'Update transport route', 'academics', 'academics', 'user', 'basic', 448),
    ('transport.route.delete', 'Delete transport route', 'academics', 'academics', 'user', 'basic', 449),
    ('transport.stop.create', 'Create transport stop', 'academics', 'academics', 'user', 'basic', 450),
    ('transport.stop.read', 'View transport stops', 'academics', 'academics', 'user', 'basic', 451),
    ('transport.stop.update', 'Update transport stop', 'academics', 'academics', 'user', 'basic', 452),
    ('transport.stop.delete', 'Delete transport stop', 'academics', 'academics', 'user', 'basic', 453),
    ('transport.vehicle.create', 'Create transport vehicle', 'academics', 'academics', 'user', 'basic', 454),
    ('transport.vehicle.read', 'View transport vehicles', 'academics', 'academics', 'user', 'basic', 455),
    ('transport.vehicle.update', 'Update transport vehicle', 'academics', 'academics', 'user', 'basic', 456),
    ('transport.vehicle.delete', 'Delete transport vehicle', 'academics', 'academics', 'user', 'basic', 457),
    ('transport.driver.create', 'Create driver assignment', 'academics', 'academics', 'user', 'basic', 458),
    ('transport.driver.read', 'View driver assignments', 'academics', 'academics', 'user', 'basic', 459),
    ('transport.driver.update', 'Update driver assignment', 'academics', 'academics', 'user', 'basic', 460),
    ('transport.driver.delete', 'Delete driver assignment', 'academics', 'academics', 'user', 'basic', 461),
    ('transport.student_assignment.create', 'Create student transport assignment', 'academics', 'academics', 'user', 'basic', 462),
    ('transport.student_assignment.read', 'View student transport assignments', 'academics', 'academics', 'user', 'basic', 463),
    ('transport.student_assignment.update', 'Update student transport assignment', 'academics', 'academics', 'user', 'basic', 464),
    ('transport.student_assignment.delete', 'Delete student transport assignment', 'academics', 'academics', 'user', 'basic', 465),
    ('academics.analytics.read', 'View academic analytics', 'academics', 'academics', 'user', 'basic', 466),
    ('academics.analytics.write', 'Refresh analytics metrics', 'academics', 'academics', 'user', 'basic', 467)
ON CONFLICT (permission_name) DO NOTHING;
INSERT INTO audit.outbox_debounce (last_processed_id, last_processed_at, batch_size)
VALUES (NULL, NOW() - INTERVAL '1 hour', 0);
CREATE OR REPLACE VIEW leave.leave_balance_detailed_view AS
WITH accrual_totals AS (
    SELECT
        entitlement_id,
        SUM(days_accrued) as total_accrued,
        SUM(fractional_days) as total_fractional
    FROM leave.leave_accrual
    GROUP BY entitlement_id
),
consumption_totals AS (
    SELECT
        entitlement_id,
        SUM(days) as total_consumed
    FROM leave.leave_ledger
    WHERE entry_type = 'consumption'
    GROUP BY entitlement_id
),
current_entitlements AS (
    SELECT
        e.*,
        COALESCE(a.total_accrued, 0) + COALESCE(a.total_fractional, 0) as accrued_total,
        COALESCE(c.total_consumed, 0) as consumed_total
    FROM leave.leave_entitlement e
    LEFT JOIN accrual_totals a ON e.entitlement_id = a.entitlement_id
    LEFT JOIN consumption_totals c ON e.entitlement_id = c.entitlement_id
    WHERE e.effective_from <= CURRENT_DATE
    AND (e.effective_to IS NULL OR e.effective_to >= CURRENT_DATE)
)
SELECT
    ce.*,
    (ce.accrued_total - ce.consumed_total) as available_balance,
    GREATEST(0, ce.total_days - ce.accrued_total) as remaining_to_accrue
FROM current_entitlements ce;
CREATE OR REPLACE VIEW leave.leave_balance_view AS
SELECT
    le.user_id,
    le.leave_type_id,
    SUM(CASE WHEN ll.entry_type = 'accrual' THEN ll.days ELSE 0 END) AS balance
FROM leave.leave_ledger ll
JOIN leave.leave_entitlement le ON ll.entitlement_id = le.entitlement_id
GROUP BY le.user_id, le.leave_type_id;
CREATE OR REPLACE VIEW payroll.statutory_contribution_summary_view AS
SELECT
    company_id,
    statutory_code,
    period_start,
    period_end,
    COUNT(DISTINCT user_id) AS total_employees,
    SUM(total_amount) AS total_amount,
    SUM(employee_amount) AS employee_share,
    SUM(employer_amount) AS employer_share,
    NOW() AS generated_at
FROM payroll.employee_statutory_contribution
GROUP BY company_id, statutory_code, period_start, period_end;
REVOKE UPDATE, DELETE ON audit.audit_logs FROM PUBLIC;
CREATE UNIQUE INDEX idx_payroll_component_global
ON payroll.payroll_component(component_code)
WHERE company_id IS NULL;
CREATE UNIQUE INDEX idx_payroll_component_company
ON payroll.payroll_component(company_id, component_code)
WHERE company_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS payroll.payroll_employee_job (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payroll_run_id UUID NOT NULL,
    user_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','processing','completed','failed')),
    attempts INT NOT NULL DEFAULT 0,
    locked_by TEXT,
    locked_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_employee_job_run
        FOREIGN KEY (payroll_run_id)
        REFERENCES payroll.payroll_run(payroll_run_id)
        ON DELETE CASCADE,
    CONSTRAINT uq_employee_job_run_user
        UNIQUE (payroll_run_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_payroll_employee_job_pending
ON payroll.payroll_employee_job (payroll_run_id)
WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_payroll_employee_job_status
ON payroll.payroll_employee_job (status);
CREATE INDEX idx_employee_job_run_status
ON payroll.payroll_employee_job(payroll_run_id, status);
CREATE INDEX idx_employee_job_pending
ON payroll.payroll_employee_job(status, created_at);
INSERT INTO users (
    user_id,
    username,
    full_name,
    phone_hash,
    phone_encrypted,
    phone_encrypted_dek,
    phone_key_id,
    is_verified,
    is_active
)
VALUES (
    '11111111-1111-1111-1111-111111111111',
    'system',
    'SYSTEM INTERNAL USER',
    'system',
    '\\x00',
    'system',
    '11111111-1111-1111-1111-111111111111',
    true,
    true
)
ON CONFLICT (user_id) DO NOTHING;
CREATE INDEX IF NOT EXISTS idx_employee_profiles_email
ON employee_profiles (email)
WHERE email IS NOT NULL;
ALTER TABLE employee_profiles
ADD CONSTRAINT uniq_employee_profiles_company_email UNIQUE (company_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS uq_employee_bank_details_active
    ON payroll.employee_bank_details (company_id, user_id)
    WHERE is_active = true;
EOSQL
echo "🧬 Initializing biometric schema..."