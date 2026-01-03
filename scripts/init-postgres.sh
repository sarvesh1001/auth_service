diff b?w this     #!/bin/bash
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
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
    -- Enable UUID extension
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    -- Enable trigram extension for fast text search
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    -- ==============================================
    -- SINGLE PERMISSIONS TABLE (For both Users and Admins)
    -- ==============================================
    CREATE TABLE permissions (
        permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        permission_name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT,
        category VARCHAR(50) NOT NULL,
        module VARCHAR(50) NOT NULL,
        scope VARCHAR(20) NOT NULL DEFAULT 'user', -- 'user' or 'admin' or 'both'
        requires_tier VARCHAR(20) DEFAULT 'basic',
        bit_index INTEGER UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- ==============================================
    -- SINGLE SYSTEM DEPARTMENTS TABLE (For both Users and Admins)
    -- ==============================================
    CREATE TABLE system_departments (
        system_department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) UNIQUE NOT NULL,
        module_code VARCHAR(100) NOT NULL,
        description TEXT,
        bitmask BIGINT NOT NULL
    );

    -- ==============================================
    -- ADMIN ROLES TABLE
    -- ==============================================
    CREATE TABLE admin_roles (
        admin_role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role_name VARCHAR(100) NOT NULL,
        role_level INTEGER NOT NULL DEFAULT 1000,
        role_type INTEGER NOT NULL DEFAULT 1, -- 1=Employee, 2=Manager, 4=Super Admin
        is_system_role BOOLEAN NOT NULL DEFAULT false,
        description TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(role_name),
        CONSTRAINT check_role_type CHECK (role_type IN (1, 2, 4)),
        -- New constraint: Only one Super Admin role (role_type = 4)
        CONSTRAINT unique_super_admin_role EXCLUDE USING btree (role_type WITH =) WHERE (role_type = 4)
    );

    -- ==============================================
    -- ADMIN ROLE PERMISSIONS TABLE
    -- ==============================================
    CREATE TABLE admin_role_permissions (
        admin_role_id UUID NOT NULL,
        permission_id UUID NOT NULL,
        granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        granted_by UUID NOT NULL,
        PRIMARY KEY (admin_role_id, permission_id),
        CONSTRAINT fk_admin_role_perms_role FOREIGN KEY (admin_role_id) REFERENCES admin_roles(admin_role_id) ON DELETE CASCADE,
        CONSTRAINT fk_admin_role_perms_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
    );

    -- ==============================================
    -- ADMIN ROLE DEPARTMENTS TABLE
    -- ==============================================
    CREATE TABLE admin_role_departments (
        admin_role_id UUID NOT NULL,
        system_department_id UUID NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (admin_role_id, system_department_id),
        CONSTRAINT fk_admin_role_departments_role FOREIGN KEY (admin_role_id) REFERENCES admin_roles(admin_role_id) ON DELETE CASCADE,
        CONSTRAINT fk_admin_role_departments_department FOREIGN KEY (system_department_id) REFERENCES system_departments(system_department_id) ON DELETE CASCADE
    );

    -- ==============================================
    -- ADMIN USERS TABLE (Updated Structure)
    -- ==============================================
    CREATE TABLE admin_users (
        admin_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        phone_hash VARCHAR(128) NOT NULL,
        phone_encrypted BYTEA NOT NULL,
        phone_key_id UUID NOT NULL,
        phone_encrypted_dek TEXT NOT NULL,
        admin_role_id UUID NOT NULL,
        role_type INTEGER NOT NULL DEFAULT 1, -- 1=Employee, 2=Manager, 4=Super Admin
        reports_to UUID REFERENCES admin_users(admin_id),
        admin_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        admin_created_by UUID,
        admin_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT true,
        data_access_scope TEXT[],
        ip_whitelist TEXT[],
        failed_login_attempts INTEGER DEFAULT 0,
        last_login TIMESTAMPTZ,
        -- New fields for search functionality
        username VARCHAR(100) NOT NULL UNIQUE,
        full_name VARCHAR(255),
        user_search_tsv TSVECTOR GENERATED ALWAYS AS (
            to_tsvector('simple', COALESCE(username, '')) ||
            to_tsvector('simple', COALESCE(full_name, ''))
        ) STORED,
        -- Foreign key constraint for admin role
        CONSTRAINT fk_admin_users_role FOREIGN KEY (admin_role_id) REFERENCES admin_roles(admin_role_id),
        CONSTRAINT check_admin_role_type CHECK (role_type IN (1, 2, 4)),
        -- New constraint: Only one Super Admin user (role_type = 4)
        CONSTRAINT unique_super_admin_user EXCLUDE USING btree (role_type WITH =) WHERE (role_type = 4)
    );

    CREATE TABLE users (
        user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        -- New fields for user search
        username VARCHAR(100) NOT NULL,
        full_name VARCHAR(255),
        user_search_tsv TSVECTOR GENERATED ALWAYS AS (
            to_tsvector('simple', COALESCE(username, '')) ||
            to_tsvector('simple', COALESCE(full_name, ''))
        ) STORED,
        -- Existing fields from old schema
        phone_hash VARCHAR(128) NOT NULL,
        phone_encrypted BYTEA NOT NULL,
        phone_encrypted_dek TEXT NOT NULL,
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

    -- Create 8 partitions for users (as in old schema)
    CREATE TABLE users_p0 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 0);
    CREATE TABLE users_p1 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 1);
    CREATE TABLE users_p2 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 2);
    CREATE TABLE users_p3 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 3);
    CREATE TABLE users_p4 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 4);
    CREATE TABLE users_p5 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 5);
    CREATE TABLE users_p6 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 6);
    CREATE TABLE users_p7 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 7);

    -- Create a unique constraint that includes the partition key
    -- This is required for partitioned tables in PostgreSQL
    ALTER TABLE users ADD CONSTRAINT unique_username UNIQUE (user_id, username);

    CREATE TABLE companies (
        company_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_name VARCHAR(255) NOT NULL,
        company_name_tsv TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', company_name)) STORED,
        owner_user_id UUID NOT NULL,
        subscription_tier VARCHAR(20) NOT NULL DEFAULT 'basic',
        subscription_status VARCHAR(20) NOT NULL DEFAULT 'active',
        max_employees INTEGER NOT NULL DEFAULT 10,
        data_region VARCHAR(10) NOT NULL DEFAULT 'us',
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        subscription_start_date TIMESTAMPTZ,
        subscription_end_date TIMestAMPTZ,
        -- Keep unique constraint from old schema
        UNIQUE(company_name, owner_user_id),
        -- Foreign key constraint
        CONSTRAINT fk_companies_owner FOREIGN KEY (owner_user_id) REFERENCES users(user_id)
    );

    CREATE TABLE roles (
        role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        role_name VARCHAR(100) NOT NULL,
        role_level INTEGER NOT NULL DEFAULT 1000,
        company_id UUID NOT NULL,
        is_system_role BOOLEAN NOT NULL DEFAULT false,
        description TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(company_id, role_name),
        CONSTRAINT fk_roles_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
    );

    CREATE TABLE role_permissions (
        role_id UUID NOT NULL,
        permission_id UUID NOT NULL,
        granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        granted_by UUID NOT NULL,
        PRIMARY KEY (role_id, permission_id),
        CONSTRAINT fk_role_perms_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
        CONSTRAINT fk_role_perms_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
    );

    CREATE TABLE departments (
        department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID NOT NULL,
        department_name VARCHAR(255) NOT NULL,
        system_department_id UUID,
        parent_department_id UUID,
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(company_id, department_name),
        CONSTRAINT fk_departments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
        CONSTRAINT fk_departments_system FOREIGN KEY (system_department_id) REFERENCES system_departments(system_department_id),
        CONSTRAINT fk_departments_parent FOREIGN KEY (parent_department_id) REFERENCES departments(department_id)
    );

    CREATE TABLE role_departments (
        role_id UUID NOT NULL,
        department_id UUID NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (role_id, department_id),
        CONSTRAINT fk_role_departments_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
        CONSTRAINT fk_role_departments_department FOREIGN KEY (department_id) REFERENCES departments(department_id) ON DELETE CASCADE
    );

    CREATE TABLE company_employees (
        company_id UUID NOT NULL,
        user_id UUID NOT NULL,
        employee_id VARCHAR(100) NOT NULL,
        role_id UUID NOT NULL,
        hire_date TIMestAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT true,
        reports_to UUID,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMestAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (company_id, user_id),
        CONSTRAINT fk_employees_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
        CONSTRAINT fk_employees_user FOREIGN KEY (user_id) REFERENCES users(user_id),
        CONSTRAINT fk_employees_role FOREIGN KEY (role_id) REFERENCES roles(role_id)
    );

    CREATE TABLE user_devices (
        device_id VARCHAR(256) PRIMARY KEY,
        user_id UUID NOT NULL,
        device_type VARCHAR(50),
        device_name VARCHAR(100),
        os_version VARCHAR(50),
        app_version VARCHAR(50),
        last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMestAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_user_devices_user FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE login_attempts (
        attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        success BOOLEAN NOT NULL,
        ip_address VARCHAR(64),
        user_agent TEXT,
        device_id VARCHAR(256),
        attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        failure_reason TEXT,
        CONSTRAINT fk_login_attempts_user FOREIGN KEY (user_id) REFERENCES users(user_id),
        CONSTRAINT fk_login_attempts_device FOREIGN KEY (device_id) REFERENCES user_devices(device_id)
    );

    -- ==============================================
    -- INDEXES
    -- ==============================================
    -- Indexes for admin_users
    CREATE INDEX idx_admin_users_search_tsv ON admin_users USING GIN (user_search_tsv);
    CREATE INDEX idx_admin_users_username_trgm ON admin_users USING GIN (username gin_trgm_ops);
    CREATE INDEX idx_admin_users_fullname_trgm ON admin_users USING GIN (full_name gin_trgm_ops);
    CREATE INDEX idx_admin_users_role ON admin_users (admin_role_id) WHERE is_active = true;
    CREATE INDEX idx_admin_users_role_type ON admin_users (role_type) WHERE is_active = true;
    CREATE INDEX idx_admin_users_role_type_role ON admin_users (role_type, admin_role_id) WHERE is_active = true;
    CREATE INDEX idx_admin_users_phone_hash ON admin_users (phone_hash);
    CREATE INDEX idx_admin_users_active ON admin_users (is_active) WHERE is_active = true;
    CREATE INDEX idx_admin_users_username ON admin_users (username);
    CREATE INDEX idx_admin_users_role_active_login ON admin_users (admin_role_id, is_active, last_login DESC);

    -- Indexes for admin_roles
    CREATE INDEX idx_admin_roles_name ON admin_roles (role_name);
    CREATE INDEX idx_admin_roles_level ON admin_roles (role_level);
    CREATE INDEX idx_admin_roles_type ON admin_roles (role_type);

    -- Indexes for admin_role_permissions
    CREATE INDEX idx_admin_role_perms_role ON admin_role_permissions (admin_role_id);
    CREATE INDEX idx_admin_role_perms_permission ON admin_role_permissions (permission_id);

    -- Indexes for admin_role_departments
    CREATE INDEX idx_admin_role_departments_role ON admin_role_departments (admin_role_id);
    CREATE INDEX idx_admin_role_departments_dept ON admin_role_departments (system_department_id);

    -- Indexes for permissions
    CREATE INDEX idx_permissions_name ON permissions (permission_name);
    CREATE INDEX idx_permissions_bit_index ON permissions (bit_index);
    CREATE INDEX idx_permissions_module ON permissions (module);
    CREATE INDEX idx_permissions_scope ON permissions (scope);

    -- Indexes for system_departments
    CREATE INDEX idx_system_departments_name ON system_departments (name);
    CREATE INDEX idx_system_departments_module ON system_departments (module_code);
    CREATE INDEX idx_system_departments_bitmask ON system_departments (bitmask);

    -- Other indexes (from original schema)
    CREATE INDEX idx_users_search_tsv ON users USING GIN (user_search_tsv);
    CREATE INDEX idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);
    CREATE INDEX idx_users_fullname_trgm ON users USING GIN (full_name gin_trgm_ops);
    CREATE INDEX idx_users_username ON users (username);
    CREATE INDEX idx_users_fullname ON users (full_name);
    CREATE INDEX idx_users_name_search ON users (username, full_name);
    CREATE INDEX idx_companies_name_tsv ON companies USING GIN (company_name_tsv);
    CREATE INDEX idx_companies_name_trgm ON companies USING GIN (company_name gin_trgm_ops);
    CREATE INDEX idx_companies_name ON companies (company_name);
    CREATE INDEX idx_companies_owner_name ON companies (owner_user_id, company_name);
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
    CREATE INDEX idx_employees_active ON company_employees (is_active);
    CREATE INDEX idx_employees_company_active ON company_employees (company_id, is_active);
    CREATE INDEX idx_employees_reports_to ON company_employees (company_id, reports_to);
    CREATE INDEX idx_departments_company ON departments (company_id);
    CREATE INDEX idx_departments_parent ON departments (parent_department_id);
    CREATE INDEX idx_departments_system ON departments (system_department_id);
    CREATE INDEX idx_role_departments_role ON role_departments (role_id);
    CREATE INDEX idx_role_departments_department ON role_departments (department_id);
    CREATE INDEX idx_user_devices_user ON user_devices (user_id);
    CREATE INDEX idx_user_devices_active ON user_devices (is_active);
    CREATE INDEX idx_user_devices_last_active ON user_devices (last_active);
    CREATE INDEX idx_login_attempts_user ON login_attempts (user_id);
    CREATE INDEX idx_login_attempts_device ON login_attempts (device_id);
    CREATE INDEX idx_login_attempts_success ON login_attempts (success);
    CREATE INDEX idx_login_attempts_time ON login_attempts (attempted_at DESC);

    -- ==============================================
    -- ADMIN USER SEARCH FUNCTIONS - FIXED VERSION
    -- ==============================================

    -- Fixed: Returns admin_role_id instead of role_level
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
        relevance_score FLOAT,  -- This is DOUBLE PRECISION
        match_type TEXT
    ) AS $$
    BEGIN
        -- Normalize empty string to NULL
        IF search_query_param = '' THEN
            search_query_param := NULL;
        END IF;

        -- Build query based on search type
        IF search_query_param IS NULL THEN
            -- Return all admins (no search query)
            RETURN QUERY
            SELECT
                au.admin_id, au.username, au.full_name, au.phone_hash,
                ar.role_name, au.admin_role_id, au.role_type,
                au.reports_to, ru.full_name as reports_to_name,
                au.is_active, au.last_login, au.admin_created_at,
                1.0::FLOAT as relevance_score,  -- Explicit cast
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
            -- Autocomplete/partial match
            RETURN QUERY
            SELECT
                au.admin_id, au.username, au.full_name, au.phone_hash,
                ar.role_name, au.admin_role_id, au.role_type,
                au.reports_to, ru.full_name as reports_to_name,
                au.is_active, au.last_login, au.admin_created_at,
                -- Cast similarity results to FLOAT (DOUBLE PRECISION)
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
            -- Full-text search
            RETURN QUERY
            SELECT
                au.admin_id, au.username, au.full_name, au.phone_hash,
                ar.role_name, au.admin_role_id, au.role_type,
                au.reports_to, ru.full_name as reports_to_name,
                au.is_active, au.last_login, au.admin_created_at,
                -- Cast ts_rank result to FLOAT (DOUBLE PRECISION)
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
    -- Function to search admin employees (role_type = 1)
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
        admin_role_id UUID,  -- Fixed: Changed from role_level to admin_role_id
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
            1,  -- Employee role type
            search_query,
            search_type,
            include_inactive,
            limit_count,
            offset_count
        );
    END;
    $$ LANGUAGE plpgsql;

    -- Function to search admin managers (role_type = 2)
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
        admin_role_id UUID,  -- Fixed: Changed from role_level to admin_role_id
        reports_to UUID,
        reports_to_name VARCHAR(255),
        is_active BOOLEAN,
        last_login TIMestAMPTZ,
        admin_created_at TIMestAMPTZ,
        relevance_score FLOAT,
        match_type TEXT
    ) AS $$
    BEGIN
        RETURN QUERY
        SELECT * FROM search_admin_users_by_role_type(
            2,  -- Manager role type
            search_query,
            search_type,
            include_inactive,
            limit_count,
            offset_count
        );
    END;
    $$ LANGUAGE plpgsql;

    -- Function to search super admins (role_type = 4)
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
        admin_role_id UUID,  -- Fixed: Changed from role_level to admin_role_id
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
            4,  -- Super Admin role type
            search_query,
            search_type,
            include_inactive,
            limit_count,
            offset_count
        );
    END;
    $$ LANGUAGE plpgsql;

    -- Function to get admins with their permissions and departments
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

    -- Function to check if admin has permission
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

    -- Function to check if admin has department access
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

    -- General admin search function - FIXED VERSION
    -- Drop and recreate the function with proper handling
    DROP FUNCTION IF EXISTS search_admin_users(TEXT, INTEGER, BOOLEAN, TEXT, INTEGER, INTEGER);
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
        -- Normalize empty string to NULL
        IF search_query_param = '' THEN
            search_query_param := NULL;
        END IF;

        -- Build query based on search type
        IF search_query_param IS NULL THEN
            -- Return all admins (no search query)
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
            -- Autocomplete/partial match
            RETURN QUERY
            SELECT
                au.admin_id, au.username, au.full_name, au.phone_hash,
                ar.role_name, au.admin_role_id, au.role_type,
                au.reports_to, ru.full_name as reports_to_name,
                au.is_active, au.last_login, au.admin_created_at,
                GREATEST(
                    COALESCE(similarity(au.username, search_query_param), 0),
                    COALESCE(similarity(au.full_name, search_query_param), 0)
                )::FLOAT as relevance_score,
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
            -- Full-text search
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
    -- Function for admin autocomplete suggestions
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
        relevance FLOAT  -- This is DOUBLE PRECISION
    ) AS $$
    BEGIN
        RETURN QUERY
        SELECT
            au.admin_id, au.username, au.full_name,
            ar.role_name, ar.role_level, au.role_type,
            au.reports_to, ru.full_name as reports_to_name,
            -- Cast similarity result to FLOAT (DOUBLE PRECISION)
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

    -- Function to get admin permissions by role
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

    -- Function to get admin departments by role
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

    -- ==============================================
    -- EXISTING USER AND COMPANY SEARCH FUNCTIONS
    -- ==============================================
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
        -- Build WHERE clause for filters and collect parameters
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

        -- Choose search method
        IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
            -- Partial matching (autocomplete) using trigram
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

            -- Add parameters
            query_params := array_append(query_params, search_query);
            query_params := array_append(query_params, '%' || search_query || '%');
            query_params := array_append(query_params, limit_count::TEXT);
            query_params := array_append(query_params, offset_count::TEXT);
        ELSE
            -- Full-text search (🔥 FIXED)
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

            -- Add parameters
            query_params := array_append(query_params, search_query);
            query_params := array_append(query_params, limit_count::TEXT);
            query_params := array_append(query_params, offset_count::TEXT);
        END IF;

        -- Execute the query
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
        -- Build WHERE clause
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

        filter_param_count := param_counter - 1; -- Count of filter parameters

        -- Choose search method
        IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
            -- Partial matching (autocomplete) using trigram
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
            -- Full-text search for complete words
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

        -- Execute the query
        RETURN QUERY EXECUTE base_query USING query_params;
    END;
    $$ LANGUAGE plpgsql;

    -- ==============================================
    -- ADDED: COMPANY EMPLOYEE SEARCH FUNCTIONS (MISSING FROM NEW SCHEMA)
    -- ==============================================
    -- Function: company_employee_search
    -- Search employees within a specific company
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
        -- Start building parameters
        query_params := array[]::text[];

        -- Add company_id as first parameter
        where_clause := where_clause || ' AND ce.company_id = $' || param_counter;
        query_params := array_append(query_params, company_id_param::TEXT);
        param_counter := param_counter + 1;

        -- Additional filters
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

        -- Choose search method
        IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
            -- Partial matching (autocomplete) using trigram
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

            -- Add search query (for similarity) and pattern (for ILIKE)
            query_params := array_append(query_params, search_query);
            query_params := array_append(query_params, '%' || search_query || '%');
            query_params := array_append(query_params, limit_count::TEXT);
            query_params := array_append(query_params, offset_count::TEXT);
        ELSE
            -- Full-text search for complete words
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

            -- Add search query, limit, and offset
            query_params := array_append(query_params, search_query);
            query_params := array_append(query_params, limit_count::TEXT);
            query_params := array_append(query_params, offset_count::TEXT);
        END IF;

        -- Execute the query
        RETURN QUERY EXECUTE base_query USING query_params;
    END;
    $$ LANGUAGE plpgsql;

    -- Function: get_company_employee_suggestions
    -- Autocomplete suggestions for company employees
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

    -- Function: find_company_employee_by_username
    -- Find company employee by username within a specific company
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

    -- ==============================================
    -- TRIGGERS
    -- ==============================================
    -- Trigger function to update search vector for admin users
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

    -- Create trigger for search vector updates for admin users
    CREATE TRIGGER update_admin_user_search_tsv
    BEFORE UPDATE OF username, full_name ON admin_users
    FOR EACH ROW EXECUTE FUNCTION update_admin_user_search_tsv();

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

    CREATE TRIGGER update_user_search_tsv
    BEFORE UPDATE OF username, full_name ON users
    FOR EACH ROW EXECUTE FUNCTION update_user_search_tsv();

    CREATE OR REPLACE FUNCTION update_company_name_tsv()
    RETURNS TRIGGER AS $$
    BEGIN
        IF NEW.company_name IS DISTINCT FROM OLD.company_name THEN
            NEW.company_name_tsv = to_tsvector('simple', NEW.company_name);
        END IF;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER update_company_name_tsv
    BEFORE UPDATE OF company_name ON companies
    FOR EACH ROW EXECUTE FUNCTION update_company_name_tsv();

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

    CREATE TRIGGER update_admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

    CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_companies_updated_at BEFORE UPDATE ON companies FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_departments_updated_at BEFORE UPDATE ON departments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_company_employees_updated_at BEFORE UPDATE ON company_employees FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_user_devices_updated_at BEFORE UPDATE ON user_devices FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    CREATE TRIGGER update_admin_roles_updated_at BEFORE UPDATE ON admin_roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

    -- ==============================================
    -- HELPER FUNCTIONS
    -- ==============================================
    -- Find users by username (exact match)
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

    -- Find companies by owner with name search
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

    -- Get user suggestions for autocomplete
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

    -- Get company suggestions for autocomplete
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

    -- Function to search admin users with department filtering
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
        -- Add department filter if provided
        IF department_ids IS NOT NULL AND array_length(department_ids, 1) > 0 THEN
            where_clause := where_clause || ' AND ard.system_department_id = ANY($' || param_counter || ')';
            query_params := array_append(query_params, array_to_string(department_ids, ','));
            param_counter := param_counter + 1;
        END IF;

        -- Add search query
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

        -- Add role type filter
        IF role_type_filter IS NOT NULL THEN
            where_clause := where_clause || ' AND au.role_type = $' || param_counter;
            query_params := array_append(query_params, role_type_filter::TEXT);
            param_counter := param_counter + 1;
        END IF;

        -- Add active status filter
        IF NOT include_inactive THEN
            where_clause := where_clause || ' AND au.is_active = true';
        END IF;

        -- Build the main query
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

        -- Add department join if filtering
        IF department_ids IS NOT NULL AND array_length(department_ids, 1) > 0 THEN
            base_query := base_query || '
                JOIN admin_role_departments ard ON au.admin_role_id = ard.admin_role_id
            ';
        END IF;

        base_query := base_query || where_clause || '
            ORDER BY relevance_score DESC, au.username ASC
            LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);

        -- Add search query for relevance calculation
        query_params := array_append(query_params, COALESCE(search_query, ''));
        query_params := array_append(query_params, limit_count::TEXT);
        query_params := array_append(query_params, offset_count::TEXT);

        RETURN QUERY EXECUTE base_query USING query_params;
    END;
    $$ LANGUAGE plpgsql;

    -- ==============================================
    -- USER AVATARS (FK → users.user_id)
    -- ==============================================
    CREATE TABLE user_avatars (
        avatar_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        -- FK owner
        user_id UUID NOT NULL,
        -- Avatar reference (NO IMAGE DATA)
        avatar_type VARCHAR(20) NOT NULL DEFAULT 'uploaded', -- initials | uploaded
        avatar_hash VARCHAR(128),        -- integrity / dedup
        avatar_object_key TEXT NOT NULL, -- local path (dev) / S3 key (prod)
        avatar_mime_type VARCHAR(50),    -- image/jpeg, image/png, image/webp
        -- State
        is_active BOOLEAN NOT NULL DEFAULT true,
        is_primary BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        -- Constraints
        CONSTRAINT fk_user_avatars_user
            FOREIGN KEY (user_id)
            REFERENCES users(user_id)
            ON DELETE CASCADE,
        -- Only one primary avatar per user
        CONSTRAINT uq_user_primary_avatar UNIQUE (user_id, is_primary)
    );

    CREATE INDEX idx_user_avatars_user_active
    ON user_avatars (user_id)
    WHERE is_active = true AND is_primary = true;

    CREATE INDEX idx_user_avatars_hash ON user_avatars (avatar_hash);

    -- ==============================================
    -- ADMIN AVATARS (FK → admin_users.admin_id)
    -- ==============================================
    CREATE TABLE admin_avatars (
        avatar_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        -- FK owner
        admin_id UUID NOT NULL,
        -- Avatar reference (NO IMAGE DATA)
        avatar_type VARCHAR(20) NOT NULL DEFAULT 'uploaded',
        avatar_hash VARCHAR(128),
        avatar_object_key TEXT NOT NULL,
        avatar_mime_type VARCHAR(50),
        -- State
        is_active BOOLEAN NOT NULL DEFAULT true,
        is_primary BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        -- Constraints
        CONSTRAINT fk_admin_avatars_admin
            FOREIGN KEY (admin_id)
            REFERENCES admin_users(admin_id)
            ON DELETE CASCADE,
        -- Only one primary avatar per admin
        CONSTRAINT uq_admin_primary_avatar UNIQUE (admin_id, is_primary)
    );

    CREATE INDEX idx_admin_avatars_admin_active
    ON admin_avatars (admin_id)
    WHERE is_active = true AND is_primary = true;

    CREATE INDEX idx_admin_avatars_hash ON admin_avatars (avatar_hash);
    
    -- ==============================================
    -- INSERT DEFAULT DATA
    -- ==============================================

    -- Insert default system departments with consistent module codes
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
    ('Super Admin Management', 'super_admin', 'Super Admin management and system control', 1 << 19)
    ON CONFLICT (name) DO NOTHING;

    -- Insert permissions with consistent module codes
    INSERT INTO permissions (permission_name, description, category, module, scope, requires_tier, bit_index) VALUES
    -- User permissions (scope = 'user')
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
    
    -- Admin Employee Management permissions (scope = 'admin')
    ('admin.employee.create', 'Create admin employees', 'employee', 'employee_management', 'admin', 'admin', 235),
    ('admin.employee.update', 'Update admin employees', 'employee', 'employee_management', 'admin', 'admin', 236),
    ('admin.employee.view', 'View admin employees', 'employee', 'employee_management', 'admin', 'admin', 237),
    ('admin.employee.delete', 'Delete admin employees', 'employee', 'employee_management', 'admin', 'admin', 238),
    ('admin.employee.assign', 'Assign admin employees to departments', 'employee', 'employee_management', 'admin', 'admin', 239),
    
    -- Admin Manager Management permissions (scope = 'admin')
    ('admin.manager.create', 'Create admin managers', 'manager', 'manager_management', 'admin', 'admin', 240),
    ('admin.manager.update', 'Update admin managers', 'manager', 'manager_management', 'admin', 'admin', 241),
    ('admin.manager.view', 'View admin managers', 'manager', 'manager_management', 'admin', 'admin', 242),
    ('admin.manager.delete', 'Delete admin managers', 'manager', 'manager_management', 'admin', 'admin', 243),
    ('admin.manager.assign', 'Assign admin managers to departments', 'manager', 'manager_management', 'admin', 'admin', 244),
    
    -- Company Management permissions (scope = 'admin')
    ('admin.company.create', 'Create companies', 'company', 'company_management', 'admin', 'admin', 245),
    ('admin.company.update', 'Update companies', 'company', 'company_management', 'admin', 'admin', 246),
    ('admin.company.view', 'View companies', 'company', 'company_management', 'admin', 'admin', 247),
    ('admin.company.delete', 'Delete companies', 'company', 'company_management', 'admin', 'admin', 248),
    ('admin.company.suspend', 'Suspend companies', 'company', 'company_management', 'admin', 'admin', 249),
    
    -- Super Admin specific permissions (scope = 'admin')
    ('admin.super.manage_roles', 'Manage all admin roles', 'role', 'super_admin', 'admin', 'super_admin', 250),
    ('admin.super.manage_permissions', 'Manage all permissions', 'permission', 'super_admin', 'admin', 'super_admin', 251),
    ('admin.super.manage_departments', 'Manage all departments', 'department', 'super_admin', 'admin', 'super_admin', 252),
    ('admin.super.system_config', 'Configure system settings', 'system', 'super_admin', 'admin', 'super_admin', 253),
    ('admin.super.audit_logs', 'View audit logs', 'audit', 'super_admin', 'admin', 'super_admin', 254)
    ON CONFLICT (permission_name) DO NOTHING;

EOSQL

echo "✅ Database schema created successfully!"