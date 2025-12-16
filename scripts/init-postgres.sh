#!/bin/bash
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
    -- Enable trigram extension for fast text search
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";

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
        subscription_end_date TIMESTAMPTZ,
        -- Keep unique constraint from old schema
        UNIQUE(company_name, owner_user_id),
        -- Foreign key constraint
        CONSTRAINT fk_companies_owner FOREIGN KEY (owner_user_id) REFERENCES users(user_id)
    );

    CREATE TABLE system_departments (
        system_department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) UNIQUE NOT NULL,
        module_code VARCHAR(100) NOT NULL,
        description TEXT,
        bitmask BIGINT NOT NULL   
    );

    CREATE TABLE permissions (
        permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        permission_name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT,
        category VARCHAR(50) NOT NULL,
        module VARCHAR(50) NOT NULL,
        requires_tier VARCHAR(20) DEFAULT 'basic',
        bit_index INTEGER UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
        CONSTRAINT fk_role_perms_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE,
        CONSTRAINT fk_role_perms_granted_by FOREIGN KEY (granted_by) REFERENCES users(user_id)
    );

    CREATE TABLE departments (
        department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID NOT NULL,
        department_name VARCHAR(255) NOT NULL,
        system_department_id UUID,
        department_head UUID,
        parent_department_id UUID,
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(company_id, department_name),
        CONSTRAINT fk_departments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
        CONSTRAINT fk_departments_system FOREIGN KEY (system_department_id) REFERENCES system_departments(system_department_id),
        CONSTRAINT fk_departments_parent FOREIGN KEY (parent_department_id) REFERENCES departments(department_id)
    );

        -- ADD THIS TABLE HERE
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
        hire_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_active BOOLEAN NOT NULL DEFAULT true,
        reports_to UUID,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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

    -- 1. Full-text search index (tsvector GIN) for user search
    CREATE INDEX idx_users_search_tsv ON users USING GIN (user_search_tsv);

    -- 2. Trigram indexes for autocomplete
    CREATE INDEX idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);
    CREATE INDEX idx_users_fullname_trgm ON users USING GIN (full_name gin_trgm_ops);

    -- 3. Standard indexes for exact matches
    CREATE INDEX idx_users_username ON users (username);
    CREATE INDEX idx_users_fullname ON users (full_name);

    -- 4. Composite index for combined search
    CREATE INDEX idx_users_name_search ON users (username, full_name);

    -- 1. Full-text search index (tsvector GIN)
    CREATE INDEX idx_companies_name_tsv ON companies USING GIN (company_name_tsv);

    -- 2. Trigram index for autocomplete (fast partial matching)
    CREATE INDEX idx_companies_name_trgm ON companies USING GIN (company_name gin_trgm_ops);

    -- 3. Standard index for exact matches
    CREATE INDEX idx_companies_name ON companies (company_name);

    -- 4. Composite index for owner searches
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
    ) AS \$\$
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
                    )::FLOAT as relevance_score,
                    ''autocomplete'' as match_type
                FROM users u
                WHERE 1=1 ' || where_clause ||
                ' AND (u.username ILIKE $' || (param_counter + 1) ||
                ' OR u.full_name ILIKE $' || (param_counter + 1) || ')
                ORDER BY relevance_score DESC, u.username ASC
                LIMIT $' || (param_counter + 2) || ' OFFSET $' || (param_counter + 3);

            -- Add search query and pattern as parameters
            query_params := array_append(query_params, search_query); -- For similarity
            query_params := array_append(query_params, '%' || search_query || '%'); -- For ILIKE pattern
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
                    u.kyc_status,
                    u.kyc_level,
                    u.is_verified,
                    u.is_active,
                    u.data_region,
                    u.created_at,
                    u.last_login,
                    ts_rank(u.user_search_tsv, plainto_tsquery(''simple'', $' || param_counter || '::text)) as relevance_score,
                    ''fulltext'' as match_type
                FROM users u
                WHERE 1=1 ' || where_clause ||
                ' AND u.user_search_tsv @@ plainto_tsquery(''simple'', $' || param_counter || '::text)
                ORDER BY relevance_score DESC, u.username ASC
                LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);

            -- Add search query, limit, and offset as parameters
            query_params := array_append(query_params, search_query);
            query_params := array_append(query_params, limit_count::TEXT);
            query_params := array_append(query_params, offset_count::TEXT);
        END IF;

        -- Debug: Log the query and parameters (remove in production)
        -- RAISE NOTICE 'Query: %', base_query;
        -- RAISE NOTICE 'Params: %', query_params;

        -- Execute the query with all parameters
        RETURN QUERY EXECUTE base_query USING query_params;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Error in user_search: %', SQLERRM;
            RAISE NOTICE 'Query: %', base_query;
            RAISE NOTICE 'Params: %', query_params;
            RAISE;
    END;
    \$\$ LANGUAGE plpgsql;

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
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

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
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

    CREATE OR REPLACE FUNCTION update_user_search_tsv()
    RETURNS TRIGGER AS \$\$
    BEGIN
        IF NEW.username IS DISTINCT FROM OLD.username OR NEW.full_name IS DISTINCT FROM OLD.full_name THEN
            NEW.user_search_tsv = to_tsvector('simple', COALESCE(NEW.username, '')) ||
                                  to_tsvector('simple', COALESCE(NEW.full_name, ''));
        END IF;
        RETURN NEW;
    END;
    \$\$ LANGUAGE plpgsql;

    CREATE TRIGGER update_user_search_tsv
    BEFORE UPDATE OF username, full_name ON users
    FOR EACH ROW EXECUTE FUNCTION update_user_search_tsv();

    CREATE OR REPLACE FUNCTION update_company_name_tsv()
    RETURNS TRIGGER AS \$\$
    BEGIN
        IF NEW.company_name IS DISTINCT FROM OLD.company_name THEN
            NEW.company_name_tsv = to_tsvector('simple', NEW.company_name);
        END IF;
        RETURN NEW;
    END;
    \$\$ LANGUAGE plpgsql;

    CREATE TRIGGER update_company_name_tsv
    BEFORE UPDATE OF company_name ON companies
    FOR EACH ROW EXECUTE FUNCTION update_company_name_tsv();

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


    -- Find users by username (exact match)
    CREATE OR REPLACE FUNCTION find_user_by_username(username_search VARCHAR(100))
    RETURNS TABLE(
        user_id UUID,
        username VARCHAR(100),
        full_name VARCHAR(255),
        phone_hash VARCHAR(128),
        is_active BOOLEAN,
        created_at TIMESTAMPTZ
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

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
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

    -- Get user suggestions for autocomplete
    CREATE OR REPLACE FUNCTION get_user_suggestions(
        prefix VARCHAR(100),
        limit_suggestions INTEGER DEFAULT 10
    ) RETURNS TABLE(
        username VARCHAR(100),
        full_name VARCHAR(255),
        user_id UUID
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

    -- Get company suggestions for autocomplete
    CREATE OR REPLACE FUNCTION get_company_suggestions(
        prefix VARCHAR(255),
        limit_suggestions INTEGER DEFAULT 10
    ) RETURNS TABLE(
        company_name VARCHAR(255),
        company_id UUID
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

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
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

    -- Find company employee by username
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
    ) AS \$\$
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
    \$\$ LANGUAGE plpgsql;

    -- Insert default departments with bitmask values
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
    ('Administration', 'administration', 'Company administration and management', 1 << 15)
    ON CONFLICT (name) DO NOTHING;

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

    -- 🔵 ADMIN / SYSTEM (20 permissions)
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


# #!/bin/bash
# set -e

# echo "🔧 Starting PostgreSQL initialization..."

# # Wait for PostgreSQL to be ready
# echo "⏳ Waiting for PostgreSQL to be ready..."
# until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
#   sleep 2
# done

# echo "✅ PostgreSQL is ready!"
# echo "🏗️ Creating database schema..."

# # Execute the SQL schema
# psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
#     -- Enable UUID extension
#     CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
#     -- Enable trigram extension for fast text search
#     CREATE EXTENSION IF NOT EXISTS "pg_trgm";

#     -- =========================================================
#     -- USERS (with username, full_name, and search optimization)
#     -- =========================================================
#     CREATE TABLE users (
#         user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         -- New fields for user search
#         username VARCHAR(100) NOT NULL,
#         full_name VARCHAR(255),
#         user_search_tsv TSVECTOR GENERATED ALWAYS AS (
#             to_tsvector('simple', COALESCE(username, '')) ||
#             to_tsvector('simple', COALESCE(full_name, ''))
#         ) STORED,
#         -- Existing fields from old schema
#         phone_hash VARCHAR(128) NOT NULL,
#         phone_encrypted BYTEA NOT NULL,
#         phone_encrypted_dek TEXT NOT NULL,
#         phone_key_id UUID NOT NULL,
#         device_id VARCHAR(256),
#         device_fingerprint VARCHAR(512),
#         kyc_status VARCHAR(50) NOT NULL DEFAULT 'pending',
#         kyc_level VARCHAR(20) NOT NULL DEFAULT 'basic',
#         kyc_verified_at TIMESTAMPTZ,
#         is_verified BOOLEAN NOT NULL DEFAULT false,
#         is_active BOOLEAN NOT NULL DEFAULT true,
#         data_region VARCHAR(20) NOT NULL DEFAULT 'us',
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         last_login TIMESTAMPTZ
#     ) PARTITION BY HASH (user_id);

#     -- Create 8 partitions for users (as in old schema)
#     CREATE TABLE users_p0 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 0);
#     CREATE TABLE users_p1 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 1);
#     CREATE TABLE users_p2 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 2);
#     CREATE TABLE users_p3 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 3);
#     CREATE TABLE users_p4 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 4);
#     CREATE TABLE users_p5 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 5);
#     CREATE TABLE users_p6 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 6);
#     CREATE TABLE users_p7 PARTITION OF users FOR VALUES WITH (MODULUS 8, REMAINDER 7);

#     -- Create a unique constraint that includes the partition key
#     -- This is required for partitioned tables in PostgreSQL
#     ALTER TABLE users ADD CONSTRAINT unique_username UNIQUE (user_id, username);

#     -- =========================================================
#     -- COMPANIES (NON-PARTITIONED with text search optimization)
#     -- =========================================================
#     CREATE TABLE companies (
#         company_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         company_name VARCHAR(255) NOT NULL,
#         company_name_tsv TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', company_name)) STORED,
#         owner_user_id UUID NOT NULL,
#         subscription_tier VARCHAR(20) NOT NULL DEFAULT 'basic',
#         subscription_status VARCHAR(20) NOT NULL DEFAULT 'active',
#         max_employees INTEGER NOT NULL DEFAULT 10,
#         data_region VARCHAR(10) NOT NULL DEFAULT 'us',
#         is_active BOOLEAN NOT NULL DEFAULT true,
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         subscription_start_date TIMESTAMPTZ,
#         subscription_end_date TIMESTAMPTZ,
#         -- Keep unique constraint from old schema
#         UNIQUE(company_name, owner_user_id),
#         -- Foreign key constraint
#         CONSTRAINT fk_companies_owner FOREIGN KEY (owner_user_id) REFERENCES users(user_id)
#     );

#     -- =========================================================
#     -- SYSTEM DEPARTMENTS (GLOBAL MODULE TEMPLATES) - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE system_departments (
#         system_department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         name VARCHAR(255) UNIQUE NOT NULL,
#         module_code VARCHAR(100) NOT NULL,
#         description TEXT
#     );

#     -- =========================================================
#     -- PERMISSIONS - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE permissions (
#         permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         permission_name VARCHAR(100) NOT NULL UNIQUE,
#         description TEXT,
#         category VARCHAR(50) NOT NULL,
#         module VARCHAR(50) NOT NULL,
#         requires_tier VARCHAR(20) DEFAULT 'basic',
#         bit_index INTEGER UNIQUE,
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
#     );

#     -- =========================================================
#     -- ROLES - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE roles (
#         role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         role_name VARCHAR(100) NOT NULL,
#         role_level INTEGER NOT NULL DEFAULT 1000,
#         company_id UUID NOT NULL,
#         is_system_role BOOLEAN NOT NULL DEFAULT false,
#         description TEXT,
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         UNIQUE(company_id, role_name),
#         CONSTRAINT fk_roles_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
#     );

#     -- =========================================================
#     -- ROLE PERMISSIONS - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE role_permissions (
#         role_id UUID NOT NULL,
#         permission_id UUID NOT NULL,
#         granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         granted_by UUID NOT NULL,
#         PRIMARY KEY (role_id, permission_id),
#         CONSTRAINT fk_role_perms_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
#         CONSTRAINT fk_role_perms_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE,
#         CONSTRAINT fk_role_perms_granted_by FOREIGN KEY (granted_by) REFERENCES users(user_id)
#     );

#     -- =========================================================
#     -- DEPARTMENTS - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE departments (
#         department_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         company_id UUID NOT NULL,
#         department_name VARCHAR(255) NOT NULL,
#         system_department_id UUID,
#         department_head UUID,
#         parent_department_id UUID,
#         is_active BOOLEAN NOT NULL DEFAULT true,
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         UNIQUE(company_id, department_name),
#         CONSTRAINT fk_departments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
#         CONSTRAINT fk_departments_system FOREIGN KEY (system_department_id) REFERENCES system_departments(system_department_id),
#         CONSTRAINT fk_departments_parent FOREIGN KEY (parent_department_id) REFERENCES departments(department_id)
#     );

#     -- =========================================================
#     -- ROLE DEPARTMENTS MAPPING - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE role_departments (
#         role_id UUID NOT NULL,
#         department_id UUID NOT NULL,
#         PRIMARY KEY (role_id, department_id),
#         CONSTRAINT fk_role_depts_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
#         CONSTRAINT fk_role_depts_dept FOREIGN KEY (department_id) REFERENCES departments(department_id) ON DELETE CASCADE
#     );

#     -- =========================================================
#     -- COMPANY EMPLOYEES - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE company_employees (
#         company_id UUID NOT NULL,
#         user_id UUID NOT NULL,
#         employee_id VARCHAR(100) NOT NULL,
#         role_id UUID NOT NULL,
#         department_id UUID,
#         hire_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         is_active BOOLEAN NOT NULL DEFAULT true,
#         reports_to UUID,
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         PRIMARY KEY (company_id, user_id),
#         CONSTRAINT fk_employees_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
#         CONSTRAINT fk_employees_user FOREIGN KEY (user_id) REFERENCES users(user_id),
#         CONSTRAINT fk_employees_role FOREIGN KEY (role_id) REFERENCES roles(role_id),
#         CONSTRAINT fk_employees_department FOREIGN KEY (department_id) REFERENCES departments(department_id)
#     );

#     -- =========================================================
#     -- USER DEVICES - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE user_devices (
#         device_id VARCHAR(256) PRIMARY KEY,
#         user_id UUID NOT NULL,
#         device_type VARCHAR(50),
#         device_name VARCHAR(100),
#         os_version VARCHAR(50),
#         app_version VARCHAR(50),
#         last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         is_active BOOLEAN NOT NULL DEFAULT true,
#         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         CONSTRAINT fk_user_devices_user FOREIGN KEY (user_id) REFERENCES users(user_id)
#     );

#     -- =========================================================
#     -- LOGIN ATTEMPTS - NON-PARTITIONED
#     -- =========================================================
#     CREATE TABLE login_attempts (
#         attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
#         user_id UUID NOT NULL,
#         success BOOLEAN NOT NULL,
#         ip_address VARCHAR(64),
#         user_agent TEXT,
#         device_id VARCHAR(256),
#         attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
#         failure_reason TEXT,
#         CONSTRAINT fk_login_attempts_user FOREIGN KEY (user_id) REFERENCES users(user_id),
#         CONSTRAINT fk_login_attempts_device FOREIGN KEY (device_id) REFERENCES user_devices(device_id)
#     );

#     -- =========================================================
#     -- USER SEARCH INDEXES
#     -- =========================================================
#     -- 1. Full-text search index (tsvector GIN) for user search
#     CREATE INDEX idx_users_search_tsv ON users USING GIN (user_search_tsv);
    
#     -- 2. Trigram indexes for autocomplete
#     CREATE INDEX idx_users_username_trgm ON users USING GIN (username gin_trgm_ops);
#     CREATE INDEX idx_users_fullname_trgm ON users USING GIN (full_name gin_trgm_ops);
    
#     -- 3. Standard indexes for exact matches
#     CREATE INDEX idx_users_username ON users (username);
#     CREATE INDEX idx_users_fullname ON users (full_name);
    
#     -- 4. Composite index for combined search
#     CREATE INDEX idx_users_name_search ON users (username, full_name);

#     -- =========================================================
#     -- TEXT SEARCH INDEXES FOR COMPANIES
#     -- =========================================================
#     -- 1. Full-text search index (tsvector GIN)
#     CREATE INDEX idx_companies_name_tsv ON companies USING GIN (company_name_tsv);
    
#     -- 2. Trigram index for autocomplete (fast partial matching)
#     CREATE INDEX idx_companies_name_trgm ON companies USING GIN (company_name gin_trgm_ops);
    
#     -- 3. Standard index for exact matches
#     CREATE INDEX idx_companies_name ON companies (company_name);
    
#     -- 4. Composite index for owner searches
#     CREATE INDEX idx_companies_owner_name ON companies (owner_user_id, company_name);

#     -- =========================================================
#     -- OTHER INDEXES (From old schema, keeping them all)
#     -- =========================================================
#     CREATE INDEX idx_users_phone_hash ON users (phone_hash);
#     CREATE INDEX idx_users_created_at ON users (created_at);
#     CREATE INDEX idx_users_status ON users (is_active, kyc_status);
#     CREATE INDEX idx_users_region ON users (data_region);
#     CREATE INDEX idx_users_kyc_status ON users(kyc_status);

#     CREATE INDEX idx_companies_owner ON companies (owner_user_id);
#     CREATE INDEX idx_companies_status ON companies (is_active, subscription_status);
#     CREATE INDEX idx_companies_region ON companies (data_region);

#     CREATE INDEX idx_roles_company ON roles (company_id);
#     CREATE INDEX idx_roles_level ON roles (role_level);

#     CREATE INDEX idx_role_perms_permission ON role_permissions (permission_id);

#     CREATE INDEX idx_employees_user ON company_employees (user_id);
#     CREATE INDEX idx_employees_role ON company_employees (role_id);
#     CREATE INDEX idx_employees_dept ON company_employees (department_id);
#     CREATE INDEX idx_employees_active ON company_employees (is_active);
#     CREATE INDEX idx_employees_company_active ON company_employees (company_id, is_active);
#     CREATE INDEX idx_employees_reports_to ON company_employees (company_id, reports_to);

#     CREATE INDEX idx_departments_company ON departments (company_id);
#     CREATE INDEX idx_departments_parent ON departments (parent_department_id);
#     CREATE INDEX idx_departments_head ON departments (department_head);
#     CREATE INDEX idx_departments_system ON departments (system_department_id);

#     CREATE INDEX idx_role_departments_role ON role_departments (role_id);
#     CREATE INDEX idx_role_departments_department ON role_departments (department_id);

#     CREATE INDEX idx_system_departments_module ON system_departments (module_code);
#     CREATE INDEX idx_system_departments_name ON system_departments (name);

#     CREATE INDEX idx_user_devices_user ON user_devices (user_id);
#     CREATE INDEX idx_user_devices_active ON user_devices (is_active);
#     CREATE INDEX idx_user_devices_last_active ON user_devices (last_active);

#     CREATE INDEX idx_login_attempts_user ON login_attempts (user_id);
#     CREATE INDEX idx_login_attempts_device ON login_attempts (device_id);
#     CREATE INDEX idx_login_attempts_success ON login_attempts (success);
#     CREATE INDEX idx_login_attempts_time ON login_attempts (attempted_at DESC);

#     -- =========================================================
#     -- FIXED: USER SEARCH HELPER FUNCTION - WITH CORRECT DOLLAR QUOTING
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION user_search(
#         search_query TEXT,
#         search_type TEXT DEFAULT 'fulltext',
#         filter_is_active BOOLEAN DEFAULT NULL,
#         filter_kyc_status TEXT DEFAULT NULL,
#         filter_data_region TEXT DEFAULT NULL,
#         filter_is_verified BOOLEAN DEFAULT NULL,
#         limit_count INTEGER DEFAULT 50,
#         offset_count INTEGER DEFAULT 0
#     ) RETURNS TABLE(
#         user_id UUID,
#         username VARCHAR(100),
#         full_name VARCHAR(255),
#         phone_hash VARCHAR(128),
#         kyc_status VARCHAR(50),
#         kyc_level VARCHAR(20),
#         is_verified BOOLEAN,
#         is_active BOOLEAN,
#         data_region VARCHAR(20),
#         created_at TIMESTAMPTZ,
#         last_login TIMESTAMPTZ,
#         relevance_score FLOAT,
#         match_type TEXT
#     ) AS \$\$
#     DECLARE
#         base_query TEXT;
#         where_clause TEXT := '';
#         query_params TEXT[];
#         param_counter INTEGER := 1;
#         filter_param_count INTEGER := 0;
#         search_param_index INTEGER := 1;
#     BEGIN
#         -- Build WHERE clause for filters and collect parameters
#         IF filter_is_active IS NOT NULL THEN
#             where_clause := where_clause || ' AND is_active = $' || param_counter;
#             query_params := array_append(query_params, filter_is_active::TEXT);
#             param_counter := param_counter + 1;
#             filter_param_count := filter_param_count + 1;
#         END IF;
        
#         IF filter_kyc_status IS NOT NULL THEN
#             where_clause := where_clause || ' AND kyc_status = $' || param_counter;
#             query_params := array_append(query_params, filter_kyc_status);
#             param_counter := param_counter + 1;
#             filter_param_count := filter_param_count + 1;
#         END IF;
        
#         IF filter_data_region IS NOT NULL THEN
#             where_clause := where_clause || ' AND data_region = $' || param_counter;
#             query_params := array_append(query_params, filter_data_region);
#             param_counter := param_counter + 1;
#             filter_param_count := filter_param_count + 1;
#         END IF;
        
#         IF filter_is_verified IS NOT NULL THEN
#             where_clause := where_clause || ' AND is_verified = $' || param_counter;
#             query_params := array_append(query_params, filter_is_verified::TEXT);
#             param_counter := param_counter + 1;
#             filter_param_count := filter_param_count + 1;
#         END IF;

#         -- Choose search method
#         IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
#             -- Partial matching (autocomplete) using trigram
#             base_query := '
#                 SELECT 
#                     u.user_id,
#                     u.username,
#                     u.full_name,
#                     u.phone_hash,
#                     u.kyc_status,
#                     u.kyc_level,
#                     u.is_verified,
#                     u.is_active,
#                     u.data_region,
#                     u.created_at,
#                     u.last_login,
#                     GREATEST(
#                         COALESCE(similarity(u.username, $' || param_counter || '), 0),
#                         COALESCE(similarity(u.full_name, $' || param_counter || '), 0)
#                     )::FLOAT as relevance_score,
#                     ''autocomplete'' as match_type
#                 FROM users u
#                 WHERE 1=1 ' || where_clause || 
#                 ' AND (u.username ILIKE $' || (param_counter + 1) ||
#                 ' OR u.full_name ILIKE $' || (param_counter + 1) || ')
#                 ORDER BY relevance_score DESC, u.username ASC
#                 LIMIT $' || (param_counter + 2) || ' OFFSET $' || (param_counter + 3);
            
#             -- Add search query and pattern as parameters
#             query_params := array_append(query_params, search_query); -- For similarity
#             query_params := array_append(query_params, '%' || search_query || '%'); -- For ILIKE pattern
#             query_params := array_append(query_params, limit_count::TEXT);
#             query_params := array_append(query_params, offset_count::TEXT);
            
#         ELSE
#             -- Full-text search for complete words
#             base_query := '
#                 SELECT 
#                     u.user_id,
#                     u.username,
#                     u.full_name,
#                     u.phone_hash,
#                     u.kyc_status,
#                     u.kyc_level,
#                     u.is_verified,
#                     u.is_active,
#                     u.data_region,
#                     u.created_at,
#                     u.last_login,
#                     ts_rank(u.user_search_tsv, plainto_tsquery(''simple'', $' || param_counter || '::text)) as relevance_score,
#                     ''fulltext'' as match_type
#                 FROM users u
#                 WHERE 1=1 ' || where_clause || 
#                 ' AND u.user_search_tsv @@ plainto_tsquery(''simple'', $' || param_counter || '::text)
#                 ORDER BY relevance_score DESC, u.username ASC
#                 LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);
            
#             -- Add search query, limit, and offset as parameters
#             query_params := array_append(query_params, search_query);
#             query_params := array_append(query_params, limit_count::TEXT);
#             query_params := array_append(query_params, offset_count::TEXT);
#         END IF;

#         -- Debug: Log the query and parameters (remove in production)
#         -- RAISE NOTICE 'Query: %', base_query;
#         -- RAISE NOTICE 'Params: %', query_params;

#         -- Execute the query with all parameters
#         RETURN QUERY EXECUTE base_query USING query_params;
#     EXCEPTION
#         WHEN OTHERS THEN
#             RAISE NOTICE 'Error in user_search: %', SQLERRM;
#             RAISE NOTICE 'Query: %', base_query;
#             RAISE NOTICE 'Params: %', query_params;
#             RAISE;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- =========================================================
#     -- FIXED: COMPANY SEARCH HELPER FUNCTION - WITH CORRECT DOLLAR QUOTING
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION company_search(
#         search_query TEXT,
#         search_type TEXT DEFAULT 'fulltext',
#         filter_owner_id UUID DEFAULT NULL,
#         filter_is_active BOOLEAN DEFAULT NULL,
#         filter_subscription_tier TEXT DEFAULT NULL,
#         filter_data_region TEXT DEFAULT NULL,
#         filter_subscription_status TEXT DEFAULT NULL,
#         limit_count INTEGER DEFAULT 50,
#         offset_count INTEGER DEFAULT 0
#     ) RETURNS TABLE(
#         company_id UUID,
#         company_name VARCHAR(255),
#         owner_user_id UUID,
#         subscription_tier VARCHAR(20),
#         subscription_status VARCHAR(20),
#         max_employees INTEGER,
#         is_active BOOLEAN,
#         data_region VARCHAR(10),
#         created_at TIMESTAMPTZ,
#         relevance_score FLOAT,
#         match_type TEXT
#     ) AS \$\$
#     DECLARE
#         base_query TEXT;
#         where_clause TEXT := '';
#         query_params TEXT[];
#         param_counter INTEGER := 1;
#         filter_param_count INTEGER := 0;
#     BEGIN
#         -- Build WHERE clause
#         IF filter_owner_id IS NOT NULL THEN
#             where_clause := where_clause || ' AND owner_user_id = $' || param_counter;
#             query_params := array_append(query_params, filter_owner_id::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_is_active IS NOT NULL THEN
#             where_clause := where_clause || ' AND is_active = $' || param_counter;
#             query_params := array_append(query_params, filter_is_active::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_subscription_tier IS NOT NULL THEN
#             where_clause := where_clause || ' AND subscription_tier = $' || param_counter;
#             query_params := array_append(query_params, filter_subscription_tier);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_data_region IS NOT NULL THEN
#             where_clause := where_clause || ' AND data_region = $' || param_counter;
#             query_params := array_append(query_params, filter_data_region);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_subscription_status IS NOT NULL THEN
#             where_clause := where_clause || ' AND subscription_status = $' || param_counter;
#             query_params := array_append(query_params, filter_subscription_status);
#             param_counter := param_counter + 1;
#         END IF;

#         filter_param_count := param_counter - 1; -- Count of filter parameters

#         -- Choose search method
#         IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
#             -- Partial matching (autocomplete) using trigram
#             base_query := '
#                 SELECT 
#                     c.company_id,
#                     c.company_name,
#                     c.owner_user_id,
#                     c.subscription_tier,
#                     c.subscription_status,
#                     c.max_employees,
#                     c.is_active,
#                     c.data_region,
#                     c.created_at,
#                     similarity(c.company_name, $' || (filter_param_count + 1) || ')::FLOAT as relevance_score,
#                     ''autocomplete'' as match_type
#                 FROM companies c
#                 WHERE 1=1 ' || where_clause || 
#                 ' AND c.company_name ILIKE $' || (filter_param_count + 2) ||
#                 ' ORDER BY relevance_score DESC, c.company_name ASC
#                 LIMIT $' || (filter_param_count + 3) || ' OFFSET $' || (filter_param_count + 4);
            
#             query_params := array_append(query_params, search_query);
#             query_params := array_append(query_params, '%' || search_query || '%');
#             query_params := array_append(query_params, limit_count::TEXT);
#             query_params := array_append(query_params, offset_count::TEXT);
            
#         ELSE
#             -- Full-text search for complete words
#             base_query := '
#                 SELECT 
#                     c.company_id,
#                     c.company_name,
#                     c.owner_user_id,
#                     c.subscription_tier,
#                     c.subscription_status,
#                     c.max_employees,
#                     c.is_active,
#                     c.data_region,
#                     c.created_at,
#                     ts_rank(c.company_name_tsv, plainto_tsquery(''simple'', $' || (filter_param_count + 1) || '::text)) as relevance_score,
#                     ''fulltext'' as match_type
#                 FROM companies c
#                 WHERE 1=1 ' || where_clause || 
#                 ' AND c.company_name_tsv @@ plainto_tsquery(''simple'', $' || (filter_param_count + 1) || '::text)
#                 ORDER BY relevance_score DESC, c.company_name ASC
#                 LIMIT $' || (filter_param_count + 2) || ' OFFSET $' || (filter_param_count + 3);
            
#             query_params := array_append(query_params, search_query);
#             query_params := array_append(query_params, limit_count::TEXT);
#             query_params := array_append(query_params, offset_count::TEXT);
#         END IF;

#         -- Execute the query
#         RETURN QUERY EXECUTE base_query USING query_params;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- =========================================================
#     -- FIXED: COMPANY EMPLOYEE SEARCH HELPER FUNCTION - WITH CORRECT DOLLAR QUOTING
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION company_employee_search(
#         search_query TEXT,
#         company_id_param UUID,
#         search_type TEXT DEFAULT 'fulltext',
#         filter_role_id UUID DEFAULT NULL,
#         filter_department_id UUID DEFAULT NULL,
#         filter_is_active BOOLEAN DEFAULT NULL,
#         filter_reports_to UUID DEFAULT NULL,
#         filter_hire_date_from TIMESTAMPTZ DEFAULT NULL,
#         filter_hire_date_to TIMESTAMPTZ DEFAULT NULL,
#         limit_count INTEGER DEFAULT 50,
#         offset_count INTEGER DEFAULT 0
#     ) RETURNS TABLE(
#         user_id UUID,
#         username VARCHAR(100),
#         full_name VARCHAR(255),
#         phone_hash VARCHAR(128),
#         employee_id VARCHAR(100),
#         role_id UUID,
#         role_name VARCHAR(100),
#         department_id UUID,
#         department_name VARCHAR(255),
#         hire_date TIMESTAMPTZ,
#         is_active BOOLEAN,
#         reports_to UUID,
#         reports_to_name VARCHAR(255),
#         created_at TIMESTAMPTZ,
#         relevance_score FLOAT,
#         match_type TEXT
#     ) AS \$\$
#     DECLARE
#         base_query TEXT;
#         where_clause TEXT := '';
#         query_params TEXT[];
#         param_counter INTEGER := 1;
#     BEGIN
#         -- Start building parameters
#         query_params := array[]::text[];
        
#         -- Add company_id as first parameter
#         where_clause := where_clause || ' AND ce.company_id = $' || param_counter;
#         query_params := array_append(query_params, company_id_param::TEXT);
#         param_counter := param_counter + 1;
        
#         -- Additional filters
#         IF filter_role_id IS NOT NULL THEN
#             where_clause := where_clause || ' AND ce.role_id = $' || param_counter;
#             query_params := array_append(query_params, filter_role_id::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_department_id IS NOT NULL THEN
#             where_clause := where_clause || ' AND ce.department_id = $' || param_counter;
#             query_params := array_append(query_params, filter_department_id::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_is_active IS NOT NULL THEN
#             where_clause := where_clause || ' AND ce.is_active = $' || param_counter;
#             query_params := array_append(query_params, filter_is_active::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_reports_to IS NOT NULL THEN
#             where_clause := where_clause || ' AND ce.reports_to = $' || param_counter;
#             query_params := array_append(query_params, filter_reports_to::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_hire_date_from IS NOT NULL THEN
#             where_clause := where_clause || ' AND ce.hire_date >= $' || param_counter;
#             query_params := array_append(query_params, filter_hire_date_from::TEXT);
#             param_counter := param_counter + 1;
#         END IF;
        
#         IF filter_hire_date_to IS NOT NULL THEN
#             where_clause := where_clause || ' AND ce.hire_date <= $' || param_counter;
#             query_params := array_append(query_params, filter_hire_date_to::TEXT);
#             param_counter := param_counter + 1;
#         END IF;

#         -- Choose search method
#         IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
#             -- Partial matching (autocomplete) using trigram
#             base_query := '
#                 SELECT 
#                     u.user_id,
#                     u.username,
#                     u.full_name,
#                     u.phone_hash,
#                     ce.employee_id,
#                     ce.role_id,
#                     r.role_name,
#                     ce.department_id,
#                     d.department_name,
#                     ce.hire_date,
#                     ce.is_active,
#                     ce.reports_to,
#                     ru.username as reports_to_name,
#                     u.created_at,
#                     GREATEST(
#                         COALESCE(similarity(u.username, $' || param_counter || '), 0),
#                         COALESCE(similarity(u.full_name, $' || param_counter || '), 0),
#                         COALESCE(similarity(ce.employee_id, $' || param_counter || '), 0)
#                     )::FLOAT as relevance_score,
#                     ''autocomplete'' as match_type
#                 FROM users u
#                 INNER JOIN company_employees ce ON u.user_id = ce.user_id
#                 INNER JOIN roles r ON ce.role_id = r.role_id
#                 LEFT JOIN departments d ON ce.department_id = d.department_id
#                 LEFT JOIN users ru ON ce.reports_to = ru.user_id
#                 WHERE 1=1 ' || where_clause || 
#                 ' AND (u.username ILIKE $' || (param_counter + 1) ||
#                 ' OR u.full_name ILIKE $' || (param_counter + 1) ||
#                 ' OR ce.employee_id ILIKE $' || (param_counter + 1) || ')
#                 ORDER BY relevance_score DESC, ce.hire_date DESC
#                 LIMIT $' || (param_counter + 2) || ' OFFSET $' || (param_counter + 3);
            
#             -- Add search query (for similarity) and pattern (for ILIKE)
#             query_params := array_append(query_params, search_query);
#             query_params := array_append(query_params, '%' || search_query || '%');
#             query_params := array_append(query_params, limit_count::TEXT);
#             query_params := array_append(query_params, offset_count::TEXT);
            
#         ELSE
#             -- Full-text search for complete words
#             base_query := '
#                 SELECT 
#                     u.user_id,
#                     u.username,
#                     u.full_name,
#                     u.phone_hash,
#                     ce.employee_id,
#                     ce.role_id,
#                     r.role_name,
#                     ce.department_id,
#                     d.department_name,
#                     ce.hire_date,
#                     ce.is_active,
#                     ce.reports_to,
#                     ru.username as reports_to_name,
#                     u.created_at,
#                     ts_rank(u.user_search_tsv, plainto_tsquery(''simple'', $' || param_counter || '::text)) as relevance_score,
#                     ''fulltext'' as match_type
#                 FROM users u
#                 INNER JOIN company_employees ce ON u.user_id = ce.user_id
#                 INNER JOIN roles r ON ce.role_id = r.role_id
#                 LEFT JOIN departments d ON ce.department_id = d.department_id
#                 LEFT JOIN users ru ON ce.reports_to = ru.user_id
#                 WHERE 1=1 ' || where_clause || 
#                 ' AND u.user_search_tsv @@ plainto_tsquery(''simple'', $' || param_counter || '::text)
#                 ORDER BY relevance_score DESC, ce.hire_date DESC
#                 LIMIT $' || (param_counter + 1) || ' OFFSET $' || (param_counter + 2);
            
#             -- Add search query, limit, and offset
#             query_params := array_append(query_params, search_query);
#             query_params := array_append(query_params, limit_count::TEXT);
#             query_params := array_append(query_params, offset_count::TEXT);
#         END IF;

#         -- Execute the query
#         RETURN QUERY EXECUTE base_query USING query_params;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- =========================================================
#     -- USER NAME UPDATE TRIGGER (to keep tsvector in sync)
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION update_user_search_tsv()
#     RETURNS TRIGGER AS \$\$
#     BEGIN
#         IF NEW.username IS DISTINCT FROM OLD.username OR NEW.full_name IS DISTINCT FROM OLD.full_name THEN
#             NEW.user_search_tsv = to_tsvector('simple', COALESCE(NEW.username, '')) ||
#                                   to_tsvector('simple', COALESCE(NEW.full_name, ''));
#         END IF;
#         RETURN NEW;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     CREATE TRIGGER update_user_search_tsv 
#     BEFORE UPDATE OF username, full_name ON users 
#     FOR EACH ROW EXECUTE FUNCTION update_user_search_tsv();

#     -- =========================================================
#     -- COMPANY NAME UPDATE TRIGGER (to keep tsvector in sync)
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION update_company_name_tsv()
#     RETURNS TRIGGER AS \$\$
#     BEGIN
#         IF NEW.company_name IS DISTINCT FROM OLD.company_name THEN
#             NEW.company_name_tsv = to_tsvector('simple', NEW.company_name);
#         END IF;
#         RETURN NEW;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     CREATE TRIGGER update_company_name_tsv 
#     BEFORE UPDATE OF company_name ON companies 
#     FOR EACH ROW EXECUTE FUNCTION update_company_name_tsv();

#     -- =========================================================
#     -- UPDATE TRIGGERS FOR ALL TABLES
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION update_updated_at_column()
#     RETURNS TRIGGER AS \$\$
#     BEGIN
#         NEW.updated_at = NOW();
#         RETURN NEW;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
#     CREATE TRIGGER update_companies_updated_at BEFORE UPDATE ON companies FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
#     CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
#     CREATE TRIGGER update_departments_updated_at BEFORE UPDATE ON departments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
#     CREATE TRIGGER update_company_employees_updated_at BEFORE UPDATE ON company_employees FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
#     CREATE TRIGGER update_user_devices_updated_at BEFORE UPDATE ON user_devices FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

#     -- =========================================================
#     -- SIMPLE SEARCH FUNCTIONS FOR QUICK LOOKUPS
#     -- =========================================================
    
#     -- Find users by username (exact match)
#     CREATE OR REPLACE FUNCTION find_user_by_username(username_search VARCHAR(100))
#     RETURNS TABLE(
#         user_id UUID,
#         username VARCHAR(100),
#         full_name VARCHAR(255),
#         phone_hash VARCHAR(128),
#         is_active BOOLEAN,
#         created_at TIMESTAMPTZ
#     ) AS \$\$
#     BEGIN
#         RETURN QUERY
#         SELECT 
#             u.user_id,
#             u.username,
#             u.full_name,
#             u.phone_hash,
#             u.is_active,
#             u.created_at
#         FROM users u
#         WHERE u.username = username_search
#         LIMIT 1;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- Find companies by owner with name search
#     CREATE OR REPLACE FUNCTION find_companies_by_owner(
#         owner_id UUID,
#         name_filter VARCHAR(255) DEFAULT NULL
#     ) RETURNS TABLE(
#         company_id UUID,
#         company_name VARCHAR(255),
#         subscription_tier VARCHAR(20),
#         subscription_status VARCHAR(20),
#         is_active BOOLEAN,
#         created_at TIMESTAMPTZ
#     ) AS \$\$
#     BEGIN
#         RETURN QUERY
#         SELECT 
#             c.company_id,
#             c.company_name,
#             c.subscription_tier,
#             c.subscription_status,
#             c.is_active,
#             c.created_at
#         FROM companies c
#         WHERE c.owner_user_id = owner_id
#         AND (name_filter IS NULL OR c.company_name ILIKE '%' || name_filter || '%')
#         ORDER BY c.created_at DESC;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- Get user suggestions for autocomplete
#     CREATE OR REPLACE FUNCTION get_user_suggestions(
#         prefix VARCHAR(100),
#         limit_suggestions INTEGER DEFAULT 10
#     ) RETURNS TABLE(
#         username VARCHAR(100),
#         full_name VARCHAR(255),
#         user_id UUID
#     ) AS \$\$
#     BEGIN
#         RETURN QUERY
#         SELECT 
#             u.username,
#             u.full_name,
#             u.user_id
#         FROM users u
#         WHERE u.username ILIKE prefix || '%'
#            OR u.full_name ILIKE prefix || '%'
#         ORDER BY 
#             CASE 
#                 WHEN u.username ILIKE prefix || '%' THEN 1
#                 WHEN u.full_name ILIKE prefix || '%' THEN 2
#                 ELSE 3
#             END,
#             u.username
#         LIMIT limit_suggestions;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- Get company suggestions for autocomplete
#     CREATE OR REPLACE FUNCTION get_company_suggestions(
#         prefix VARCHAR(255),
#         limit_suggestions INTEGER DEFAULT 10
#     ) RETURNS TABLE(
#         company_name VARCHAR(255),
#         company_id UUID
#     ) AS \$\$
#     BEGIN
#         RETURN QUERY
#         SELECT 
#             c.company_name,
#             c.company_id
#         FROM companies c
#         WHERE c.company_name ILIKE prefix || '%'
#         ORDER BY c.company_name
#         LIMIT limit_suggestions;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- =========================================================
#     -- FIXED: Get company employee suggestions for autocomplete
#     -- =========================================================
#     CREATE OR REPLACE FUNCTION get_company_employee_suggestions(
#         company_id_param UUID,
#         prefix VARCHAR(100),
#         limit_suggestions INTEGER DEFAULT 10
#     ) RETURNS TABLE(
#         username VARCHAR(100),
#         full_name VARCHAR(255),
#         user_id UUID,
#         employee_id VARCHAR(100),
#         role_name VARCHAR(100)
#     ) AS \$\$
#     BEGIN
#         RETURN QUERY
#         SELECT 
#             u.username,
#             u.full_name,
#             u.user_id,
#             ce.employee_id,
#             r.role_name
#         FROM users u
#         INNER JOIN company_employees ce ON u.user_id = ce.user_id
#         INNER JOIN roles r ON ce.role_id = r.role_id
#         WHERE ce.company_id = company_id_param  -- FIXED: Use parameter name, not column name
#         AND ce.is_active = true
#         AND (u.username ILIKE prefix || '%'
#              OR u.full_name ILIKE prefix || '%'
#              OR ce.employee_id ILIKE prefix || '%')
#         ORDER BY 
#             CASE 
#                 WHEN u.username ILIKE prefix || '%' THEN 1
#                 WHEN u.full_name ILIKE prefix || '%' THEN 2
#                 WHEN ce.employee_id ILIKE prefix || '%' THEN 3
#                 ELSE 4
#             END,
#             u.username
#         LIMIT limit_suggestions;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- Find company employee by username
#     CREATE OR REPLACE FUNCTION find_company_employee_by_username(
#         company_id_search UUID,
#         username_search VARCHAR(100)
#     ) RETURNS TABLE(
#         user_id UUID,
#         username VARCHAR(100),
#         full_name VARCHAR(255),
#         phone_hash VARCHAR(128),
#         employee_id VARCHAR(100),
#         role_id UUID,
#         role_name VARCHAR(100),
#         department_id UUID,
#         department_name VARCHAR(255),
#         is_active BOOLEAN,
#         hire_date TIMESTAMPTZ
#     ) AS \$\$
#     BEGIN
#         RETURN QUERY
#         SELECT 
#             u.user_id,
#             u.username,
#             u.full_name,
#             u.phone_hash,
#             ce.employee_id,
#             ce.role_id,
#             r.role_name,
#             ce.department_id,
#             d.department_name,
#             ce.is_active,
#             ce.hire_date
#         FROM users u
#         INNER JOIN company_employees ce ON u.user_id = ce.user_id
#         INNER JOIN roles r ON ce.role_id = r.role_id
#         LEFT JOIN departments d ON ce.department_id = d.department_id
#         WHERE ce.company_id = company_id_search
#         AND u.username = username_search
#         LIMIT 1;
#     END;
#     \$\$ LANGUAGE plpgsql;

#     -- =========================================================
#     -- SEED DATA: SYSTEM DEPARTMENTS (from old schema)
#     -- =========================================================
#     INSERT INTO system_departments (name, module_code, description) VALUES
#     ('HR', 'hr', 'Human resource management'),
#     ('Finance', 'finance', 'Finance operations'),
#     ('Accounting', 'accounting', 'Accounting and ledger'),
#     ('Procurement', 'procurement', 'Purchasing & vendor mgmt'),
#     ('Inventory', 'inventory', 'Stock & warehouse'),
#     ('Logistics', 'logistics', 'Dispatch & delivery'),
#     ('Sales', 'sales', 'Lead & pipeline mgmt'),
#     ('Marketing', 'marketing', 'Campaigns & analysis'),
#     ('Customer Support', 'support', 'Support & helpdesk'),
#     ('Operations', 'operations', 'Operations & workflows'),
#     ('IT', 'it', 'IT assets & incidents'),
#     ('Production', 'production', 'Manufacturing operations'),
#     ('Quality Control', 'qc', 'QC inspections'),
#     ('Quality Assurance', 'qa', 'QA processes'),
#     ('R&D', 'rnd', 'Research & development'),
#     ('Administration', 'administration', 'Company administration and management')
#     ON CONFLICT (name) DO NOTHING;
    
#     -- =========================================================
#     -- COMPLETE ENTERPRISE PERMISSIONS (235+ from old schema)
#     -- =========================================================
#     -- 🔵 HR MODULE (20 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('hr.employee.create', 'Create employees', 'employee', 'hr', 'basic', 0),
#     ('hr.employee.update', 'Update employees', 'employee', 'hr', 'basic', 1),
#     ('hr.employee.delete', 'Delete employees', 'employee', 'hr', 'basic', 2),
#     ('hr.employee.view', 'View employees', 'employee', 'hr', 'basic', 3),
#     ('hr.employee.search', 'Search employees', 'employee', 'hr', 'basic', 4),
#     ('hr.employee.terminate', 'Terminate employees', 'employee', 'hr', 'basic', 5),
#     ('hr.employee.transfer', 'Transfer employees', 'employee', 'hr', 'basic', 6),
#     ('hr.document.upload', 'Upload documents', 'document', 'hr', 'basic', 7),
#     ('hr.document.view', 'View documents', 'document', 'hr', 'basic', 8),
#     ('hr.document.delete', 'Delete documents', 'document', 'hr', 'basic', 9),
#     ('hr.position.create', 'Create positions', 'position', 'hr', 'basic', 10),
#     ('hr.position.update', 'Update positions', 'position', 'hr', 'basic', 11),
#     ('hr.position.delete', 'Delete positions', 'position', 'hr', 'basic', 12),
#     ('hr.position.view', 'View positions', 'position', 'hr', 'basic', 13),
#     ('hr.leave.request', 'Request leave', 'leave', 'hr', 'basic', 14),
#     ('hr.leave.approve', 'Approve leave', 'leave', 'hr', 'basic', 15),
#     ('hr.leave.reject', 'Reject leave', 'leave', 'hr', 'basic', 16),
#     ('hr.leave.view', 'View leave', 'leave', 'hr', 'basic', 17),
#     ('hr.attendance.view', 'View attendance', 'attendance', 'hr', 'basic', 18),
#     ('hr.attendance.update', 'Update attendance', 'attendance', 'hr', 'basic', 19)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 FINANCE MODULE (19 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('finance.invoice.create', 'Create invoices', 'invoice', 'finance', 'basic', 20),
#     ('finance.invoice.update', 'Update invoices', 'invoice', 'finance', 'basic', 21),
#     ('finance.invoice.delete', 'Delete invoices', 'invoice', 'finance', 'basic', 22),
#     ('finance.invoice.view', 'View invoices', 'invoice', 'finance', 'basic', 23),
#     ('finance.invoice.send', 'Send invoices', 'invoice', 'finance', 'basic', 24),
#     ('finance.invoice.approve', 'Approve invoices', 'invoice', 'finance', 'basic', 25),
#     ('finance.payment.process', 'Process payments', 'payment', 'finance', 'basic', 26),
#     ('finance.payment.refund', 'Process refunds', 'payment', 'finance', 'basic', 27),
#     ('finance.payment.view', 'View payments', 'payment', 'finance', 'basic', 28),
#     ('finance.statement.view', 'View statements', 'statement', 'finance', 'basic', 29),
#     ('finance.statement.download', 'Download statements', 'statement', 'finance', 'basic', 30),
#     ('finance.tax.create', 'Create tax records', 'tax', 'finance', 'basic', 31),
#     ('finance.tax.update', 'Update tax records', 'tax', 'finance', 'basic', 32),
#     ('finance.tax.view', 'View tax records', 'tax', 'finance', 'basic', 33),
#     ('finance.tax.delete', 'Delete tax records', 'tax', 'finance', 'basic', 34),
#     ('finance.budget.create', 'Create budgets', 'budget', 'finance', 'basic', 35),
#     ('finance.budget.update', 'Update budgets', 'budget', 'finance', 'basic', 36),
#     ('finance.budget.delete', 'Delete budgets', 'budget', 'finance', 'basic', 37),
#     ('finance.budget.view', 'View budgets', 'budget', 'finance', 'basic', 38)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 ACCOUNTING MODULE (10 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('accounting.ledger.view', 'View ledger', 'ledger', 'accounting', 'basic', 39),
#     ('accounting.journal.create', 'Create journal entries', 'journal', 'accounting', 'basic', 40),
#     ('accounting.journal.update', 'Update journal entries', 'journal', 'accounting', 'basic', 41),
#     ('accounting.journal.delete', 'Delete journal entries', 'journal', 'accounting', 'basic', 42),
#     ('accounting.journal.view', 'View journal entries', 'journal', 'accounting', 'basic', 43),
#     ('accounting.pl.view', 'View profit/loss', 'pl', 'accounting', 'basic', 44),
#     ('accounting.balance_sheet.view', 'View balance sheet', 'balance_sheet', 'accounting', 'basic', 45),
#     ('accounting.cashflow.view', 'View cash flow', 'cashflow', 'accounting', 'basic', 46),
#     ('accounting.reconcile', 'Reconcile accounts', 'reconcile', 'accounting', 'basic', 47),
#     ('accounting.report.export', 'Export reports', 'report', 'accounting', 'basic', 48)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 PROCUREMENT MODULE (15 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('procurement.po.create', 'Create purchase orders', 'po', 'procurement', 'basic', 49),
#     ('procurement.po.update', 'Update purchase orders', 'po', 'procurement', 'basic', 50),
#     ('procurement.po.approve', 'Approve purchase orders', 'po', 'procurement', 'basic', 51),
#     ('procurement.po.reject', 'Reject purchase orders', 'po', 'procurement', 'basic', 52),
#     ('procurement.po.delete', 'Delete purchase orders', 'po', 'procurement', 'basic', 53),
#     ('procurement.po.view', 'View purchase orders', 'po', 'procurement', 'basic', 54),
#     ('procurement.vendor.create', 'Create vendors', 'vendor', 'procurement', 'basic', 55),
#     ('procurement.vendor.update', 'Update vendors', 'vendor', 'procurement', 'basic', 56),
#     ('procurement.vendor.block', 'Block vendors', 'vendor', 'procurement', 'basic', 57),
#     ('procurement.vendor.delete', 'Delete vendors', 'vendor', 'procurement', 'basic', 58),
#     ('procurement.vendor.view', 'View vendors', 'vendor', 'procurement', 'basic', 59),
#     ('procurement.request.create', 'Create procurement requests', 'request', 'procurement', 'basic', 60),
#     ('procurement.request.update', 'Update procurement requests', 'request', 'procurement', 'basic', 61),
#     ('procurement.request.delete', 'Delete procurement requests', 'request', 'procurement', 'basic', 62),
#     ('procurement.request.view', 'View procurement requests', 'request', 'procurement', 'basic', 63)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 INVENTORY MODULE (18 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('inventory.item.create', 'Create items', 'item', 'inventory', 'basic', 64),
#     ('inventory.item.update', 'Update items', 'item', 'inventory', 'basic', 65),
#     ('inventory.item.delete', 'Delete items', 'item', 'inventory', 'basic', 66),
#     ('inventory.item.view', 'View items', 'item', 'inventory', 'basic', 67),
#     ('inventory.stock.in', 'Stock in items', 'stock', 'inventory', 'basic', 68),
#     ('inventory.stock.out', 'Stock out items', 'stock', 'inventory', 'basic', 69),
#     ('inventory.stock.transfer', 'Transfer stock', 'stock', 'inventory', 'basic', 70),
#     ('inventory.stock.adjust', 'Adjust stock', 'stock', 'inventory', 'basic', 71),
#     ('inventory.stock.audit', 'Audit stock', 'stock', 'inventory', 'basic', 72),
#     ('inventory.stock.view', 'View stock', 'stock', 'inventory', 'basic', 73),
#     ('inventory.batch.create', 'Create batches', 'batch', 'inventory', 'basic', 74),
#     ('inventory.batch.update', 'Update batches', 'batch', 'inventory', 'basic', 75),
#     ('inventory.batch.view', 'View batches', 'batch', 'inventory', 'basic', 76),
#     ('inventory.batch.delete', 'Delete batches', 'batch', 'inventory', 'basic', 77),
#     ('inventory.warehouse.create', 'Create warehouses', 'warehouse', 'inventory', 'basic', 78),
#     ('inventory.warehouse.update', 'Update warehouses', 'warehouse', 'inventory', 'basic', 79),
#     ('inventory.warehouse.delete', 'Delete warehouses', 'warehouse', 'inventory', 'basic', 80),
#     ('inventory.warehouse.view', 'View warehouses', 'warehouse', 'inventory', 'basic', 81)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 LOGISTICS MODULE (12 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('logistics.shipment.create', 'Create shipments', 'shipment', 'logistics', 'basic', 82),
#     ('logistics.shipment.update', 'Update shipments', 'shipment', 'logistics', 'basic', 83),
#     ('logistics.shipment.delete', 'Delete shipments', 'shipment', 'logistics', 'basic', 84),
#     ('logistics.shipment.view', 'View shipments', 'shipment', 'logistics', 'basic', 85),
#     ('logistics.tracking.view', 'View tracking', 'tracking', 'logistics', 'basic', 86),
#     ('logistics.route.create', 'Create routes', 'route', 'logistics', 'basic', 87),
#     ('logistics.route.update', 'Update routes', 'route', 'logistics', 'basic', 88),
#     ('logistics.route.delete', 'Delete routes', 'route', 'logistics', 'basic', 89),
#     ('logistics.route.view', 'View routes', 'route', 'logistics', 'basic', 90),
#     ('logistics.vehicle.assign', 'Assign vehicles', 'vehicle', 'logistics', 'basic', 91),
#     ('logistics.vehicle.update', 'Update vehicles', 'vehicle', 'logistics', 'basic', 92),
#     ('logistics.vehicle.view', 'View vehicles', 'vehicle', 'logistics', 'basic', 93)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 SALES MODULE (16 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('sales.lead.create', 'Create sales leads', 'lead', 'sales', 'basic', 94),
#     ('sales.lead.update', 'Update sales leads', 'lead', 'sales', 'basic', 95),
#     ('sales.lead.delete', 'Delete sales leads', 'lead', 'sales', 'basic', 96),
#     ('sales.lead.view', 'View sales leads', 'lead', 'sales', 'basic', 97),
#     ('sales.deal.create', 'Create deals', 'deal', 'sales', 'basic', 98),
#     ('sales.deal.update', 'Update deals', 'deal', 'sales', 'basic', 99),
#     ('sales.deal.delete', 'Delete deals', 'deal', 'sales', 'basic', 100),
#     ('sales.deal.view', 'View deals', 'deal', 'sales', 'basic', 101),
#     ('sales.deal.close', 'Close deals', 'deal', 'sales', 'basic', 102),
#     ('sales.quote.create', 'Create quotes', 'quote', 'sales', 'basic', 103),
#     ('sales.quote.update', 'Update quotes', 'quote', 'sales', 'basic', 104),
#     ('sales.quote.delete', 'Delete quotes', 'quote', 'sales', 'basic', 105),
#     ('sales.quote.view', 'View quotes', 'quote', 'sales', 'basic', 106),
#     ('sales.target.create', 'Create sales targets', 'target', 'sales', 'basic', 107),
#     ('sales.target.update', 'Update sales targets', 'target', 'sales', 'basic', 108),
#     ('sales.target.view', 'View sales targets', 'target', 'sales', 'basic', 109)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 MARKETING MODULE (12 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('marketing.campaign.create', 'Create campaigns', 'campaign', 'marketing', 'basic', 110),
#     ('marketing.campaign.update', 'Update campaigns', 'campaign', 'marketing', 'basic', 111),
#     ('marketing.campaign.delete', 'Delete campaigns', 'campaign', 'marketing', 'basic', 112),
#     ('marketing.campaign.view', 'View campaigns', 'campaign', 'marketing', 'basic', 113),
#     ('marketing.analytics.view', 'View analytics', 'analytics', 'marketing', 'basic', 114),
#     ('marketing.audience.create', 'Create audiences', 'audience', 'marketing', 'basic', 115),
#     ('marketing.audience.update', 'Update audiences', 'audience', 'marketing', 'basic', 116),
#     ('marketing.audience.delete', 'Delete audiences', 'audience', 'marketing', 'basic', 117),
#     ('marketing.audience.view', 'View audiences', 'audience', 'marketing', 'basic', 118),
#     ('marketing.budget.create', 'Create marketing budgets', 'budget', 'marketing', 'basic', 119),
#     ('marketing.budget.update', 'Update marketing budgets', 'budget', 'marketing', 'basic', 120),
#     ('marketing.budget.view', 'View marketing budgets', 'budget', 'marketing', 'basic', 121)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 CUSTOMER SUPPORT (11 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('support.ticket.create', 'Create support tickets', 'ticket', 'support', 'basic', 122),
#     ('support.ticket.update', 'Update support tickets', 'ticket', 'support', 'basic', 123),
#     ('support.ticket.assign', 'Assign support tickets', 'ticket', 'support', 'basic', 124),
#     ('support.ticket.close', 'Close support tickets', 'ticket', 'support', 'basic', 125),
#     ('support.ticket.delete', 'Delete support tickets', 'ticket', 'support', 'basic', 126),
#     ('support.ticket.view', 'View support tickets', 'ticket', 'support', 'basic', 127),
#     ('support.faq.create', 'Create FAQs', 'faq', 'support', 'basic', 128),
#     ('support.faq.update', 'Update FAQs', 'faq', 'support', 'basic', 129),
#     ('support.faq.delete', 'Delete FAQs', 'faq', 'support', 'basic', 130),
#     ('support.faq.view', 'View FAQs', 'faq', 'support', 'basic', 131),
#     ('support.report.view', 'View support reports', 'report', 'support', 'basic', 132)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 OPERATIONS (14 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('operations.task.create', 'Create tasks', 'task', 'operations', 'basic', 133),
#     ('operations.task.update', 'Update tasks', 'task', 'operations', 'basic', 134),
#     ('operations.task.delete', 'Delete tasks', 'task', 'operations', 'basic', 135),
#     ('operations.task.view', 'View tasks', 'task', 'operations', 'basic', 136),
#     ('operations.task.assign', 'Assign tasks', 'task', 'operations', 'basic', 137),
#     ('operations.task.complete', 'Complete tasks', 'task', 'operations', 'basic', 138),
#     ('operations.shift.create', 'Create shifts', 'shift', 'operations', 'basic', 139),
#     ('operations.shift.update', 'Update shifts', 'shift', 'operations', 'basic', 140),
#     ('operations.shift.delete', 'Delete shifts', 'shift', 'operations', 'basic', 141),
#     ('operations.shift.view', 'View shifts', 'shift', 'operations', 'basic', 142),
#     ('operations.workflow.create', 'Create workflows', 'workflow', 'operations', 'basic', 143),
#     ('operations.workflow.update', 'Update workflows', 'workflow', 'operations', 'basic', 144),
#     ('operations.workflow.delete', 'Delete workflows', 'workflow', 'operations', 'basic', 145),
#     ('operations.workflow.view', 'View workflows', 'workflow', 'operations', 'basic', 146)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 IT MODULE (14 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('it.asset.create', 'Create IT assets', 'asset', 'it', 'basic', 147),
#     ('it.asset.update', 'Update IT assets', 'asset', 'it', 'basic', 148),
#     ('it.asset.delete', 'Delete IT assets', 'asset', 'it', 'basic', 149),
#     ('it.asset.view', 'View IT assets', 'asset', 'it', 'basic', 150),
#     ('it.incident.create', 'Create incidents', 'incident', 'it', 'basic', 151),
#     ('it.incident.update', 'Update incidents', 'incident', 'it', 'basic', 152),
#     ('it.incident.resolve', 'Resolve incidents', 'incident', 'it', 'basic', 153),
#     ('it.incident.close', 'Close incidents', 'incident', 'it', 'basic', 154),
#     ('it.incident.view', 'View incidents', 'incident', 'it', 'basic', 155),
#     ('it.access.request', 'Request access', 'access', 'it', 'basic', 156),
#     ('it.access.grant', 'Grant access', 'access', 'it', 'basic', 157),
#     ('it.access.revoke', 'Revoke access', 'access', 'it', 'basic', 158),
#     ('it.system.config.update', 'Update system config', 'system', 'it', 'basic', 159),
#     ('it.system.config.view', 'View system config', 'system', 'it', 'basic', 160)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 PRODUCTION (16 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('production.order.create', 'Create production orders', 'order', 'production', 'basic', 161),
#     ('production.order.update', 'Update production orders', 'order', 'production', 'basic', 162),
#     ('production.order.start', 'Start production orders', 'order', 'production', 'basic', 163),
#     ('production.order.pause', 'Pause production orders', 'order', 'production', 'basic', 164),
#     ('production.order.finish', 'Finish production orders', 'order', 'production', 'basic', 165),
#     ('production.order.cancel', 'Cancel production orders', 'order', 'production', 'basic', 166),
#     ('production.order.delete', 'Delete production orders', 'order', 'production', 'basic', 167),
#     ('production.order.view', 'View production orders', 'order', 'production', 'basic', 168),
#     ('production.bom.create', 'Create BOMs', 'bom', 'production', 'basic', 169),
#     ('production.bom.update', 'Update BOMs', 'bom', 'production', 'basic', 170),
#     ('production.bom.delete', 'Delete BOMs', 'bom', 'production', 'basic', 171),
#     ('production.bom.view', 'View BOMs', 'bom', 'production', 'basic', 172),
#     ('production.route.create', 'Create routes', 'route', 'production', 'basic', 173),
#     ('production.route.update', 'Update routes', 'route', 'production', 'basic', 174),
#     ('production.route.view', 'View routes', 'route', 'production', 'basic', 175),
#     ('production.route.delete', 'Delete routes', 'route', 'production', 'basic', 176)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 QUALITY CONTROL (10 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('qc.inspection.create', 'Create inspections', 'inspection', 'qc', 'basic', 177),
#     ('qc.inspection.update', 'Update inspections', 'inspection', 'qc', 'basic', 178),
#     ('qc.inspection.approve', 'Approve inspections', 'inspection', 'qc', 'basic', 179),
#     ('qc.inspection.reject', 'Reject inspections', 'inspection', 'qc', 'basic', 180),
#     ('qc.inspection.delete', 'Delete inspections', 'inspection', 'qc', 'basic', 181),
#     ('qc.inspection.view', 'View inspections', 'inspection', 'qc', 'basic', 182),
#     ('qc.batch.hold', 'Hold batches', 'batch', 'qc', 'basic', 183),
#     ('qc.batch.release', 'Release batches', 'batch', 'qc', 'basic', 184),
#     ('qc.report.generate', 'Generate QC reports', 'report', 'qc', 'basic', 185),
#     ('qc.report.view', 'View QC reports', 'report', 'qc', 'basic', 186)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 QUALITY ASSURANCE (10 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('qa.test.create', 'Create tests', 'test', 'qa', 'basic', 187),
#     ('qa.test.update', 'Update tests', 'test', 'qa', 'basic', 188),
#     ('qa.test.delete', 'Delete tests', 'test', 'qa', 'basic', 189),
#     ('qa.test.execute', 'Execute tests', 'test', 'qa', 'basic', 190),
#     ('qa.test.view', 'View tests', 'test', 'qa', 'basic', 191),
#     ('qa.audit.create', 'Create audits', 'audit', 'qa', 'basic', 192),
#     ('qa.audit.update', 'Update audits', 'audit', 'qa', 'basic', 193),
#     ('qa.audit.view', 'View audits', 'audit', 'qa', 'basic', 194),
#     ('qa.report.generate', 'Generate QA reports', 'report', 'qa', 'basic', 195),
#     ('qa.report.view', 'View QA reports', 'report', 'qa', 'basic', 196)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 R&D (12 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('rnd.experiment.create', 'Create experiments', 'experiment', 'rnd', 'basic', 197),
#     ('rnd.experiment.update', 'Update experiments', 'experiment', 'rnd', 'basic', 198),
#     ('rnd.experiment.delete', 'Delete experiments', 'experiment', 'rnd', 'basic', 199),
#     ('rnd.experiment.view', 'View experiments', 'experiment', 'rnd', 'basic', 200),
#     ('rnd.prototype.create', 'Create prototypes', 'prototype', 'rnd', 'basic', 201),
#     ('rnd.prototype.update', 'Update prototypes', 'prototype', 'rnd', 'basic', 202),
#     ('rnd.prototype.view', 'View prototypes', 'prototype', 'rnd', 'basic', 203),
#     ('rnd.prototype.delete', 'Delete prototypes', 'prototype', 'rnd', 'basic', 204),
#     ('rnd.document.create', 'Create R&D documents', 'document', 'rnd', 'basic', 205),
#     ('rnd.document.update', 'Update R&D documents', 'document', 'rnd', 'basic', 206),
#     ('rnd.document.view', 'View R&D documents', 'document', 'rnd', 'basic', 207),
#     ('rnd.document.delete', 'Delete R&D documents', 'document', 'rnd', 'basic', 208)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 ADMIN / SYSTEM (20 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('admin.user.create', 'Create users', 'user', 'admin', 'admin', 209),
#     ('admin.user.update', 'Update users', 'user', 'admin', 'admin', 210),
#     ('admin.user.view', 'View users', 'user', 'admin', 'admin', 211),
#     ('admin.user.delete', 'Delete users', 'user', 'admin', 'admin', 212),
#     ('admin.role.create', 'Create roles', 'role', 'admin', 'admin', 213),
#     ('admin.role.update', 'Update roles', 'role', 'admin', 'admin', 214),
#     ('admin.role.delete', 'Delete roles', 'role', 'admin', 'admin', 215),
#     ('admin.role.view', 'View roles', 'role', 'admin', 'admin', 216),
#     ('admin.permission.assign', 'Assign permissions', 'permission', 'admin', 'admin', 217),
#     ('admin.permission.revoke', 'Revoke permissions', 'permission', 'admin', 'admin', 218),
#     ('admin.permission.view', 'View permissions', 'permission', 'admin', 'admin', 219),
#     ('admin.department.create', 'Create departments', 'department', 'admin', 'admin', 220),
#     ('admin.department.update', 'Update departments', 'department', 'admin', 'admin', 221),
#     ('admin.department.delete', 'Delete departments', 'department', 'admin', 'admin', 222),
#     ('admin.department.view', 'View departments', 'department', 'admin', 'admin', 223),
#     ('admin.company.update', 'Update company', 'company', 'admin', 'admin', 224),
#     ('admin.company.view', 'View company', 'company', 'admin', 'admin', 225),
#     ('admin.company.suspend', 'Suspend company', 'company', 'admin', 'admin', 226),
#     ('admin.audit.logs.view', 'View audit logs', 'audit', 'admin', 'admin', 227),
#     ('admin.audit.logs.export', 'Export audit logs', 'audit', 'admin', 'admin', 228)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- 🔵 ADMINISTRATION MODULE (6 permissions)
#     INSERT INTO permissions (permission_name, description, category, module, requires_tier, bit_index) VALUES
#     ('administrative.department.view', 'View company departments', 'department', 'administration', 'basic', 229),
#     ('administrative.department.create', 'Create departments', 'department', 'administration', 'basic', 230),
#     ('administrative.department.update', 'Update departments', 'department', 'administration', 'basic', 231),
#     ('administrative.department.delete', 'Delete departments', 'department', 'administration', 'basic', 232),
#     ('administrative.employee.view', 'View company employees', 'employee', 'administration', 'basic', 233),
#     ('administrative.employee.manage', 'Manage company employees', 'employee', 'administration', 'basic', 234)
#     ON CONFLICT (permission_name) DO NOTHING;

#     -- =========================================================
#     -- APPLICATION-LEVEL DATA INTEGRITY CONSTRAINTS
#     -- =========================================================
#     -- ✅ NOTE: The following constraints must be enforced at application level:
#     -- 1. company_employees.reports_to must reference a user in the same company
#     -- 2. departments.department_head must be an employee of the same company
#     -- 
#     -- These cannot be implemented as database foreign keys due to circular dependencies,
#     -- but MUST be enforced by your application business logic to prevent:
#     -- - Cross-company reporting chains
#     -- - Cross-company department heads
#     -- - Orphaned reporting structures

# EOSQL

# echo "✅ PostgreSQL schema created successfully!"
# echo ""
# echo "✅ ALL FIXES APPLIED:"
# echo "   • Fixed all dollar quoting issues in function definitions"
# echo "   • Fixed 'user_search' function parameter counting"
# echo "   • Fixed 'company_search' function parameter counting" 
# echo "   • FIXED 'company_employee_search' function - updated with corrected version"
# echo "   • FIXED 'get_company_employee_suggestions' function - updated with corrected version"
# echo "   • Added proper parameter offset calculation for filter parameters"
# echo ""
# echo "🚀 USER SEARCH OPTIMIZATIONS ADDED:"
# echo "   • Added username and full_name fields to users table ✅"
# echo "   • Added user_search_tsv (tsvector) column ✅"
# echo "   • Created GIN index on tsvector (idx_users_search_tsv) ✅"
# echo "   • Created trigram indexes for autocomplete (username & full_name) ✅"
# echo "   • Added user_search() function with filters ✅"
# echo "   • Added user name update trigger ✅"
# echo ""
# echo "🚀 COMPANY SEARCH OPTIMIZATIONS ADDED:"
# echo "   • Added company_name_tsv (tsvector) column ✅"
# echo "   • Created GIN index on tsvector (idx_companies_name_tsv) ✅"
# echo "   • Created trigram index for autocomplete (idx_companies_name_trgm) ✅"
# echo "   • Added company_search() function ✅"
# echo "   • Added company name update trigger ✅"
# echo ""
# echo "🚀 COMPANY EMPLOYEE SEARCH FUNCTIONS ADDED:"
# echo "   • Added company_employee_search() function ✅"
# echo "   • Added get_company_employee_suggestions() function ✅"
# echo "   • Added find_company_employee_by_username() function ✅"
# echo ""
# echo "📊 Database Summary:"
# echo "   • Users table with 8 partitions + username/full_name search ✅"
# echo "   • Companies table NON-PARTITIONED with text search ✅"
# echo "   • All other tables NON-PARTITIONED (roles, departments, etc.) ✅"
# echo "   • 235 Enterprise Permissions across all modules ✅"
# echo "   • 16 System Departments (ERP modules) ✅"
# echo "   • Performance indexes on all key columns ✅"
# echo "   • All foreign keys defined directly in table creation ✅"
# echo "   • User search functions: user_search(), find_user_by_username() ✅"
# echo "   • Company search functions: company_search(), find_companies_by_owner() ✅"
# echo "   • Company employee search: company_employee_search(), get_company_employee_suggestions() ✅"
# echo "   • Autocomplete functions: get_user_suggestions(), get_company_suggestions(), get_company_employee_suggestions() ✅"
# echo ""
# echo "🎉 PostgreSQL RBAC initialization completed with comprehensive search capabilities and ALL BUGS FIXED!"