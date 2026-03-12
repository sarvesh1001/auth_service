--
-- PostgreSQL database dump
--

\restrict 7s5fHEFJfjbdl2IYRqxH2UvZp7viyghq8bxtRll80ObTF40gKg92STNH3DLfffg

-- Dumped from database version 15.15
-- Dumped by pg_dump version 15.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: attendance; Type: SCHEMA; Schema: -; Owner: auth_user
--

CREATE SCHEMA attendance;


ALTER SCHEMA attendance OWNER TO auth_user;

--
-- Name: audit; Type: SCHEMA; Schema: -; Owner: auth_user
--

CREATE SCHEMA audit;


ALTER SCHEMA audit OWNER TO auth_user;

--
-- Name: biometric; Type: SCHEMA; Schema: -; Owner: auth_user
--

CREATE SCHEMA biometric;


ALTER SCHEMA biometric OWNER TO auth_user;

--
-- Name: leave; Type: SCHEMA; Schema: -; Owner: auth_user
--

CREATE SCHEMA leave;


ALTER SCHEMA leave OWNER TO auth_user;

--
-- Name: payroll; Type: SCHEMA; Schema: -; Owner: auth_user
--

CREATE SCHEMA payroll;


ALTER SCHEMA payroll OWNER TO auth_user;

--
-- Name: btree_gist; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public;


--
-- Name: EXTENSION btree_gist; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION btree_gist IS 'support for indexing common datatypes in GiST';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: audit_logs_outbox_trigger(); Type: FUNCTION; Schema: audit; Owner: auth_user
--

CREATE FUNCTION audit.audit_logs_outbox_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION audit.audit_logs_outbox_trigger() OWNER TO auth_user;

--
-- Name: revoke_biometric_on_exit(); Type: FUNCTION; Schema: biometric; Owner: auth_user
--

CREATE FUNCTION biometric.revoke_biometric_on_exit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE biometric.face_embeddings
    SET is_active = false,
        updated_at = NOW()
    WHERE company_id = NEW.company_id
      AND user_id = NEW.user_id
      AND is_active = true;

    RETURN NEW;
END;
$$;


ALTER FUNCTION biometric.revoke_biometric_on_exit() OWNER TO auth_user;

--
-- Name: calculate_fractional_accrual(integer, text, integer); Type: FUNCTION; Schema: leave; Owner: auth_user
--

CREATE FUNCTION leave.calculate_fractional_accrual(p_total_days integer, p_accrual_method text, p_months_count integer DEFAULT 1) RETURNS numeric
    LANGUAGE plpgsql IMMUTABLE
    AS $$
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
$$;


ALTER FUNCTION leave.calculate_fractional_accrual(p_total_days integer, p_accrual_method text, p_months_count integer) OWNER TO auth_user;

--
-- Name: close_active_entitlements(uuid, uuid, uuid, date); Type: FUNCTION; Schema: leave; Owner: auth_user
--

CREATE FUNCTION leave.close_active_entitlements(p_company_id uuid, p_user_id uuid, p_policy_id uuid, p_effective_to date) RETURNS integer
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE leave.leave_entitlement
    SET effective_to = p_effective_to
    WHERE company_id = p_company_id
      AND user_id = p_user_id
      AND policy_id = p_policy_id
      AND effective_to IS NULL;
    RETURN ROW_COUNT;
END;
$$;


ALTER FUNCTION leave.close_active_entitlements(p_company_id uuid, p_user_id uuid, p_policy_id uuid, p_effective_to date) OWNER TO auth_user;

--
-- Name: get_user_effective_policy(uuid, uuid, date); Type: FUNCTION; Schema: leave; Owner: auth_user
--

CREATE FUNCTION leave.get_user_effective_policy(p_company_id uuid, p_user_id uuid, p_as_of date DEFAULT CURRENT_DATE) RETURNS TABLE(policy_id uuid, policy_name text, applies_to_type text, applies_to_id text, priority integer, effective_from date, effective_to date, rule_leave_type_id uuid, rule_total_days integer, rule_accrual_method text, rule_carry_forward_limit integer)
    LANGUAGE plpgsql STABLE
    AS $$
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
$$;


ALTER FUNCTION leave.get_user_effective_policy(p_company_id uuid, p_user_id uuid, p_as_of date) OWNER TO auth_user;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: leave; Owner: auth_user
--

CREATE FUNCTION leave.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


ALTER FUNCTION leave.update_updated_at_column() OWNER TO auth_user;

--
-- Name: admin_has_department_access(uuid, bigint); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.admin_has_department_access(admin_id_param uuid, department_bitmask bigint) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.admin_has_department_access(admin_id_param uuid, department_bitmask bigint) OWNER TO auth_user;

--
-- Name: admin_has_permission(uuid, character varying); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.admin_has_permission(admin_id_param uuid, permission_name_param character varying) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.admin_has_permission(admin_id_param uuid, permission_name_param character varying) OWNER TO auth_user;

--
-- Name: cascade_department_soft_delete(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.cascade_department_soft_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.is_active = true AND NEW.is_active = false THEN
        PERFORM deactivate_child_departments(OLD.department_id);
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.cascade_department_soft_delete() OWNER TO auth_user;

--
-- Name: check_recent_attendance_duplicate(uuid, uuid, character varying, timestamp with time zone, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.check_recent_attendance_duplicate(p_company_id uuid, p_user_id uuid, p_event_type character varying, p_event_time timestamp with time zone, p_time_window_minutes integer DEFAULT 5) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE duplicate_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO duplicate_count
    FROM attendance_events
    WHERE company_id = p_company_id AND user_id = p_user_id
      AND event_type = p_event_type AND source_type != 'correction'
      AND ABS(EXTRACT(EPOCH FROM (event_time - p_event_time))) <= p_time_window_minutes * 60;
    RETURN duplicate_count > 0;
END;
$$;


ALTER FUNCTION public.check_recent_attendance_duplicate(p_company_id uuid, p_user_id uuid, p_event_type character varying, p_event_time timestamp with time zone, p_time_window_minutes integer) OWNER TO auth_user;

--
-- Name: close_positions_on_department_deactivate(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.close_positions_on_department_deactivate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.is_active = true AND NEW.is_active = false THEN
        UPDATE positions SET is_open = false WHERE department_id = OLD.department_id AND is_open = true;
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.close_positions_on_department_deactivate() OWNER TO auth_user;

--
-- Name: company_employee_search(text, uuid, text, uuid, uuid, boolean, uuid, timestamp with time zone, timestamp with time zone, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.company_employee_search(search_query text, company_id_param uuid, search_type text DEFAULT 'fulltext'::text, filter_role_id uuid DEFAULT NULL::uuid, filter_department_id uuid DEFAULT NULL::uuid, filter_is_active boolean DEFAULT NULL::boolean, filter_reports_to uuid DEFAULT NULL::uuid, filter_hire_date_from timestamp with time zone DEFAULT NULL::timestamp with time zone, filter_hire_date_to timestamp with time zone DEFAULT NULL::timestamp with time zone, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(user_id uuid, username character varying, full_name character varying, phone_hash character varying, employee_id character varying, role_id uuid, role_name character varying, department_id uuid, department_name character varying, hire_date timestamp with time zone, is_active boolean, reports_to uuid, reports_to_name character varying, created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $_$
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
$_$;


ALTER FUNCTION public.company_employee_search(search_query text, company_id_param uuid, search_type text, filter_role_id uuid, filter_department_id uuid, filter_is_active boolean, filter_reports_to uuid, filter_hire_date_from timestamp with time zone, filter_hire_date_to timestamp with time zone, limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: company_search(text, text, uuid, boolean, text, text, text, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.company_search(search_query text, search_type text DEFAULT 'fulltext'::text, filter_owner_id uuid DEFAULT NULL::uuid, filter_is_active boolean DEFAULT NULL::boolean, filter_subscription_tier text DEFAULT NULL::text, filter_data_region text DEFAULT NULL::text, filter_subscription_status text DEFAULT NULL::text, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(company_id uuid, company_name character varying, owner_user_id uuid, subscription_tier character varying, subscription_status character varying, max_employees integer, is_active boolean, data_region character varying, created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $_$
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
$_$;


ALTER FUNCTION public.company_search(search_query text, search_type text, filter_owner_id uuid, filter_is_active boolean, filter_subscription_tier text, filter_data_region text, filter_subscription_status text, limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: deactivate_child_departments(uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.deactivate_child_departments(p_dept_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    child_id UUID;
BEGIN
    FOR child_id IN SELECT department_id FROM departments WHERE parent_department_id = p_dept_id AND is_active = true LOOP
        UPDATE departments SET is_active = false WHERE department_id = child_id;
        PERFORM deactivate_child_departments(child_id);
    END LOOP;
END;
$$;


ALTER FUNCTION public.deactivate_child_departments(p_dept_id uuid) OWNER TO auth_user;

--
-- Name: enforce_department_limit(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.enforce_department_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.enforce_department_limit() OWNER TO auth_user;

--
-- Name: enforce_employee_limit(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.enforce_employee_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.enforce_employee_limit() OWNER TO auth_user;

--
-- Name: enforce_schedule_cancellation(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.enforce_schedule_cancellation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status = 'cancelled' AND OLD.schedule_date > CURRENT_DATE THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'active' THEN
        RAISE EXCEPTION 'Direct modification not allowed. Cancel and regenerate.';
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.enforce_schedule_cancellation() OWNER TO auth_user;

--
-- Name: enforce_scheduled_employee_exits(date, uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.enforce_scheduled_employee_exits(p_effective_date date DEFAULT CURRENT_DATE, p_enforced_by uuid DEFAULT NULL::uuid) RETURNS integer
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.enforce_scheduled_employee_exits(p_effective_date date, p_enforced_by uuid) OWNER TO auth_user;

--
-- Name: enforce_unique_active_department_name(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.enforce_unique_active_department_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.enforce_unique_active_department_name() OWNER TO auth_user;

--
-- Name: find_companies_by_owner(uuid, character varying); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.find_companies_by_owner(owner_id uuid, name_filter character varying DEFAULT NULL::character varying) RETURNS TABLE(company_id uuid, company_name character varying, subscription_tier character varying, subscription_status character varying, is_active boolean, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.find_companies_by_owner(owner_id uuid, name_filter character varying) OWNER TO auth_user;

--
-- Name: find_company_employee_by_username(uuid, character varying); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.find_company_employee_by_username(company_id_search uuid, username_search character varying) RETURNS TABLE(user_id uuid, username character varying, full_name character varying, phone_hash character varying, employee_id character varying, role_id uuid, role_name character varying, department_id uuid, department_name character varying, is_active boolean, hire_date timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.find_company_employee_by_username(company_id_search uuid, username_search character varying) OWNER TO auth_user;

--
-- Name: find_existing_correction(uuid, uuid, character varying, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.find_existing_correction(p_company_id uuid, p_user_id uuid, p_event_type character varying, p_event_time timestamp with time zone) RETURNS TABLE(attendance_event_id uuid, company_id uuid, user_id uuid, event_type character varying, event_time timestamp with time zone, source_type character varying, source_id uuid, device_id character varying, ip_address character varying, metadata jsonb, created_at timestamp with time zone, created_by uuid)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY SELECT ae.attendance_event_id, ae.company_id, ae.user_id, ae.event_type, ae.event_time,
                        ae.source_type, ae.source_id, ae.device_id, ae.ip_address,
                        ae.metadata, ae.created_at, ae.created_by
                 FROM attendance_events ae
                 WHERE ae.company_id = p_company_id AND ae.user_id = p_user_id
                   AND ae.event_type = p_event_type AND ae.event_time = p_event_time
                   AND ae.source_type = 'correction' LIMIT 1;
END;
$$;


ALTER FUNCTION public.find_existing_correction(p_company_id uuid, p_user_id uuid, p_event_type character varying, p_event_time timestamp with time zone) OWNER TO auth_user;

--
-- Name: find_user_by_username(character varying); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.find_user_by_username(username_search character varying) RETURNS TABLE(user_id uuid, username character varying, full_name character varying, phone_hash character varying, is_active boolean, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.find_user_by_username(username_search character varying) OWNER TO auth_user;

--
-- Name: get_active_employee_count(uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_active_employee_count(p_company_id uuid) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE total INTEGER;
BEGIN
    SELECT COUNT(*) INTO total FROM company_employees WHERE company_id = p_company_id AND is_active = true;
    RETURN total;
END;
$$;


ALTER FUNCTION public.get_active_employee_count(p_company_id uuid) OWNER TO auth_user;

--
-- Name: get_admin_role_departments(uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_admin_role_departments(role_id_param uuid) RETURNS TABLE(department_id uuid, name character varying, module_code character varying, description text, bitmask bigint)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_admin_role_departments(role_id_param uuid) OWNER TO auth_user;

--
-- Name: get_admin_role_permissions(uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_admin_role_permissions(role_id_param uuid) RETURNS TABLE(permission_id uuid, permission_name character varying, description text, category character varying, module character varying, scope character varying, bit_index integer)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_admin_role_permissions(role_id_param uuid) OWNER TO auth_user;

--
-- Name: get_admin_suggestions(character varying, integer, boolean, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_admin_suggestions(prefix character varying, role_type_filter integer DEFAULT NULL::integer, exclude_super_admin boolean DEFAULT true, limit_suggestions integer DEFAULT 10) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, role_name character varying, role_level integer, role_type integer, reports_to uuid, reports_to_name character varying, relevance double precision)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_admin_suggestions(prefix character varying, role_type_filter integer, exclude_super_admin boolean, limit_suggestions integer) OWNER TO auth_user;

--
-- Name: get_admin_with_permissions(uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_admin_with_permissions(admin_id_param uuid) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, role_name character varying, role_level integer, role_type integer, permissions jsonb, departments jsonb, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_admin_with_permissions(admin_id_param uuid) OWNER TO auth_user;

--
-- Name: get_company_employee_suggestions(uuid, character varying, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_company_employee_suggestions(company_id_param uuid, prefix character varying, limit_suggestions integer DEFAULT 10) RETURNS TABLE(username character varying, full_name character varying, user_id uuid, employee_id character varying, role_name character varying)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_company_employee_suggestions(company_id_param uuid, prefix character varying, limit_suggestions integer) OWNER TO auth_user;

--
-- Name: get_company_suggestions(character varying, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_company_suggestions(prefix character varying, limit_suggestions integer DEFAULT 10) RETURNS TABLE(company_name character varying, company_id uuid)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_company_suggestions(prefix character varying, limit_suggestions integer) OWNER TO auth_user;

--
-- Name: get_user_suggestions(character varying, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.get_user_suggestions(prefix character varying, limit_suggestions integer DEFAULT 10) RETURNS TABLE(username character varying, full_name character varying, user_id uuid)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_user_suggestions(prefix character varying, limit_suggestions integer) OWNER TO auth_user;

--
-- Name: mark_employee_rehired(uuid, uuid); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.mark_employee_rehired(p_company_id uuid, p_user_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE employee_exit SET exit_state = 'rehired' WHERE company_id = p_company_id AND user_id = p_user_id AND exit_state = 'effective';
    UPDATE company_employees SET is_active = true WHERE company_id = p_company_id AND user_id = p_user_id;
END;
$$;


ALTER FUNCTION public.mark_employee_rehired(p_company_id uuid, p_user_id uuid) OWNER TO auth_user;

--
-- Name: prevent_attendance_update_if_locked(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_attendance_update_if_locked() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.is_payroll_locked = true THEN
        RAISE EXCEPTION 'Attendance is payroll locked';
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.prevent_attendance_update_if_locked() OWNER TO auth_user;

--
-- Name: prevent_child_on_inactive_parent(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_child_on_inactive_parent() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.prevent_child_on_inactive_parent() OWNER TO auth_user;

--
-- Name: prevent_department_delete(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_department_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Hard delete of departments is not allowed';
END;
$$;


ALTER FUNCTION public.prevent_department_delete() OWNER TO auth_user;

--
-- Name: prevent_exit_for_inactive_employee(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_exit_for_inactive_employee() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE active_status BOOLEAN;
BEGIN
    SELECT is_active INTO active_status FROM company_employees WHERE company_id = NEW.company_id AND user_id = NEW.user_id;
    IF active_status IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'Cannot create exit for inactive employee';
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.prevent_exit_for_inactive_employee() OWNER TO auth_user;

--
-- Name: prevent_past_schedule_update(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_past_schedule_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.schedule_date <= CURRENT_DATE THEN
        RAISE EXCEPTION 'Past or current schedules are immutable';
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.prevent_past_schedule_update() OWNER TO auth_user;

--
-- Name: prevent_position_in_inactive_department(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_position_in_inactive_department() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    dept_active BOOLEAN;
BEGIN
    SELECT is_active INTO dept_active FROM departments WHERE department_id = NEW.department_id;
    IF dept_active = false THEN
        RAISE EXCEPTION 'Cannot assign position to inactive department';
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.prevent_position_in_inactive_department() OWNER TO auth_user;

--
-- Name: prevent_structure_update_if_used(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.prevent_structure_update_if_used() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.prevent_structure_update_if_used() OWNER TO auth_user;

--
-- Name: revoke_enrollment_on_exit(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.revoke_enrollment_on_exit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE attendance_user_device_identifiers
    SET is_active = false,
        unenrolled_at = NOW(),
        revoked_reason = 'employee_exit'
    WHERE company_id = NEW.company_id
      AND user_id = NEW.user_id
      AND is_active = true;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.revoke_enrollment_on_exit() OWNER TO auth_user;

--
-- Name: search_admin_employees(text, text, boolean, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.search_admin_employees(search_query text DEFAULT NULL::text, search_type text DEFAULT 'autocomplete'::text, include_inactive boolean DEFAULT false, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, phone_hash character varying, role_name character varying, admin_role_id uuid, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone, admin_created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.search_admin_employees(search_query text, search_type text, include_inactive boolean, limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: search_admin_managers(text, text, boolean, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.search_admin_managers(search_query text DEFAULT NULL::text, search_type text DEFAULT 'autocomplete'::text, include_inactive boolean DEFAULT false, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, phone_hash character varying, role_name character varying, admin_role_id uuid, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone, admin_created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.search_admin_managers(search_query text, search_type text, include_inactive boolean, limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: search_admin_users(text, integer, boolean, text, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.search_admin_users(search_query_param text DEFAULT NULL::text, role_type_filter_param integer DEFAULT NULL::integer, include_inactive_param boolean DEFAULT false, search_type_param text DEFAULT 'autocomplete'::text, limit_count_param integer DEFAULT 50, offset_count_param integer DEFAULT 0) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, phone_hash character varying, role_name character varying, admin_role_id uuid, role_type integer, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone, admin_created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql STABLE
    AS $$
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
$$;


ALTER FUNCTION public.search_admin_users(search_query_param text, role_type_filter_param integer, include_inactive_param boolean, search_type_param text, limit_count_param integer, offset_count_param integer) OWNER TO auth_user;

--
-- Name: search_admin_users_by_role_type(integer, text, text, boolean, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.search_admin_users_by_role_type(role_type_param integer, search_query text DEFAULT NULL::text, search_type text DEFAULT 'autocomplete'::text, include_inactive boolean DEFAULT false, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, phone_hash character varying, role_name character varying, admin_role_id uuid, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone, admin_created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.search_admin_users_by_role_type(role_type_param integer, search_query text, search_type text, include_inactive boolean, limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: search_admin_users_with_departments(text, integer, boolean, text, uuid[], integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.search_admin_users_with_departments(search_query text DEFAULT NULL::text, role_type_filter integer DEFAULT NULL::integer, include_inactive boolean DEFAULT false, search_type text DEFAULT 'autocomplete'::text, department_ids uuid[] DEFAULT NULL::uuid[], limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, phone_hash character varying, role_name character varying, admin_role_id uuid, role_type integer, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone, admin_created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $_$
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
$_$;


ALTER FUNCTION public.search_admin_users_with_departments(search_query text, role_type_filter integer, include_inactive boolean, search_type text, department_ids uuid[], limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: search_super_admins(text, text, boolean, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.search_super_admins(search_query text DEFAULT NULL::text, search_type text DEFAULT 'autocomplete'::text, include_inactive boolean DEFAULT false, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(admin_id uuid, username character varying, full_name character varying, phone_hash character varying, role_name character varying, admin_role_id uuid, reports_to uuid, reports_to_name character varying, is_active boolean, last_login timestamp with time zone, admin_created_at timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.search_super_admins(search_query text, search_type text, include_inactive boolean, limit_count integer, offset_count integer) OWNER TO auth_user;

--
-- Name: sync_employee_department_on_position(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.sync_employee_department_on_position() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.sync_employee_department_on_position() OWNER TO auth_user;

--
-- Name: sync_employee_role_history(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.sync_employee_role_history() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE employee_role_history SET end_date = CURRENT_DATE WHERE user_id = NEW.user_id AND end_date IS NULL;
    INSERT INTO employee_role_history (user_id, role_id, start_date, reason)
    VALUES (NEW.user_id, NEW.role_id, CURRENT_DATE,
            CASE WHEN TG_OP = 'INSERT' THEN 'initial role assignment' ELSE 'role change' END);
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.sync_employee_role_history() OWNER TO auth_user;

--
-- Name: update_admin_user_search_tsv(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.update_admin_user_search_tsv() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.username IS DISTINCT FROM OLD.username OR NEW.full_name IS DISTINCT FROM OLD.full_name THEN
        NEW.user_search_tsv = to_tsvector('simple', COALESCE(NEW.username, '')) ||
                              to_tsvector('simple', COALESCE(NEW.full_name, ''));
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_admin_user_search_tsv() OWNER TO auth_user;

--
-- Name: update_company_name_tsv(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.update_company_name_tsv() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.company_name IS DISTINCT FROM OLD.company_name THEN
        NEW.company_name_tsv = to_tsvector('simple', NEW.company_name);
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_company_name_tsv() OWNER TO auth_user;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.update_updated_at_column() OWNER TO auth_user;

--
-- Name: update_user_search_tsv(); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.update_user_search_tsv() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.username IS DISTINCT FROM OLD.username OR NEW.full_name IS DISTINCT FROM OLD.full_name THEN
        NEW.user_search_tsv = to_tsvector('simple', COALESCE(NEW.username, '')) ||
                              to_tsvector('simple', COALESCE(NEW.full_name, ''));
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_user_search_tsv() OWNER TO auth_user;

--
-- Name: user_search(text, text, boolean, text, text, boolean, integer, integer); Type: FUNCTION; Schema: public; Owner: auth_user
--

CREATE FUNCTION public.user_search(search_query text, search_type text DEFAULT 'fulltext'::text, filter_is_active boolean DEFAULT NULL::boolean, filter_kyc_status text DEFAULT NULL::text, filter_data_region text DEFAULT NULL::text, filter_is_verified boolean DEFAULT NULL::boolean, limit_count integer DEFAULT 50, offset_count integer DEFAULT 0) RETURNS TABLE(user_id uuid, username character varying, full_name character varying, phone_hash character varying, kyc_status character varying, kyc_level character varying, is_verified boolean, is_active boolean, data_region character varying, created_at timestamp with time zone, last_login timestamp with time zone, relevance_score double precision, match_type text)
    LANGUAGE plpgsql STABLE
    AS $_$
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
$_$;


ALTER FUNCTION public.user_search(search_query text, search_type text, filter_is_active boolean, filter_kyc_status text, filter_data_region text, filter_is_verified boolean, limit_count integer, offset_count integer) OWNER TO auth_user;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: attendance_batch_outbox; Type: TABLE; Schema: attendance; Owner: auth_user
--

CREATE TABLE attendance.attendance_batch_outbox (
    outbox_id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type character varying(50) NOT NULL,
    aggregate_id uuid NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    error_message text
);


ALTER TABLE attendance.attendance_batch_outbox OWNER TO auth_user;

--
-- Name: attendance_events_outbox; Type: TABLE; Schema: attendance; Owner: auth_user
--

CREATE TABLE attendance.attendance_events_outbox (
    outbox_id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type character varying(50) NOT NULL,
    aggregate_id uuid NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone
);


ALTER TABLE attendance.attendance_events_outbox OWNER TO auth_user;

--
-- Name: audit_logs; Type: TABLE; Schema: audit; Owner: auth_user
--

CREATE TABLE audit.audit_logs (
    audit_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid,
    module character varying(50) NOT NULL,
    action character varying(100) NOT NULL,
    entity_type character varying(50) NOT NULL,
    entity_id uuid,
    actor_type character varying(20) NOT NULL,
    actor_id uuid,
    before_state jsonb,
    after_state jsonb,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE audit.audit_logs OWNER TO auth_user;

--
-- Name: audit_logs_outbox; Type: TABLE; Schema: audit; Owner: auth_user
--

CREATE TABLE audit.audit_logs_outbox (
    outbox_id uuid DEFAULT gen_random_uuid() NOT NULL,
    audit_id uuid NOT NULL,
    operation character varying(10) NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    error_message text
);


ALTER TABLE audit.audit_logs_outbox OWNER TO auth_user;

--
-- Name: outbox_debounce; Type: TABLE; Schema: audit; Owner: auth_user
--

CREATE TABLE audit.outbox_debounce (
    debounce_id uuid DEFAULT gen_random_uuid() NOT NULL,
    last_processed_id uuid,
    last_processed_at timestamp with time zone DEFAULT now() NOT NULL,
    batch_size integer DEFAULT 0
);


ALTER TABLE audit.outbox_debounce OWNER TO auth_user;

--
-- Name: device_embedding_sync; Type: TABLE; Schema: biometric; Owner: auth_user
--

CREATE TABLE biometric.device_embedding_sync (
    sync_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    device_id character varying(256) NOT NULL,
    model_version character varying(50) NOT NULL,
    last_synced_at timestamp with time zone,
    last_full_sync timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE biometric.device_embedding_sync OWNER TO auth_user;

--
-- Name: embedding_audit_log; Type: TABLE; Schema: biometric; Owner: auth_user
--

CREATE TABLE biometric.embedding_audit_log (
    audit_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    action character varying(30) NOT NULL,
    model_version character varying(50),
    acted_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    metadata jsonb
);


ALTER TABLE biometric.embedding_audit_log OWNER TO auth_user;

--
-- Name: face_embeddings; Type: TABLE; Schema: biometric; Owner: auth_user
--

CREATE TABLE biometric.face_embeddings (
    embedding_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    embedding_vector double precision[] NOT NULL,
    model_version character varying(50) NOT NULL,
    embedding_dim integer NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT face_embeddings_embedding_dim_check CHECK ((embedding_dim = ANY (ARRAY[128, 512])))
);


ALTER TABLE biometric.face_embeddings OWNER TO auth_user;

--
-- Name: leave_accrual; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_accrual (
    accrual_id uuid DEFAULT gen_random_uuid() NOT NULL,
    entitlement_id uuid NOT NULL,
    accrual_date date NOT NULL,
    days_accrued integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    fractional_days numeric(10,4) DEFAULT 0.0,
    cumulative_balance numeric(10,4) GENERATED ALWAYS AS (((days_accrued)::numeric + fractional_days)) STORED
);


ALTER TABLE leave.leave_accrual OWNER TO auth_user;

--
-- Name: leave_entitlement; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_entitlement (
    entitlement_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    leave_type_id uuid NOT NULL,
    policy_id uuid,
    source text DEFAULT 'policy'::text NOT NULL,
    total_days integer NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    position_id uuid,
    work_center_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE leave.leave_entitlement OWNER TO auth_user;

--
-- Name: leave_ledger; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_ledger (
    ledger_id uuid DEFAULT gen_random_uuid() NOT NULL,
    entitlement_id uuid NOT NULL,
    leave_request_id uuid,
    entry_type text NOT NULL,
    days integer NOT NULL,
    entry_date date NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT check_entry_type CHECK ((entry_type = ANY (ARRAY['accrual'::text, 'consumption'::text, 'reversal'::text])))
);


ALTER TABLE leave.leave_ledger OWNER TO auth_user;

--
-- Name: leave_balance_detailed_view; Type: VIEW; Schema: leave; Owner: auth_user
--

CREATE VIEW leave.leave_balance_detailed_view AS
 WITH accrual_totals AS (
         SELECT leave_accrual.entitlement_id,
            sum(leave_accrual.days_accrued) AS total_accrued,
            sum(leave_accrual.fractional_days) AS total_fractional
           FROM leave.leave_accrual
          GROUP BY leave_accrual.entitlement_id
        ), consumption_totals AS (
         SELECT leave_ledger.entitlement_id,
            sum(leave_ledger.days) AS total_consumed
           FROM leave.leave_ledger
          WHERE (leave_ledger.entry_type = 'consumption'::text)
          GROUP BY leave_ledger.entitlement_id
        ), current_entitlements AS (
         SELECT e.entitlement_id,
            e.company_id,
            e.user_id,
            e.leave_type_id,
            e.policy_id,
            e.source,
            e.total_days,
            e.effective_from,
            e.effective_to,
            e.position_id,
            e.work_center_code,
            e.created_at,
            e.updated_at,
            ((COALESCE(a.total_accrued, (0)::bigint))::numeric + COALESCE(a.total_fractional, (0)::numeric)) AS accrued_total,
            COALESCE(c.total_consumed, (0)::bigint) AS consumed_total
           FROM ((leave.leave_entitlement e
             LEFT JOIN accrual_totals a ON ((e.entitlement_id = a.entitlement_id)))
             LEFT JOIN consumption_totals c ON ((e.entitlement_id = c.entitlement_id)))
          WHERE ((e.effective_from <= CURRENT_DATE) AND ((e.effective_to IS NULL) OR (e.effective_to >= CURRENT_DATE)))
        )
 SELECT ce.entitlement_id,
    ce.company_id,
    ce.user_id,
    ce.leave_type_id,
    ce.policy_id,
    ce.source,
    ce.total_days,
    ce.effective_from,
    ce.effective_to,
    ce.position_id,
    ce.work_center_code,
    ce.created_at,
    ce.updated_at,
    ce.accrued_total,
    ce.consumed_total,
    (ce.accrued_total - (ce.consumed_total)::numeric) AS available_balance,
    GREATEST((0)::numeric, ((ce.total_days)::numeric - ce.accrued_total)) AS remaining_to_accrue
   FROM current_entitlements ce;


ALTER TABLE leave.leave_balance_detailed_view OWNER TO auth_user;

--
-- Name: leave_balance_snapshot; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_balance_snapshot (
    snapshot_id uuid DEFAULT gen_random_uuid() NOT NULL,
    entitlement_id uuid NOT NULL,
    balance_days integer NOT NULL,
    calculated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE leave.leave_balance_snapshot OWNER TO auth_user;

--
-- Name: leave_balance_view; Type: VIEW; Schema: leave; Owner: auth_user
--

CREATE VIEW leave.leave_balance_view AS
 SELECT le.user_id,
    le.leave_type_id,
    sum(
        CASE
            WHEN (ll.entry_type = 'accrual'::text) THEN ll.days
            ELSE 0
        END) AS balance
   FROM (leave.leave_ledger ll
     JOIN leave.leave_entitlement le ON ((ll.entitlement_id = le.entitlement_id)))
  GROUP BY le.user_id, le.leave_type_id;


ALTER TABLE leave.leave_balance_view OWNER TO auth_user;

--
-- Name: leave_policy; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_policy (
    policy_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    policy_name text NOT NULL,
    applies_to_type text NOT NULL,
    applies_to_id text,
    applies_to_position_id uuid,
    applies_to_work_center_code text,
    priority integer DEFAULT 100 NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_leave_policy_scope CHECK ((applies_to_type = ANY (ARRAY['position'::text, 'work_center'::text, 'org_unit'::text, 'company'::text])))
);


ALTER TABLE leave.leave_policy OWNER TO auth_user;

--
-- Name: leave_policy_resolution; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_policy_resolution (
    resolution_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    policy_id uuid,
    resolved_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text,
    metadata jsonb,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE leave.leave_policy_resolution OWNER TO auth_user;

--
-- Name: leave_policy_rule; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_policy_rule (
    policy_rule_id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_id uuid NOT NULL,
    leave_type_id uuid NOT NULL,
    total_days integer NOT NULL,
    accrual_method text NOT NULL,
    carry_forward_limit integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_lpr_accrual_method CHECK ((accrual_method = ANY (ARRAY['monthly'::text, 'quarterly'::text, 'yearly'::text, 'none'::text])))
);


ALTER TABLE leave.leave_policy_rule OWNER TO auth_user;

--
-- Name: leave_request; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_request (
    leave_request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    leave_type_id uuid NOT NULL,
    start_date date NOT NULL,
    end_date date NOT NULL,
    total_days integer NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    requested_by uuid,
    approved_by uuid,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_at timestamp with time zone,
    CONSTRAINT check_status CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'cancelled'::text])))
);


ALTER TABLE leave.leave_request OWNER TO auth_user;

--
-- Name: leave_type; Type: TABLE; Schema: leave; Owner: auth_user
--

CREATE TABLE leave.leave_type (
    leave_type_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    code text NOT NULL,
    name text NOT NULL,
    is_paid boolean DEFAULT true NOT NULL,
    requires_approval boolean DEFAULT true NOT NULL,
    accrual_method text NOT NULL,
    carry_forward_limit integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE leave.leave_type OWNER TO auth_user;

--
-- Name: arrears; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.arrears (
    arrears_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    payroll_run_id uuid,
    effective_from date NOT NULL,
    effective_to date NOT NULL,
    amount numeric(14,2) NOT NULL,
    reason text,
    processed boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    component_code character varying(50)
);


ALTER TABLE payroll.arrears OWNER TO auth_user;

--
-- Name: attendance_rule; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.attendance_rule (
    rule_id uuid NOT NULL,
    company_id uuid NOT NULL,
    rule_type character varying(50) NOT NULL,
    calculation_type character varying(50) NOT NULL,
    value numeric(10,4) NOT NULL,
    based_on character varying(50),
    threshold_minutes integer DEFAULT 0,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    created_by uuid,
    updated_at timestamp without time zone,
    updated_by uuid,
    component_code character varying(50)
);


ALTER TABLE payroll.attendance_rule OWNER TO auth_user;

--
-- Name: company_payroll_settings; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.company_payroll_settings (
    company_id uuid NOT NULL,
    default_fine_component character varying(50),
    default_arrears_component character varying(50),
    default_loan_component character varying(50),
    default_basic_component character varying(50),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE payroll.company_payroll_settings OWNER TO auth_user;

--
-- Name: company_statutory_config; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.company_statutory_config (
    company_statutory_config_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    effective_from date DEFAULT CURRENT_DATE NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    created_by uuid,
    version integer DEFAULT 1 NOT NULL
);


ALTER TABLE payroll.company_statutory_config OWNER TO auth_user;

--
-- Name: company_statutory_profile; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.company_statutory_profile (
    profile_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    country_code character varying(10) NOT NULL,
    financial_year_start_month integer DEFAULT 4 NOT NULL,
    supports_multiple_regimes boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE payroll.company_statutory_profile OWNER TO auth_user;

--
-- Name: company_tax_slab; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.company_tax_slab (
    slab_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    statutory_code character varying(50) NOT NULL,
    min_income numeric(14,2) NOT NULL,
    max_income numeric(14,2),
    tax_percentage numeric(5,2) NOT NULL,
    slab_order integer DEFAULT 1 NOT NULL,
    is_percentage boolean DEFAULT true NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    version integer DEFAULT 1 NOT NULL,
    rule_set_id uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid
);


ALTER TABLE payroll.company_tax_slab OWNER TO auth_user;

--
-- Name: emi_transaction; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.emi_transaction (
    emi_id uuid DEFAULT gen_random_uuid() NOT NULL,
    loan_id uuid NOT NULL,
    due_date date NOT NULL,
    paid_date date,
    amount numeric(14,2) NOT NULL,
    payroll_run_id uuid,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    penalty_amount numeric(10,2) DEFAULT 0,
    paid_amount numeric(10,2),
    remaining_amount numeric(10,2),
    payment_status character varying(20) DEFAULT 'pending'::character varying
);


ALTER TABLE payroll.emi_transaction OWNER TO auth_user;

--
-- Name: employee_bank_details; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.employee_bank_details (
    bank_detail_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    account_holder character varying(255) NOT NULL,
    account_number text NOT NULL,
    ifsc_code character varying(20) NOT NULL,
    bank_name character varying(255),
    branch character varying(255),
    account_type character varying(20),
    is_active boolean DEFAULT true NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE payroll.employee_bank_details OWNER TO auth_user;

--
-- Name: employee_fine; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.employee_fine (
    fine_id uuid NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    fine_amount numeric(12,2) NOT NULL,
    reason text NOT NULL,
    fine_date date NOT NULL,
    is_processed boolean DEFAULT false NOT NULL,
    payroll_run_id uuid,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    component_code character varying(50)
);


ALTER TABLE payroll.employee_fine OWNER TO auth_user;

--
-- Name: employee_loan; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.employee_loan (
    loan_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    loan_type character varying(20) NOT NULL,
    principal_amount numeric(14,2) NOT NULL,
    emi_amount numeric(14,2) NOT NULL,
    interest_rate numeric(5,2),
    total_emis integer NOT NULL,
    emis_paid integer DEFAULT 0 NOT NULL,
    disbursed_at date NOT NULL,
    first_emi_date date NOT NULL,
    closure_date date,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    component_code character varying(50),
    interest_type character varying(20) DEFAULT 'flat'::character varying,
    tenure_months integer,
    outstanding_balance numeric(14,2),
    penalty_rate numeric(5,2) DEFAULT 0,
    allow_partial_payment boolean DEFAULT true
);


ALTER TABLE payroll.employee_loan OWNER TO auth_user;

--
-- Name: employee_salary; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.employee_salary (
    employee_salary_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    salary_structure_id uuid NOT NULL,
    monthly_ctc numeric(14,2) NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    version integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    pay_type character varying(20) DEFAULT 'monthly'::character varying NOT NULL,
    CONSTRAINT employee_salary_pay_type_check CHECK (((pay_type)::text = ANY ((ARRAY['monthly'::character varying, 'daily_wage'::character varying, 'hourly'::character varying])::text[])))
);


ALTER TABLE payroll.employee_salary OWNER TO auth_user;

--
-- Name: employee_statutory_contribution; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.employee_statutory_contribution (
    contribution_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    statutory_code character varying(50) NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    employee_amount numeric(12,2) NOT NULL,
    employer_amount numeric(12,2) NOT NULL,
    total_amount numeric(12,2) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE payroll.employee_statutory_contribution OWNER TO auth_user;

--
-- Name: employee_statutory_profile; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.employee_statutory_profile (
    profile_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    statutory_code character varying(50) NOT NULL,
    opt_in boolean DEFAULT true NOT NULL,
    special_category character varying(50),
    regime character varying(20),
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    version integer DEFAULT 1 NOT NULL,
    rule_set_id uuid
);


ALTER TABLE payroll.employee_statutory_profile OWNER TO auth_user;

--
-- Name: loan_payment; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.loan_payment (
    payment_id uuid DEFAULT gen_random_uuid() NOT NULL,
    loan_id uuid NOT NULL,
    emi_id uuid,
    amount numeric(14,2) NOT NULL,
    penalty numeric(14,2) DEFAULT 0,
    paid_at timestamp with time zone NOT NULL,
    source character varying(20) NOT NULL,
    payroll_run_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT loan_payment_amount_check CHECK ((amount > (0)::numeric)),
    CONSTRAINT loan_payment_penalty_check CHECK ((penalty >= (0)::numeric)),
    CONSTRAINT loan_payment_source_check CHECK (((source)::text = ANY ((ARRAY['payroll'::character varying, 'manual'::character varying, 'adjustment'::character varying])::text[])))
);


ALTER TABLE payroll.loan_payment OWNER TO auth_user;

--
-- Name: payroll_adjustment; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_adjustment (
    adjustment_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    component_code character varying(50) NOT NULL,
    amount numeric(12,2) NOT NULL,
    adjustment_type character varying(20),
    reason text,
    applicable_month date NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    CONSTRAINT payroll_adjustment_adjustment_type_check CHECK (((adjustment_type)::text = ANY ((ARRAY['addition'::character varying, 'deduction'::character varying])::text[])))
);


ALTER TABLE payroll.payroll_adjustment OWNER TO auth_user;

--
-- Name: payroll_component; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_component (
    component_code character varying(50) NOT NULL,
    component_type character varying(40) NOT NULL,
    description text,
    is_taxable boolean DEFAULT false NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    contribution_side character varying(20) DEFAULT 'none'::character varying,
    company_id uuid NOT NULL,
    CONSTRAINT payroll_component_component_type_check CHECK (((component_type)::text = ANY (ARRAY[('earning'::character varying)::text, ('deduction'::character varying)::text]))),
    CONSTRAINT payroll_component_contribution_side_check CHECK (((contribution_side)::text = ANY ((ARRAY['employee'::character varying, 'employer'::character varying, 'none'::character varying])::text[])))
);


ALTER TABLE payroll.payroll_component OWNER TO auth_user;

--
-- Name: payroll_item; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_item (
    payroll_item_id uuid DEFAULT gen_random_uuid() NOT NULL,
    payroll_run_id uuid NOT NULL,
    user_id uuid NOT NULL,
    payable_days numeric(5,2) NOT NULL,
    unpaid_days numeric(5,2) NOT NULL,
    gross_amount numeric(12,2) NOT NULL,
    net_amount numeric(12,2) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by uuid,
    version_number integer DEFAULT 1 NOT NULL,
    is_superseded boolean DEFAULT false NOT NULL,
    superseded_at timestamp without time zone,
    superseded_by uuid
);


ALTER TABLE payroll.payroll_item OWNER TO auth_user;

--
-- Name: payroll_job; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_job (
    job_id uuid NOT NULL,
    company_id uuid NOT NULL,
    payroll_run_id uuid NOT NULL,
    status text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 3 NOT NULL,
    priority integer DEFAULT 5,
    retry_count integer DEFAULT 0,
    max_retries integer DEFAULT 3,
    error_message text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    next_run_at timestamp with time zone DEFAULT now(),
    locked_by text,
    locked_at timestamp without time zone
);


ALTER TABLE payroll.payroll_job OWNER TO auth_user;

--
-- Name: payroll_ledger; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_ledger (
    ledger_id uuid DEFAULT gen_random_uuid() NOT NULL,
    payroll_item_id uuid NOT NULL,
    component_code character varying(50) NOT NULL,
    amount numeric(12,2) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE payroll.payroll_ledger OWNER TO auth_user;

--
-- Name: payroll_period_lock; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_period_lock (
    lock_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    locked_by uuid,
    locked_at timestamp with time zone DEFAULT now(),
    reason text
);


ALTER TABLE payroll.payroll_period_lock OWNER TO auth_user;

--
-- Name: payroll_run; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_run (
    payroll_run_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    status character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    total_employees integer,
    processed_count integer DEFAULT 0,
    failed_count integer DEFAULT 0,
    last_processed_at timestamp with time zone,
    CONSTRAINT payroll_run_status_check CHECK (((status)::text = ANY ((ARRAY['draft'::character varying, 'processing'::character varying, 'calculated'::character varying, 'approved'::character varying, 'paid'::character varying, 'failed'::character varying, 'partially_processed'::character varying])::text[])))
);


ALTER TABLE payroll.payroll_run OWNER TO auth_user;

--
-- Name: payroll_snapshot; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_snapshot (
    snapshot_id uuid DEFAULT gen_random_uuid() NOT NULL,
    payroll_run_id uuid NOT NULL,
    company_id uuid NOT NULL,
    snapshot_type character varying(30) NOT NULL,
    snapshot_data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    rule_set_id uuid,
    rule_hash text,
    CONSTRAINT payroll_snapshot_snapshot_type_check CHECK (((snapshot_type)::text = ANY ((ARRAY['run'::character varying, 'item'::character varying, 'salary'::character varying, 'tax'::character varying, 'statutory'::character varying, 'employee_full_snapshot'::character varying])::text[])))
);


ALTER TABLE payroll.payroll_snapshot OWNER TO auth_user;

--
-- Name: payroll_tax_profile; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_tax_profile (
    profile_name character varying(100) NOT NULL,
    country_code character varying(10) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE payroll.payroll_tax_profile OWNER TO auth_user;

--
-- Name: payroll_tax_rule; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payroll_tax_rule (
    tax_rule_id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_code character varying(50) NOT NULL,
    calculation_type character varying(20) NOT NULL,
    rule_definition jsonb,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE payroll.payroll_tax_rule OWNER TO auth_user;

--
-- Name: payslip; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payslip (
    payslip_id uuid DEFAULT gen_random_uuid() NOT NULL,
    payroll_run_id uuid NOT NULL,
    user_id uuid NOT NULL,
    pdf_object_key text NOT NULL,
    generated_at timestamp with time zone DEFAULT now(),
    sent_at timestamp with time zone
);


ALTER TABLE payroll.payslip OWNER TO auth_user;

--
-- Name: payslip_template; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.payslip_template (
    template_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    template_name character varying(150),
    footer_declaration text,
    authorized_signatory character varying(150),
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE payroll.payslip_template OWNER TO auth_user;

--
-- Name: salary_structure; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.salary_structure (
    salary_structure_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    structure_name character varying(150) NOT NULL,
    currency_code character varying(10) DEFAULT 'INR'::character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    created_by uuid,
    version integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid
);


ALTER TABLE payroll.salary_structure OWNER TO auth_user;

--
-- Name: salary_structure_component; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.salary_structure_component (
    mapping_id uuid DEFAULT gen_random_uuid() NOT NULL,
    salary_structure_id uuid NOT NULL,
    component_code character varying(50) NOT NULL,
    calculation_type character varying(20) NOT NULL,
    value numeric(12,4) NOT NULL,
    based_on_component character varying(50),
    sequence_order integer DEFAULT 1,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT salary_structure_component_calculation_type_check CHECK (((calculation_type)::text = ANY ((ARRAY['fixed'::character varying, 'percentage'::character varying])::text[])))
);


ALTER TABLE payroll.salary_structure_component OWNER TO auth_user;

--
-- Name: statutory_component_definition; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.statutory_component_definition (
    company_id uuid NOT NULL,
    statutory_code character varying(50) NOT NULL,
    description text,
    country_code character varying(10) NOT NULL,
    calculation_basis character varying(30) NOT NULL,
    has_employee_contribution boolean DEFAULT true NOT NULL,
    has_employer_contribution boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    CONSTRAINT statutory_component_definition_calculation_basis_check CHECK (((calculation_basis)::text = ANY ((ARRAY['basic'::character varying, 'gross'::character varying, 'ctc'::character varying, 'taxable_income'::character varying])::text[])))
);


ALTER TABLE payroll.statutory_component_definition OWNER TO auth_user;

--
-- Name: statutory_component_mapping; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.statutory_component_mapping (
    mapping_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    statutory_code character varying(50) NOT NULL,
    component_code character varying(50) NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    version integer DEFAULT 1 NOT NULL,
    rule_set_id uuid
);


ALTER TABLE payroll.statutory_component_mapping OWNER TO auth_user;

--
-- Name: statutory_contribution_rule; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.statutory_contribution_rule (
    rule_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    rule_set_id uuid NOT NULL,
    statutory_code character varying(50) NOT NULL,
    contribution_side character varying(20) NOT NULL,
    calculation_type character varying(20) NOT NULL,
    rate_value numeric(10,4),
    wage_ceiling numeric(14,2),
    min_threshold numeric(14,2),
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid,
    CONSTRAINT statutory_contribution_rule_calculation_type_check CHECK (((calculation_type)::text = ANY ((ARRAY['percentage'::character varying, 'fixed'::character varying, 'slab'::character varying])::text[]))),
    CONSTRAINT statutory_contribution_rule_contribution_side_check CHECK (((contribution_side)::text = ANY ((ARRAY['employee'::character varying, 'employer'::character varying])::text[])))
);


ALTER TABLE payroll.statutory_contribution_rule OWNER TO auth_user;

--
-- Name: statutory_deduction_limit; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.statutory_deduction_limit (
    limit_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    rule_set_id uuid NOT NULL,
    limit_code character varying(50) NOT NULL,
    limit_value numeric(14,2) NOT NULL,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE payroll.statutory_deduction_limit OWNER TO auth_user;

--
-- Name: statutory_rule_set; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.statutory_rule_set (
    rule_set_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    country_code character varying(10) NOT NULL,
    version_label character varying(50) NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    deactivated_at timestamp with time zone,
    deactivated_by uuid
);


ALTER TABLE payroll.statutory_rule_set OWNER TO auth_user;

--
-- Name: tax_declaration; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.tax_declaration (
    declaration_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    financial_year character varying(9) NOT NULL,
    declaration_type character varying(50) NOT NULL,
    amount numeric(14,2) NOT NULL,
    supporting_docs text[],
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    verified_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE payroll.tax_declaration OWNER TO auth_user;

--
-- Name: tax_declaration_type; Type: TABLE; Schema: payroll; Owner: auth_user
--

CREATE TABLE payroll.tax_declaration_type (
    company_id uuid NOT NULL,
    type_code character varying(50) NOT NULL,
    description text,
    max_limit numeric(14,2),
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE payroll.tax_declaration_type OWNER TO auth_user;

--
-- Name: admin_avatars; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.admin_avatars (
    avatar_id uuid DEFAULT gen_random_uuid() NOT NULL,
    admin_id uuid NOT NULL,
    avatar_type character varying(20) DEFAULT 'uploaded'::character varying NOT NULL,
    avatar_hash character varying(128),
    avatar_object_key text NOT NULL,
    avatar_mime_type character varying(50),
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.admin_avatars OWNER TO auth_user;

--
-- Name: admin_role_departments; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.admin_role_departments (
    admin_role_id uuid NOT NULL,
    system_department_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.admin_role_departments OWNER TO auth_user;

--
-- Name: admin_role_permissions; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.admin_role_permissions (
    admin_role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_by uuid NOT NULL
);


ALTER TABLE public.admin_role_permissions OWNER TO auth_user;

--
-- Name: admin_roles; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.admin_roles (
    admin_role_id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_name character varying(100) NOT NULL,
    role_level integer DEFAULT 1000 NOT NULL,
    role_type integer DEFAULT 1 NOT NULL,
    is_system_role boolean DEFAULT false NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT check_role_type CHECK ((role_type = ANY (ARRAY[1, 2, 4])))
);


ALTER TABLE public.admin_roles OWNER TO auth_user;

--
-- Name: admin_users; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.admin_users (
    admin_id uuid DEFAULT gen_random_uuid() NOT NULL,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_key_id uuid NOT NULL,
    phone_encrypted_dek text NOT NULL,
    admin_role_id uuid NOT NULL,
    role_type integer DEFAULT 1 NOT NULL,
    reports_to uuid,
    admin_created_at timestamp with time zone DEFAULT now() NOT NULL,
    admin_created_by uuid,
    admin_updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_access_scope text[],
    ip_whitelist text[],
    failed_login_attempts integer DEFAULT 0,
    last_login timestamp with time zone,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    CONSTRAINT check_admin_role_type CHECK ((role_type = ANY (ARRAY[1, 2, 4])))
);


ALTER TABLE public.admin_users OWNER TO auth_user;

--
-- Name: attendance_daily_summary; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_daily_summary (
    attendance_summary_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    attendance_date date NOT NULL,
    status character varying(30) NOT NULL,
    worked_minutes integer,
    overtime_minutes integer,
    late_minutes integer,
    metadata jsonb,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    generated_by character varying(30) DEFAULT 'system'::character varying,
    is_payroll_locked boolean DEFAULT false NOT NULL,
    is_finalized boolean DEFAULT false NOT NULL,
    is_payable boolean DEFAULT false NOT NULL,
    expected_minutes integer
);


ALTER TABLE public.attendance_daily_summary OWNER TO auth_user;

--
-- Name: attendance_device_heartbeats; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_device_heartbeats (
    heartbeat_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    device_id character varying(256) NOT NULL,
    source_type character varying(30) NOT NULL,
    device_time timestamp with time zone,
    server_time timestamp with time zone DEFAULT now() NOT NULL,
    firmware_version text,
    ip_address inet,
    status character varying(20) DEFAULT 'online'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_device_heartbeats OWNER TO auth_user;

--
-- Name: attendance_device_punch_batches; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_device_punch_batches (
    batch_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    device_id character varying(256) NOT NULL,
    batch_ref text NOT NULL,
    total_events integer NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    failure_reason text
);


ALTER TABLE public.attendance_device_punch_batches OWNER TO auth_user;

--
-- Name: attendance_device_punch_failures; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_device_punch_failures (
    failure_id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    company_id uuid NOT NULL,
    device_id character varying(256) NOT NULL,
    device_user_code character varying(100),
    event_type character varying(30),
    event_time timestamp with time zone,
    failure_reason text NOT NULL,
    raw_event jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_device_punch_failures OWNER TO auth_user;

--
-- Name: attendance_device_tokens; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_device_tokens (
    token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    device_id character varying(64) NOT NULL,
    source_type character varying(32) NOT NULL,
    token_hash text NOT NULL,
    token_version integer DEFAULT 1 NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    issued_by uuid,
    revoked_by uuid,
    revoke_reason text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_device_tokens OWNER TO auth_user;

--
-- Name: attendance_device_trust_history; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_device_trust_history (
    trust_id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_id character varying(256) NOT NULL,
    company_id uuid NOT NULL,
    action character varying(20) NOT NULL,
    reason text,
    acted_by uuid,
    acted_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_device_trust_history OWNER TO auth_user;

--
-- Name: attendance_devices; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_devices (
    device_id character varying(256) NOT NULL,
    company_id uuid NOT NULL,
    source_type character varying(30) NOT NULL,
    device_code character varying(100) NOT NULL,
    device_name character varying(100),
    manufacturer character varying(100),
    model character varying(100),
    work_center_code character varying(100),
    location_id uuid,
    ip_address inet,
    mac_address character varying(50),
    is_active boolean DEFAULT true NOT NULL,
    is_trusted boolean DEFAULT true NOT NULL,
    last_seen_at timestamp with time zone,
    installed_at timestamp with time zone,
    last_punch_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_devices OWNER TO auth_user;

--
-- Name: attendance_event_types; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_event_types (
    event_type character varying(30) NOT NULL,
    category character varying(30) NOT NULL,
    description text,
    is_user_triggered boolean DEFAULT true NOT NULL,
    is_system_generated boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


ALTER TABLE public.attendance_event_types OWNER TO auth_user;

--
-- Name: attendance_events; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_events (
    attendance_event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    event_type character varying(30) NOT NULL,
    event_time timestamp with time zone NOT NULL,
    source_type character varying(30) NOT NULL,
    source_id uuid,
    device_id character varying(256),
    ip_address character varying(64),
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    event_date date GENERATED ALWAYS AS (((event_time AT TIME ZONE 'UTC'::text))::date) STORED,
    context jsonb,
    device_user_code character varying(100),
    raw_event_payload jsonb
);


ALTER TABLE public.attendance_events OWNER TO auth_user;

--
-- Name: attendance_locations; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_locations (
    location_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    name character varying(100),
    location_type character varying(30),
    geo_lat numeric,
    geo_lng numeric,
    location_code character varying(50),
    zone character varying(100),
    is_active boolean DEFAULT true
);


ALTER TABLE public.attendance_locations OWNER TO auth_user;

--
-- Name: attendance_policies; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_policies (
    policy_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    work_center_code text,
    position_id uuid,
    policy_code character varying(50) NOT NULL,
    policy_type character varying(30) NOT NULL,
    rules jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_policies OWNER TO auth_user;

--
-- Name: attendance_source_types; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_source_types (
    source_type character varying(30) NOT NULL,
    description text NOT NULL,
    category character varying(30) NOT NULL,
    requires_device boolean DEFAULT false NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    allow_backdated boolean DEFAULT false NOT NULL,
    allow_future boolean DEFAULT false NOT NULL,
    trust_level smallint DEFAULT 1 NOT NULL,
    is_self_service boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attendance_source_types OWNER TO auth_user;

--
-- Name: attendance_sources; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_sources (
    source_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    source_type character varying(30) NOT NULL,
    name character varying(100) NOT NULL,
    reference_type character varying(30),
    reference_id uuid,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid
);


ALTER TABLE public.attendance_sources OWNER TO auth_user;

--
-- Name: attendance_user_device_identifiers; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.attendance_user_device_identifiers (
    mapping_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id character varying(256) NOT NULL,
    source_type character varying(30) NOT NULL,
    device_user_code character varying(100) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    enrolled_at timestamp with time zone DEFAULT now() NOT NULL,
    unenrolled_at timestamp with time zone,
    created_by uuid,
    enrollment_version integer DEFAULT 1 NOT NULL,
    revoked_reason text,
    revoked_by uuid,
    CONSTRAINT chk_created_by_not_zero CHECK (((created_by IS NULL) OR (created_by <> '00000000-0000-0000-0000-000000000000'::uuid)))
);


ALTER TABLE public.attendance_user_device_identifiers OWNER TO auth_user;

--
-- Name: companies; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.companies (
    company_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_name character varying(255) NOT NULL,
    company_name_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, (company_name)::text)) STORED,
    owner_user_id uuid NOT NULL,
    subscription_tier character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    subscription_status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    max_employees integer DEFAULT 10 NOT NULL,
    max_departments integer DEFAULT 5 NOT NULL,
    data_region character varying(10) DEFAULT 'us'::character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    subscription_start_date timestamp with time zone,
    subscription_end_date timestamp with time zone,
    financial_year_start_month integer DEFAULT 4 NOT NULL,
    CONSTRAINT check_max_departments CHECK (((max_departments > 0) AND (max_departments <= 1000))),
    CONSTRAINT companies_financial_year_start_month_check CHECK (((financial_year_start_month >= 1) AND (financial_year_start_month <= 12)))
);


ALTER TABLE public.companies OWNER TO auth_user;

--
-- Name: company_attendance_rules; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.company_attendance_rules (
    company_id uuid NOT NULL,
    allowed_source_types character varying(30)[] NOT NULL,
    allow_multiple_checkins boolean DEFAULT false NOT NULL,
    timezone character varying(50) DEFAULT 'UTC'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.company_attendance_rules OWNER TO auth_user;

--
-- Name: company_employees; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.company_employees (
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    employee_id character varying(100) NOT NULL,
    role_id uuid NOT NULL,
    hire_date timestamp with time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    reports_to uuid,
    position_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.company_employees OWNER TO auth_user;

--
-- Name: department_attendance_rules; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.department_attendance_rules (
    rule_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    department_id uuid NOT NULL,
    allowed_source_types character varying(30)[] NOT NULL,
    allowed_event_types character varying(30)[] NOT NULL,
    require_location boolean DEFAULT false NOT NULL,
    require_device boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.department_attendance_rules OWNER TO auth_user;

--
-- Name: departments; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.departments (
    department_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    department_name character varying(255) NOT NULL,
    system_department_id uuid,
    parent_department_id uuid,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.departments OWNER TO auth_user;

--
-- Name: employee_department_history; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.employee_department_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    company_id uuid NOT NULL,
    department_id uuid NOT NULL,
    start_date date NOT NULL,
    end_date date,
    change_reason text,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.employee_department_history OWNER TO auth_user;

--
-- Name: employee_documents; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.employee_documents (
    document_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    company_id uuid NOT NULL,
    document_type character varying(50),
    document_name character varying(255),
    document_object_key text NOT NULL,
    mime_type character varying(50),
    is_confidential boolean DEFAULT false,
    uploaded_by uuid,
    uploaded_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.employee_documents OWNER TO auth_user;

--
-- Name: employee_exit; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.employee_exit (
    exit_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    company_id uuid NOT NULL,
    exit_date date NOT NULL,
    exit_reason text,
    eligible_for_rehire boolean DEFAULT false,
    exit_state character varying(20) DEFAULT 'scheduled'::character varying NOT NULL,
    enforced_at timestamp with time zone,
    enforced_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT chk_exit_state CHECK (((exit_state)::text = ANY ((ARRAY['scheduled'::character varying, 'effective'::character varying, 'cancelled'::character varying, 'rehired'::character varying])::text[])))
);


ALTER TABLE public.employee_exit OWNER TO auth_user;

--
-- Name: employee_profiles; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.employee_profiles (
    employee_profile_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    company_id uuid NOT NULL,
    date_of_birth date,
    gender character varying(20),
    marital_status character varying(20),
    nationality character varying(50),
    employment_type character varying(30),
    employment_status character varying(30) DEFAULT 'active'::character varying NOT NULL,
    probation_end_date date,
    confirmation_date date,
    job_title character varying(255),
    grade character varying(50),
    cost_center character varying(50),
    tax_id character varying(50),
    social_security_id character varying(50),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT chk_employment_status CHECK (((employment_status)::text = ANY ((ARRAY['active'::character varying, 'notice'::character varying, 'terminated'::character varying, 'on_hold'::character varying])::text[])))
);


ALTER TABLE public.employee_profiles OWNER TO auth_user;

--
-- Name: employee_role_history; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.employee_role_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    start_date date,
    end_date date,
    reason text
);


ALTER TABLE public.employee_role_history OWNER TO auth_user;

--
-- Name: login_attempts; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.login_attempts (
    attempt_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    success boolean NOT NULL,
    ip_address character varying(64),
    user_agent text,
    device_id character varying(256),
    attempted_at timestamp with time zone DEFAULT now() NOT NULL,
    failure_reason text
);


ALTER TABLE public.login_attempts OWNER TO auth_user;

--
-- Name: off_requests; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.off_requests (
    off_request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    request_dates date[] NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying,
    requested_by uuid,
    approved_by uuid,
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.off_requests OWNER TO auth_user;

--
-- Name: org_unit_members; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.org_unit_members (
    org_unit_id uuid NOT NULL,
    user_id uuid NOT NULL,
    effective_from date NOT NULL,
    effective_to date
);


ALTER TABLE public.org_unit_members OWNER TO auth_user;

--
-- Name: org_unit_roles; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.org_unit_roles (
    org_unit_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role character varying(30) NOT NULL,
    position_id uuid,
    effective_from date NOT NULL,
    effective_to date
);


ALTER TABLE public.org_unit_roles OWNER TO auth_user;

--
-- Name: org_units; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.org_units (
    org_unit_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    org_unit_type character varying(30) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    department_id uuid,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.org_units OWNER TO auth_user;

--
-- Name: permissions; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.permissions (
    permission_id uuid DEFAULT gen_random_uuid() NOT NULL,
    permission_name character varying(100) NOT NULL,
    description text,
    category character varying(50) NOT NULL,
    module character varying(50) NOT NULL,
    scope character varying(20) DEFAULT 'user'::character varying NOT NULL,
    requires_tier character varying(20) DEFAULT 'basic'::character varying,
    bit_index integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.permissions OWNER TO auth_user;

--
-- Name: positions; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.positions (
    position_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    department_id uuid NOT NULL,
    title character varying(255),
    is_open boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    is_schedulable boolean DEFAULT true NOT NULL,
    attendance_required boolean DEFAULT true NOT NULL,
    overtime_allowed boolean DEFAULT false NOT NULL,
    work_center_code character varying(100)
);


ALTER TABLE public.positions OWNER TO auth_user;

--
-- Name: role_departments; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.role_departments (
    role_id uuid NOT NULL,
    department_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.role_departments OWNER TO auth_user;

--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.role_permissions (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_by uuid NOT NULL
);


ALTER TABLE public.role_permissions OWNER TO auth_user;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.roles (
    role_id uuid DEFAULT gen_random_uuid() NOT NULL,
    role_name character varying(100) NOT NULL,
    role_level integer DEFAULT 1000 NOT NULL,
    company_id uuid NOT NULL,
    is_system_role boolean DEFAULT false NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.roles OWNER TO auth_user;

--
-- Name: schedule_instances; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.schedule_instances (
    schedule_instance_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    schedule_date date NOT NULL,
    schedule_template_id uuid NOT NULL,
    expected_start timestamp with time zone,
    expected_end timestamp with time zone,
    timezone character varying(50) DEFAULT 'UTC'::character varying NOT NULL,
    metadata jsonb,
    generated_at timestamp with time zone DEFAULT now(),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    cancel_reason character varying(50),
    cancelled_at timestamp with time zone,
    work_center_code character varying(100),
    device_user_code character varying(100),
    raw_event_payload jsonb
);


ALTER TABLE public.schedule_instances OWNER TO auth_user;

--
-- Name: schedule_overrides; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.schedule_overrides (
    override_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    override_date date NOT NULL,
    override_type character varying(20) NOT NULL,
    reason text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT chk_override_type CHECK (((override_type)::text = ANY ((ARRAY['off'::character varying, 'force_work'::character varying, 'holiday_override'::character varying])::text[])))
);


ALTER TABLE public.schedule_overrides OWNER TO auth_user;

--
-- Name: schedule_templates; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.schedule_templates (
    schedule_template_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    calendar_id uuid NOT NULL,
    template_type character varying(30) NOT NULL,
    name character varying(100) NOT NULL,
    rules jsonb NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT chk_template_type CHECK (((template_type)::text = ANY ((ARRAY['office'::character varying, 'shift'::character varying, 'class'::character varying])::text[])))
);


ALTER TABLE public.schedule_templates OWNER TO auth_user;

--
-- Name: system_departments; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.system_departments (
    system_department_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    module_code character varying(100) NOT NULL,
    description text,
    bitmask bigint NOT NULL
);


ALTER TABLE public.system_departments OWNER TO auth_user;

--
-- Name: user_attendance_policies; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_attendance_policies (
    user_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    assigned_by uuid,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.user_attendance_policies OWNER TO auth_user;

--
-- Name: user_attendance_profiles; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_attendance_profiles (
    user_id uuid NOT NULL,
    company_id uuid NOT NULL,
    override_source_types character varying(30)[],
    override_event_types character varying(30)[],
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.user_attendance_profiles OWNER TO auth_user;

--
-- Name: user_avatars; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_avatars (
    avatar_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    avatar_type character varying(20) DEFAULT 'uploaded'::character varying NOT NULL,
    avatar_hash character varying(128),
    avatar_object_key text NOT NULL,
    avatar_mime_type character varying(50),
    is_active boolean DEFAULT true NOT NULL,
    is_primary boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_avatars OWNER TO auth_user;

--
-- Name: user_devices; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_devices (
    device_id character varying(256) NOT NULL,
    user_id uuid NOT NULL,
    device_type character varying(50),
    device_name character varying(100),
    os_version character varying(50),
    app_version character varying(50),
    last_active timestamp with time zone DEFAULT now() NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_devices OWNER TO auth_user;

--
-- Name: user_off_entitlements; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_off_entitlements (
    entitlement_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    period_type character varying(20) NOT NULL,
    off_count integer NOT NULL,
    requires_approval boolean DEFAULT true,
    effective_from date NOT NULL,
    effective_to date,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT chk_period_type CHECK (((period_type)::text = ANY ((ARRAY['weekly'::character varying, 'monthly'::character varying])::text[])))
);


ALTER TABLE public.user_off_entitlements OWNER TO auth_user;

--
-- Name: user_schedule_assignments; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_schedule_assignments (
    user_id uuid NOT NULL,
    schedule_template_id uuid NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    assigned_by uuid,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.user_schedule_assignments OWNER TO auth_user;

--
-- Name: user_work_center_assignments; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.user_work_center_assignments (
    assignment_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    user_id uuid NOT NULL,
    work_center_code character varying(100) NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.user_work_center_assignments OWNER TO auth_user;

--
-- Name: users; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
)
PARTITION BY HASH (user_id);


ALTER TABLE public.users OWNER TO auth_user;

--
-- Name: users_p0; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p0 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p0 OWNER TO auth_user;

--
-- Name: users_p1; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p1 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p1 OWNER TO auth_user;

--
-- Name: users_p2; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p2 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p2 OWNER TO auth_user;

--
-- Name: users_p3; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p3 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p3 OWNER TO auth_user;

--
-- Name: users_p4; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p4 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p4 OWNER TO auth_user;

--
-- Name: users_p5; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p5 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p5 OWNER TO auth_user;

--
-- Name: users_p6; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p6 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p6 OWNER TO auth_user;

--
-- Name: users_p7; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.users_p7 (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    username character varying(100) NOT NULL,
    full_name character varying(255),
    user_search_tsv tsvector GENERATED ALWAYS AS ((to_tsvector('simple'::regconfig, (COALESCE(username, ''::character varying))::text) || to_tsvector('simple'::regconfig, (COALESCE(full_name, ''::character varying))::text))) STORED,
    phone_hash character varying(128) NOT NULL,
    phone_encrypted bytea NOT NULL,
    phone_encrypted_dek text NOT NULL,
    phone_key_id uuid NOT NULL,
    device_id character varying(256),
    device_fingerprint character varying(512),
    kyc_status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    kyc_level character varying(20) DEFAULT 'basic'::character varying NOT NULL,
    kyc_verified_at timestamp with time zone,
    is_verified boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    data_region character varying(20) DEFAULT 'us'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login timestamp with time zone
);


ALTER TABLE public.users_p7 OWNER TO auth_user;

--
-- Name: work_calendars; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.work_calendars (
    calendar_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    year integer NOT NULL,
    name character varying(100) NOT NULL,
    timezone character varying(50) DEFAULT 'UTC'::character varying NOT NULL,
    working_days integer[] NOT NULL,
    holidays jsonb,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.work_calendars OWNER TO auth_user;

--
-- Name: work_center_shifts; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.work_center_shifts (
    mapping_id uuid DEFAULT gen_random_uuid() NOT NULL,
    company_id uuid NOT NULL,
    work_center_code character varying(100) NOT NULL,
    shift_id uuid NOT NULL,
    effective_from date NOT NULL,
    effective_to date,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.work_center_shifts OWNER TO auth_user;

--
-- Name: work_centers; Type: TABLE; Schema: public; Owner: auth_user
--

CREATE TABLE public.work_centers (
    work_center_code character varying(100) NOT NULL,
    company_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    timezone character varying(50) DEFAULT 'UTC'::character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.work_centers OWNER TO auth_user;

--
-- Name: users_p0; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p0 FOR VALUES WITH (modulus 8, remainder 0);


--
-- Name: users_p1; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p1 FOR VALUES WITH (modulus 8, remainder 1);


--
-- Name: users_p2; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p2 FOR VALUES WITH (modulus 8, remainder 2);


--
-- Name: users_p3; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p3 FOR VALUES WITH (modulus 8, remainder 3);


--
-- Name: users_p4; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p4 FOR VALUES WITH (modulus 8, remainder 4);


--
-- Name: users_p5; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p5 FOR VALUES WITH (modulus 8, remainder 5);


--
-- Name: users_p6; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p6 FOR VALUES WITH (modulus 8, remainder 6);


--
-- Name: users_p7; Type: TABLE ATTACH; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users ATTACH PARTITION public.users_p7 FOR VALUES WITH (modulus 8, remainder 7);


--
-- Name: attendance_batch_outbox attendance_batch_outbox_pkey; Type: CONSTRAINT; Schema: attendance; Owner: auth_user
--

ALTER TABLE ONLY attendance.attendance_batch_outbox
    ADD CONSTRAINT attendance_batch_outbox_pkey PRIMARY KEY (outbox_id);


--
-- Name: attendance_events_outbox attendance_events_outbox_pkey; Type: CONSTRAINT; Schema: attendance; Owner: auth_user
--

ALTER TABLE ONLY attendance.attendance_events_outbox
    ADD CONSTRAINT attendance_events_outbox_pkey PRIMARY KEY (outbox_id);


--
-- Name: audit_logs_outbox audit_logs_outbox_pkey; Type: CONSTRAINT; Schema: audit; Owner: auth_user
--

ALTER TABLE ONLY audit.audit_logs_outbox
    ADD CONSTRAINT audit_logs_outbox_pkey PRIMARY KEY (outbox_id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: audit; Owner: auth_user
--

ALTER TABLE ONLY audit.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (audit_id);


--
-- Name: outbox_debounce outbox_debounce_pkey; Type: CONSTRAINT; Schema: audit; Owner: auth_user
--

ALTER TABLE ONLY audit.outbox_debounce
    ADD CONSTRAINT outbox_debounce_pkey PRIMARY KEY (debounce_id);


--
-- Name: device_embedding_sync device_embedding_sync_pkey; Type: CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.device_embedding_sync
    ADD CONSTRAINT device_embedding_sync_pkey PRIMARY KEY (sync_id);


--
-- Name: embedding_audit_log embedding_audit_log_pkey; Type: CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.embedding_audit_log
    ADD CONSTRAINT embedding_audit_log_pkey PRIMARY KEY (audit_id);


--
-- Name: face_embeddings face_embeddings_pkey; Type: CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.face_embeddings
    ADD CONSTRAINT face_embeddings_pkey PRIMARY KEY (embedding_id);


--
-- Name: device_embedding_sync unique_company_device; Type: CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.device_embedding_sync
    ADD CONSTRAINT unique_company_device UNIQUE (company_id, device_id);


--
-- Name: face_embeddings unique_company_user; Type: CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.face_embeddings
    ADD CONSTRAINT unique_company_user UNIQUE (company_id, user_id);


--
-- Name: leave_accrual leave_accrual_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_accrual
    ADD CONSTRAINT leave_accrual_pkey PRIMARY KEY (accrual_id);


--
-- Name: leave_balance_snapshot leave_balance_snapshot_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_balance_snapshot
    ADD CONSTRAINT leave_balance_snapshot_pkey PRIMARY KEY (snapshot_id);


--
-- Name: leave_entitlement leave_entitlement_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_entitlement
    ADD CONSTRAINT leave_entitlement_pkey PRIMARY KEY (entitlement_id);


--
-- Name: leave_ledger leave_ledger_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_ledger
    ADD CONSTRAINT leave_ledger_pkey PRIMARY KEY (ledger_id);


--
-- Name: leave_policy leave_policy_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy
    ADD CONSTRAINT leave_policy_pkey PRIMARY KEY (policy_id);


--
-- Name: leave_policy_resolution leave_policy_resolution_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy_resolution
    ADD CONSTRAINT leave_policy_resolution_pkey PRIMARY KEY (resolution_id);


--
-- Name: leave_policy_rule leave_policy_rule_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy_rule
    ADD CONSTRAINT leave_policy_rule_pkey PRIMARY KEY (policy_rule_id);


--
-- Name: leave_policy_rule leave_policy_rule_policy_id_leave_type_id_key; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy_rule
    ADD CONSTRAINT leave_policy_rule_policy_id_leave_type_id_key UNIQUE (policy_id, leave_type_id);


--
-- Name: leave_request leave_request_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_request
    ADD CONSTRAINT leave_request_pkey PRIMARY KEY (leave_request_id);


--
-- Name: leave_type leave_type_pkey; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_type
    ADD CONSTRAINT leave_type_pkey PRIMARY KEY (leave_type_id);


--
-- Name: leave_accrual unique_entitlement_accrual_date; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_accrual
    ADD CONSTRAINT unique_entitlement_accrual_date UNIQUE (entitlement_id, accrual_date);


--
-- Name: leave_type uq_leave_type_company_code; Type: CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_type
    ADD CONSTRAINT uq_leave_type_company_code UNIQUE (company_id, code);


--
-- Name: arrears arrears_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.arrears
    ADD CONSTRAINT arrears_pkey PRIMARY KEY (arrears_id);


--
-- Name: attendance_rule attendance_rule_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.attendance_rule
    ADD CONSTRAINT attendance_rule_pkey PRIMARY KEY (rule_id);


--
-- Name: company_payroll_settings company_payroll_settings_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_payroll_settings
    ADD CONSTRAINT company_payroll_settings_pkey PRIMARY KEY (company_id);


--
-- Name: company_statutory_config company_statutory_config_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_statutory_config
    ADD CONSTRAINT company_statutory_config_pkey PRIMARY KEY (company_statutory_config_id);


--
-- Name: company_statutory_profile company_statutory_profile_company_id_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_statutory_profile
    ADD CONSTRAINT company_statutory_profile_company_id_key UNIQUE (company_id);


--
-- Name: company_statutory_profile company_statutory_profile_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_statutory_profile
    ADD CONSTRAINT company_statutory_profile_pkey PRIMARY KEY (profile_id);


--
-- Name: company_tax_slab company_tax_slab_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_tax_slab
    ADD CONSTRAINT company_tax_slab_pkey PRIMARY KEY (slab_id);


--
-- Name: emi_transaction emi_transaction_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.emi_transaction
    ADD CONSTRAINT emi_transaction_pkey PRIMARY KEY (emi_id);


--
-- Name: employee_bank_details employee_bank_details_company_id_user_id_effective_from_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_bank_details
    ADD CONSTRAINT employee_bank_details_company_id_user_id_effective_from_key UNIQUE (company_id, user_id, effective_from);


--
-- Name: employee_bank_details employee_bank_details_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_bank_details
    ADD CONSTRAINT employee_bank_details_pkey PRIMARY KEY (bank_detail_id);


--
-- Name: employee_fine employee_fine_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_fine
    ADD CONSTRAINT employee_fine_pkey PRIMARY KEY (fine_id);


--
-- Name: employee_loan employee_loan_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_loan
    ADD CONSTRAINT employee_loan_pkey PRIMARY KEY (loan_id);


--
-- Name: employee_salary employee_salary_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_salary
    ADD CONSTRAINT employee_salary_pkey PRIMARY KEY (employee_salary_id);


--
-- Name: employee_statutory_contribution employee_statutory_contribution_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_contribution
    ADD CONSTRAINT employee_statutory_contribution_pkey PRIMARY KEY (contribution_id);


--
-- Name: employee_statutory_profile employee_statutory_profile_company_id_user_id_statutory_cod_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT employee_statutory_profile_company_id_user_id_statutory_cod_key UNIQUE (company_id, user_id, statutory_code, effective_from);


--
-- Name: employee_statutory_profile employee_statutory_profile_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT employee_statutory_profile_pkey PRIMARY KEY (profile_id);


--
-- Name: loan_payment loan_payment_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.loan_payment
    ADD CONSTRAINT loan_payment_pkey PRIMARY KEY (payment_id);


--
-- Name: payroll_period_lock no_overlap_payroll_period_lock; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_period_lock
    ADD CONSTRAINT no_overlap_payroll_period_lock EXCLUDE USING gist (company_id WITH =, daterange(period_start, period_end, '[]'::text) WITH &&);


--
-- Name: statutory_rule_set no_overlapping_rulesets; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_rule_set
    ADD CONSTRAINT no_overlapping_rulesets EXCLUDE USING gist (company_id WITH =, country_code WITH =, daterange(effective_from, COALESCE(effective_to, 'infinity'::date), '[]'::text) WITH &&);


--
-- Name: employee_statutory_profile no_overlapping_statutory_profiles; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT no_overlapping_statutory_profiles EXCLUDE USING gist (company_id WITH =, user_id WITH =, statutory_code WITH =, daterange(effective_from, COALESCE(effective_to, 'infinity'::date), '[]'::text) WITH &&) WHERE ((is_active = true));


--
-- Name: payroll_adjustment payroll_adjustment_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_adjustment
    ADD CONSTRAINT payroll_adjustment_pkey PRIMARY KEY (adjustment_id);


--
-- Name: payroll_component payroll_component_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_component
    ADD CONSTRAINT payroll_component_pkey PRIMARY KEY (company_id, component_code);


--
-- Name: payroll_item payroll_item_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_item
    ADD CONSTRAINT payroll_item_pkey PRIMARY KEY (payroll_item_id);


--
-- Name: payroll_job payroll_job_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_job
    ADD CONSTRAINT payroll_job_pkey PRIMARY KEY (job_id);


--
-- Name: payroll_ledger payroll_ledger_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_ledger
    ADD CONSTRAINT payroll_ledger_pkey PRIMARY KEY (ledger_id);


--
-- Name: payroll_period_lock payroll_period_lock_company_id_period_start_period_end_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_period_lock
    ADD CONSTRAINT payroll_period_lock_company_id_period_start_period_end_key UNIQUE (company_id, period_start, period_end);


--
-- Name: payroll_period_lock payroll_period_lock_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_period_lock
    ADD CONSTRAINT payroll_period_lock_pkey PRIMARY KEY (lock_id);


--
-- Name: payroll_run payroll_run_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_run
    ADD CONSTRAINT payroll_run_pkey PRIMARY KEY (payroll_run_id);


--
-- Name: payroll_snapshot payroll_snapshot_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_snapshot
    ADD CONSTRAINT payroll_snapshot_pkey PRIMARY KEY (snapshot_id);


--
-- Name: payroll_tax_rule payroll_tax_rule_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_tax_rule
    ADD CONSTRAINT payroll_tax_rule_pkey PRIMARY KEY (tax_rule_id);


--
-- Name: payslip payslip_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payslip
    ADD CONSTRAINT payslip_pkey PRIMARY KEY (payslip_id);


--
-- Name: payslip_template payslip_template_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payslip_template
    ADD CONSTRAINT payslip_template_pkey PRIMARY KEY (template_id);


--
-- Name: salary_structure salary_structure_company_id_structure_name_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.salary_structure
    ADD CONSTRAINT salary_structure_company_id_structure_name_key UNIQUE (company_id, structure_name);


--
-- Name: salary_structure_component salary_structure_component_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.salary_structure_component
    ADD CONSTRAINT salary_structure_component_pkey PRIMARY KEY (mapping_id);


--
-- Name: salary_structure salary_structure_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.salary_structure
    ADD CONSTRAINT salary_structure_pkey PRIMARY KEY (salary_structure_id);


--
-- Name: statutory_component_definition statutory_component_definition_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_definition
    ADD CONSTRAINT statutory_component_definition_pkey PRIMARY KEY (company_id, statutory_code);


--
-- Name: statutory_component_mapping statutory_component_mapping_company_id_statutory_code_compo_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_mapping
    ADD CONSTRAINT statutory_component_mapping_company_id_statutory_code_compo_key UNIQUE (company_id, statutory_code, component_code, effective_from);


--
-- Name: statutory_component_mapping statutory_component_mapping_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_mapping
    ADD CONSTRAINT statutory_component_mapping_pkey PRIMARY KEY (mapping_id);


--
-- Name: statutory_contribution_rule statutory_contribution_rule_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_contribution_rule
    ADD CONSTRAINT statutory_contribution_rule_pkey PRIMARY KEY (rule_id);


--
-- Name: statutory_deduction_limit statutory_deduction_limit_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_deduction_limit
    ADD CONSTRAINT statutory_deduction_limit_pkey PRIMARY KEY (limit_id);


--
-- Name: statutory_rule_set statutory_rule_set_company_id_country_code_effective_from_key; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_rule_set
    ADD CONSTRAINT statutory_rule_set_company_id_country_code_effective_from_key UNIQUE (company_id, country_code, effective_from);


--
-- Name: statutory_rule_set statutory_rule_set_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_rule_set
    ADD CONSTRAINT statutory_rule_set_pkey PRIMARY KEY (rule_set_id);


--
-- Name: tax_declaration tax_declaration_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration
    ADD CONSTRAINT tax_declaration_pkey PRIMARY KEY (declaration_id);


--
-- Name: tax_declaration_type tax_declaration_type_pkey; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration_type
    ADD CONSTRAINT tax_declaration_type_pkey PRIMARY KEY (company_id, type_code);


--
-- Name: payslip uq_payslip_run_user; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payslip
    ADD CONSTRAINT uq_payslip_run_user UNIQUE (payroll_run_id, user_id);


--
-- Name: salary_structure_component uq_structure_component; Type: CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.salary_structure_component
    ADD CONSTRAINT uq_structure_component UNIQUE (salary_structure_id, component_code);


--
-- Name: admin_avatars admin_avatars_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_avatars
    ADD CONSTRAINT admin_avatars_pkey PRIMARY KEY (avatar_id);


--
-- Name: admin_role_departments admin_role_departments_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_role_departments
    ADD CONSTRAINT admin_role_departments_pkey PRIMARY KEY (admin_role_id, system_department_id);


--
-- Name: admin_role_permissions admin_role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_role_permissions
    ADD CONSTRAINT admin_role_permissions_pkey PRIMARY KEY (admin_role_id, permission_id);


--
-- Name: admin_roles admin_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_roles
    ADD CONSTRAINT admin_roles_pkey PRIMARY KEY (admin_role_id);


--
-- Name: admin_roles admin_roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_roles
    ADD CONSTRAINT admin_roles_role_name_key UNIQUE (role_name);


--
-- Name: admin_users admin_users_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_pkey PRIMARY KEY (admin_id);


--
-- Name: admin_users admin_users_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_username_key UNIQUE (username);


--
-- Name: attendance_daily_summary attendance_daily_summary_company_id_user_id_attendance_date_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_daily_summary
    ADD CONSTRAINT attendance_daily_summary_company_id_user_id_attendance_date_key UNIQUE (company_id, user_id, attendance_date);


--
-- Name: attendance_daily_summary attendance_daily_summary_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_daily_summary
    ADD CONSTRAINT attendance_daily_summary_pkey PRIMARY KEY (attendance_summary_id);


--
-- Name: attendance_device_heartbeats attendance_device_heartbeats_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_heartbeats
    ADD CONSTRAINT attendance_device_heartbeats_pkey PRIMARY KEY (heartbeat_id);


--
-- Name: attendance_device_punch_batches attendance_device_punch_batches_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_punch_batches
    ADD CONSTRAINT attendance_device_punch_batches_pkey PRIMARY KEY (batch_id);


--
-- Name: attendance_device_punch_failures attendance_device_punch_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_punch_failures
    ADD CONSTRAINT attendance_device_punch_failures_pkey PRIMARY KEY (failure_id);


--
-- Name: attendance_device_tokens attendance_device_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_tokens
    ADD CONSTRAINT attendance_device_tokens_pkey PRIMARY KEY (token_id);


--
-- Name: attendance_device_trust_history attendance_device_trust_history_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_trust_history
    ADD CONSTRAINT attendance_device_trust_history_pkey PRIMARY KEY (trust_id);


--
-- Name: attendance_devices attendance_devices_company_id_device_code_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_devices
    ADD CONSTRAINT attendance_devices_company_id_device_code_key UNIQUE (company_id, device_code);


--
-- Name: attendance_devices attendance_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_devices
    ADD CONSTRAINT attendance_devices_pkey PRIMARY KEY (device_id);


--
-- Name: attendance_event_types attendance_event_types_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_event_types
    ADD CONSTRAINT attendance_event_types_pkey PRIMARY KEY (event_type);


--
-- Name: attendance_events attendance_events_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_events
    ADD CONSTRAINT attendance_events_pkey PRIMARY KEY (attendance_event_id);


--
-- Name: attendance_locations attendance_locations_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_locations
    ADD CONSTRAINT attendance_locations_pkey PRIMARY KEY (location_id);


--
-- Name: attendance_policies attendance_policies_company_id_policy_code_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_policies
    ADD CONSTRAINT attendance_policies_company_id_policy_code_key UNIQUE (company_id, policy_code);


--
-- Name: attendance_policies attendance_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_policies
    ADD CONSTRAINT attendance_policies_pkey PRIMARY KEY (policy_id);


--
-- Name: attendance_source_types attendance_source_types_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_source_types
    ADD CONSTRAINT attendance_source_types_pkey PRIMARY KEY (source_type);


--
-- Name: attendance_sources attendance_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_sources
    ADD CONSTRAINT attendance_sources_pkey PRIMARY KEY (source_id);


--
-- Name: attendance_user_device_identifiers attendance_user_device_identifiers_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_user_device_identifiers
    ADD CONSTRAINT attendance_user_device_identifiers_pkey PRIMARY KEY (mapping_id);


--
-- Name: companies companies_company_name_owner_user_id_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.companies
    ADD CONSTRAINT companies_company_name_owner_user_id_key UNIQUE (company_name, owner_user_id);


--
-- Name: companies companies_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.companies
    ADD CONSTRAINT companies_pkey PRIMARY KEY (company_id);


--
-- Name: company_attendance_rules company_attendance_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.company_attendance_rules
    ADD CONSTRAINT company_attendance_rules_pkey PRIMARY KEY (company_id);


--
-- Name: company_employees company_employees_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.company_employees
    ADD CONSTRAINT company_employees_pkey PRIMARY KEY (company_id, user_id);


--
-- Name: department_attendance_rules department_attendance_rules_company_id_department_id_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.department_attendance_rules
    ADD CONSTRAINT department_attendance_rules_company_id_department_id_key UNIQUE (company_id, department_id);


--
-- Name: department_attendance_rules department_attendance_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.department_attendance_rules
    ADD CONSTRAINT department_attendance_rules_pkey PRIMARY KEY (rule_id);


--
-- Name: departments departments_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_pkey PRIMARY KEY (department_id);


--
-- Name: employee_department_history employee_department_history_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_department_history
    ADD CONSTRAINT employee_department_history_pkey PRIMARY KEY (id);


--
-- Name: employee_documents employee_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_documents
    ADD CONSTRAINT employee_documents_pkey PRIMARY KEY (document_id);


--
-- Name: employee_exit employee_exit_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_exit
    ADD CONSTRAINT employee_exit_pkey PRIMARY KEY (exit_id);


--
-- Name: employee_profiles employee_profiles_company_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_profiles
    ADD CONSTRAINT employee_profiles_company_id_user_id_key UNIQUE (company_id, user_id);


--
-- Name: employee_profiles employee_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_profiles
    ADD CONSTRAINT employee_profiles_pkey PRIMARY KEY (employee_profile_id);


--
-- Name: employee_role_history employee_role_history_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_role_history
    ADD CONSTRAINT employee_role_history_pkey PRIMARY KEY (id);


--
-- Name: login_attempts login_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT login_attempts_pkey PRIMARY KEY (attempt_id);


--
-- Name: work_center_shifts no_overlap_work_center_shifts; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_center_shifts
    ADD CONSTRAINT no_overlap_work_center_shifts EXCLUDE USING gist (company_id WITH =, work_center_code WITH =, daterange(effective_from, COALESCE(effective_to, 'infinity'::date)) WITH &&);


--
-- Name: user_schedule_assignments no_overlapping_schedules; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_schedule_assignments
    ADD CONSTRAINT no_overlapping_schedules EXCLUDE USING gist (user_id WITH =, daterange(effective_from, COALESCE(effective_to, 'infinity'::date), '[]'::text) WITH &&);


--
-- Name: off_requests off_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.off_requests
    ADD CONSTRAINT off_requests_pkey PRIMARY KEY (off_request_id);


--
-- Name: org_unit_members org_unit_members_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_members
    ADD CONSTRAINT org_unit_members_pkey PRIMARY KEY (org_unit_id, user_id, effective_from);


--
-- Name: org_unit_roles org_unit_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_roles
    ADD CONSTRAINT org_unit_roles_pkey PRIMARY KEY (org_unit_id, user_id, role, effective_from);


--
-- Name: org_units org_units_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_units
    ADD CONSTRAINT org_units_pkey PRIMARY KEY (org_unit_id);


--
-- Name: permissions permissions_bit_index_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_bit_index_key UNIQUE (bit_index);


--
-- Name: permissions permissions_permission_name_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_permission_name_key UNIQUE (permission_name);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (permission_id);


--
-- Name: positions positions_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.positions
    ADD CONSTRAINT positions_pkey PRIMARY KEY (position_id);


--
-- Name: role_departments role_departments_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.role_departments
    ADD CONSTRAINT role_departments_pkey PRIMARY KEY (role_id, department_id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_company_id_role_name_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_company_id_role_name_key UNIQUE (company_id, role_name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- Name: schedule_instances schedule_instances_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_instances
    ADD CONSTRAINT schedule_instances_pkey PRIMARY KEY (schedule_instance_id);


--
-- Name: schedule_overrides schedule_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_overrides
    ADD CONSTRAINT schedule_overrides_pkey PRIMARY KEY (override_id);


--
-- Name: schedule_overrides schedule_overrides_user_id_override_date_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_overrides
    ADD CONSTRAINT schedule_overrides_user_id_override_date_key UNIQUE (user_id, override_date);


--
-- Name: schedule_templates schedule_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_templates
    ADD CONSTRAINT schedule_templates_pkey PRIMARY KEY (schedule_template_id);


--
-- Name: system_departments system_departments_name_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.system_departments
    ADD CONSTRAINT system_departments_name_key UNIQUE (name);


--
-- Name: system_departments system_departments_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.system_departments
    ADD CONSTRAINT system_departments_pkey PRIMARY KEY (system_department_id);


--
-- Name: positions uniq_position_title_per_dept; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.positions
    ADD CONSTRAINT uniq_position_title_per_dept UNIQUE (company_id, department_id, title);


--
-- Name: admin_roles unique_super_admin_role; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_roles
    ADD CONSTRAINT unique_super_admin_role EXCLUDE USING btree (role_type WITH =) WHERE ((role_type = 4));


--
-- Name: admin_users unique_super_admin_user; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT unique_super_admin_user EXCLUDE USING btree (role_type WITH =) WHERE ((role_type = 4));


--
-- Name: users unique_username; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT unique_username UNIQUE (user_id, username);


--
-- Name: admin_avatars uq_admin_primary_avatar; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_avatars
    ADD CONSTRAINT uq_admin_primary_avatar UNIQUE (admin_id, is_primary);


--
-- Name: user_avatars uq_user_primary_avatar; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_avatars
    ADD CONSTRAINT uq_user_primary_avatar UNIQUE (user_id, is_primary);


--
-- Name: work_calendars uq_work_calendar_company_year; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_calendars
    ADD CONSTRAINT uq_work_calendar_company_year UNIQUE (company_id, year);


--
-- Name: user_attendance_policies user_attendance_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_attendance_policies
    ADD CONSTRAINT user_attendance_policies_pkey PRIMARY KEY (user_id, policy_id, effective_from);


--
-- Name: user_attendance_profiles user_attendance_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_attendance_profiles
    ADD CONSTRAINT user_attendance_profiles_pkey PRIMARY KEY (user_id);


--
-- Name: user_avatars user_avatars_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_avatars
    ADD CONSTRAINT user_avatars_pkey PRIMARY KEY (avatar_id);


--
-- Name: user_devices user_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT user_devices_pkey PRIMARY KEY (device_id);


--
-- Name: user_off_entitlements user_off_entitlements_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_off_entitlements
    ADD CONSTRAINT user_off_entitlements_pkey PRIMARY KEY (entitlement_id);


--
-- Name: user_schedule_assignments user_schedule_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_schedule_assignments
    ADD CONSTRAINT user_schedule_assignments_pkey PRIMARY KEY (user_id, schedule_template_id, effective_from);


--
-- Name: user_work_center_assignments user_work_center_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_work_center_assignments
    ADD CONSTRAINT user_work_center_assignments_pkey PRIMARY KEY (assignment_id);


--
-- Name: user_work_center_assignments user_work_center_assignments_user_id_work_center_code_effec_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_work_center_assignments
    ADD CONSTRAINT user_work_center_assignments_user_id_work_center_code_effec_key UNIQUE (user_id, work_center_code, effective_from);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users_p0 users_p0_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p0
    ADD CONSTRAINT users_p0_pkey PRIMARY KEY (user_id);


--
-- Name: users_p0 users_p0_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p0
    ADD CONSTRAINT users_p0_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p1 users_p1_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p1
    ADD CONSTRAINT users_p1_pkey PRIMARY KEY (user_id);


--
-- Name: users_p1 users_p1_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p1
    ADD CONSTRAINT users_p1_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p2 users_p2_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p2
    ADD CONSTRAINT users_p2_pkey PRIMARY KEY (user_id);


--
-- Name: users_p2 users_p2_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p2
    ADD CONSTRAINT users_p2_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p3 users_p3_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p3
    ADD CONSTRAINT users_p3_pkey PRIMARY KEY (user_id);


--
-- Name: users_p3 users_p3_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p3
    ADD CONSTRAINT users_p3_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p4 users_p4_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p4
    ADD CONSTRAINT users_p4_pkey PRIMARY KEY (user_id);


--
-- Name: users_p4 users_p4_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p4
    ADD CONSTRAINT users_p4_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p5 users_p5_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p5
    ADD CONSTRAINT users_p5_pkey PRIMARY KEY (user_id);


--
-- Name: users_p5 users_p5_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p5
    ADD CONSTRAINT users_p5_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p6 users_p6_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p6
    ADD CONSTRAINT users_p6_pkey PRIMARY KEY (user_id);


--
-- Name: users_p6 users_p6_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p6
    ADD CONSTRAINT users_p6_user_id_username_key UNIQUE (user_id, username);


--
-- Name: users_p7 users_p7_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p7
    ADD CONSTRAINT users_p7_pkey PRIMARY KEY (user_id);


--
-- Name: users_p7 users_p7_user_id_username_key; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.users_p7
    ADD CONSTRAINT users_p7_user_id_username_key UNIQUE (user_id, username);


--
-- Name: work_calendars work_calendars_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_calendars
    ADD CONSTRAINT work_calendars_pkey PRIMARY KEY (calendar_id);


--
-- Name: work_center_shifts work_center_shifts_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_center_shifts
    ADD CONSTRAINT work_center_shifts_pkey PRIMARY KEY (mapping_id);


--
-- Name: work_centers work_centers_pkey; Type: CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_centers
    ADD CONSTRAINT work_centers_pkey PRIMARY KEY (company_id, work_center_code);


--
-- Name: idx_attendance_batch_outbox_unprocessed; Type: INDEX; Schema: attendance; Owner: auth_user
--

CREATE INDEX idx_attendance_batch_outbox_unprocessed ON attendance.attendance_batch_outbox USING btree (created_at) WHERE (processed_at IS NULL);


--
-- Name: idx_attendance_outbox_unprocessed; Type: INDEX; Schema: attendance; Owner: auth_user
--

CREATE INDEX idx_attendance_outbox_unprocessed ON attendance.attendance_events_outbox USING btree (processed_at) WHERE (processed_at IS NULL);


--
-- Name: idx_audit_logs_company_time; Type: INDEX; Schema: audit; Owner: auth_user
--

CREATE INDEX idx_audit_logs_company_time ON audit.audit_logs USING btree (company_id, created_at DESC);


--
-- Name: idx_audit_logs_entity; Type: INDEX; Schema: audit; Owner: auth_user
--

CREATE INDEX idx_audit_logs_entity ON audit.audit_logs USING btree (entity_type, entity_id);


--
-- Name: idx_audit_logs_module_action; Type: INDEX; Schema: audit; Owner: auth_user
--

CREATE INDEX idx_audit_logs_module_action ON audit.audit_logs USING btree (module, action);


--
-- Name: idx_audit_logs_outbox_unprocessed; Type: INDEX; Schema: audit; Owner: auth_user
--

CREATE INDEX idx_audit_logs_outbox_unprocessed ON audit.audit_logs_outbox USING btree (created_at) WHERE (processed_at IS NULL);


--
-- Name: idx_device_embedding_sync_company; Type: INDEX; Schema: biometric; Owner: auth_user
--

CREATE INDEX idx_device_embedding_sync_company ON biometric.device_embedding_sync USING btree (company_id);


--
-- Name: idx_face_embeddings_active; Type: INDEX; Schema: biometric; Owner: auth_user
--

CREATE INDEX idx_face_embeddings_active ON biometric.face_embeddings USING btree (company_id, is_active) WHERE (is_active = true);


--
-- Name: idx_face_embeddings_company; Type: INDEX; Schema: biometric; Owner: auth_user
--

CREATE INDEX idx_face_embeddings_company ON biometric.face_embeddings USING btree (company_id);


--
-- Name: idx_face_embeddings_sync_lookup; Type: INDEX; Schema: biometric; Owner: auth_user
--

CREATE INDEX idx_face_embeddings_sync_lookup ON biometric.face_embeddings USING btree (company_id, model_version, updated_at);


--
-- Name: idx_face_embeddings_updated; Type: INDEX; Schema: biometric; Owner: auth_user
--

CREATE INDEX idx_face_embeddings_updated ON biometric.face_embeddings USING btree (company_id, model_version, updated_at);


--
-- Name: idx_leave_accrual_date; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_accrual_date ON leave.leave_accrual USING btree (accrual_date);


--
-- Name: idx_leave_accrual_entitlement; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_accrual_entitlement ON leave.leave_accrual USING btree (entitlement_id);


--
-- Name: idx_leave_accrual_entitlement_date; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_accrual_entitlement_date ON leave.leave_accrual USING btree (entitlement_id, accrual_date);


--
-- Name: idx_leave_balance_snapshot_entitlement; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_balance_snapshot_entitlement ON leave.leave_balance_snapshot USING btree (entitlement_id);


--
-- Name: idx_leave_entitlement_company_user; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_entitlement_company_user ON leave.leave_entitlement USING btree (company_id, user_id);


--
-- Name: idx_leave_entitlement_current; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_entitlement_current ON leave.leave_entitlement USING btree (user_id, leave_type_id) WHERE (effective_to IS NULL);


--
-- Name: idx_leave_entitlement_dates; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_entitlement_dates ON leave.leave_entitlement USING btree (effective_from, effective_to);


--
-- Name: idx_leave_entitlement_leave_type; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_entitlement_leave_type ON leave.leave_entitlement USING btree (leave_type_id);


--
-- Name: idx_leave_entitlement_user; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_entitlement_user ON leave.leave_entitlement USING btree (user_id);


--
-- Name: idx_leave_ledger_entitlement; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_ledger_entitlement ON leave.leave_ledger USING btree (entitlement_id);


--
-- Name: idx_leave_ledger_entitlement_date; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_ledger_entitlement_date ON leave.leave_ledger USING btree (entitlement_id, entry_date);


--
-- Name: idx_leave_ledger_entry_date; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_ledger_entry_date ON leave.leave_ledger USING btree (entry_date);


--
-- Name: idx_leave_ledger_entry_type; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_ledger_entry_type ON leave.leave_ledger USING btree (entry_type);


--
-- Name: idx_leave_ledger_request; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_ledger_request ON leave.leave_ledger USING btree (leave_request_id);


--
-- Name: idx_leave_ledger_request_type; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_ledger_request_type ON leave.leave_ledger USING btree (leave_request_id, entry_type) WHERE (leave_request_id IS NOT NULL);


--
-- Name: idx_leave_policy_company_active; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_policy_company_active ON leave.leave_policy USING btree (company_id, is_active);


--
-- Name: idx_leave_policy_position; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_policy_position ON leave.leave_policy USING btree (applies_to_position_id);


--
-- Name: idx_leave_policy_scope_priority; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_policy_scope_priority ON leave.leave_policy USING btree (company_id, applies_to_type, priority, is_active);


--
-- Name: idx_leave_policy_work_center; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_policy_work_center ON leave.leave_policy USING btree (applies_to_work_center_code);


--
-- Name: idx_leave_request_approved_by; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_approved_by ON leave.leave_request USING btree (approved_by) WHERE (approved_by IS NOT NULL);


--
-- Name: idx_leave_request_company_user; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_company_user ON leave.leave_request USING btree (company_id, user_id);


--
-- Name: idx_leave_request_date_range; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_date_range ON leave.leave_request USING gist (daterange(start_date, end_date, '[]'::text));


--
-- Name: idx_leave_request_dates; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_dates ON leave.leave_request USING btree (start_date, end_date);


--
-- Name: idx_leave_request_leave_type; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_leave_type ON leave.leave_request USING btree (leave_type_id);


--
-- Name: idx_leave_request_pending; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_pending ON leave.leave_request USING btree (company_id) WHERE (status = 'pending'::text);


--
-- Name: idx_leave_request_requested_at; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_requested_at ON leave.leave_request USING btree (requested_at DESC);


--
-- Name: idx_leave_request_status; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_status ON leave.leave_request USING btree (status);


--
-- Name: idx_leave_request_user; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_request_user ON leave.leave_request USING btree (user_id);


--
-- Name: idx_leave_type_accrual_method; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_type_accrual_method ON leave.leave_type USING btree (accrual_method);


--
-- Name: idx_leave_type_code; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_type_code ON leave.leave_type USING btree (code);


--
-- Name: idx_leave_type_company; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE INDEX idx_leave_type_company ON leave.leave_type USING btree (company_id);


--
-- Name: uq_active_entitlement_per_leave; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE UNIQUE INDEX uq_active_entitlement_per_leave ON leave.leave_entitlement USING btree (company_id, user_id, leave_type_id, source) WHERE (effective_to IS NULL);


--
-- Name: uq_active_leave_policy_position; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE UNIQUE INDEX uq_active_leave_policy_position ON leave.leave_policy USING btree (company_id, applies_to_position_id) WHERE ((applies_to_type = 'position'::text) AND (is_active = true));


--
-- Name: uq_active_leave_policy_work_center; Type: INDEX; Schema: leave; Owner: auth_user
--

CREATE UNIQUE INDEX uq_active_leave_policy_work_center ON leave.leave_policy USING btree (company_id, applies_to_work_center_code) WHERE ((applies_to_type = 'work_center'::text) AND (is_active = true));


--
-- Name: idx_attendance_rule_company; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_attendance_rule_company ON payroll.attendance_rule USING btree (company_id, is_active);


--
-- Name: idx_emi_loan_due_status; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_emi_loan_due_status ON payroll.emi_transaction USING btree (loan_id, due_date) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_emi_user_period; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_emi_user_period ON payroll.emi_transaction USING btree (due_date) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_emp_stat_profile_active_range; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_emp_stat_profile_active_range ON payroll.employee_statutory_profile USING gist (company_id, user_id, statutory_code, daterange(effective_from, effective_to));


--
-- Name: idx_employee_fine_user; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_employee_fine_user ON payroll.employee_fine USING btree (company_id, user_id, is_processed);


--
-- Name: idx_employee_salary_active_lookup; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_employee_salary_active_lookup ON payroll.employee_salary USING btree (company_id, user_id, effective_from) WHERE (is_active = true);


--
-- Name: idx_employee_salary_range; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_employee_salary_range ON payroll.employee_salary USING gist (daterange(effective_from, COALESCE(effective_to, 'infinity'::date), '[]'::text));


--
-- Name: idx_employee_salary_version; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_employee_salary_version ON payroll.employee_salary USING btree (employee_salary_id, version);


--
-- Name: idx_loan_payment_emi; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_loan_payment_emi ON payroll.loan_payment USING btree (emi_id);


--
-- Name: idx_loan_payment_loan; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_loan_payment_loan ON payroll.loan_payment USING btree (loan_id);


--
-- Name: idx_loan_payment_paid_at; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_loan_payment_paid_at ON payroll.loan_payment USING btree (paid_at);


--
-- Name: idx_loan_payment_payroll_run; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_loan_payment_payroll_run ON payroll.loan_payment USING btree (payroll_run_id);


--
-- Name: idx_loan_payment_run; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_loan_payment_run ON payroll.loan_payment USING btree (payroll_run_id);


--
-- Name: idx_one_active_salary; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX idx_one_active_salary ON payroll.employee_salary USING btree (company_id, user_id) WHERE (is_active = true);


--
-- Name: idx_payroll_adjustment_lookup; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_adjustment_lookup ON payroll.payroll_adjustment USING btree (company_id, user_id, applicable_month);


--
-- Name: idx_payroll_component_system; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_component_system ON payroll.payroll_component USING btree (is_system) WHERE (is_system = true);


--
-- Name: idx_payroll_component_taxable; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_component_taxable ON payroll.payroll_component USING btree (is_taxable) WHERE (is_taxable = true);


--
-- Name: idx_payroll_component_type; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_component_type ON payroll.payroll_component USING btree (component_type);


--
-- Name: idx_payroll_item_created_at; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_item_created_at ON payroll.payroll_item USING btree (created_at DESC);


--
-- Name: idx_payroll_item_run; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_item_run ON payroll.payroll_item USING btree (payroll_run_id);


--
-- Name: idx_payroll_item_run_active; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_item_run_active ON payroll.payroll_item USING btree (payroll_run_id) WHERE (is_superseded = false);


--
-- Name: idx_payroll_item_user; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_item_user ON payroll.payroll_item USING btree (user_id);


--
-- Name: idx_payroll_ledger_component; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_ledger_component ON payroll.payroll_ledger USING btree (component_code);


--
-- Name: idx_payroll_ledger_created_at; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_ledger_created_at ON payroll.payroll_ledger USING btree (created_at DESC);


--
-- Name: idx_payroll_ledger_item; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_ledger_item ON payroll.payroll_ledger USING btree (payroll_item_id);


--
-- Name: idx_payroll_ledger_item_component; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_ledger_item_component ON payroll.payroll_ledger USING btree (payroll_item_id, component_code);


--
-- Name: idx_payroll_period_lock_company_range; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_period_lock_company_range ON payroll.payroll_period_lock USING btree (company_id, period_start, period_end);


--
-- Name: idx_payroll_period_lock_range; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_period_lock_range ON payroll.payroll_period_lock USING gist (company_id, daterange(period_start, period_end, '[]'::text));


--
-- Name: idx_payroll_run_company; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_run_company ON payroll.payroll_run USING btree (company_id);


--
-- Name: idx_payroll_run_created_at; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_run_created_at ON payroll.payroll_run USING btree (created_at DESC);


--
-- Name: idx_payroll_run_period; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_run_period ON payroll.payroll_run USING btree (period_start, period_end);


--
-- Name: idx_payroll_run_status; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_run_status ON payroll.payroll_run USING btree (status) WHERE ((status)::text = ANY ((ARRAY['draft'::character varying, 'calculated'::character varying])::text[]));


--
-- Name: idx_payroll_snapshot_company; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_snapshot_company ON payroll.payroll_snapshot USING btree (company_id);


--
-- Name: idx_payroll_snapshot_run; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_snapshot_run ON payroll.payroll_snapshot USING btree (payroll_run_id);


--
-- Name: idx_payroll_tax_profile_active; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_tax_profile_active ON payroll.payroll_tax_profile USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_payroll_tax_profile_country; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_tax_profile_country ON payroll.payroll_tax_profile USING btree (country_code);


--
-- Name: idx_payroll_tax_profile_created_at; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_tax_profile_created_at ON payroll.payroll_tax_profile USING btree (created_at DESC);


--
-- Name: idx_payroll_tax_rule_component; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_tax_rule_component ON payroll.payroll_tax_rule USING btree (component_code);


--
-- Name: idx_payroll_tax_rule_type; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_payroll_tax_rule_type ON payroll.payroll_tax_rule USING btree (calculation_type);


--
-- Name: idx_salary_structure_components_lookup; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_salary_structure_components_lookup ON payroll.salary_structure_component USING btree (salary_structure_id, sequence_order);


--
-- Name: idx_salary_structure_version; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_salary_structure_version ON payroll.salary_structure USING btree (salary_structure_id, version);


--
-- Name: idx_scd_company; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_scd_company ON payroll.statutory_component_definition USING btree (company_id);


--
-- Name: idx_scr_lookup; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_scr_lookup ON payroll.statutory_contribution_rule USING btree (company_id, statutory_code, contribution_side, effective_from);


--
-- Name: idx_scr_ruleset; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE INDEX idx_scr_ruleset ON payroll.statutory_contribution_rule USING btree (rule_set_id);


--
-- Name: uq_company_tax_slab_active; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX uq_company_tax_slab_active ON payroll.company_tax_slab USING btree (company_id, statutory_code, min_income, max_income, effective_from, rule_set_id) WHERE (is_active = true);


--
-- Name: uq_payroll_item_active; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX uq_payroll_item_active ON payroll.payroll_item USING btree (payroll_run_id, user_id) WHERE (is_superseded = false);


--
-- Name: uq_payroll_item_run_user; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX uq_payroll_item_run_user ON payroll.payroll_item USING btree (payroll_run_id, user_id);


--
-- Name: uq_payroll_job_active_run; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX uq_payroll_job_active_run ON payroll.payroll_job USING btree (payroll_run_id) WHERE (status = ANY (ARRAY['queued'::text, 'processing'::text]));


--
-- Name: uq_statutory_contribution_rule_active; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX uq_statutory_contribution_rule_active ON payroll.statutory_contribution_rule USING btree (company_id, statutory_code, contribution_side, effective_from, rule_set_id) WHERE (is_active = true);


--
-- Name: ux_payroll_item_active; Type: INDEX; Schema: payroll; Owner: auth_user
--

CREATE UNIQUE INDEX ux_payroll_item_active ON payroll.payroll_item USING btree (payroll_run_id, user_id) WHERE (is_superseded = false);


--
-- Name: idx_active_enrollment_lookup; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_active_enrollment_lookup ON public.attendance_user_device_identifiers USING btree (company_id, device_id, device_user_code) WHERE (is_active = true);


--
-- Name: idx_admin_avatars_admin_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_avatars_admin_active ON public.admin_avatars USING btree (admin_id) WHERE ((is_active = true) AND (is_primary = true));


--
-- Name: idx_admin_avatars_hash; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_avatars_hash ON public.admin_avatars USING btree (avatar_hash);


--
-- Name: idx_admin_role_departments_dept; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_role_departments_dept ON public.admin_role_departments USING btree (system_department_id);


--
-- Name: idx_admin_role_departments_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_role_departments_role ON public.admin_role_departments USING btree (admin_role_id);


--
-- Name: idx_admin_role_perms_permission; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_role_perms_permission ON public.admin_role_permissions USING btree (permission_id);


--
-- Name: idx_admin_role_perms_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_role_perms_role ON public.admin_role_permissions USING btree (admin_role_id);


--
-- Name: idx_admin_roles_level; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_roles_level ON public.admin_roles USING btree (role_level);


--
-- Name: idx_admin_roles_name; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_roles_name ON public.admin_roles USING btree (role_name);


--
-- Name: idx_admin_roles_type; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_roles_type ON public.admin_roles USING btree (role_type);


--
-- Name: idx_admin_users_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_active ON public.admin_users USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_admin_users_fullname_trgm; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_fullname_trgm ON public.admin_users USING gin (full_name public.gin_trgm_ops);


--
-- Name: idx_admin_users_phone_hash; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_phone_hash ON public.admin_users USING btree (phone_hash);


--
-- Name: idx_admin_users_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_role ON public.admin_users USING btree (admin_role_id) WHERE (is_active = true);


--
-- Name: idx_admin_users_role_active_login; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_role_active_login ON public.admin_users USING btree (admin_role_id, is_active, last_login DESC);


--
-- Name: idx_admin_users_role_type; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_role_type ON public.admin_users USING btree (role_type) WHERE (is_active = true);


--
-- Name: idx_admin_users_role_type_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_role_type_role ON public.admin_users USING btree (role_type, admin_role_id) WHERE (is_active = true);


--
-- Name: idx_admin_users_search_tsv; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_search_tsv ON public.admin_users USING gin (user_search_tsv);


--
-- Name: idx_admin_users_username; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_username ON public.admin_users USING btree (username);


--
-- Name: idx_admin_users_username_trgm; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_admin_users_username_trgm ON public.admin_users USING gin (username public.gin_trgm_ops);


--
-- Name: idx_attendance_daily_summary_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_daily_summary_company ON public.attendance_daily_summary USING btree (company_id);


--
-- Name: idx_attendance_daily_summary_date_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_daily_summary_date_status ON public.attendance_daily_summary USING btree (attendance_date, status);


--
-- Name: idx_attendance_daily_summary_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_daily_summary_status ON public.attendance_daily_summary USING btree (status);


--
-- Name: idx_attendance_daily_summary_user_date; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_daily_summary_user_date ON public.attendance_daily_summary USING btree (user_id, attendance_date DESC);


--
-- Name: idx_attendance_events_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_company ON public.attendance_events USING btree (company_id);


--
-- Name: idx_attendance_events_company_event_date; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_company_event_date ON public.attendance_events USING btree (company_id, event_date);


--
-- Name: idx_attendance_events_device_time; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_device_time ON public.attendance_events USING btree (company_id, user_id, device_id, event_type, event_time DESC) WHERE ((device_id IS NOT NULL) AND ((source_type)::text <> 'correction'::text));


--
-- Name: idx_attendance_events_event_date; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_event_date ON public.attendance_events USING btree (event_date);


--
-- Name: idx_attendance_events_source; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_source ON public.attendance_events USING btree (source_type, source_id);


--
-- Name: idx_attendance_events_type; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_type ON public.attendance_events USING btree (event_type);


--
-- Name: idx_attendance_events_user_time; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_user_time ON public.attendance_events USING btree (user_id, event_time DESC);


--
-- Name: idx_attendance_events_user_type_time; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_events_user_type_time ON public.attendance_events USING btree (company_id, user_id, event_type, event_time DESC) WHERE ((source_type)::text <> 'correction'::text);


--
-- Name: idx_attendance_locations_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_locations_active ON public.attendance_locations USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_attendance_locations_code; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_locations_code ON public.attendance_locations USING btree (company_id, location_code) WHERE (location_code IS NOT NULL);


--
-- Name: idx_attendance_locations_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_locations_company ON public.attendance_locations USING btree (company_id);


--
-- Name: idx_attendance_locations_zone; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_locations_zone ON public.attendance_locations USING btree (company_id, zone) WHERE (zone IS NOT NULL);


--
-- Name: idx_attendance_policies_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_policies_active ON public.attendance_policies USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_attendance_policies_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_policies_company ON public.attendance_policies USING btree (company_id);


--
-- Name: idx_attendance_policies_effective; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_policies_effective ON public.user_attendance_policies USING btree (user_id, effective_from, effective_to);


--
-- Name: idx_attendance_policies_position; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_policies_position ON public.attendance_policies USING btree (position_id) WHERE (position_id IS NOT NULL);


--
-- Name: idx_attendance_sources_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_sources_active ON public.attendance_sources USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_attendance_sources_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_sources_company ON public.attendance_sources USING btree (company_id);


--
-- Name: idx_attendance_sources_type; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_attendance_sources_type ON public.attendance_sources USING btree (source_type);


--
-- Name: idx_batch_failures_batch; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_batch_failures_batch ON public.attendance_device_punch_failures USING btree (batch_id);


--
-- Name: idx_batch_failures_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_batch_failures_company ON public.attendance_device_punch_failures USING btree (company_id, created_at DESC);


--
-- Name: idx_companies_name; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_name ON public.companies USING btree (company_name);


--
-- Name: idx_companies_name_trgm; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_name_trgm ON public.companies USING gin (company_name public.gin_trgm_ops);


--
-- Name: idx_companies_name_tsv; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_name_tsv ON public.companies USING gin (company_name_tsv);


--
-- Name: idx_companies_owner; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_owner ON public.companies USING btree (owner_user_id);


--
-- Name: idx_companies_owner_name; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_owner_name ON public.companies USING btree (owner_user_id, company_name);


--
-- Name: idx_companies_region; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_region ON public.companies USING btree (data_region);


--
-- Name: idx_companies_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_companies_status ON public.companies USING btree (is_active, subscription_status);


--
-- Name: idx_company_attendance_rules_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_company_attendance_rules_company ON public.company_attendance_rules USING btree (company_id);


--
-- Name: idx_company_employees_position; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_company_employees_position ON public.company_employees USING btree (position_id) WHERE (position_id IS NOT NULL);


--
-- Name: idx_department_attendance_rules_dept; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_department_attendance_rules_dept ON public.department_attendance_rules USING btree (department_id);


--
-- Name: idx_departments_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_departments_company ON public.departments USING btree (company_id);


--
-- Name: idx_departments_company_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_departments_company_active ON public.departments USING btree (company_id) WHERE (is_active = true);


--
-- Name: idx_departments_parent; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_departments_parent ON public.departments USING btree (parent_department_id);


--
-- Name: idx_departments_parent_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_departments_parent_active ON public.departments USING btree (parent_department_id) WHERE (is_active = true);


--
-- Name: idx_departments_system; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_departments_system ON public.departments USING btree (system_department_id);


--
-- Name: idx_device_heartbeats_latest; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_device_heartbeats_latest ON public.attendance_device_heartbeats USING btree (company_id, device_id, created_at DESC);


--
-- Name: idx_device_tokens_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_device_tokens_active ON public.attendance_device_tokens USING btree (company_id, device_id, is_active);


--
-- Name: idx_device_tokens_device; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_device_tokens_device ON public.attendance_device_tokens USING btree (company_id, device_id);


--
-- Name: idx_employee_department_history_dates; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_department_history_dates ON public.employee_department_history USING btree (start_date, end_date);


--
-- Name: idx_employee_department_history_dept; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_department_history_dept ON public.employee_department_history USING btree (department_id);


--
-- Name: idx_employee_department_history_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_department_history_user ON public.employee_department_history USING btree (user_id);


--
-- Name: idx_employee_documents_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_documents_company ON public.employee_documents USING btree (company_id);


--
-- Name: idx_employee_documents_type; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_documents_type ON public.employee_documents USING btree (document_type);


--
-- Name: idx_employee_documents_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_documents_user ON public.employee_documents USING btree (user_id);


--
-- Name: idx_employee_exit_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_exit_company ON public.employee_exit USING btree (company_id);


--
-- Name: idx_employee_exit_date; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_exit_date ON public.employee_exit USING btree (exit_date);


--
-- Name: idx_employee_exit_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_exit_user ON public.employee_exit USING btree (user_id);


--
-- Name: idx_employee_profiles_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_profiles_company ON public.employee_profiles USING btree (company_id);


--
-- Name: idx_employee_profiles_employment_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_profiles_employment_status ON public.employee_profiles USING btree (employment_status) WHERE ((employment_status)::text = 'active'::text);


--
-- Name: idx_employee_profiles_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_profiles_user ON public.employee_profiles USING btree (user_id);


--
-- Name: idx_employee_role_history_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_role_history_role ON public.employee_role_history USING btree (role_id);


--
-- Name: idx_employee_role_history_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employee_role_history_user ON public.employee_role_history USING btree (user_id);


--
-- Name: idx_employees_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employees_active ON public.company_employees USING btree (is_active);


--
-- Name: idx_employees_company_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employees_company_active ON public.company_employees USING btree (company_id, is_active);


--
-- Name: idx_employees_reports_to; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employees_reports_to ON public.company_employees USING btree (company_id, reports_to);


--
-- Name: idx_employees_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employees_role ON public.company_employees USING btree (role_id);


--
-- Name: idx_employees_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_employees_user ON public.company_employees USING btree (user_id);


--
-- Name: idx_login_attempts_device; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_login_attempts_device ON public.login_attempts USING btree (device_id);


--
-- Name: idx_login_attempts_success; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_login_attempts_success ON public.login_attempts USING btree (success);


--
-- Name: idx_login_attempts_time; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_login_attempts_time ON public.login_attempts USING btree (attempted_at DESC);


--
-- Name: idx_login_attempts_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_login_attempts_user ON public.login_attempts USING btree (user_id);


--
-- Name: idx_off_requests_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_off_requests_user ON public.off_requests USING btree (user_id, company_id);


--
-- Name: idx_org_units_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_org_units_company ON public.org_units USING btree (company_id, org_unit_type) WHERE (is_active = true);


--
-- Name: idx_oum_user_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_oum_user_active ON public.org_unit_members USING btree (user_id) WHERE (effective_to IS NULL);


--
-- Name: idx_our_user_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_our_user_active ON public.org_unit_roles USING btree (user_id) WHERE (effective_to IS NULL);


--
-- Name: idx_permissions_bit_index; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_permissions_bit_index ON public.permissions USING btree (bit_index);


--
-- Name: idx_permissions_module; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_permissions_module ON public.permissions USING btree (module);


--
-- Name: idx_permissions_name; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_permissions_name ON public.permissions USING btree (permission_name);


--
-- Name: idx_permissions_scope; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_permissions_scope ON public.permissions USING btree (scope);


--
-- Name: idx_positions_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_positions_company ON public.positions USING btree (company_id);


--
-- Name: idx_positions_department; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_positions_department ON public.positions USING btree (department_id);


--
-- Name: idx_positions_open; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_positions_open ON public.positions USING btree (is_open) WHERE (is_open = true);


--
-- Name: idx_positions_work_center; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_positions_work_center ON public.positions USING btree (company_id, work_center_code) WHERE (work_center_code IS NOT NULL);


--
-- Name: idx_role_departments_department; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_role_departments_department ON public.role_departments USING btree (department_id);


--
-- Name: idx_role_departments_role; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_role_departments_role ON public.role_departments USING btree (role_id);


--
-- Name: idx_role_perms_permission; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_role_perms_permission ON public.role_permissions USING btree (permission_id);


--
-- Name: idx_roles_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_roles_company ON public.roles USING btree (company_id);


--
-- Name: idx_roles_level; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_roles_level ON public.roles USING btree (role_level);


--
-- Name: idx_schedule_instances_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_instances_company ON public.schedule_instances USING btree (company_id);


--
-- Name: idx_schedule_instances_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_instances_status ON public.schedule_instances USING btree (status) WHERE ((status)::text = 'active'::text);


--
-- Name: idx_schedule_instances_template; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_instances_template ON public.schedule_instances USING btree (schedule_template_id);


--
-- Name: idx_schedule_instances_user_date; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_instances_user_date ON public.schedule_instances USING btree (user_id, schedule_date);


--
-- Name: idx_schedule_overrides_user_date; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_overrides_user_date ON public.schedule_overrides USING btree (user_id, override_date);


--
-- Name: idx_schedule_templates_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_templates_active ON public.schedule_templates USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_schedule_templates_calendar; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_templates_calendar ON public.schedule_templates USING btree (calendar_id);


--
-- Name: idx_schedule_templates_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_schedule_templates_company ON public.schedule_templates USING btree (company_id);


--
-- Name: idx_system_departments_bitmask; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_system_departments_bitmask ON public.system_departments USING btree (bitmask);


--
-- Name: idx_system_departments_module; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_system_departments_module ON public.system_departments USING btree (module_code);


--
-- Name: idx_system_departments_name; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_system_departments_name ON public.system_departments USING btree (name);


--
-- Name: idx_user_attendance_policies_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX idx_user_attendance_policies_active ON public.user_attendance_policies USING btree (user_id) WHERE (effective_to IS NULL);


--
-- Name: idx_user_attendance_policies_dates; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_attendance_policies_dates ON public.user_attendance_policies USING btree (effective_from, effective_to);


--
-- Name: idx_user_attendance_policies_policy; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_attendance_policies_policy ON public.user_attendance_policies USING btree (policy_id);


--
-- Name: idx_user_attendance_policies_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_attendance_policies_user ON public.user_attendance_policies USING btree (user_id);


--
-- Name: idx_user_attendance_profiles_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_attendance_profiles_user ON public.user_attendance_profiles USING btree (user_id);


--
-- Name: idx_user_avatars_hash; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_avatars_hash ON public.user_avatars USING btree (avatar_hash);


--
-- Name: idx_user_avatars_user_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_avatars_user_active ON public.user_avatars USING btree (user_id) WHERE ((is_active = true) AND (is_primary = true));


--
-- Name: idx_user_devices_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_devices_active ON public.user_devices USING btree (is_active);


--
-- Name: idx_user_devices_last_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_devices_last_active ON public.user_devices USING btree (last_active);


--
-- Name: idx_user_devices_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_devices_user ON public.user_devices USING btree (user_id);


--
-- Name: idx_user_off_entitlements_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_off_entitlements_user ON public.user_off_entitlements USING btree (user_id, company_id);


--
-- Name: idx_user_schedule_assignments_dates; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_schedule_assignments_dates ON public.user_schedule_assignments USING btree (effective_from, effective_to);


--
-- Name: idx_user_schedule_assignments_template; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_schedule_assignments_template ON public.user_schedule_assignments USING btree (schedule_template_id);


--
-- Name: idx_user_schedule_assignments_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_schedule_assignments_user ON public.user_schedule_assignments USING btree (user_id);


--
-- Name: idx_user_work_center_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_work_center_company ON public.user_work_center_assignments USING btree (company_id, work_center_code, is_active);


--
-- Name: idx_user_work_center_user; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_user_work_center_user ON public.user_work_center_assignments USING btree (user_id, is_active, effective_from DESC);


--
-- Name: idx_users_created_at; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_created_at ON ONLY public.users USING btree (created_at);


--
-- Name: idx_users_fullname; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_fullname ON ONLY public.users USING btree (full_name);


--
-- Name: idx_users_fullname_trgm; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_fullname_trgm ON ONLY public.users USING gin (full_name public.gin_trgm_ops);


--
-- Name: idx_users_kyc_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_kyc_status ON ONLY public.users USING btree (kyc_status);


--
-- Name: idx_users_name_search; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_name_search ON ONLY public.users USING btree (username, full_name);


--
-- Name: idx_users_phone_hash; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_phone_hash ON ONLY public.users USING btree (phone_hash);


--
-- Name: idx_users_region; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_region ON ONLY public.users USING btree (data_region);


--
-- Name: idx_users_search_tsv; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_search_tsv ON ONLY public.users USING gin (user_search_tsv);


--
-- Name: idx_users_status; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_status ON ONLY public.users USING btree (is_active, kyc_status);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_username ON ONLY public.users USING btree (username);


--
-- Name: idx_users_username_trgm; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_users_username_trgm ON ONLY public.users USING gin (username public.gin_trgm_ops);


--
-- Name: idx_work_calendars_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_calendars_active ON public.work_calendars USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_work_calendars_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_calendars_company ON public.work_calendars USING btree (company_id);


--
-- Name: idx_work_center_shifts_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_center_shifts_active ON public.work_center_shifts USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_work_center_shifts_code; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_center_shifts_code ON public.work_center_shifts USING btree (work_center_code);


--
-- Name: idx_work_center_shifts_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_center_shifts_company ON public.work_center_shifts USING btree (company_id);


--
-- Name: idx_work_center_shifts_dates; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_center_shifts_dates ON public.work_center_shifts USING btree (effective_from, effective_to);


--
-- Name: idx_work_centers_company; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX idx_work_centers_company ON public.work_centers USING btree (company_id, is_active);


--
-- Name: uniq_active_attendance_policy_position; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uniq_active_attendance_policy_position ON public.attendance_policies USING btree (position_id) WHERE (is_active = true);


--
-- Name: uniq_active_attendance_policy_work_center; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uniq_active_attendance_policy_work_center ON public.attendance_policies USING btree (work_center_code) WHERE (is_active = true);


--
-- Name: uniq_active_device_code; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uniq_active_device_code ON public.attendance_user_device_identifiers USING btree (company_id, device_id, device_user_code) WHERE (is_active = true);


--
-- Name: uniq_active_user_device_source; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uniq_active_user_device_source ON public.attendance_user_device_identifiers USING btree (company_id, device_id, user_id, source_type) WHERE (is_active = true);


--
-- Name: uniq_correction_event; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uniq_correction_event ON public.attendance_events USING btree (company_id, user_id, event_type, event_time) WHERE ((source_type)::text = 'correction'::text);


--
-- Name: uniq_enrollment_version; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uniq_enrollment_version ON public.attendance_user_device_identifiers USING btree (company_id, device_id, user_id, source_type, enrollment_version);


--
-- Name: uq_departments_company_name_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uq_departments_company_name_active ON public.departments USING btree (company_id, department_name) WHERE (is_active = true);


--
-- Name: uq_device_batch_ref; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uq_device_batch_ref ON public.attendance_device_punch_batches USING btree (company_id, device_id, batch_ref);


--
-- Name: uq_employee_active_department; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uq_employee_active_department ON public.employee_department_history USING btree (user_id) WHERE (end_date IS NULL);


--
-- Name: uq_employee_exit_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uq_employee_exit_active ON public.employee_exit USING btree (company_id, user_id) WHERE ((exit_state)::text = ANY ((ARRAY['scheduled'::character varying, 'effective'::character varying])::text[]));


--
-- Name: uq_employee_role_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uq_employee_role_active ON public.employee_role_history USING btree (user_id) WHERE (end_date IS NULL);


--
-- Name: uq_schedule_instances_user_date_active; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE UNIQUE INDEX uq_schedule_instances_user_date_active ON public.schedule_instances USING btree (user_id, schedule_date) WHERE ((status)::text = 'active'::text);


--
-- Name: users_p0_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_created_at_idx ON public.users_p0 USING btree (created_at);


--
-- Name: users_p0_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_data_region_idx ON public.users_p0 USING btree (data_region);


--
-- Name: users_p0_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_full_name_idx ON public.users_p0 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p0_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_full_name_idx1 ON public.users_p0 USING btree (full_name);


--
-- Name: users_p0_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_is_active_kyc_status_idx ON public.users_p0 USING btree (is_active, kyc_status);


--
-- Name: users_p0_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_kyc_status_idx ON public.users_p0 USING btree (kyc_status);


--
-- Name: users_p0_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_phone_hash_idx ON public.users_p0 USING btree (phone_hash);


--
-- Name: users_p0_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_user_search_tsv_idx ON public.users_p0 USING gin (user_search_tsv);


--
-- Name: users_p0_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_username_full_name_idx ON public.users_p0 USING btree (username, full_name);


--
-- Name: users_p0_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_username_idx ON public.users_p0 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p0_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p0_username_idx1 ON public.users_p0 USING btree (username);


--
-- Name: users_p1_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_created_at_idx ON public.users_p1 USING btree (created_at);


--
-- Name: users_p1_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_data_region_idx ON public.users_p1 USING btree (data_region);


--
-- Name: users_p1_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_full_name_idx ON public.users_p1 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p1_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_full_name_idx1 ON public.users_p1 USING btree (full_name);


--
-- Name: users_p1_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_is_active_kyc_status_idx ON public.users_p1 USING btree (is_active, kyc_status);


--
-- Name: users_p1_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_kyc_status_idx ON public.users_p1 USING btree (kyc_status);


--
-- Name: users_p1_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_phone_hash_idx ON public.users_p1 USING btree (phone_hash);


--
-- Name: users_p1_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_user_search_tsv_idx ON public.users_p1 USING gin (user_search_tsv);


--
-- Name: users_p1_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_username_full_name_idx ON public.users_p1 USING btree (username, full_name);


--
-- Name: users_p1_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_username_idx ON public.users_p1 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p1_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p1_username_idx1 ON public.users_p1 USING btree (username);


--
-- Name: users_p2_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_created_at_idx ON public.users_p2 USING btree (created_at);


--
-- Name: users_p2_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_data_region_idx ON public.users_p2 USING btree (data_region);


--
-- Name: users_p2_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_full_name_idx ON public.users_p2 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p2_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_full_name_idx1 ON public.users_p2 USING btree (full_name);


--
-- Name: users_p2_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_is_active_kyc_status_idx ON public.users_p2 USING btree (is_active, kyc_status);


--
-- Name: users_p2_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_kyc_status_idx ON public.users_p2 USING btree (kyc_status);


--
-- Name: users_p2_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_phone_hash_idx ON public.users_p2 USING btree (phone_hash);


--
-- Name: users_p2_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_user_search_tsv_idx ON public.users_p2 USING gin (user_search_tsv);


--
-- Name: users_p2_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_username_full_name_idx ON public.users_p2 USING btree (username, full_name);


--
-- Name: users_p2_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_username_idx ON public.users_p2 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p2_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p2_username_idx1 ON public.users_p2 USING btree (username);


--
-- Name: users_p3_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_created_at_idx ON public.users_p3 USING btree (created_at);


--
-- Name: users_p3_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_data_region_idx ON public.users_p3 USING btree (data_region);


--
-- Name: users_p3_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_full_name_idx ON public.users_p3 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p3_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_full_name_idx1 ON public.users_p3 USING btree (full_name);


--
-- Name: users_p3_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_is_active_kyc_status_idx ON public.users_p3 USING btree (is_active, kyc_status);


--
-- Name: users_p3_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_kyc_status_idx ON public.users_p3 USING btree (kyc_status);


--
-- Name: users_p3_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_phone_hash_idx ON public.users_p3 USING btree (phone_hash);


--
-- Name: users_p3_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_user_search_tsv_idx ON public.users_p3 USING gin (user_search_tsv);


--
-- Name: users_p3_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_username_full_name_idx ON public.users_p3 USING btree (username, full_name);


--
-- Name: users_p3_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_username_idx ON public.users_p3 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p3_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p3_username_idx1 ON public.users_p3 USING btree (username);


--
-- Name: users_p4_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_created_at_idx ON public.users_p4 USING btree (created_at);


--
-- Name: users_p4_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_data_region_idx ON public.users_p4 USING btree (data_region);


--
-- Name: users_p4_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_full_name_idx ON public.users_p4 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p4_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_full_name_idx1 ON public.users_p4 USING btree (full_name);


--
-- Name: users_p4_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_is_active_kyc_status_idx ON public.users_p4 USING btree (is_active, kyc_status);


--
-- Name: users_p4_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_kyc_status_idx ON public.users_p4 USING btree (kyc_status);


--
-- Name: users_p4_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_phone_hash_idx ON public.users_p4 USING btree (phone_hash);


--
-- Name: users_p4_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_user_search_tsv_idx ON public.users_p4 USING gin (user_search_tsv);


--
-- Name: users_p4_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_username_full_name_idx ON public.users_p4 USING btree (username, full_name);


--
-- Name: users_p4_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_username_idx ON public.users_p4 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p4_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p4_username_idx1 ON public.users_p4 USING btree (username);


--
-- Name: users_p5_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_created_at_idx ON public.users_p5 USING btree (created_at);


--
-- Name: users_p5_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_data_region_idx ON public.users_p5 USING btree (data_region);


--
-- Name: users_p5_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_full_name_idx ON public.users_p5 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p5_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_full_name_idx1 ON public.users_p5 USING btree (full_name);


--
-- Name: users_p5_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_is_active_kyc_status_idx ON public.users_p5 USING btree (is_active, kyc_status);


--
-- Name: users_p5_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_kyc_status_idx ON public.users_p5 USING btree (kyc_status);


--
-- Name: users_p5_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_phone_hash_idx ON public.users_p5 USING btree (phone_hash);


--
-- Name: users_p5_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_user_search_tsv_idx ON public.users_p5 USING gin (user_search_tsv);


--
-- Name: users_p5_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_username_full_name_idx ON public.users_p5 USING btree (username, full_name);


--
-- Name: users_p5_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_username_idx ON public.users_p5 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p5_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p5_username_idx1 ON public.users_p5 USING btree (username);


--
-- Name: users_p6_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_created_at_idx ON public.users_p6 USING btree (created_at);


--
-- Name: users_p6_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_data_region_idx ON public.users_p6 USING btree (data_region);


--
-- Name: users_p6_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_full_name_idx ON public.users_p6 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p6_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_full_name_idx1 ON public.users_p6 USING btree (full_name);


--
-- Name: users_p6_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_is_active_kyc_status_idx ON public.users_p6 USING btree (is_active, kyc_status);


--
-- Name: users_p6_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_kyc_status_idx ON public.users_p6 USING btree (kyc_status);


--
-- Name: users_p6_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_phone_hash_idx ON public.users_p6 USING btree (phone_hash);


--
-- Name: users_p6_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_user_search_tsv_idx ON public.users_p6 USING gin (user_search_tsv);


--
-- Name: users_p6_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_username_full_name_idx ON public.users_p6 USING btree (username, full_name);


--
-- Name: users_p6_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_username_idx ON public.users_p6 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p6_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p6_username_idx1 ON public.users_p6 USING btree (username);


--
-- Name: users_p7_created_at_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_created_at_idx ON public.users_p7 USING btree (created_at);


--
-- Name: users_p7_data_region_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_data_region_idx ON public.users_p7 USING btree (data_region);


--
-- Name: users_p7_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_full_name_idx ON public.users_p7 USING gin (full_name public.gin_trgm_ops);


--
-- Name: users_p7_full_name_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_full_name_idx1 ON public.users_p7 USING btree (full_name);


--
-- Name: users_p7_is_active_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_is_active_kyc_status_idx ON public.users_p7 USING btree (is_active, kyc_status);


--
-- Name: users_p7_kyc_status_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_kyc_status_idx ON public.users_p7 USING btree (kyc_status);


--
-- Name: users_p7_phone_hash_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_phone_hash_idx ON public.users_p7 USING btree (phone_hash);


--
-- Name: users_p7_user_search_tsv_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_user_search_tsv_idx ON public.users_p7 USING gin (user_search_tsv);


--
-- Name: users_p7_username_full_name_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_username_full_name_idx ON public.users_p7 USING btree (username, full_name);


--
-- Name: users_p7_username_idx; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_username_idx ON public.users_p7 USING gin (username public.gin_trgm_ops);


--
-- Name: users_p7_username_idx1; Type: INDEX; Schema: public; Owner: auth_user
--

CREATE INDEX users_p7_username_idx1 ON public.users_p7 USING btree (username);


--
-- Name: users_p0_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p0_created_at_idx;


--
-- Name: users_p0_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p0_data_region_idx;


--
-- Name: users_p0_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p0_full_name_idx;


--
-- Name: users_p0_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p0_full_name_idx1;


--
-- Name: users_p0_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p0_is_active_kyc_status_idx;


--
-- Name: users_p0_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p0_kyc_status_idx;


--
-- Name: users_p0_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p0_phone_hash_idx;


--
-- Name: users_p0_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p0_pkey;


--
-- Name: users_p0_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p0_user_id_username_key;


--
-- Name: users_p0_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p0_user_search_tsv_idx;


--
-- Name: users_p0_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p0_username_full_name_idx;


--
-- Name: users_p0_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p0_username_idx;


--
-- Name: users_p0_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p0_username_idx1;


--
-- Name: users_p1_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p1_created_at_idx;


--
-- Name: users_p1_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p1_data_region_idx;


--
-- Name: users_p1_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p1_full_name_idx;


--
-- Name: users_p1_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p1_full_name_idx1;


--
-- Name: users_p1_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p1_is_active_kyc_status_idx;


--
-- Name: users_p1_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p1_kyc_status_idx;


--
-- Name: users_p1_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p1_phone_hash_idx;


--
-- Name: users_p1_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p1_pkey;


--
-- Name: users_p1_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p1_user_id_username_key;


--
-- Name: users_p1_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p1_user_search_tsv_idx;


--
-- Name: users_p1_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p1_username_full_name_idx;


--
-- Name: users_p1_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p1_username_idx;


--
-- Name: users_p1_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p1_username_idx1;


--
-- Name: users_p2_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p2_created_at_idx;


--
-- Name: users_p2_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p2_data_region_idx;


--
-- Name: users_p2_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p2_full_name_idx;


--
-- Name: users_p2_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p2_full_name_idx1;


--
-- Name: users_p2_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p2_is_active_kyc_status_idx;


--
-- Name: users_p2_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p2_kyc_status_idx;


--
-- Name: users_p2_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p2_phone_hash_idx;


--
-- Name: users_p2_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p2_pkey;


--
-- Name: users_p2_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p2_user_id_username_key;


--
-- Name: users_p2_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p2_user_search_tsv_idx;


--
-- Name: users_p2_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p2_username_full_name_idx;


--
-- Name: users_p2_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p2_username_idx;


--
-- Name: users_p2_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p2_username_idx1;


--
-- Name: users_p3_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p3_created_at_idx;


--
-- Name: users_p3_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p3_data_region_idx;


--
-- Name: users_p3_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p3_full_name_idx;


--
-- Name: users_p3_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p3_full_name_idx1;


--
-- Name: users_p3_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p3_is_active_kyc_status_idx;


--
-- Name: users_p3_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p3_kyc_status_idx;


--
-- Name: users_p3_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p3_phone_hash_idx;


--
-- Name: users_p3_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p3_pkey;


--
-- Name: users_p3_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p3_user_id_username_key;


--
-- Name: users_p3_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p3_user_search_tsv_idx;


--
-- Name: users_p3_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p3_username_full_name_idx;


--
-- Name: users_p3_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p3_username_idx;


--
-- Name: users_p3_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p3_username_idx1;


--
-- Name: users_p4_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p4_created_at_idx;


--
-- Name: users_p4_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p4_data_region_idx;


--
-- Name: users_p4_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p4_full_name_idx;


--
-- Name: users_p4_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p4_full_name_idx1;


--
-- Name: users_p4_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p4_is_active_kyc_status_idx;


--
-- Name: users_p4_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p4_kyc_status_idx;


--
-- Name: users_p4_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p4_phone_hash_idx;


--
-- Name: users_p4_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p4_pkey;


--
-- Name: users_p4_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p4_user_id_username_key;


--
-- Name: users_p4_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p4_user_search_tsv_idx;


--
-- Name: users_p4_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p4_username_full_name_idx;


--
-- Name: users_p4_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p4_username_idx;


--
-- Name: users_p4_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p4_username_idx1;


--
-- Name: users_p5_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p5_created_at_idx;


--
-- Name: users_p5_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p5_data_region_idx;


--
-- Name: users_p5_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p5_full_name_idx;


--
-- Name: users_p5_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p5_full_name_idx1;


--
-- Name: users_p5_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p5_is_active_kyc_status_idx;


--
-- Name: users_p5_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p5_kyc_status_idx;


--
-- Name: users_p5_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p5_phone_hash_idx;


--
-- Name: users_p5_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p5_pkey;


--
-- Name: users_p5_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p5_user_id_username_key;


--
-- Name: users_p5_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p5_user_search_tsv_idx;


--
-- Name: users_p5_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p5_username_full_name_idx;


--
-- Name: users_p5_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p5_username_idx;


--
-- Name: users_p5_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p5_username_idx1;


--
-- Name: users_p6_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p6_created_at_idx;


--
-- Name: users_p6_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p6_data_region_idx;


--
-- Name: users_p6_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p6_full_name_idx;


--
-- Name: users_p6_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p6_full_name_idx1;


--
-- Name: users_p6_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p6_is_active_kyc_status_idx;


--
-- Name: users_p6_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p6_kyc_status_idx;


--
-- Name: users_p6_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p6_phone_hash_idx;


--
-- Name: users_p6_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p6_pkey;


--
-- Name: users_p6_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p6_user_id_username_key;


--
-- Name: users_p6_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p6_user_search_tsv_idx;


--
-- Name: users_p6_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p6_username_full_name_idx;


--
-- Name: users_p6_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p6_username_idx;


--
-- Name: users_p6_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p6_username_idx1;


--
-- Name: users_p7_created_at_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_created_at ATTACH PARTITION public.users_p7_created_at_idx;


--
-- Name: users_p7_data_region_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_region ATTACH PARTITION public.users_p7_data_region_idx;


--
-- Name: users_p7_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname_trgm ATTACH PARTITION public.users_p7_full_name_idx;


--
-- Name: users_p7_full_name_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_fullname ATTACH PARTITION public.users_p7_full_name_idx1;


--
-- Name: users_p7_is_active_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_status ATTACH PARTITION public.users_p7_is_active_kyc_status_idx;


--
-- Name: users_p7_kyc_status_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_kyc_status ATTACH PARTITION public.users_p7_kyc_status_idx;


--
-- Name: users_p7_phone_hash_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_phone_hash ATTACH PARTITION public.users_p7_phone_hash_idx;


--
-- Name: users_p7_pkey; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.users_pkey ATTACH PARTITION public.users_p7_pkey;


--
-- Name: users_p7_user_id_username_key; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.unique_username ATTACH PARTITION public.users_p7_user_id_username_key;


--
-- Name: users_p7_user_search_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_search_tsv ATTACH PARTITION public.users_p7_user_search_tsv_idx;


--
-- Name: users_p7_username_full_name_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_name_search ATTACH PARTITION public.users_p7_username_full_name_idx;


--
-- Name: users_p7_username_idx; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username_trgm ATTACH PARTITION public.users_p7_username_idx;


--
-- Name: users_p7_username_idx1; Type: INDEX ATTACH; Schema: public; Owner: auth_user
--

ALTER INDEX public.idx_users_username ATTACH PARTITION public.users_p7_username_idx1;


--
-- Name: audit_logs audit_logs_outbox_trigger; Type: TRIGGER; Schema: audit; Owner: auth_user
--

CREATE TRIGGER audit_logs_outbox_trigger AFTER INSERT ON audit.audit_logs FOR EACH ROW EXECUTE FUNCTION audit.audit_logs_outbox_trigger();


--
-- Name: leave_entitlement update_leave_entitlement_updated_at; Type: TRIGGER; Schema: leave; Owner: auth_user
--

CREATE TRIGGER update_leave_entitlement_updated_at BEFORE UPDATE ON leave.leave_entitlement FOR EACH ROW EXECUTE FUNCTION leave.update_updated_at_column();


--
-- Name: leave_policy_rule update_leave_policy_rule_updated_at; Type: TRIGGER; Schema: leave; Owner: auth_user
--

CREATE TRIGGER update_leave_policy_rule_updated_at BEFORE UPDATE ON leave.leave_policy_rule FOR EACH ROW EXECUTE FUNCTION leave.update_updated_at_column();


--
-- Name: leave_policy update_leave_policy_updated_at; Type: TRIGGER; Schema: leave; Owner: auth_user
--

CREATE TRIGGER update_leave_policy_updated_at BEFORE UPDATE ON leave.leave_policy FOR EACH ROW EXECUTE FUNCTION leave.update_updated_at_column();


--
-- Name: salary_structure trg_prevent_structure_update; Type: TRIGGER; Schema: payroll; Owner: auth_user
--

CREATE TRIGGER trg_prevent_structure_update BEFORE UPDATE ON payroll.salary_structure FOR EACH ROW EXECUTE FUNCTION public.prevent_structure_update_if_used();


--
-- Name: departments trg_cascade_department_soft_delete; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_cascade_department_soft_delete BEFORE UPDATE OF is_active ON public.departments FOR EACH ROW EXECUTE FUNCTION public.cascade_department_soft_delete();


--
-- Name: departments trg_close_positions_on_department_deactivate; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_close_positions_on_department_deactivate BEFORE UPDATE OF is_active ON public.departments FOR EACH ROW EXECUTE FUNCTION public.close_positions_on_department_deactivate();


--
-- Name: departments trg_enforce_department_limit; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_enforce_department_limit BEFORE INSERT OR UPDATE OF is_active ON public.departments FOR EACH ROW EXECUTE FUNCTION public.enforce_department_limit();


--
-- Name: company_employees trg_enforce_employee_limit; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_enforce_employee_limit BEFORE INSERT OR UPDATE OF is_active ON public.company_employees FOR EACH ROW EXECUTE FUNCTION public.enforce_employee_limit();


--
-- Name: schedule_instances trg_enforce_schedule_cancel; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_enforce_schedule_cancel BEFORE UPDATE ON public.schedule_instances FOR EACH ROW EXECUTE FUNCTION public.enforce_schedule_cancellation();


--
-- Name: departments trg_no_department_delete; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_no_department_delete BEFORE DELETE ON public.departments FOR EACH ROW EXECUTE FUNCTION public.prevent_department_delete();


--
-- Name: attendance_daily_summary trg_prevent_attendance_update_if_locked; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_prevent_attendance_update_if_locked BEFORE DELETE OR UPDATE ON public.attendance_daily_summary FOR EACH ROW EXECUTE FUNCTION public.prevent_attendance_update_if_locked();


--
-- Name: departments trg_prevent_child_on_inactive_parent; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_prevent_child_on_inactive_parent BEFORE INSERT OR UPDATE OF parent_department_id ON public.departments FOR EACH ROW EXECUTE FUNCTION public.prevent_child_on_inactive_parent();


--
-- Name: employee_exit trg_prevent_exit_for_inactive_employee; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_prevent_exit_for_inactive_employee BEFORE INSERT ON public.employee_exit FOR EACH ROW EXECUTE FUNCTION public.prevent_exit_for_inactive_employee();


--
-- Name: schedule_instances trg_prevent_past_schedule_update; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_prevent_past_schedule_update BEFORE DELETE OR UPDATE ON public.schedule_instances FOR EACH ROW EXECUTE FUNCTION public.prevent_past_schedule_update();


--
-- Name: positions trg_prevent_position_in_inactive_department; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_prevent_position_in_inactive_department BEFORE INSERT OR UPDATE ON public.positions FOR EACH ROW EXECUTE FUNCTION public.prevent_position_in_inactive_department();


--
-- Name: employee_exit trg_revoke_biometric_on_exit; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_revoke_biometric_on_exit AFTER UPDATE OF exit_state ON public.employee_exit FOR EACH ROW WHEN (((new.exit_state)::text = 'effective'::text)) EXECUTE FUNCTION biometric.revoke_biometric_on_exit();


--
-- Name: employee_exit trg_revoke_device_on_employee_exit; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_revoke_device_on_employee_exit AFTER UPDATE OF exit_state ON public.employee_exit FOR EACH ROW WHEN (((new.exit_state)::text = 'effective'::text)) EXECUTE FUNCTION public.revoke_enrollment_on_exit();


--
-- Name: company_employees trg_sync_department_on_position; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_sync_department_on_position AFTER INSERT OR UPDATE OF position_id ON public.company_employees FOR EACH ROW EXECUTE FUNCTION public.sync_employee_department_on_position();


--
-- Name: company_employees trg_sync_role_history; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_sync_role_history AFTER INSERT OR UPDATE OF role_id ON public.company_employees FOR EACH ROW EXECUTE FUNCTION public.sync_employee_role_history();


--
-- Name: departments trg_unique_active_department_name; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER trg_unique_active_department_name BEFORE INSERT OR UPDATE OF department_name, is_active ON public.departments FOR EACH ROW EXECUTE FUNCTION public.enforce_unique_active_department_name();


--
-- Name: admin_roles update_admin_roles_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_admin_roles_updated_at BEFORE UPDATE ON public.admin_roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: admin_users update_admin_user_search_tsv; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_admin_user_search_tsv BEFORE UPDATE OF username, full_name ON public.admin_users FOR EACH ROW EXECUTE FUNCTION public.update_admin_user_search_tsv();


--
-- Name: admin_users update_admin_users_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_admin_users_updated_at BEFORE UPDATE ON public.admin_users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: attendance_policies update_attendance_policies_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_attendance_policies_updated_at BEFORE UPDATE ON public.attendance_policies FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: companies update_companies_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_companies_updated_at BEFORE UPDATE ON public.companies FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: company_employees update_company_employees_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_company_employees_updated_at BEFORE UPDATE ON public.company_employees FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: companies update_company_name_tsv; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_company_name_tsv BEFORE UPDATE OF company_name ON public.companies FOR EACH ROW EXECUTE FUNCTION public.update_company_name_tsv();


--
-- Name: departments update_departments_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_departments_updated_at BEFORE UPDATE ON public.departments FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: employee_profiles update_employee_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_employee_profiles_updated_at BEFORE UPDATE ON public.employee_profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: org_units update_org_units_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_org_units_updated_at BEFORE UPDATE ON public.org_units FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: roles update_roles_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON public.roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: user_devices update_user_devices_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_user_devices_updated_at BEFORE UPDATE ON public.user_devices FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users update_user_search_tsv; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_user_search_tsv BEFORE UPDATE OF username, full_name ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_user_search_tsv();


--
-- Name: user_work_center_assignments update_user_work_center_assignments_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_user_work_center_assignments_updated_at BEFORE UPDATE ON public.user_work_center_assignments FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: work_center_shifts update_work_center_shifts_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_work_center_shifts_updated_at BEFORE UPDATE ON public.work_center_shifts FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: work_centers update_work_centers_updated_at; Type: TRIGGER; Schema: public; Owner: auth_user
--

CREATE TRIGGER update_work_centers_updated_at BEFORE UPDATE ON public.work_centers FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: device_embedding_sync fk_device_sync_device; Type: FK CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.device_embedding_sync
    ADD CONSTRAINT fk_device_sync_device FOREIGN KEY (device_id) REFERENCES public.attendance_devices(device_id) ON DELETE CASCADE;


--
-- Name: embedding_audit_log fk_embedding_audit_employee; Type: FK CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.embedding_audit_log
    ADD CONSTRAINT fk_embedding_audit_employee FOREIGN KEY (company_id, user_id) REFERENCES public.company_employees(company_id, user_id) ON DELETE CASCADE;


--
-- Name: face_embeddings fk_face_embeddings_employee; Type: FK CONSTRAINT; Schema: biometric; Owner: auth_user
--

ALTER TABLE ONLY biometric.face_embeddings
    ADD CONSTRAINT fk_face_embeddings_employee FOREIGN KEY (company_id, user_id) REFERENCES public.company_employees(company_id, user_id) ON DELETE CASCADE;


--
-- Name: leave_balance_snapshot fk_lbs_entitlement; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_balance_snapshot
    ADD CONSTRAINT fk_lbs_entitlement FOREIGN KEY (entitlement_id) REFERENCES leave.leave_entitlement(entitlement_id) ON DELETE CASCADE;


--
-- Name: leave_accrual fk_leave_accrual_entitlement; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_accrual
    ADD CONSTRAINT fk_leave_accrual_entitlement FOREIGN KEY (entitlement_id) REFERENCES leave.leave_entitlement(entitlement_id) ON DELETE CASCADE;


--
-- Name: leave_entitlement fk_leave_entitlement_company; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_entitlement
    ADD CONSTRAINT fk_leave_entitlement_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: leave_entitlement fk_leave_entitlement_policy; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_entitlement
    ADD CONSTRAINT fk_leave_entitlement_policy FOREIGN KEY (policy_id) REFERENCES leave.leave_policy(policy_id) ON DELETE SET NULL;


--
-- Name: leave_entitlement fk_leave_entitlement_type; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_entitlement
    ADD CONSTRAINT fk_leave_entitlement_type FOREIGN KEY (leave_type_id) REFERENCES leave.leave_type(leave_type_id);


--
-- Name: leave_entitlement fk_leave_entitlement_user; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_entitlement
    ADD CONSTRAINT fk_leave_entitlement_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: leave_ledger fk_leave_ledger_entitlement; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_ledger
    ADD CONSTRAINT fk_leave_ledger_entitlement FOREIGN KEY (entitlement_id) REFERENCES leave.leave_entitlement(entitlement_id) ON DELETE CASCADE;


--
-- Name: leave_ledger fk_leave_ledger_request; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_ledger
    ADD CONSTRAINT fk_leave_ledger_request FOREIGN KEY (leave_request_id) REFERENCES leave.leave_request(leave_request_id) ON DELETE SET NULL;


--
-- Name: leave_policy fk_leave_policy_company; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy
    ADD CONSTRAINT fk_leave_policy_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: leave_policy fk_leave_policy_position; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy
    ADD CONSTRAINT fk_leave_policy_position FOREIGN KEY (applies_to_position_id) REFERENCES public.positions(position_id) ON DELETE CASCADE;


--
-- Name: leave_request fk_leave_request_company; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_request
    ADD CONSTRAINT fk_leave_request_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: leave_request fk_leave_request_type; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_request
    ADD CONSTRAINT fk_leave_request_type FOREIGN KEY (leave_type_id) REFERENCES leave.leave_type(leave_type_id);


--
-- Name: leave_request fk_leave_request_user; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_request
    ADD CONSTRAINT fk_leave_request_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: leave_type fk_leave_type_company; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_type
    ADD CONSTRAINT fk_leave_type_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: leave_policy_rule fk_lpr_leave_type; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy_rule
    ADD CONSTRAINT fk_lpr_leave_type FOREIGN KEY (leave_type_id) REFERENCES leave.leave_type(leave_type_id) ON DELETE CASCADE;


--
-- Name: leave_policy_rule fk_lpr_policy; Type: FK CONSTRAINT; Schema: leave; Owner: auth_user
--

ALTER TABLE ONLY leave.leave_policy_rule
    ADD CONSTRAINT fk_lpr_policy FOREIGN KEY (policy_id) REFERENCES leave.leave_policy(policy_id) ON DELETE CASCADE;


--
-- Name: company_payroll_settings company_payroll_settings_company_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_payroll_settings
    ADD CONSTRAINT company_payroll_settings_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: emi_transaction emi_transaction_loan_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.emi_transaction
    ADD CONSTRAINT emi_transaction_loan_id_fkey FOREIGN KEY (loan_id) REFERENCES payroll.employee_loan(loan_id) ON DELETE CASCADE;


--
-- Name: emi_transaction emi_transaction_payroll_run_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.emi_transaction
    ADD CONSTRAINT emi_transaction_payroll_run_id_fkey FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id);


--
-- Name: employee_bank_details employee_bank_details_company_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_bank_details
    ADD CONSTRAINT employee_bank_details_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: employee_bank_details employee_bank_details_user_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_bank_details
    ADD CONSTRAINT employee_bank_details_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_loan employee_loan_company_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_loan
    ADD CONSTRAINT employee_loan_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_loan employee_loan_created_by_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_loan
    ADD CONSTRAINT employee_loan_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.admin_users(admin_id);


--
-- Name: employee_loan employee_loan_user_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_loan
    ADD CONSTRAINT employee_loan_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: payroll_adjustment fk_adjust_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_adjustment
    ADD CONSTRAINT fk_adjust_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: arrears fk_arrears_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.arrears
    ADD CONSTRAINT fk_arrears_component FOREIGN KEY (company_id, component_code) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: attendance_rule fk_attendance_rule_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.attendance_rule
    ADD CONSTRAINT fk_attendance_rule_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: attendance_rule fk_attendance_rule_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.attendance_rule
    ADD CONSTRAINT fk_attendance_rule_component FOREIGN KEY (company_id, component_code) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: attendance_rule fk_attendance_rule_created_by; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.attendance_rule
    ADD CONSTRAINT fk_attendance_rule_created_by FOREIGN KEY (created_by) REFERENCES public.users(user_id);


--
-- Name: attendance_rule fk_attendance_rule_updated_by; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.attendance_rule
    ADD CONSTRAINT fk_attendance_rule_updated_by FOREIGN KEY (updated_by) REFERENCES public.users(user_id);


--
-- Name: company_statutory_config fk_csc_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_statutory_config
    ADD CONSTRAINT fk_csc_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: company_payroll_settings fk_default_arrears_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_payroll_settings
    ADD CONSTRAINT fk_default_arrears_component FOREIGN KEY (company_id, default_arrears_component) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: company_payroll_settings fk_default_basic_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_payroll_settings
    ADD CONSTRAINT fk_default_basic_component FOREIGN KEY (company_id, default_basic_component) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: company_payroll_settings fk_default_fine_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_payroll_settings
    ADD CONSTRAINT fk_default_fine_component FOREIGN KEY (company_id, default_fine_component) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: company_payroll_settings fk_default_loan_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_payroll_settings
    ADD CONSTRAINT fk_default_loan_component FOREIGN KEY (company_id, default_loan_component) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: employee_salary fk_emp_salary_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_salary
    ADD CONSTRAINT fk_emp_salary_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_salary fk_emp_salary_structure; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_salary
    ADD CONSTRAINT fk_emp_salary_structure FOREIGN KEY (salary_structure_id) REFERENCES payroll.salary_structure(salary_structure_id);


--
-- Name: employee_salary fk_emp_salary_user; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_salary
    ADD CONSTRAINT fk_emp_salary_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_fine fk_employee_fine_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_fine
    ADD CONSTRAINT fk_employee_fine_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_fine fk_employee_fine_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_fine
    ADD CONSTRAINT fk_employee_fine_component FOREIGN KEY (company_id, component_code) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: employee_fine fk_employee_fine_created_by; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_fine
    ADD CONSTRAINT fk_employee_fine_created_by FOREIGN KEY (created_by) REFERENCES public.users(user_id);


--
-- Name: employee_fine fk_employee_fine_payroll_run; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_fine
    ADD CONSTRAINT fk_employee_fine_payroll_run FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id);


--
-- Name: employee_fine fk_employee_fine_user; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_fine
    ADD CONSTRAINT fk_employee_fine_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_loan fk_employee_loan_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_loan
    ADD CONSTRAINT fk_employee_loan_component FOREIGN KEY (company_id, component_code) REFERENCES payroll.payroll_component(company_id, component_code);


--
-- Name: employee_statutory_contribution fk_esc_definition; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_contribution
    ADD CONSTRAINT fk_esc_definition FOREIGN KEY (company_id, statutory_code) REFERENCES payroll.statutory_component_definition(company_id, statutory_code) ON DELETE CASCADE;


--
-- Name: employee_statutory_contribution fk_esc_user; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_contribution
    ADD CONSTRAINT fk_esc_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_statutory_profile fk_esp_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT fk_esp_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_statutory_profile fk_esp_definition; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT fk_esp_definition FOREIGN KEY (company_id, statutory_code) REFERENCES payroll.statutory_component_definition(company_id, statutory_code) ON DELETE CASCADE;


--
-- Name: employee_statutory_profile fk_esp_ruleset; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT fk_esp_ruleset FOREIGN KEY (rule_set_id) REFERENCES payroll.statutory_rule_set(rule_set_id) ON DELETE CASCADE;


--
-- Name: employee_statutory_profile fk_esp_user; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.employee_statutory_profile
    ADD CONSTRAINT fk_esp_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: payroll_ledger fk_ledger_item; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_ledger
    ADD CONSTRAINT fk_ledger_item FOREIGN KEY (payroll_item_id) REFERENCES payroll.payroll_item(payroll_item_id) ON DELETE CASCADE;


--
-- Name: statutory_deduction_limit fk_limit_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_deduction_limit
    ADD CONSTRAINT fk_limit_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: statutory_deduction_limit fk_limit_ruleset; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_deduction_limit
    ADD CONSTRAINT fk_limit_ruleset FOREIGN KEY (rule_set_id) REFERENCES payroll.statutory_rule_set(rule_set_id) ON DELETE CASCADE;


--
-- Name: payroll_item fk_payroll_item_run; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_item
    ADD CONSTRAINT fk_payroll_item_run FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE;


--
-- Name: payroll_item fk_payroll_item_user; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_item
    ADD CONSTRAINT fk_payroll_item_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: payroll_run fk_payroll_run_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_run
    ADD CONSTRAINT fk_payroll_run_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: payroll_period_lock fk_period_lock_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_period_lock
    ADD CONSTRAINT fk_period_lock_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: statutory_rule_set fk_rule_set_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_rule_set
    ADD CONSTRAINT fk_rule_set_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: salary_structure fk_salary_structure_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.salary_structure
    ADD CONSTRAINT fk_salary_structure_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: statutory_component_definition fk_scd_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_definition
    ADD CONSTRAINT fk_scd_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: statutory_component_mapping fk_scm_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_mapping
    ADD CONSTRAINT fk_scm_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: statutory_component_mapping fk_scm_definition; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_mapping
    ADD CONSTRAINT fk_scm_definition FOREIGN KEY (company_id, statutory_code) REFERENCES payroll.statutory_component_definition(company_id, statutory_code) ON DELETE CASCADE;


--
-- Name: statutory_component_mapping fk_scm_ruleset; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_component_mapping
    ADD CONSTRAINT fk_scm_ruleset FOREIGN KEY (rule_set_id) REFERENCES payroll.statutory_rule_set(rule_set_id) ON DELETE CASCADE;


--
-- Name: statutory_contribution_rule fk_scr_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_contribution_rule
    ADD CONSTRAINT fk_scr_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: statutory_contribution_rule fk_scr_component; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_contribution_rule
    ADD CONSTRAINT fk_scr_component FOREIGN KEY (company_id, statutory_code) REFERENCES payroll.statutory_component_definition(company_id, statutory_code) ON DELETE CASCADE;


--
-- Name: statutory_contribution_rule fk_scr_ruleset; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.statutory_contribution_rule
    ADD CONSTRAINT fk_scr_ruleset FOREIGN KEY (rule_set_id) REFERENCES payroll.statutory_rule_set(rule_set_id) ON DELETE CASCADE;


--
-- Name: payroll_snapshot fk_snapshot_run; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_snapshot
    ADD CONSTRAINT fk_snapshot_run FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE;


--
-- Name: salary_structure_component fk_ssc_structure; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.salary_structure_component
    ADD CONSTRAINT fk_ssc_structure FOREIGN KEY (salary_structure_id) REFERENCES payroll.salary_structure(salary_structure_id) ON DELETE CASCADE;


--
-- Name: company_statutory_profile fk_stat_profile_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_statutory_profile
    ADD CONSTRAINT fk_stat_profile_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: tax_declaration fk_tax_declaration_type; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration
    ADD CONSTRAINT fk_tax_declaration_type FOREIGN KEY (company_id, declaration_type) REFERENCES payroll.tax_declaration_type(company_id, type_code);


--
-- Name: company_tax_slab fk_tax_slab_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_tax_slab
    ADD CONSTRAINT fk_tax_slab_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: company_tax_slab fk_tax_slab_definition; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_tax_slab
    ADD CONSTRAINT fk_tax_slab_definition FOREIGN KEY (company_id, statutory_code) REFERENCES payroll.statutory_component_definition(company_id, statutory_code) ON DELETE CASCADE;


--
-- Name: company_tax_slab fk_tax_slab_ruleset; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.company_tax_slab
    ADD CONSTRAINT fk_tax_slab_ruleset FOREIGN KEY (rule_set_id) REFERENCES payroll.statutory_rule_set(rule_set_id) ON DELETE CASCADE;


--
-- Name: payslip_template fk_template_company; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payslip_template
    ADD CONSTRAINT fk_template_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: loan_payment loan_payment_emi_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.loan_payment
    ADD CONSTRAINT loan_payment_emi_id_fkey FOREIGN KEY (emi_id) REFERENCES payroll.emi_transaction(emi_id) ON DELETE SET NULL;


--
-- Name: loan_payment loan_payment_loan_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.loan_payment
    ADD CONSTRAINT loan_payment_loan_id_fkey FOREIGN KEY (loan_id) REFERENCES payroll.employee_loan(loan_id) ON DELETE CASCADE;


--
-- Name: loan_payment loan_payment_payroll_run_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.loan_payment
    ADD CONSTRAINT loan_payment_payroll_run_id_fkey FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE SET NULL;


--
-- Name: payroll_component payroll_component_company_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payroll_component
    ADD CONSTRAINT payroll_component_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: payslip payslip_payroll_run_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payslip
    ADD CONSTRAINT payslip_payroll_run_id_fkey FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id) ON DELETE CASCADE;


--
-- Name: payslip payslip_user_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.payslip
    ADD CONSTRAINT payslip_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: tax_declaration tax_declaration_company_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration
    ADD CONSTRAINT tax_declaration_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: tax_declaration_type tax_declaration_type_company_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration_type
    ADD CONSTRAINT tax_declaration_type_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: tax_declaration tax_declaration_user_id_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration
    ADD CONSTRAINT tax_declaration_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: tax_declaration tax_declaration_verified_by_fkey; Type: FK CONSTRAINT; Schema: payroll; Owner: auth_user
--

ALTER TABLE ONLY payroll.tax_declaration
    ADD CONSTRAINT tax_declaration_verified_by_fkey FOREIGN KEY (verified_by) REFERENCES public.users(user_id);


--
-- Name: admin_users admin_users_reports_to_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_reports_to_fkey FOREIGN KEY (reports_to) REFERENCES public.admin_users(admin_id);


--
-- Name: attendance_device_trust_history attendance_device_trust_history_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_trust_history
    ADD CONSTRAINT attendance_device_trust_history_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.attendance_devices(device_id);


--
-- Name: attendance_devices attendance_devices_source_type_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_devices
    ADD CONSTRAINT attendance_devices_source_type_fkey FOREIGN KEY (source_type) REFERENCES public.attendance_source_types(source_type);


--
-- Name: attendance_user_device_identifiers attendance_user_device_identifiers_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_user_device_identifiers
    ADD CONSTRAINT attendance_user_device_identifiers_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.attendance_devices(device_id);


--
-- Name: attendance_user_device_identifiers attendance_user_device_identifiers_source_type_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_user_device_identifiers
    ADD CONSTRAINT attendance_user_device_identifiers_source_type_fkey FOREIGN KEY (source_type) REFERENCES public.attendance_source_types(source_type);


--
-- Name: employee_department_history employee_department_history_department_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_department_history
    ADD CONSTRAINT employee_department_history_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(department_id);


--
-- Name: employee_department_history employee_department_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_department_history
    ADD CONSTRAINT employee_department_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_documents employee_documents_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_documents
    ADD CONSTRAINT employee_documents_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_documents employee_documents_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_documents
    ADD CONSTRAINT employee_documents_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_exit employee_exit_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_exit
    ADD CONSTRAINT employee_exit_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_exit employee_exit_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_exit
    ADD CONSTRAINT employee_exit_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_profiles employee_profiles_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_profiles
    ADD CONSTRAINT employee_profiles_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: employee_profiles employee_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_profiles
    ADD CONSTRAINT employee_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: employee_role_history employee_role_history_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_role_history
    ADD CONSTRAINT employee_role_history_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id);


--
-- Name: employee_role_history employee_role_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_role_history
    ADD CONSTRAINT employee_role_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: admin_avatars fk_admin_avatars_admin; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_avatars
    ADD CONSTRAINT fk_admin_avatars_admin FOREIGN KEY (admin_id) REFERENCES public.admin_users(admin_id) ON DELETE CASCADE;


--
-- Name: admin_role_departments fk_admin_role_departments_department; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_role_departments
    ADD CONSTRAINT fk_admin_role_departments_department FOREIGN KEY (system_department_id) REFERENCES public.system_departments(system_department_id) ON DELETE CASCADE;


--
-- Name: admin_role_departments fk_admin_role_departments_role; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_role_departments
    ADD CONSTRAINT fk_admin_role_departments_role FOREIGN KEY (admin_role_id) REFERENCES public.admin_roles(admin_role_id) ON DELETE CASCADE;


--
-- Name: admin_role_permissions fk_admin_role_perms_permission; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_role_permissions
    ADD CONSTRAINT fk_admin_role_perms_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(permission_id) ON DELETE CASCADE;


--
-- Name: admin_role_permissions fk_admin_role_perms_role; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_role_permissions
    ADD CONSTRAINT fk_admin_role_perms_role FOREIGN KEY (admin_role_id) REFERENCES public.admin_roles(admin_role_id) ON DELETE CASCADE;


--
-- Name: admin_users fk_admin_users_role; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT fk_admin_users_role FOREIGN KEY (admin_role_id) REFERENCES public.admin_roles(admin_role_id);


--
-- Name: attendance_events fk_att_events_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_events
    ADD CONSTRAINT fk_att_events_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: attendance_events fk_att_events_source; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_events
    ADD CONSTRAINT fk_att_events_source FOREIGN KEY (source_id) REFERENCES public.attendance_sources(source_id);


--
-- Name: attendance_events fk_att_events_source_type; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_events
    ADD CONSTRAINT fk_att_events_source_type FOREIGN KEY (source_type) REFERENCES public.attendance_source_types(source_type);


--
-- Name: attendance_events fk_att_events_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_events
    ADD CONSTRAINT fk_att_events_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: attendance_locations fk_att_locations_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_locations
    ADD CONSTRAINT fk_att_locations_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: attendance_daily_summary fk_att_summary_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_daily_summary
    ADD CONSTRAINT fk_att_summary_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: attendance_daily_summary fk_att_summary_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_daily_summary
    ADD CONSTRAINT fk_att_summary_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: attendance_user_device_identifiers fk_attendance_enroll_created_by; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_user_device_identifiers
    ADD CONSTRAINT fk_attendance_enroll_created_by FOREIGN KEY (created_by) REFERENCES public.users(user_id);


--
-- Name: attendance_user_device_identifiers fk_attendance_enroll_employee; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_user_device_identifiers
    ADD CONSTRAINT fk_attendance_enroll_employee FOREIGN KEY (company_id, user_id) REFERENCES public.company_employees(company_id, user_id) ON DELETE CASCADE;


--
-- Name: attendance_events fk_attendance_events_event_type; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_events
    ADD CONSTRAINT fk_attendance_events_event_type FOREIGN KEY (event_type) REFERENCES public.attendance_event_types(event_type);


--
-- Name: attendance_policies fk_attendance_policies_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_policies
    ADD CONSTRAINT fk_attendance_policies_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: attendance_policies fk_attendance_policies_position; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_policies
    ADD CONSTRAINT fk_attendance_policies_position FOREIGN KEY (position_id) REFERENCES public.positions(position_id);


--
-- Name: attendance_sources fk_attendance_sources_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_sources
    ADD CONSTRAINT fk_attendance_sources_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: attendance_sources fk_attendance_sources_type; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_sources
    ADD CONSTRAINT fk_attendance_sources_type FOREIGN KEY (source_type) REFERENCES public.attendance_source_types(source_type);


--
-- Name: attendance_device_punch_batches fk_batch_device; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_punch_batches
    ADD CONSTRAINT fk_batch_device FOREIGN KEY (device_id) REFERENCES public.attendance_devices(device_id) ON DELETE CASCADE;


--
-- Name: work_calendars fk_calendar_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_calendars
    ADD CONSTRAINT fk_calendar_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: companies fk_companies_owner; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.companies
    ADD CONSTRAINT fk_companies_owner FOREIGN KEY (owner_user_id) REFERENCES public.users(user_id);


--
-- Name: company_attendance_rules fk_company_attendance_rules_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.company_attendance_rules
    ADD CONSTRAINT fk_company_attendance_rules_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: departments fk_departments_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT fk_departments_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: departments fk_departments_parent; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT fk_departments_parent FOREIGN KEY (parent_department_id) REFERENCES public.departments(department_id);


--
-- Name: departments fk_departments_system; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT fk_departments_system FOREIGN KEY (system_department_id) REFERENCES public.system_departments(system_department_id);


--
-- Name: department_attendance_rules fk_dept_att_rules_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.department_attendance_rules
    ADD CONSTRAINT fk_dept_att_rules_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: department_attendance_rules fk_dept_att_rules_department; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.department_attendance_rules
    ADD CONSTRAINT fk_dept_att_rules_department FOREIGN KEY (department_id) REFERENCES public.departments(department_id) ON DELETE CASCADE;


--
-- Name: attendance_device_tokens fk_device_token_device; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_tokens
    ADD CONSTRAINT fk_device_token_device FOREIGN KEY (device_id) REFERENCES public.attendance_devices(device_id) ON DELETE CASCADE;


--
-- Name: employee_profiles fk_employee_profile_membership; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.employee_profiles
    ADD CONSTRAINT fk_employee_profile_membership FOREIGN KEY (company_id, user_id) REFERENCES public.company_employees(company_id, user_id) ON DELETE CASCADE;


--
-- Name: company_employees fk_employees_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.company_employees
    ADD CONSTRAINT fk_employees_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: company_employees fk_employees_role; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.company_employees
    ADD CONSTRAINT fk_employees_role FOREIGN KEY (role_id) REFERENCES public.roles(role_id);


--
-- Name: company_employees fk_employees_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.company_employees
    ADD CONSTRAINT fk_employees_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: user_off_entitlements fk_ent_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_off_entitlements
    ADD CONSTRAINT fk_ent_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: user_off_entitlements fk_ent_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_off_entitlements
    ADD CONSTRAINT fk_ent_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: attendance_device_punch_failures fk_failure_batch; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_punch_failures
    ADD CONSTRAINT fk_failure_batch FOREIGN KEY (batch_id) REFERENCES public.attendance_device_punch_batches(batch_id) ON DELETE CASCADE;


--
-- Name: attendance_device_heartbeats fk_heartbeat_device; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.attendance_device_heartbeats
    ADD CONSTRAINT fk_heartbeat_device FOREIGN KEY (device_id) REFERENCES public.attendance_devices(device_id) ON DELETE CASCADE;


--
-- Name: login_attempts fk_login_attempts_device; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT fk_login_attempts_device FOREIGN KEY (device_id) REFERENCES public.user_devices(device_id);


--
-- Name: login_attempts fk_login_attempts_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT fk_login_attempts_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: off_requests fk_or_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.off_requests
    ADD CONSTRAINT fk_or_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: off_requests fk_or_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.off_requests
    ADD CONSTRAINT fk_or_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: org_units fk_org_units_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_units
    ADD CONSTRAINT fk_org_units_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: org_units fk_org_units_department; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_units
    ADD CONSTRAINT fk_org_units_department FOREIGN KEY (department_id) REFERENCES public.departments(department_id);


--
-- Name: org_unit_members fk_oum_org_unit; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_members
    ADD CONSTRAINT fk_oum_org_unit FOREIGN KEY (org_unit_id) REFERENCES public.org_units(org_unit_id) ON DELETE CASCADE;


--
-- Name: org_unit_members fk_oum_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_members
    ADD CONSTRAINT fk_oum_user FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: org_unit_roles fk_our_org_unit; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_roles
    ADD CONSTRAINT fk_our_org_unit FOREIGN KEY (org_unit_id) REFERENCES public.org_units(org_unit_id) ON DELETE CASCADE;


--
-- Name: org_unit_roles fk_our_position; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_roles
    ADD CONSTRAINT fk_our_position FOREIGN KEY (position_id) REFERENCES public.positions(position_id);


--
-- Name: org_unit_roles fk_our_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.org_unit_roles
    ADD CONSTRAINT fk_our_user FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: positions fk_positions_work_center; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.positions
    ADD CONSTRAINT fk_positions_work_center FOREIGN KEY (company_id, work_center_code) REFERENCES public.work_centers(company_id, work_center_code);


--
-- Name: role_departments fk_role_departments_department; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.role_departments
    ADD CONSTRAINT fk_role_departments_department FOREIGN KEY (department_id) REFERENCES public.departments(department_id);


--
-- Name: role_departments fk_role_departments_role; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.role_departments
    ADD CONSTRAINT fk_role_departments_role FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- Name: role_permissions fk_role_perms_permission; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT fk_role_perms_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(permission_id) ON DELETE CASCADE;


--
-- Name: role_permissions fk_role_perms_role; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT fk_role_perms_role FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- Name: roles fk_roles_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT fk_roles_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: schedule_templates fk_schedule_calendar; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_templates
    ADD CONSTRAINT fk_schedule_calendar FOREIGN KEY (calendar_id) REFERENCES public.work_calendars(calendar_id);


--
-- Name: schedule_templates fk_schedule_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_templates
    ADD CONSTRAINT fk_schedule_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: schedule_instances fk_schedule_instances_work_center; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_instances
    ADD CONSTRAINT fk_schedule_instances_work_center FOREIGN KEY (company_id, work_center_code) REFERENCES public.work_centers(company_id, work_center_code);


--
-- Name: schedule_instances fk_si_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_instances
    ADD CONSTRAINT fk_si_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: schedule_instances fk_si_template; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_instances
    ADD CONSTRAINT fk_si_template FOREIGN KEY (schedule_template_id) REFERENCES public.schedule_templates(schedule_template_id);


--
-- Name: schedule_instances fk_si_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_instances
    ADD CONSTRAINT fk_si_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: schedule_overrides fk_so_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_overrides
    ADD CONSTRAINT fk_so_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: schedule_overrides fk_so_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.schedule_overrides
    ADD CONSTRAINT fk_so_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: user_attendance_policies fk_uap_policy; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_attendance_policies
    ADD CONSTRAINT fk_uap_policy FOREIGN KEY (policy_id) REFERENCES public.attendance_policies(policy_id);


--
-- Name: user_attendance_policies fk_uap_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_attendance_policies
    ADD CONSTRAINT fk_uap_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: user_schedule_assignments fk_usa_template; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_schedule_assignments
    ADD CONSTRAINT fk_usa_template FOREIGN KEY (schedule_template_id) REFERENCES public.schedule_templates(schedule_template_id);


--
-- Name: user_schedule_assignments fk_usa_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_schedule_assignments
    ADD CONSTRAINT fk_usa_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: user_attendance_profiles fk_user_att_profile_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_attendance_profiles
    ADD CONSTRAINT fk_user_att_profile_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: user_attendance_profiles fk_user_att_profile_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_attendance_profiles
    ADD CONSTRAINT fk_user_att_profile_user FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_avatars fk_user_avatars_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_avatars
    ADD CONSTRAINT fk_user_avatars_user FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_devices fk_user_devices_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT fk_user_devices_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: user_work_center_assignments fk_user_work_center_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_work_center_assignments
    ADD CONSTRAINT fk_user_work_center_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id);


--
-- Name: user_work_center_assignments fk_user_work_center_user; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_work_center_assignments
    ADD CONSTRAINT fk_user_work_center_user FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: user_work_center_assignments fk_uwca_work_center; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.user_work_center_assignments
    ADD CONSTRAINT fk_uwca_work_center FOREIGN KEY (company_id, work_center_code) REFERENCES public.work_centers(company_id, work_center_code);


--
-- Name: work_center_shifts fk_wcs_work_center; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_center_shifts
    ADD CONSTRAINT fk_wcs_work_center FOREIGN KEY (company_id, work_center_code) REFERENCES public.work_centers(company_id, work_center_code);


--
-- Name: work_center_shifts fk_work_center_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_center_shifts
    ADD CONSTRAINT fk_work_center_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: work_center_shifts fk_work_center_shift; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_center_shifts
    ADD CONSTRAINT fk_work_center_shift FOREIGN KEY (shift_id) REFERENCES public.schedule_templates(schedule_template_id) ON DELETE CASCADE;


--
-- Name: work_centers fk_work_centers_company; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.work_centers
    ADD CONSTRAINT fk_work_centers_company FOREIGN KEY (company_id) REFERENCES public.companies(company_id) ON DELETE CASCADE;


--
-- Name: positions positions_department_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: auth_user
--

ALTER TABLE ONLY public.positions
    ADD CONSTRAINT positions_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(department_id);


--
-- PostgreSQL database dump complete
--

\unrestrict 7s5fHEFJfjbdl2IYRqxH2UvZp7viyghq8bxtRll80ObTF40gKg92STNH3DLfffg

