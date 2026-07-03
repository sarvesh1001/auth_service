#!/bin/bash
set -e
echo "🧬 Initializing biometric schema..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE SCHEMA IF NOT EXISTS attendance;
CREATE SCHEMA IF NOT EXISTS biometric;

CREATE TABLE IF NOT EXISTS attendance.attendance_source_types (
    source_type        VARCHAR(30) PRIMARY KEY,
    description        TEXT NOT NULL,
    category           VARCHAR(30) NOT NULL,
    requires_device    BOOLEAN NOT NULL DEFAULT false,
    is_system          BOOLEAN NOT NULL DEFAULT false,
    allow_backdated    BOOLEAN NOT NULL DEFAULT false,
    allow_future       BOOLEAN NOT NULL DEFAULT false,
    trust_level        SMALLINT NOT NULL DEFAULT 1,
    is_self_service    BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attendance.attendance_devices (
    device_id        VARCHAR(256) PRIMARY KEY,
    company_id       UUID NOT NULL,
    source_type      VARCHAR(30) NOT NULL,
    device_code      VARCHAR(100) NOT NULL,
    device_name      VARCHAR(100),
    manufacturer     VARCHAR(100),
    model            VARCHAR(100),
    work_center_code VARCHAR(100),
    location_id      UUID,
    ip_address       INET,
    mac_address      VARCHAR(50),
    is_active        BOOLEAN NOT NULL DEFAULT true,
    is_trusted       BOOLEAN NOT NULL DEFAULT true,
    last_seen_at     TIMESTAMPTZ,
    installed_at     TIMESTAMPTZ,
    last_punch_at    TIMESTAMPTZ,
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, device_code),
    UNIQUE (company_id, device_id),   -- ✅ FIX: added this unique constraint
    FOREIGN KEY (source_type) REFERENCES attendance.attendance_source_types(source_type)
);

CREATE TABLE IF NOT EXISTS attendance.attendance_device_tokens (
    token_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    device_id      VARCHAR(64) NOT NULL,
    source_type    VARCHAR(32) NOT NULL,
    token_hash     TEXT NOT NULL,
    token_version  INT NOT NULL DEFAULT 1,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    issued_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    issued_by      UUID,
    revoked_by     UUID,
    revoke_reason  TEXT,
    metadata       JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_device_token_device FOREIGN KEY (device_id) REFERENCES attendance.attendance_devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.attendance_device_heartbeats (
    heartbeat_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    device_id        VARCHAR(256) NOT NULL,
    source_type      VARCHAR(30) NOT NULL,
    device_time      TIMESTAMPTZ,
    server_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    firmware_version TEXT,
    ip_address       INET,
    status           VARCHAR(20) NOT NULL DEFAULT 'online',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_heartbeat_device FOREIGN KEY (device_id) REFERENCES attendance.attendance_devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.attendance_device_punch_batches (
    batch_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    device_id      VARCHAR(256) NOT NULL,
    batch_ref      TEXT NOT NULL,
    total_events   INT NOT NULL,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at   TIMESTAMPTZ,
    status         VARCHAR(30) NOT NULL DEFAULT 'pending',
    failure_reason TEXT,
    CONSTRAINT fk_batch_device FOREIGN KEY (device_id) REFERENCES attendance.attendance_devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.attendance_device_punch_failures (
    failure_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id        UUID NOT NULL,
    company_id      UUID NOT NULL,
    device_id       VARCHAR(256) NOT NULL,
    device_user_code VARCHAR(100),
    event_type      VARCHAR(30),
    event_time      TIMESTAMPTZ,
    failure_reason  TEXT NOT NULL,
    raw_event       JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_failure_batch FOREIGN KEY (batch_id) REFERENCES attendance.attendance_device_punch_batches (batch_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.attendance_device_trust_history (
    trust_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id  VARCHAR(256) NOT NULL,
    company_id UUID NOT NULL,
    action     VARCHAR(20) NOT NULL,
    reason     TEXT,
    acted_by   UUID,
    acted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id) REFERENCES attendance.attendance_devices(device_id)
);

CREATE TABLE IF NOT EXISTS attendance.device_enrollments (
    mapping_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id        UUID NOT NULL,
    subject_type      VARCHAR(20) NOT NULL,          -- 'employee', 'student', 'customer'
    subject_id        UUID NOT NULL,                 -- user_id, student_id, customer_id
    device_id         VARCHAR(256) NOT NULL,
    source_type       VARCHAR(30) NOT NULL,
    device_user_code  VARCHAR(100) NOT NULL,
    is_active         BOOLEAN NOT NULL DEFAULT true,
    enrolled_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    unenrolled_at     TIMESTAMPTZ,
    created_by        UUID,
    enrollment_version INT NOT NULL DEFAULT 1,
    revoked_reason    TEXT,
    revoked_by        UUID,
    last_used_at      TIMESTAMPTZ,
    FOREIGN KEY (company_id, device_id) REFERENCES attendance.attendance_devices(company_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (source_type) REFERENCES attendance.attendance_source_types(source_type),
    UNIQUE (company_id, device_id, source_type, device_user_code)  -- one active enrollment per device+code
);

CREATE INDEX idx_device_enrollments_subject ON attendance.device_enrollments(company_id, subject_type, subject_id) WHERE is_active = true;
CREATE INDEX idx_device_enrollments_device_code ON attendance.device_enrollments(company_id, device_id, device_user_code) WHERE is_active = true;

CREATE TABLE IF NOT EXISTS attendance.attendance_sources (
    source_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    source_type    VARCHAR(30) NOT NULL,
    name           VARCHAR(100) NOT NULL,
    reference_type VARCHAR(30),
    reference_id   UUID,
    is_active      BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     UUID,
    CONSTRAINT fk_attendance_sources_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_attendance_sources_type FOREIGN KEY (source_type) REFERENCES attendance.attendance_source_types(source_type)
);

CREATE TABLE IF NOT EXISTS attendance.attendance_event_types (
    event_type          VARCHAR(30) PRIMARY KEY,
    category            VARCHAR(30) NOT NULL,
    description         TEXT,
    is_user_triggered   BOOLEAN NOT NULL DEFAULT true,
    is_system_generated BOOLEAN NOT NULL DEFAULT false,
    is_active           BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS attendance.attendance_events (
    attendance_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    subject_type        VARCHAR(20) NOT NULL,        -- 'employee', 'student', 'customer'
    subject_id          UUID NOT NULL,               -- user_id, student_id, customer_id
    event_type          VARCHAR(30) NOT NULL,
    event_time          TIMESTAMPTZ NOT NULL,
    source_type         VARCHAR(30) NOT NULL,
    source_id           UUID,
    device_id           VARCHAR(256),
    device_user_code    VARCHAR(100),
    ip_address          VARCHAR(64),
    metadata            JSONB,
    context             JSONB,
    raw_event_payload   JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID,
    event_date          DATE GENERATED ALWAYS AS ((event_time AT TIME ZONE 'UTC')::date) STORED,
    CONSTRAINT fk_att_events_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_att_events_source_type FOREIGN KEY (source_type) REFERENCES attendance.attendance_source_types(source_type),
    CONSTRAINT fk_att_events_source FOREIGN KEY (source_id) REFERENCES attendance.attendance_sources(source_id),
    CONSTRAINT fk_attendance_events_event_type FOREIGN KEY (event_type) REFERENCES attendance.attendance_event_types(event_type)
);

CREATE INDEX idx_att_events_subject_time ON attendance.attendance_events (company_id, subject_type, subject_id, event_time DESC);
CREATE INDEX idx_att_events_company_event_date ON attendance.attendance_events (company_id, event_date);

CREATE TABLE IF NOT EXISTS attendance.attendance_policies (
    policy_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    work_center_code TEXT,
    position_id      UUID,
    policy_code      VARCHAR(50) NOT NULL,
    policy_type      VARCHAR(30) NOT NULL,
    rules            JSONB NOT NULL,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, policy_code),
    CONSTRAINT fk_attendance_policies_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_attendance_policies_position FOREIGN KEY (position_id) REFERENCES positions(position_id)
);

CREATE TABLE IF NOT EXISTS attendance.user_attendance_policies (
    user_id        UUID NOT NULL,
    policy_id      UUID NOT NULL,
    effective_from DATE NOT NULL,
    effective_to   DATE,
    assigned_by    UUID,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, policy_id, effective_from),
    CONSTRAINT fk_uap_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_uap_policy FOREIGN KEY (policy_id) REFERENCES attendance.attendance_policies(policy_id)
);

CREATE TABLE IF NOT EXISTS attendance.attendance_daily_summary (
    attendance_summary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL,
    subject_type          VARCHAR(20) NOT NULL,
    subject_id            UUID NOT NULL,
    attendance_date       DATE NOT NULL,
    status                VARCHAR(30) NOT NULL,
    worked_minutes        INTEGER,
    overtime_minutes      INTEGER,
    late_minutes          INTEGER,
    expected_minutes      INTEGER,
    metadata              JSONB,
    generated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by          VARCHAR(30) DEFAULT 'system',
    is_payroll_locked     BOOLEAN NOT NULL DEFAULT false,
    is_finalized          BOOLEAN NOT NULL DEFAULT false,
    is_payable            BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (company_id, subject_type, subject_id, attendance_date)
);

CREATE INDEX idx_att_summary_subject_date ON attendance.attendance_daily_summary (company_id, subject_type, subject_id, attendance_date DESC);

CREATE TABLE IF NOT EXISTS attendance.attendance_locations (
    location_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id    UUID NOT NULL,
    name          VARCHAR(100),
    location_type VARCHAR(30),
    geo_lat       NUMERIC,
    geo_lng       NUMERIC,
    location_code VARCHAR(50),
    zone          VARCHAR(100),
    is_active     BOOLEAN DEFAULT true,
    CONSTRAINT fk_att_locations_company FOREIGN KEY (company_id) REFERENCES companies(company_id)
);

CREATE TABLE IF NOT EXISTS attendance.work_centers (
    work_center_code VARCHAR(100) NOT NULL,
    company_id       UUID NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    timezone         VARCHAR(50) NOT NULL DEFAULT 'UTC',
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_work_centers_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    PRIMARY KEY (company_id, work_center_code)
);

CREATE TABLE IF NOT EXISTS attendance.work_calendars (
    calendar_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID NOT NULL,
    year         INTEGER NOT NULL,
    name         VARCHAR(100) NOT NULL,
    timezone     VARCHAR(50) NOT NULL DEFAULT 'UTC',
    working_days INTEGER[] NOT NULL,
    holidays     JSONB,
    is_active    BOOLEAN DEFAULT true,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_calendar_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT uq_work_calendar_company_year UNIQUE (company_id, year)
);

CREATE TABLE IF NOT EXISTS attendance.schedule_templates (
    schedule_template_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    calendar_id          UUID NOT NULL,
    template_type        VARCHAR(30) NOT NULL,
    name                 VARCHAR(100) NOT NULL,
    rules                JSONB NOT NULL,
    is_active            BOOLEAN DEFAULT true,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT chk_template_type CHECK (template_type IN ('office', 'shift', 'class')),
    CONSTRAINT fk_schedule_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_schedule_calendar FOREIGN KEY (calendar_id) REFERENCES attendance.work_calendars(calendar_id)
);

CREATE TABLE IF NOT EXISTS attendance.user_schedule_assignments (
    user_id              UUID NOT NULL,
    schedule_template_id UUID NOT NULL,
    effective_from       DATE NOT NULL,
    effective_to         DATE,
    assigned_by          UUID,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, schedule_template_id, effective_from),
    CONSTRAINT no_overlapping_schedules EXCLUDE USING gist (
        user_id WITH =,
        daterange(effective_from, COALESCE(effective_to, 'infinity'), '[]') WITH &&
    ),
    CONSTRAINT fk_usa_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_usa_template FOREIGN KEY (schedule_template_id) REFERENCES attendance.schedule_templates(schedule_template_id)
);

CREATE TABLE IF NOT EXISTS attendance.schedule_instances (
    schedule_instance_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    user_id              UUID NOT NULL,
    schedule_date        DATE NOT NULL,
    schedule_template_id UUID NOT NULL,
    expected_start       TIMESTAMPTZ,
    expected_end         TIMESTAMPTZ,
    timezone             VARCHAR(50) NOT NULL DEFAULT 'UTC',
    metadata             JSONB,
    generated_at         TIMESTAMPTZ DEFAULT NOW(),
    status               VARCHAR(20) NOT NULL DEFAULT 'active',
    cancel_reason        VARCHAR(50),
    cancelled_at         TIMESTAMPTZ,
    work_center_code     VARCHAR(100),
    device_user_code     VARCHAR(100),
    raw_event_payload    JSONB,
    CONSTRAINT fk_si_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_si_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_si_template FOREIGN KEY (schedule_template_id) REFERENCES attendance.schedule_templates(schedule_template_id),
    CONSTRAINT fk_schedule_instances_work_center FOREIGN KEY (company_id, work_center_code)
        REFERENCES attendance.work_centers(company_id, work_center_code)
);

CREATE TABLE IF NOT EXISTS attendance.work_center_shifts (
    mapping_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id        UUID NOT NULL,
    work_center_code  VARCHAR(100) NOT NULL,
    shift_id          UUID NOT NULL,
    effective_from    DATE NOT NULL,
    effective_to      DATE,
    is_active         BOOLEAN DEFAULT true,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_work_center_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_work_center_shift FOREIGN KEY (shift_id) REFERENCES attendance.schedule_templates(schedule_template_id) ON DELETE CASCADE,
    CONSTRAINT fk_wcs_work_center FOREIGN KEY (company_id, work_center_code) REFERENCES attendance.work_centers(company_id, work_center_code),
    CONSTRAINT no_overlap_work_center_shifts EXCLUDE USING gist (
        company_id WITH =,
        work_center_code WITH =,
        daterange(effective_from, COALESCE(effective_to, 'infinity')) WITH &&
    )
);

CREATE TABLE IF NOT EXISTS attendance.user_work_center_assignments (
    assignment_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id        UUID NOT NULL,
    user_id           UUID NOT NULL,
    work_center_code  VARCHAR(100) NOT NULL,
    effective_from    DATE NOT NULL,
    effective_to      DATE,
    is_active         BOOLEAN DEFAULT true,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (user_id, work_center_code, effective_from),
    CONSTRAINT fk_user_work_center_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_user_work_center_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_uwca_work_center FOREIGN KEY (company_id, work_center_code) REFERENCES attendance.work_centers(company_id, work_center_code)
);

CREATE TABLE IF NOT EXISTS attendance.company_attendance_rules (
    company_id              UUID PRIMARY KEY,
    allowed_source_types    VARCHAR(30)[] NOT NULL,
    allow_multiple_checkins BOOLEAN NOT NULL DEFAULT false,
    timezone                VARCHAR(50) NOT NULL DEFAULT 'UTC',
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_company_attendance_rules_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.department_attendance_rules (
    rule_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id              UUID NOT NULL,
    department_id           UUID NOT NULL,
    allowed_source_types    VARCHAR(30)[] NOT NULL,
    allowed_event_types     VARCHAR(30)[] NOT NULL,
    require_location        BOOLEAN NOT NULL DEFAULT false,
    require_device          BOOLEAN NOT NULL DEFAULT false,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (company_id, department_id),
    CONSTRAINT fk_dept_att_rules_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_dept_att_rules_department FOREIGN KEY (department_id) REFERENCES departments(department_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.user_attendance_profiles (
    user_id                 UUID PRIMARY KEY,
    company_id              UUID NOT NULL,
    override_source_types   VARCHAR(30)[],
    override_event_types    VARCHAR(30)[],
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_user_att_profile_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_user_att_profile_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance.user_off_entitlements (
    entitlement_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    period_type      VARCHAR(20) NOT NULL,
    off_count        INTEGER NOT NULL,
    requires_approval BOOLEAN DEFAULT true,
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_ent_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_ent_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT chk_period_type CHECK (period_type IN ('weekly','monthly'))
);

CREATE TABLE IF NOT EXISTS attendance.off_requests (
    off_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    user_id        UUID NOT NULL,
    request_dates  DATE[] NOT NULL,
    status         VARCHAR(20) DEFAULT 'pending',
    requested_by   UUID,
    approved_by    UUID,
    approved_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_or_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_or_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS attendance.schedule_overrides (
    override_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    user_id        UUID NOT NULL,
    override_date  DATE NOT NULL,
    override_type  VARCHAR(20) NOT NULL,
    reason         TEXT,
    created_by     UUID,
    created_at     TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (user_id, override_date),
    CONSTRAINT fk_so_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_so_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT chk_override_type CHECK (override_type IN ('off','force_work','holiday_override'))
);

CREATE TABLE IF NOT EXISTS attendance.attendance_events_outbox (
    outbox_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   VARCHAR(50) NOT NULL,
    aggregate_id UUID NOT NULL,
    payload      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attendance.attendance_batch_outbox (
    outbox_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type    VARCHAR(50) NOT NULL,
    aggregate_id  UUID NOT NULL,
    payload       JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at  TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS biometric.unified_face_embeddings (
    embedding_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    subject_type     VARCHAR(20) NOT NULL,          -- 'employee', 'student', 'customer'
    subject_id       UUID NOT NULL,                 -- user_id, student_id, customer_id
    embedding_vector DOUBLE PRECISION[] NOT NULL,
    model_version    VARCHAR(50) NOT NULL,
    embedding_dim    INTEGER NOT NULL,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT face_embeddings_embedding_dim_check CHECK (embedding_dim IN (128,512)),
    UNIQUE (company_id, subject_type, subject_id)   -- one active embedding per subject
);

CREATE TABLE IF NOT EXISTS biometric.device_embedding_sync (
    sync_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    device_id      VARCHAR(256) NOT NULL,
    model_version  VARCHAR(50) NOT NULL,
    last_synced_at TIMESTAMPTZ,
    last_full_sync TIMESTAMPTZ,
    created_at     TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT unique_company_device UNIQUE (company_id, device_id),
    CONSTRAINT fk_device_sync_device
        FOREIGN KEY (device_id)
        REFERENCES attendance.attendance_devices(device_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS biometric.unified_embedding_audit_log (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL,
    subject_type    VARCHAR(20) NOT NULL,
    subject_id      UUID NOT NULL,
    action          VARCHAR(30) NOT NULL,
    model_version   VARCHAR(50),
    acted_by        UUID,
    created_at      TIMESTAMPTZ DEFAULT now(),
    metadata        JSONB
);

CREATE TABLE IF NOT EXISTS academics.student_attendance (
    attendance_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrollment_id   UUID NOT NULL REFERENCES academics.enrollments(enrollment_id) ON DELETE CASCADE,
    attendance_date DATE NOT NULL,
    status          VARCHAR(20) NOT NULL CHECK (status IN ('present','absent','late','half-day','holiday','exempted')),
    marked_by       UUID REFERENCES users(user_id),
    remarks         TEXT,
    source_type     VARCHAR(30),
    device_id       VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES users(user_id),
    UNIQUE (enrollment_id, attendance_date)
);

CREATE TABLE IF NOT EXISTS academics.student_attendance_summary (
    summary_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id      UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
    academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
    term_id         UUID REFERENCES academics.term(term_id) ON DELETE CASCADE,
    total_present   INTEGER DEFAULT 0,
    total_absent    INTEGER DEFAULT 0,
    total_late      INTEGER DEFAULT 0,
    total_half_day  INTEGER DEFAULT 0,
    total_working_days INTEGER DEFAULT 0,
    attendance_percentage NUMERIC(5,2) GENERATED ALWAYS AS (
        CASE
            WHEN total_working_days > 0 THEN (total_present::NUMERIC / total_working_days) * 100
            ELSE 0
        END
    ) STORED,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (student_id, academic_year_id, term_id)
);

CREATE TABLE IF NOT EXISTS academics.student_attendance_exemptions (
    exemption_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id      UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
    from_date       DATE NOT NULL,
    to_date         DATE NOT NULL,
    reason          TEXT,
    approved_by     UUID REFERENCES users(user_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES users(user_id),
    CONSTRAINT check_dates CHECK (from_date <= to_date)
);

CREATE TABLE IF NOT EXISTS academics.academic_session (
    session_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timetable_entry_id  UUID NOT NULL REFERENCES academics.timetable_entries(entry_id) ON DELETE CASCADE,
    session_date        DATE NOT NULL,
    start_time          TIME NOT NULL,
    end_time            TIME NOT NULL,
    teacher_id          UUID REFERENCES academics.teachers(teacher_id),
    room_id             UUID REFERENCES academics.rooms(room_id),
    status              VARCHAR(20) NOT NULL DEFAULT 'scheduled'
                        CHECK (status IN ('scheduled', 'ongoing', 'completed', 'cancelled')),
    section_id          UUID NOT NULL REFERENCES academics.section(section_id),
    subject_id          UUID NOT NULL REFERENCES academics.subject(subject_id),
    slot_id             UUID NOT NULL REFERENCES academics.timetable_slots(slot_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID REFERENCES users(user_id),
    updated_by          UUID REFERENCES users(user_id),
    UNIQUE(timetable_entry_id, session_date)
);

CREATE TABLE IF NOT EXISTS academics.student_session_attendance (
    attendance_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES academics.academic_session(session_id) ON DELETE CASCADE,
    enrollment_id   UUID NOT NULL REFERENCES academics.enrollments(enrollment_id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL CHECK (status IN ('present', 'absent', 'late', 'excused')),
    marked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    marked_by       UUID REFERENCES users(user_id),
    source_type     VARCHAR(30) NOT NULL,
    device_id       VARCHAR(256),
    is_auto         BOOLEAN DEFAULT false,
    remarks         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(session_id, enrollment_id)
);

CREATE TABLE IF NOT EXISTS academics.attendance_session (
    session_mark_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES academics.academic_session(session_id) ON DELETE CASCADE,
    marked_by       UUID REFERENCES users(user_id),
    source_type     VARCHAR(20),
    status          VARCHAR(20) DEFAULT 'completed',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(session_id)
);

CREATE TABLE IF NOT EXISTS analytics.student_session_summary (
    student_id            UUID PRIMARY KEY REFERENCES academics.students(student_id),
    academic_year_id      UUID REFERENCES academics.academic_year(academic_year_id),
    term_id               UUID REFERENCES academics.term(term_id),
    total_sessions        INTEGER NOT NULL DEFAULT 0,
    present_sessions      INTEGER NOT NULL DEFAULT 0,
    absent_sessions       INTEGER NOT NULL DEFAULT 0,
    late_sessions         INTEGER NOT NULL DEFAULT 0,
    excused_sessions      INTEGER NOT NULL DEFAULT 0,
    attendance_percentage NUMERIC(5,2) GENERATED ALWAYS AS
        (CASE WHEN total_sessions > 0 THEN (present_sessions::NUMERIC / total_sessions) * 100 ELSE 0 END) STORED,
    last_updated          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analytics.section_session_metrics (
    section_id            UUID REFERENCES academics.section(section_id),
    session_date          DATE NOT NULL,
    total_enrolled        INTEGER NOT NULL,
    present_count         INTEGER NOT NULL,
    absent_count          INTEGER NOT NULL,
    late_count            INTEGER NOT NULL,
    marked_by_teacher     INTEGER,
    marked_by_biometric   INTEGER,
    PRIMARY KEY (section_id, session_date)
);

CREATE TABLE IF NOT EXISTS analytics.teacher_session_metrics (
    teacher_id            UUID REFERENCES academics.teachers(teacher_id),
    academic_year_id      UUID REFERENCES academics.academic_year(academic_year_id),
    total_sessions_taught INTEGER NOT NULL,
    sessions_marked       INTEGER NOT NULL,
    sessions_with_biometric INTEGER NOT NULL,
    last_updated          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (teacher_id, academic_year_id)
);

CREATE TABLE IF NOT EXISTS analytics.biometric_usage_metrics (
    device_id             VARCHAR(256),
    company_id            UUID REFERENCES companies(company_id),
    date                  DATE NOT NULL,
    total_punches         INTEGER NOT NULL,
    successful_matches    INTEGER NOT NULL,
    failed_matches        INTEGER NOT NULL,
    unique_students       INTEGER NOT NULL,
    PRIMARY KEY (device_id, date)
);

ALTER TABLE analytics.academic_year_metrics
ADD COLUMN IF NOT EXISTS total_sessions_generated      INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_period_attendances      INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_biometric_attendances   INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_manual_period_attendances INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_face_embeddings_active ON biometric.unified_face_embeddings(company_id, is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_face_embeddings_company ON biometric.unified_face_embeddings(company_id);
CREATE INDEX IF NOT EXISTS idx_face_embeddings_sync_lookup ON biometric.unified_face_embeddings(company_id, model_version, updated_at);
CREATE INDEX IF NOT EXISTS idx_face_embeddings_updated ON biometric.unified_face_embeddings(company_id, model_version, updated_at);
CREATE INDEX IF NOT EXISTS idx_device_embedding_sync_company ON biometric.device_embedding_sync(company_id);

CREATE INDEX IF NOT EXISTS idx_attendance_sources_company ON attendance.attendance_sources (company_id);
CREATE INDEX IF NOT EXISTS idx_attendance_sources_type ON attendance.attendance_sources (source_type);
CREATE INDEX IF NOT EXISTS idx_attendance_sources_active ON attendance.attendance_sources (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_attendance_events_company ON attendance.attendance_events (company_id);
CREATE INDEX IF NOT EXISTS idx_attendance_events_type ON attendance.attendance_events (event_type);
CREATE INDEX IF NOT EXISTS idx_attendance_events_source ON attendance.attendance_events (source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_attendance_events_event_date ON attendance.attendance_events (event_date);
CREATE INDEX IF NOT EXISTS idx_attendance_events_company_event_date ON attendance.attendance_events (company_id, event_date);
CREATE INDEX IF NOT EXISTS idx_attendance_events_user_type_time ON attendance.attendance_events (company_id, subject_type, subject_id, event_type, event_time DESC) WHERE source_type != 'correction';
CREATE INDEX IF NOT EXISTS idx_attendance_events_device_time ON attendance.attendance_events (company_id, subject_type, subject_id, device_id, event_type, event_time DESC) WHERE device_id IS NOT NULL AND source_type != 'correction';
CREATE INDEX IF NOT EXISTS idx_attendance_policies_company ON attendance.attendance_policies (company_id);
CREATE INDEX IF NOT EXISTS idx_attendance_policies_position ON attendance.attendance_policies (position_id) WHERE position_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_attendance_policies_active ON attendance.attendance_policies (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_user_attendance_policies_user ON attendance.user_attendance_policies (user_id);
CREATE INDEX IF NOT EXISTS idx_user_attendance_policies_policy ON attendance.user_attendance_policies (policy_id);
CREATE INDEX IF NOT EXISTS idx_user_attendance_policies_dates ON attendance.user_attendance_policies (effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_attendance_policies_effective ON attendance.user_attendance_policies (user_id, effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_attendance_daily_summary_subject_date ON attendance.attendance_daily_summary (company_id, subject_type, subject_id, attendance_date DESC);
CREATE INDEX IF NOT EXISTS idx_attendance_daily_summary_company ON attendance.attendance_daily_summary (company_id);
CREATE INDEX IF NOT EXISTS idx_attendance_daily_summary_status ON attendance.attendance_daily_summary (status);
CREATE INDEX IF NOT EXISTS idx_attendance_daily_summary_date_status ON attendance.attendance_daily_summary (attendance_date, status);
CREATE INDEX IF NOT EXISTS idx_attendance_locations_company ON attendance.attendance_locations (company_id);
CREATE INDEX IF NOT EXISTS idx_attendance_locations_active ON attendance.attendance_locations (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_attendance_locations_code ON attendance.attendance_locations (company_id, location_code) WHERE location_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_attendance_locations_zone ON attendance.attendance_locations (company_id, zone) WHERE zone IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_work_center_shifts_code ON attendance.work_center_shifts (work_center_code);
CREATE INDEX IF NOT EXISTS idx_work_center_shifts_company ON attendance.work_center_shifts (company_id);
CREATE INDEX IF NOT EXISTS idx_work_center_shifts_active ON attendance.work_center_shifts (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_work_center_shifts_dates ON attendance.work_center_shifts (effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_user_work_center_user ON attendance.user_work_center_assignments (user_id, is_active, effective_from DESC);
CREATE INDEX IF NOT EXISTS idx_user_work_center_company ON attendance.user_work_center_assignments (company_id, work_center_code, is_active);
CREATE INDEX IF NOT EXISTS idx_work_centers_company ON attendance.work_centers (company_id, is_active);
CREATE INDEX IF NOT EXISTS idx_work_calendars_company ON attendance.work_calendars (company_id);
CREATE INDEX IF NOT EXISTS idx_work_calendars_active ON attendance.work_calendars (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_schedule_templates_company ON attendance.schedule_templates (company_id);
CREATE INDEX IF NOT EXISTS idx_schedule_templates_calendar ON attendance.schedule_templates (calendar_id);
CREATE INDEX IF NOT EXISTS idx_schedule_templates_active ON attendance.schedule_templates (is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_user_schedule_assignments_user ON attendance.user_schedule_assignments (user_id);
CREATE INDEX IF NOT EXISTS idx_user_schedule_assignments_template ON attendance.user_schedule_assignments (schedule_template_id);
CREATE INDEX IF NOT EXISTS idx_user_schedule_assignments_dates ON attendance.user_schedule_assignments (effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_schedule_instances_user_date ON attendance.schedule_instances (user_id, schedule_date);
CREATE INDEX IF NOT EXISTS idx_schedule_instances_company ON attendance.schedule_instances (company_id);
CREATE INDEX IF NOT EXISTS idx_schedule_instances_template ON attendance.schedule_instances (schedule_template_id);
CREATE INDEX IF NOT EXISTS idx_schedule_instances_status ON attendance.schedule_instances (status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_company_attendance_rules_company ON attendance.company_attendance_rules (company_id);
CREATE INDEX IF NOT EXISTS idx_department_attendance_rules_dept ON attendance.department_attendance_rules (department_id);
CREATE INDEX IF NOT EXISTS idx_user_attendance_profiles_user ON attendance.user_attendance_profiles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_off_entitlements_user ON attendance.user_off_entitlements (user_id, company_id);
CREATE INDEX IF NOT EXISTS idx_off_requests_user ON attendance.off_requests (user_id, company_id);
CREATE INDEX IF NOT EXISTS idx_schedule_overrides_user_date ON attendance.schedule_overrides (user_id, override_date);
CREATE INDEX IF NOT EXISTS idx_attendance_outbox_unprocessed ON attendance.attendance_events_outbox (created_at) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_attendance_batch_outbox_unprocessed ON attendance.attendance_batch_outbox (created_at) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_attendance_enrollment ON academics.student_attendance(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON academics.student_attendance(attendance_date);
CREATE INDEX IF NOT EXISTS idx_attendance_status ON academics.student_attendance(status);
CREATE INDEX IF NOT EXISTS idx_att_summary_student ON academics.student_attendance_summary(student_id);
CREATE INDEX IF NOT EXISTS idx_att_summary_year ON academics.student_attendance_summary(academic_year_id);
CREATE INDEX IF NOT EXISTS idx_att_summary_term ON academics.student_attendance_summary(term_id);
CREATE INDEX IF NOT EXISTS idx_att_exempt_student ON academics.student_attendance_exemptions(student_id);
CREATE INDEX IF NOT EXISTS idx_att_exempt_dates ON academics.student_attendance_exemptions(from_date, to_date);
CREATE INDEX IF NOT EXISTS idx_academic_session_section_date ON academics.academic_session(section_id, session_date);
CREATE INDEX IF NOT EXISTS idx_academic_session_teacher_date ON academics.academic_session(teacher_id, session_date);
CREATE INDEX IF NOT EXISTS idx_academic_session_subject ON academics.academic_session(subject_id);
CREATE INDEX IF NOT EXISTS idx_academic_session_status ON academics.academic_session(status) WHERE status = 'ongoing';
CREATE INDEX IF NOT EXISTS idx_ssa_session ON academics.student_session_attendance(session_id);
CREATE INDEX IF NOT EXISTS idx_ssa_enrollment ON academics.student_session_attendance(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_ssa_session_enrollment ON academics.student_session_attendance(session_id, enrollment_id);
CREATE INDEX IF NOT EXISTS idx_ssa_source_type ON academics.student_session_attendance(source_type);
CREATE INDEX IF NOT EXISTS idx_ssa_marked_at ON academics.student_session_attendance(marked_at DESC);
CREATE INDEX IF NOT EXISTS idx_attendance_session_session_id ON academics.attendance_session(session_id);

CREATE OR REPLACE FUNCTION check_recent_attendance_duplicate(
    p_company_id UUID,
    p_subject_type VARCHAR(20),
    p_subject_id UUID,
    p_event_type VARCHAR(30),
    p_event_time TIMESTAMPTZ,
    p_time_window_minutes INTEGER DEFAULT 5
) RETURNS BOOLEAN AS $$
DECLARE duplicate_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO duplicate_count
    FROM attendance.attendance_events
    WHERE company_id = p_company_id
      AND subject_type = p_subject_type
      AND subject_id = p_subject_id
      AND event_type = p_event_type
      AND source_type != 'correction'
      AND ABS(EXTRACT(EPOCH FROM (event_time - p_event_time))) <= p_time_window_minutes * 60;
    RETURN duplicate_count > 0;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION find_existing_correction(
    p_company_id UUID,
    p_subject_type VARCHAR(20),
    p_subject_id UUID,
    p_event_type VARCHAR(30),
    p_event_time TIMESTAMPTZ
) RETURNS TABLE (
    attendance_event_id UUID, company_id UUID, subject_type VARCHAR(20), subject_id UUID,
    event_type VARCHAR(30), event_time TIMESTAMPTZ,
    source_type VARCHAR(30), source_id UUID, device_id VARCHAR(256), ip_address VARCHAR(64),
    metadata JSONB, created_at TIMESTAMPTZ, created_by UUID
) AS $$
BEGIN
    RETURN QUERY SELECT ae.attendance_event_id, ae.company_id, ae.subject_type, ae.subject_id,
                        ae.event_type, ae.event_time,
                        ae.source_type, ae.source_id, ae.device_id, ae.ip_address,
                        ae.metadata, ae.created_at, ae.created_by
                 FROM attendance.attendance_events ae
                 WHERE ae.company_id = p_company_id
                   AND ae.subject_type = p_subject_type
                   AND ae.subject_id = p_subject_id
                   AND ae.event_type = p_event_type
                   AND ae.event_time = p_event_time
                   AND ae.source_type = 'correction' LIMIT 1;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION revoke_enrollment_on_exit()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE attendance.device_enrollments
    SET is_active = false,
        unenrolled_at = NOW(),
        revoked_reason = 'employee_exit'
    WHERE company_id = NEW.company_id
      AND subject_type = 'employee'
      AND subject_id = NEW.user_id
      AND is_active = true;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION biometric.revoke_biometric_on_exit()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE biometric.unified_face_embeddings
    SET is_active = false,
        updated_at = NOW()
    WHERE company_id = NEW.company_id
      AND subject_type = 'employee'
      AND subject_id = NEW.user_id
      AND is_active = true;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_attendance_update_if_locked()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.is_payroll_locked = true THEN
        RAISE EXCEPTION 'Attendance is payroll locked';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_past_schedule_update()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.schedule_date <= CURRENT_DATE THEN
        RAISE EXCEPTION 'Past or current schedules are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enforce_schedule_cancellation()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status = 'cancelled' AND OLD.schedule_date > CURRENT_DATE THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'active' THEN
        RAISE EXCEPTION 'Direct modification not allowed. Cancel and regenerate.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_past_schedule_update
    BEFORE UPDATE OR DELETE ON attendance.schedule_instances
    FOR EACH ROW
    EXECUTE FUNCTION prevent_past_schedule_update();

CREATE TRIGGER trg_enforce_schedule_cancel
    BEFORE UPDATE ON attendance.schedule_instances
    FOR EACH ROW
    EXECUTE FUNCTION enforce_schedule_cancellation();

CREATE TRIGGER trg_revoke_device_on_employee_exit
    AFTER UPDATE OF exit_state ON employee_exit
    FOR EACH ROW
    WHEN (NEW.exit_state = 'effective')
    EXECUTE FUNCTION revoke_enrollment_on_exit();

CREATE TRIGGER trg_revoke_biometric_on_exit
    AFTER UPDATE OF exit_state ON employee_exit
    FOR EACH ROW
    WHEN (NEW.exit_state = 'effective')
    EXECUTE FUNCTION biometric.revoke_biometric_on_exit();

CREATE TRIGGER trg_prevent_attendance_update_if_locked
    BEFORE UPDATE OR DELETE ON attendance.attendance_daily_summary
    FOR EACH ROW
    EXECUTE FUNCTION prevent_attendance_update_if_locked();

INSERT INTO attendance.attendance_source_types
    (source_type, description, category, requires_device, is_system,
     allow_backdated, allow_future, trust_level, is_self_service)
VALUES
    ('mobile', 'Mobile App Punch', 'mobile', false, false, false, false, 2, true),
    ('web', 'Web Portal Punch', 'web', false, false, false, false, 2, true),
    ('biometric', 'Biometric Attendance Device', 'biometric', true, false, false, false, 5, false),
    ('kiosk', 'Shared Kiosk / Tablet', 'machine', true, false, false, false, 4, true),
    ('manual', 'Manual Attendance Entry', 'manual', false, false, true, false, 1, false),
    ('correction', 'Attendance Correction', 'manual', false, false, true, false, 1, false),
    ('system', 'System Generated Attendance', 'system', false, true, false, false, 5, false),
    ('import', 'Bulk Attendance Import', 'system', false, true, true, false, 4, false),
    ('api', 'External Attendance API', 'system', false, true, false, false, 3, false),
    ('factory', 'Factory Machine Sync', 'machine', true, true, false, false, 5, true),
    ('classroom', 'Classroom / Lab Attendance', 'machine', true, false, false, false, 3, true),
    ('geo', 'Geo-fenced Mobile Attendance', 'mobile', false, false, false, false, 3, true)
ON CONFLICT DO NOTHING;

INSERT INTO attendance.attendance_event_types
    (event_type, category, description, is_user_triggered, is_system_generated)
VALUES
    ('check_in', 'core', 'User check-in', true, false),
    ('check_out', 'core', 'User check-out', true, false),
    ('break_start', 'core', 'Break started', true, false),
    ('break_end', 'core', 'Break ended', true, false),
    ('shift_start', 'shift', 'Shift started', true, false),
    ('shift_end', 'shift', 'Shift ended', true, false),
    ('overtime_start', 'shift', 'Overtime started', true, false),
    ('overtime_end', 'shift', 'Overtime ended', true, false),
    ('early_exit', 'shift', 'Left early', false, true),
    ('late_entry', 'shift', 'Late arrival', false, true),
    ('gate_entry', 'location', 'Gate entry', true, false),
    ('gate_exit', 'location', 'Gate exit', true, false),
    ('zone_entry', 'location', 'Zone entry', true, false),
    ('zone_exit', 'location', 'Zone exit', true, false),
    ('class_start', 'class', 'Class started', true, false),
    ('class_end', 'class', 'Class ended', true, false),
    ('session_join', 'class', 'Joined session', true, false),
    ('session_leave', 'class', 'Left session', true, false),
    ('leave_start', 'leave', 'Leave started', false, true),
    ('leave_end', 'leave', 'Leave ended', false, true),
    ('absent_marked', 'leave', 'Absent marked', false, true),
    ('holiday_marked', 'leave', 'Holiday', false, true),
    ('weekly_off', 'leave', 'Weekly off', false, true),
    ('manual_check_in', 'manual', 'Manual check-in', false, false),
    ('manual_check_out', 'manual', 'Manual check-out', false, false),
    ('manual_override', 'manual', 'Manual override', false, false),
    ('attendance_adjustment', 'manual', 'Attendance adjustment', false, false),
    ('biometric_sync', 'system', 'Biometric sync', false, true),
    ('system_generated', 'system', 'System generated event', false, true),
    ('imported_event', 'system', 'Imported attendance', false, true),
    ('missing_punch', 'exception', 'Missing punch', false, true),
    ('duplicate_punch', 'exception', 'Duplicate punch', false, true),
    ('invalid_punch', 'exception', 'Invalid punch', false, true),
    ('policy_violation', 'exception', 'Attendance policy violation', false, true)
ON CONFLICT DO NOTHING;

ALTER TABLE attendance.attendance_locations
ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS attendance.attendance_exemptions (
    exemption_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    subject_type   VARCHAR(20) NOT NULL,          -- 'student', 'employee', 'customer'
    subject_id     UUID NOT NULL,                 -- student_id, user_id, customer_id
    from_date      DATE NOT NULL,
    to_date        DATE NOT NULL,
    reason         TEXT,
    approved_by    UUID,                          -- user who approved the exemption
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     UUID,
    CONSTRAINT check_exemption_dates CHECK (from_date <= to_date),
    CONSTRAINT fk_exempt_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);

CREATE INDEX idx_att_exempt_subject ON attendance.attendance_exemptions (company_id, subject_type, subject_id);
CREATE INDEX idx_att_exempt_dates   ON attendance.attendance_exemptions (from_date, to_date);
COMMENT ON TABLE attendance.attendance_exemptions IS 'Exemptions for any subject type (students, employees, etc.) for specific date ranges.';

CREATE TABLE IF NOT EXISTS attendance.attendance_session_summary (
    summary_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    subject_type   VARCHAR(20) NOT NULL,          -- 'student', 'employee', 'customer'
    subject_id     UUID NOT NULL,
    session_id     UUID NOT NULL,                 -- references your external session (e.g., academic_session.session_id)
    session_date   DATE NOT NULL,                 -- denormalized for efficient querying
    status         VARCHAR(20) NOT NULL,          -- 'present', 'absent', 'late', 'excused'
    marked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    marked_by      UUID,                          -- user or device that marked it
    source_type    VARCHAR(30) NOT NULL,          -- 'web', 'biometric', 'manual', etc.
    device_id      VARCHAR(256),                  -- if marked by device
    is_auto        BOOLEAN NOT NULL DEFAULT false, -- true if auto-generated (e.g., biometric)
    remarks        TEXT,
    metadata       JSONB,                         -- store academic_year_id, term_id, section_id, etc.
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_session_summary_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    UNIQUE (company_id, subject_type, subject_id, session_id)   -- one status per subject per session
);

CREATE INDEX idx_att_session_summary_subject ON attendance.attendance_session_summary (company_id, subject_type, subject_id);
CREATE INDEX idx_att_session_summary_session ON attendance.attendance_session_summary (session_id);
CREATE INDEX idx_att_session_summary_date   ON attendance.attendance_session_summary (session_date);
CREATE INDEX idx_att_session_summary_status ON attendance.attendance_session_summary (status);
COMMENT ON TABLE attendance.attendance_session_summary IS 'Per-session attendance for any subject type (students in class, employees in meetings, etc.).';
ALTER TABLE positions ADD CONSTRAINT fk_positions_work_center
    FOREIGN KEY (company_id, work_center_code)
    REFERENCES attendance.work_centers(company_id, work_center_code);
CREATE OR REPLACE FUNCTION sync_work_center_assignment()
RETURNS TRIGGER AS $$
DECLARE
    wc_code VARCHAR;
    effective_date DATE;
BEGIN
    -- Determine effective_from: use hire_date for new employees, or current date for updates
    IF TG_OP = 'INSERT' THEN
        effective_date := NEW.hire_date;
    ELSIF TG_OP = 'UPDATE' AND OLD.position_id IS DISTINCT FROM NEW.position_id THEN
        effective_date := NOW();
    ELSE
        RETURN NEW; -- no change, do nothing
    END IF;

    -- Get the work_center_code from positions
    SELECT work_center_code INTO wc_code
    FROM positions
    WHERE position_id = NEW.position_id;

    IF wc_code IS NULL THEN
        -- If no work center defined, skip
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND OLD.position_id IS DISTINCT FROM NEW.position_id) THEN
        -- If updating, close the old assignment if exists
        IF TG_OP = 'UPDATE' THEN
            UPDATE attendance.user_work_center_assignments
            SET effective_to = NOW(), is_active = false
            WHERE user_id = NEW.user_id
              AND effective_to IS NULL
              AND is_active = true;
        END IF;

        -- Insert new assignment
        INSERT INTO attendance.user_work_center_assignments (
            assignment_id, company_id, user_id, work_center_code, effective_from, effective_to, is_active, created_at
        ) VALUES (
            gen_random_uuid(),
            NEW.company_id,   -- add this
            NEW.user_id,
            wc_code,
            effective_date,
            NULL,
            true,
            NOW()
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_sync_work_center_assignment
AFTER INSERT OR UPDATE OF position_id ON company_employees
FOR EACH ROW
EXECUTE FUNCTION sync_work_center_assignment();
ALTER TABLE attendance.attendance_source_types 
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
ALTER TABLE payroll.payroll_run DROP CONSTRAINT payroll_run_status_check;
ALTER TABLE payroll.payroll_run ADD CONSTRAINT payroll_run_status_check 
CHECK (status IN ('draft','processing','executing','calculated','approved','paid','failed','partially_processed','cancelled'));

ALTER TABLE payroll.payroll_component
ADD CONSTRAINT uq_payroll_component_company_code UNIQUE (company_id, component_code);

ALTER TABLE payroll.payroll_item
ADD CONSTRAINT payroll_item_run_user_unique UNIQUE (payroll_run_id, user_id);


-- Add polymorphic columns
ALTER TABLE attendance.user_attendance_policies 
ADD COLUMN IF NOT EXISTS subject_type VARCHAR(20),
ADD COLUMN IF NOT EXISTS subject_id UUID;

-- Populate existing rows (all are employees)
UPDATE attendance.user_attendance_policies 
SET subject_type = 'employee', subject_id = user_id 
WHERE subject_type IS NULL;

-- Make user_id nullable and drop its FK constraint
ALTER TABLE attendance.user_attendance_policies 
ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE attendance.user_attendance_policies 
DROP CONSTRAINT IF EXISTS fk_uap_user;

-- Add constraint: either user_id is set, or subject_type + subject_id are set
ALTER TABLE attendance.user_attendance_policies 
ADD CONSTRAINT chk_user_or_subject CHECK (
    (user_id IS NOT NULL) OR (subject_type IS NOT NULL AND subject_id IS NOT NULL)
);

-- Create index for efficient lookup
CREATE INDEX IF NOT EXISTS idx_uap_subject 
ON attendance.user_attendance_policies (subject_type, subject_id, effective_from, effective_to);
EOSQL
echo "✅ Biometric schema initialized successfully!"