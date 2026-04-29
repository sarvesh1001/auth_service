    -- =====================================================
    -- ACADEMICS SCHEMA (FULLY AUDITED & SOFT‑DELETED)
    -- =====================================================
    CREATE SCHEMA IF NOT EXISTS academics;

    -- =====================================================
    -- ACADEMIC STRUCTURE (MUST HAVE: ALL 3 COLUMNS)
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.academic_year (
        academic_year_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name             VARCHAR(50) NOT NULL,
        start_date       DATE NOT NULL,
        end_date         DATE NOT NULL,
        is_current       BOOLEAN NOT NULL DEFAULT false,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ,
        CONSTRAINT check_academic_year_dates CHECK (start_date < end_date)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_academic_year_unique_active 
        ON academics.academic_year(company_id, name) 
        WHERE deleted_at IS NULL;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_academic_year_dates_active 
        ON academics.academic_year(company_id, start_date, end_date) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.term (
        term_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        name             VARCHAR(50) NOT NULL,
        start_date       DATE NOT NULL,
        end_date         DATE NOT NULL,
        is_current       BOOLEAN NOT NULL DEFAULT false,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ,
        CONSTRAINT check_term_dates CHECK (start_date < end_date)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_term_unique_active 
        ON academics.term(academic_year_id, name) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.course (
        course_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id  UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        code        VARCHAR(20) NOT NULL,
        name        VARCHAR(255) NOT NULL,
        description TEXT,
        credits     INTEGER,
        is_active   BOOLEAN NOT NULL DEFAULT true,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by  UUID REFERENCES users(user_id),
        updated_by  UUID REFERENCES users(user_id),
        deleted_at  TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_course_code_active 
        ON academics.course(company_id, code) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.section (
        section_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        course_id       UUID NOT NULL REFERENCES academics.course(course_id) ON DELETE CASCADE,
        term_id         UUID NOT NULL REFERENCES academics.term(term_id) ON DELETE CASCADE,
        name            VARCHAR(50) NOT NULL,
        capacity        INTEGER,
        is_active       BOOLEAN NOT NULL DEFAULT true,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_section_unique_active 
        ON academics.section(course_id, term_id, name) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.subject (
        subject_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id      UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        code            VARCHAR(20) NOT NULL,
        name            VARCHAR(255) NOT NULL,
        description     TEXT,
        credits         INTEGER,
        is_active       BOOLEAN NOT NULL DEFAULT true,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_subject_code_active 
        ON academics.subject(company_id, code) 
        WHERE deleted_at IS NULL;

    -- subject_course_mapping (NO AUDIT COLUMNS)
    CREATE TABLE IF NOT EXISTS academics.subject_course_mapping (
        mapping_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        course_id       UUID NOT NULL REFERENCES academics.course(course_id) ON DELETE CASCADE,
        subject_id      UUID NOT NULL REFERENCES academics.subject(subject_id) ON DELETE CASCADE,
        term_number     INTEGER,
        is_compulsory   BOOLEAN NOT NULL DEFAULT true,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (course_id, subject_id, term_number)
    );

    -- =====================================================
    -- STUDENT DOMAIN
    -- =====================================================

    -- UPDATED students table with encrypted fields
    CREATE TABLE IF NOT EXISTS academics.students (
        student_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id      UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,

        first_name      VARCHAR(100) NOT NULL,
        last_name       VARCHAR(100),

        admission_no    VARCHAR(50),

        -- Email (encrypted)
        email                TEXT,
        email_dek            TEXT,
        email_key_id         TEXT,

        -- Student's own phone (encrypted)
        phone                TEXT,
        phone_dek            TEXT,
        phone_key_id         TEXT,

        date_of_birth   DATE,
        gender          VARCHAR(20),
        blood_group     VARCHAR(5),
        nationality     VARCHAR(50),
        religion        VARCHAR(50),
        category        VARCHAR(50),

        -- Aadhar (encrypted)
        aadhar_no            TEXT,
        aadhar_no_dek        TEXT,
        aadhar_no_key_id     TEXT,

        -- Emergency contact (encrypted)
        emergency_contact_name  VARCHAR(100),
        emergency_contact_phone TEXT,
        emergency_contact_phone_dek TEXT,
        emergency_contact_phone_key_id TEXT,

        medical_conditions      TEXT,

        status          VARCHAR(20) NOT NULL DEFAULT 'active'
            CHECK (status IN ('active','inactive','alumni','transferred')),

        version         INT NOT NULL DEFAULT 0,

        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );
    -- Indexes for students (new and updated)
    CREATE UNIQUE INDEX IF NOT EXISTS idx_students_admission_no_active 
        ON academics.students(company_id, admission_no) 
        WHERE deleted_at IS NULL;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_students_email_active
        ON academics.students(company_id, email)
        WHERE deleted_at IS NULL AND email IS NOT NULL;

    CREATE INDEX IF NOT EXISTS idx_students_company ON academics.students(company_id);
    CREATE INDEX IF NOT EXISTS idx_students_not_deleted ON academics.students(deleted_at) WHERE deleted_at IS NULL;


    CREATE TABLE IF NOT EXISTS academics.student_guardians (
        guardian_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id      UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        guardian_name   VARCHAR(255) NOT NULL,
        relation        VARCHAR(50) NOT NULL,
        
        -- Phone (encrypted)
        phone                TEXT,
        phone_dek            TEXT,
        phone_key_id         TEXT,
        
        -- Email (encrypted)
        email                TEXT,
        email_dek            TEXT,
        email_key_id         TEXT,
        
        address         TEXT,
        is_primary      BOOLEAN NOT NULL DEFAULT false,
        occupation      VARCHAR(100),
        income          NUMERIC(12,2),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS academics.admissions (
        admission_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id      UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        admission_date  DATE NOT NULL,
        class_applied_for VARCHAR(50),
        admission_status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (admission_status IN ('pending','approved','rejected')),
        remarks         TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id)
    );

    -- Updated academics.enrollments table with audit columns (updated_by, version)
    CREATE TABLE IF NOT EXISTS academics.enrollments (
        enrollment_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        section_id       UUID NOT NULL REFERENCES academics.section(section_id) ON DELETE CASCADE,
        enrollment_date  DATE NOT NULL DEFAULT CURRENT_DATE,
        roll_number      VARCHAR(20),
        status           VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'withdrawn')),
        version          INT NOT NULL DEFAULT 0,                     -- ✅ added for optimistic locking
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),             -- ✅ added for audit trail
        UNIQUE (student_id, academic_year_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_documents (
        document_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id      UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        document_type   VARCHAR(50) NOT NULL,
        document_name   VARCHAR(255),
        file_url        TEXT NOT NULL,
        uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        verified        BOOLEAN DEFAULT false,
        verified_by     UUID REFERENCES users(user_id),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_previous_education (
        prev_edu_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id      UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        school_name     VARCHAR(255),
        board           VARCHAR(100),
        year_of_passing INTEGER,
        percentage      NUMERIC(5,2),
        grade           VARCHAR(20),
        qualification   VARCHAR(100),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- =====================================================
    -- TEACHER DOMAIN
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.teachers (
        teacher_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id      UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        employee_code   VARCHAR(50),
        qualification   TEXT,
        specialization  VARCHAR(255),
        joining_date    DATE,
        status          VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','resigned')),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_teachers_employee_code_active 
        ON academics.teachers(company_id, employee_code) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.teacher_subjects (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        teacher_id      UUID NOT NULL REFERENCES academics.teachers(teacher_id) ON DELETE CASCADE,
        subject_id      UUID NOT NULL REFERENCES academics.subject(subject_id) ON DELETE CASCADE,
        is_primary      BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (teacher_id, subject_id)
    );

    CREATE TABLE IF NOT EXISTS academics.teacher_sections (
        id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        teacher_id      UUID NOT NULL REFERENCES academics.teachers(teacher_id) ON DELETE CASCADE,
        section_id      UUID NOT NULL REFERENCES academics.section(section_id) ON DELETE CASCADE,
        is_class_teacher BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (teacher_id, section_id)
    );

    CREATE TABLE IF NOT EXISTS academics.teacher_schedule_preferences (
        preference_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        teacher_id      UUID NOT NULL REFERENCES academics.teachers(teacher_id) ON DELETE CASCADE,
        day_of_week     INTEGER NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
        preferred_start_time TIME,
        preferred_end_time TIME,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        UNIQUE (teacher_id, day_of_week)
    );
    -- =====================================================
    -- TIMETABLE
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.rooms (
        room_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id      UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        room_code       VARCHAR(20) NOT NULL,
        room_name       VARCHAR(100),
        capacity        INTEGER,
        building        VARCHAR(100),
        floor           INTEGER,
        is_active       BOOLEAN NOT NULL DEFAULT true,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_rooms_code_active 
        ON academics.rooms(company_id, room_code) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.timetables (
        timetable_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        term_id         UUID NOT NULL REFERENCES academics.term(term_id) ON DELETE CASCADE,
        section_id      UUID NOT NULL REFERENCES academics.section(section_id) ON DELETE CASCADE,
        version         INTEGER NOT NULL DEFAULT 1,
        effective_from  DATE NOT NULL DEFAULT CURRENT_DATE,
        effective_to    DATE,
        is_active       BOOLEAN NOT NULL DEFAULT true,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_timetables_unique_active 
        ON academics.timetables(term_id, section_id, version) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.timetable_slots (
        slot_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        timetable_id    UUID NOT NULL REFERENCES academics.timetables(timetable_id) ON DELETE CASCADE,
        day_of_week     INTEGER NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
        start_time      TIME NOT NULL,
        end_time        TIME NOT NULL,
        slot_number     INTEGER,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        UNIQUE (timetable_id, day_of_week, start_time)
    );

    CREATE TABLE IF NOT EXISTS academics.timetable_entries (
        entry_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        slot_id         UUID NOT NULL REFERENCES academics.timetable_slots(slot_id) ON DELETE CASCADE,
        subject_id      UUID NOT NULL REFERENCES academics.subject(subject_id) ON DELETE CASCADE,
        teacher_id      UUID NOT NULL REFERENCES academics.teachers(teacher_id) ON DELETE CASCADE,
        room_id         UUID REFERENCES academics.rooms(room_id) ON DELETE SET NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.timetable_changes (
        change_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        entry_id        UUID NOT NULL REFERENCES academics.timetable_entries(entry_id) ON DELETE CASCADE,
        change_date     DATE NOT NULL,
        new_teacher_id  UUID REFERENCES academics.teachers(teacher_id) ON DELETE SET NULL,
        new_room_id     UUID REFERENCES academics.rooms(room_id) ON DELETE SET NULL,
        reason          TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id)
    );

    -- =====================================================
    -- ATTENDANCE
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.student_attendance (
        attendance_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        enrollment_id   UUID NOT NULL REFERENCES academics.enrollments(enrollment_id) ON DELETE CASCADE,
        attendance_date DATE NOT NULL,
        status          VARCHAR(20) NOT NULL CHECK (status IN ('present','absent','late','half-day','holiday','exempted')),
        marked_by       UUID REFERENCES users(user_id),
        remarks         TEXT,
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

    -- =====================================================
    -- ASSIGNMENTS
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.assignments (
        assignment_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        section_id      UUID NOT NULL REFERENCES academics.section(section_id) ON DELETE CASCADE,
        subject_id      UUID NOT NULL REFERENCES academics.subject(subject_id) ON DELETE CASCADE,
        teacher_id      UUID NOT NULL REFERENCES academics.teachers(teacher_id) ON DELETE CASCADE,
        title           VARCHAR(255) NOT NULL,
        description     TEXT,
        due_date        TIMESTAMPTZ NOT NULL,
        max_marks       NUMERIC(6,2),
        attachment_url  TEXT,
        is_published    BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE TABLE academics.assignment_submissions (
        submission_id   UUID PRIMARY KEY,
        assignment_id   UUID NOT NULL REFERENCES academics.assignments(assignment_id),
        student_id      UUID NOT NULL REFERENCES academics.students(student_id),  -- who submitted
        submission_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        file_url        TEXT,
        remarks         TEXT,
        status          VARCHAR(20) NOT NULL DEFAULT 'submitted',
        marks_obtained  NUMERIC(6,2),
        feedback        TEXT,
        graded_by       UUID REFERENCES users(user_id),
        graded_at       TIMESTAMPTZ,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- audit timestamp
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (assignment_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS academics.assignment_grades (
        grade_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        submission_id   UUID NOT NULL REFERENCES academics.assignment_submissions(submission_id) ON DELETE CASCADE,
        marks           NUMERIC(6,2) NOT NULL,
        graded_by       UUID NOT NULL REFERENCES users(user_id),
        graded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        remarks         TEXT,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS academics.assignment_comments (
        comment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        submission_id   UUID NOT NULL REFERENCES academics.assignment_submissions(submission_id) ON DELETE CASCADE,
        comment_by      UUID NOT NULL REFERENCES users(user_id),
        comment         TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    -- =====================================================
    -- EXAMS
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.exams (
        exam_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        term_id         UUID NOT NULL REFERENCES academics.term(term_id) ON DELETE CASCADE,
        exam_name       VARCHAR(255) NOT NULL,
        start_date      DATE NOT NULL,
        end_date        DATE NOT NULL,
        description     TEXT,
        is_active       BOOLEAN NOT NULL DEFAULT true,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS academics.exam_schedules (
        schedule_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        exam_id         UUID NOT NULL REFERENCES academics.exams(exam_id) ON DELETE CASCADE,
        subject_id      UUID NOT NULL REFERENCES academics.subject(subject_id) ON DELETE CASCADE,
        date            DATE NOT NULL,
        start_time      TIME,
        end_time        TIME,
        room_id         UUID REFERENCES academics.rooms(room_id) ON DELETE SET NULL,
        max_marks       NUMERIC(6,2),
        passing_marks   NUMERIC(6,2),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        UNIQUE (exam_id, subject_id)
    );

    CREATE TABLE IF NOT EXISTS academics.exam_results (
        result_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        exam_id         UUID NOT NULL REFERENCES academics.exams(exam_id) ON DELETE CASCADE,
        enrollment_id   UUID NOT NULL REFERENCES academics.enrollments(enrollment_id) ON DELETE CASCADE,
        subject_id      UUID NOT NULL REFERENCES academics.subject(subject_id) ON DELETE CASCADE,
        marks_obtained  NUMERIC(6,2),
        grade           VARCHAR(10),
        remarks         TEXT,
        entered_by      UUID REFERENCES users(user_id),
        entered_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        UNIQUE (exam_id, enrollment_id, subject_id)
    );

    CREATE TABLE IF NOT EXISTS academics.exam_grades (
        grade_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        exam_id         UUID NOT NULL REFERENCES academics.exams(exam_id) ON DELETE CASCADE,
        grade_name      VARCHAR(20) NOT NULL,
        min_marks       NUMERIC(6,2) NOT NULL,
        max_marks       NUMERIC(6,2) NOT NULL,
        grade_point     NUMERIC(4,2),   -- changed from NUMERIC(3,2) to allow up to 99.99
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (exam_id, grade_name)
    );
    CREATE TABLE IF NOT EXISTS academics.grading_policies (
        policy_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id      UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        policy_name     VARCHAR(100) NOT NULL,
        grading_scale   VARCHAR(20) NOT NULL CHECK (grading_scale IN ('percentage','grade_point','letter_grade')),
        is_default      BOOLEAN NOT NULL DEFAULT false,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by      UUID REFERENCES users(user_id),
        updated_by      UUID REFERENCES users(user_id),
        deleted_at      TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_grading_policies_name_active 
        ON academics.grading_policies(company_id, policy_name) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.grade_boundaries (
        boundary_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        policy_id       UUID NOT NULL REFERENCES academics.grading_policies(policy_id) ON DELETE CASCADE,
        grade           VARCHAR(10) NOT NULL,
        min_percentage  NUMERIC(5,2) NOT NULL,
        max_percentage  NUMERIC(5,2) NOT NULL,
        grade_point     NUMERIC(3,2),
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (policy_id, grade)
    );

    -- =====================================================
    -- FEES
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.fee_structures (
        fee_structure_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        course_id        UUID NOT NULL REFERENCES academics.course(course_id) ON DELETE CASCADE,
        section_id       UUID REFERENCES academics.section(section_id) ON DELETE CASCADE,
        fee_structure_name VARCHAR(255) NOT NULL,
        total_amount     NUMERIC(12,2) NOT NULL DEFAULT 0,
        is_active        BOOLEAN NOT NULL DEFAULT true,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ,
        UNIQUE (academic_year_id, course_id, section_id, fee_structure_name)
    );

    CREATE TABLE IF NOT EXISTS academics.fee_structure_items (
        item_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        fee_structure_id UUID NOT NULL REFERENCES academics.fee_structures(fee_structure_id) ON DELETE CASCADE,
        fee_head         VARCHAR(100) NOT NULL,
        amount           NUMERIC(12,2) NOT NULL,
        is_mandatory     BOOLEAN NOT NULL DEFAULT true,
        description      TEXT,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_fee_invoices (
        invoice_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        fee_structure_id UUID NOT NULL REFERENCES academics.fee_structures(fee_structure_id) ON DELETE CASCADE,
        invoice_no       VARCHAR(50) UNIQUE NOT NULL,
        due_date         DATE NOT NULL,
        total_amount     NUMERIC(12,2) NOT NULL,
        paid_amount      NUMERIC(12,2) NOT NULL DEFAULT 0,
        balance          NUMERIC(12,2) GENERATED ALWAYS AS (total_amount - paid_amount) STORED,
        status           VARCHAR(20) NOT NULL DEFAULT 'unpaid' CHECK (status IN ('unpaid','partial','paid','overdue','cancelled')),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_fee_invoice_items (
        invoice_item_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        invoice_id       UUID NOT NULL REFERENCES academics.student_fee_invoices(invoice_id) ON DELETE CASCADE,
        fee_head         VARCHAR(100) NOT NULL,
        amount           NUMERIC(12,2) NOT NULL,
        is_mandatory     BOOLEAN NOT NULL DEFAULT true,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_fee_payments (
        payment_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        invoice_id       UUID NOT NULL REFERENCES academics.student_fee_invoices(invoice_id) ON DELETE CASCADE,
        payment_date     DATE NOT NULL DEFAULT CURRENT_DATE,
        amount           NUMERIC(12,2) NOT NULL,
        payment_mode     VARCHAR(50) NOT NULL CHECK (payment_mode IN ('cash','cheque','online','bank_transfer','card','other')),
        transaction_id   VARCHAR(100),
        receipt_no       VARCHAR(50),
        remarks          TEXT,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.fee_discounts (
        discount_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        discount_type    VARCHAR(50) NOT NULL CHECK (discount_type IN ('percentage','fixed')),
        discount_value   NUMERIC(12,2) NOT NULL,
        reason           TEXT,
        approved_by      UUID REFERENCES users(user_id),
        valid_from       DATE,
        valid_until      DATE,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.fee_penalties (
        penalty_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        invoice_id       UUID NOT NULL REFERENCES academics.student_fee_invoices(invoice_id) ON DELETE CASCADE,
        penalty_date     DATE NOT NULL,
        amount           NUMERIC(12,2) NOT NULL,
        reason           TEXT,
        waived           BOOLEAN NOT NULL DEFAULT false,
        waived_by        UUID REFERENCES users(user_id),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.fee_receipts (
        receipt_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        payment_id       UUID NOT NULL REFERENCES academics.student_fee_payments(payment_id) ON DELETE CASCADE,
        receipt_no       VARCHAR(50) UNIQUE NOT NULL,
        receipt_data     JSONB,
        generated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    -- =====================================================
    -- LIBRARY
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.library_categories (
        category_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        category_name    VARCHAR(100) NOT NULL,
        description      TEXT,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_lib_categories_name_active 
        ON academics.library_categories(company_id, category_name) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.library_books (
        book_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        category_id      UUID REFERENCES academics.library_categories(category_id) ON DELETE SET NULL,
        title            VARCHAR(255) NOT NULL,
        author           VARCHAR(255),
        isbn             VARCHAR(20),
        publisher        VARCHAR(255),
        edition          VARCHAR(50),
        language         VARCHAR(50),
        pages            INTEGER,
        publication_year INTEGER,
        description      TEXT,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX idx_lib_books_isbn_active 
    ON academics.library_books (company_id, isbn) 
    WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.library_book_copies (
        copy_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        book_id          UUID NOT NULL REFERENCES academics.library_books(book_id) ON DELETE CASCADE,
        accession_no     VARCHAR(50) UNIQUE NOT NULL,
        status           VARCHAR(20) NOT NULL DEFAULT 'available' CHECK (status IN ('available','issued','lost','damaged','reserved')),
        purchase_date    DATE,
        cost             NUMERIC(10,2),
        shelf_location   VARCHAR(50),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.library_issues (
        issue_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        copy_id          UUID NOT NULL REFERENCES academics.library_book_copies(copy_id) ON DELETE CASCADE,
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        issue_date       DATE NOT NULL DEFAULT CURRENT_DATE,
        due_date         DATE NOT NULL,
        returned_date    DATE,
        status           VARCHAR(20) NOT NULL DEFAULT 'issued' CHECK (status IN ('issued','returned','overdue','lost')),
        issued_by        UUID REFERENCES users(user_id),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.library_returns (
        return_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        issue_id         UUID NOT NULL REFERENCES academics.library_issues(issue_id) ON DELETE CASCADE,
        return_date      DATE NOT NULL,
        fine_amount      NUMERIC(10,2) DEFAULT 0,
        remarks          TEXT,
        received_by      UUID REFERENCES users(user_id),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.library_fines (
        fine_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        issue_id         UUID NOT NULL REFERENCES academics.library_issues(issue_id) ON DELETE CASCADE,
        fine_amount      NUMERIC(10,2) NOT NULL,
        paid             BOOLEAN NOT NULL DEFAULT false,
        paid_date        DATE,
        payment_mode     VARCHAR(50),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    -- =====================================================
    -- TRANSPORT
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.transport_routes (
        route_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        route_name       VARCHAR(100) NOT NULL,
        start_point      VARCHAR(255),
        end_point        VARCHAR(255),
        distance_km      NUMERIC(5,2),
        is_active        BOOLEAN NOT NULL DEFAULT true,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_routes_name_active 
        ON academics.transport_routes(company_id, route_name) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.transport_stops (
        stop_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        route_id         UUID NOT NULL REFERENCES academics.transport_routes(route_id) ON DELETE CASCADE,
        stop_name        VARCHAR(255) NOT NULL,
        stop_order       INTEGER NOT NULL,
        latitude         NUMERIC(10,8),
        longitude        NUMERIC(11,8),
        pickup_time      TIME,
        drop_time        TIME,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        UNIQUE (route_id, stop_order)
    );

    CREATE TABLE IF NOT EXISTS academics.transport_vehicles (
        vehicle_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        vehicle_no       VARCHAR(50) NOT NULL,
        vehicle_type     VARCHAR(50),
        capacity         INTEGER,
        insurance_expiry DATE,
        fitness_expiry   DATE,
        is_active        BOOLEAN NOT NULL DEFAULT true,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        deleted_at       TIMESTAMPTZ
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_vehicles_no_active 
        ON academics.transport_vehicles(company_id, vehicle_no) 
        WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.transport_driver_assignments (
        assignment_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        vehicle_id       UUID NOT NULL REFERENCES academics.transport_vehicles(vehicle_id) ON DELETE CASCADE,
        driver_name      VARCHAR(255) NOT NULL,
        driver_phone     VARCHAR(20),
        driver_license   VARCHAR(50),
        assignment_date  DATE NOT NULL,
        end_date         DATE,
        is_active        BOOLEAN NOT NULL DEFAULT true,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_transport_assignments (
        assignment_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        route_id         UUID NOT NULL REFERENCES academics.transport_routes(route_id) ON DELETE CASCADE,
        stop_id          UUID NOT NULL REFERENCES academics.transport_stops(stop_id) ON DELETE CASCADE,
        pickup_point     VARCHAR(255),
        drop_point       VARCHAR(255),
        effective_from   DATE NOT NULL,
        effective_to     DATE,
        is_active        BOOLEAN NOT NULL DEFAULT true,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        UNIQUE (student_id, effective_from)
    );

    -- =====================================================
    -- NOTIFICATIONS
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.notifications (
        notification_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        title            VARCHAR(255) NOT NULL,
        message          TEXT NOT NULL,
        type             VARCHAR(50) NOT NULL CHECK (type IN ('info','warning','alert','event','announcement')),
        priority         VARCHAR(20) NOT NULL DEFAULT 'normal' CHECK (priority IN ('low','normal','high','urgent')),
        created_by       UUID REFERENCES users(user_id),
        updated_by       UUID REFERENCES users(user_id),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at       TIMESTAMPTZ,
        deleted_at       TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS academics.notification_targets (
        notification_target_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        notification_id  UUID NOT NULL REFERENCES academics.notifications(notification_id) ON DELETE CASCADE,
        target_type      VARCHAR(50) NOT NULL CHECK (target_type IN ('student','teacher','section','course','company','user')),
        target_entity_id UUID NOT NULL,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS academics.notification_reads (
        read_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        notification_id  UUID NOT NULL REFERENCES academics.notifications(notification_id) ON DELETE CASCADE,
        user_id          UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        read_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by       UUID REFERENCES users(user_id),
        UNIQUE (notification_id, user_id)
    );

    -- =====================================================
    -- ANALYTICS / REPORTING (NO AUDIT COLUMNS)
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.student_performance_summary (
        summary_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        term_id          UUID REFERENCES academics.term(term_id) ON DELETE CASCADE,
        overall_percentage NUMERIC(5,2),
        grade            VARCHAR(10),
        rank             INTEGER,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (student_id, academic_year_id, term_id)
    );

    CREATE TABLE IF NOT EXISTS academics.student_rankings (
        ranking_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        term_id          UUID REFERENCES academics.term(term_id) ON DELETE CASCADE,
        rank             INTEGER NOT NULL,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (academic_year_id, term_id, rank)
    );

    CREATE TABLE IF NOT EXISTS academics.class_performance_summary (
        class_summary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        section_id       UUID NOT NULL REFERENCES academics.section(section_id) ON DELETE CASCADE,
        academic_year_id UUID NOT NULL REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        term_id          UUID REFERENCES academics.term(term_id) ON DELETE CASCADE,
        average_percentage NUMERIC(5,2),
        pass_percentage  NUMERIC(5,2),
        total_students   INTEGER,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (section_id, academic_year_id, term_id)
    );

    -- =====================================================
    -- EVENTS / AUDIT
    -- =====================================================

    CREATE TABLE IF NOT EXISTS academics.academic_events (
        event_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        event_name       VARCHAR(255) NOT NULL,
        event_date       DATE NOT NULL,
        start_time       TIME,
        end_time         TIME,
        location         VARCHAR(255),
        description      TEXT,
        created_by       UUID REFERENCES users(user_id),
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS academics.student_activity_log (
        log_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        activity_type    VARCHAR(100) NOT NULL,
        description      TEXT NOT NULL,
        metadata         JSONB,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS academics.exam_result_audit (
        audit_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        result_id        UUID NOT NULL REFERENCES academics.exam_results(result_id) ON DELETE CASCADE,
        changed_by       UUID NOT NULL REFERENCES users(user_id),
        change_type      VARCHAR(20) NOT NULL CHECK (change_type IN ('insert','update','delete')),
        old_marks        NUMERIC(6,2),
        new_marks        NUMERIC(6,2),
        changed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS academics.fee_transaction_audit (
        audit_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        payment_id       UUID NOT NULL REFERENCES academics.student_fee_payments(payment_id) ON DELETE CASCADE,
        action           VARCHAR(20) NOT NULL CHECK (action IN ('created','updated','deleted','refunded')),
        old_data         JSONB,
        new_data         JSONB,
        changed_by       UUID REFERENCES users(user_id),
        changed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- =====================================================
    -- INDEXES (including original ones and new soft‑delete filters)
    -- =====================================================

    -- academic_year
    CREATE INDEX IF NOT EXISTS idx_academic_year_company ON academics.academic_year(company_id);
    CREATE INDEX IF NOT EXISTS idx_academic_year_current ON academics.academic_year(is_current) WHERE is_current = true;
    CREATE INDEX IF NOT EXISTS idx_academic_year_not_deleted ON academics.academic_year(deleted_at) WHERE deleted_at IS NULL;

    -- term
    CREATE INDEX IF NOT EXISTS idx_term_academic_year ON academics.term(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_term_current ON academics.term(is_current) WHERE is_current = true;
    CREATE INDEX IF NOT EXISTS idx_term_not_deleted ON academics.term(deleted_at) WHERE deleted_at IS NULL;

    -- course
    CREATE INDEX IF NOT EXISTS idx_course_company ON academics.course(company_id);
    CREATE INDEX IF NOT EXISTS idx_course_code ON academics.course(code);
    CREATE INDEX IF NOT EXISTS idx_course_not_deleted ON academics.course(deleted_at) WHERE deleted_at IS NULL;

    -- section
    CREATE INDEX IF NOT EXISTS idx_section_course ON academics.section(course_id);
    CREATE INDEX IF NOT EXISTS idx_section_term ON academics.section(term_id);
    CREATE INDEX IF NOT EXISTS idx_section_active ON academics.section(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_section_not_deleted ON academics.section(deleted_at) WHERE deleted_at IS NULL;

    -- subject
    CREATE INDEX IF NOT EXISTS idx_subject_company ON academics.subject(company_id);
    CREATE INDEX IF NOT EXISTS idx_subject_code ON academics.subject(code);
    CREATE INDEX IF NOT EXISTS idx_subject_not_deleted ON academics.subject(deleted_at) WHERE deleted_at IS NULL;

    -- subject_course_mapping
    CREATE INDEX IF NOT EXISTS idx_scm_course ON academics.subject_course_mapping(course_id);
    CREATE INDEX IF NOT EXISTS idx_scm_subject ON academics.subject_course_mapping(subject_id);

    -- students (updated indexes: added unique filtered indexes, removed plain admission_no index)
    CREATE INDEX IF NOT EXISTS idx_students_company ON academics.students(company_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_students_admission_no_active ON academics.students(company_id, admission_no) WHERE deleted_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_students_email_active ON academics.students(company_id, email) WHERE deleted_at IS NULL AND email IS NOT NULL;
    CREATE INDEX idx_students_status ON academics.students(company_id, status) WHERE deleted_at IS NULL;
    CREATE INDEX idx_students_name ON academics.students(company_id, first_name, last_name) WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_students_not_deleted ON academics.students(deleted_at) WHERE deleted_at IS NULL;

    -- student_guardians
    CREATE INDEX IF NOT EXISTS idx_guardians_student ON academics.student_guardians(student_id);
    CREATE INDEX IF NOT EXISTS idx_guardians_primary ON academics.student_guardians(student_id, is_primary) WHERE is_primary = true;

    -- admissions
    CREATE INDEX IF NOT EXISTS idx_admissions_student ON academics.admissions(student_id);
    CREATE INDEX IF NOT EXISTS idx_admissions_academic_year ON academics.admissions(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_admissions_status ON academics.admissions(admission_status);

    -- enrollments
    CREATE INDEX IF NOT EXISTS idx_enrollments_student ON academics.enrollments(student_id);
    CREATE INDEX IF NOT EXISTS idx_enrollments_section ON academics.enrollments(section_id);
    CREATE INDEX IF NOT EXISTS idx_enrollments_academic_year ON academics.enrollments(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_enrollments_status ON academics.enrollments(status);
    CREATE INDEX IF NOT EXISTS idx_enrollments_active ON academics.enrollments(student_id) WHERE status = 'active';
    CREATE INDEX IF NOT EXISTS idx_enrollments_student_year ON academics.enrollments(student_id, academic_year_id);

    -- student_documents
    CREATE INDEX IF NOT EXISTS idx_student_docs_student ON academics.student_documents(student_id);
    CREATE INDEX IF NOT EXISTS idx_student_docs_type ON academics.student_documents(document_type);

    -- student_previous_education
    CREATE INDEX IF NOT EXISTS idx_prev_edu_student ON academics.student_previous_education(student_id);

    -- teachers
    CREATE INDEX IF NOT EXISTS idx_teachers_company ON academics.teachers(company_id);
    CREATE INDEX IF NOT EXISTS idx_teachers_user ON academics.teachers(user_id);
    CREATE INDEX IF NOT EXISTS idx_teachers_employee_code ON academics.teachers(employee_code);
    CREATE INDEX IF NOT EXISTS idx_teachers_status ON academics.teachers(status);
    CREATE INDEX IF NOT EXISTS idx_teachers_not_deleted ON academics.teachers(deleted_at) WHERE deleted_at IS NULL;

    -- teacher_subjects
    CREATE INDEX IF NOT EXISTS idx_teacher_subjects_teacher ON academics.teacher_subjects(teacher_id);
    CREATE INDEX IF NOT EXISTS idx_teacher_subjects_subject ON academics.teacher_subjects(subject_id);

    -- teacher_sections
    CREATE INDEX IF NOT EXISTS idx_teacher_sections_teacher ON academics.teacher_sections(teacher_id);
    CREATE INDEX IF NOT EXISTS idx_teacher_sections_section ON academics.teacher_sections(section_id);
    CREATE INDEX IF NOT EXISTS idx_teacher_sections_class_teacher ON academics.teacher_sections(is_class_teacher) WHERE is_class_teacher = true;

    -- teacher_schedule_preferences
    CREATE INDEX IF NOT EXISTS idx_teacher_preferences_teacher ON academics.teacher_schedule_preferences(teacher_id);

    -- rooms
    CREATE INDEX IF NOT EXISTS idx_rooms_company ON academics.rooms(company_id);
    CREATE INDEX IF NOT EXISTS idx_rooms_code ON academics.rooms(room_code);
    CREATE INDEX IF NOT EXISTS idx_rooms_active ON academics.rooms(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_rooms_not_deleted ON academics.rooms(deleted_at) WHERE deleted_at IS NULL;

    -- timetables
    CREATE INDEX IF NOT EXISTS idx_timetables_term ON academics.timetables(term_id);
    CREATE INDEX IF NOT EXISTS idx_timetables_section ON academics.timetables(section_id);
    CREATE INDEX IF NOT EXISTS idx_timetables_active ON academics.timetables(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_timetables_not_deleted ON academics.timetables(deleted_at) WHERE deleted_at IS NULL;

    -- timetable_slots
    CREATE INDEX IF NOT EXISTS idx_slots_timetable ON academics.timetable_slots(timetable_id);
    CREATE INDEX IF NOT EXISTS idx_slots_day ON academics.timetable_slots(day_of_week);

    -- timetable_entries
    CREATE INDEX IF NOT EXISTS idx_entries_slot ON academics.timetable_entries(slot_id);
    CREATE INDEX IF NOT EXISTS idx_entries_subject ON academics.timetable_entries(subject_id);
    CREATE INDEX IF NOT EXISTS idx_entries_teacher ON academics.timetable_entries(teacher_id);
    CREATE INDEX IF NOT EXISTS idx_entries_room ON academics.timetable_entries(room_id);

    -- timetable_changes
    CREATE INDEX IF NOT EXISTS idx_changes_entry ON academics.timetable_changes(entry_id);
    CREATE INDEX IF NOT EXISTS idx_changes_date ON academics.timetable_changes(change_date);

    -- student_attendance
    CREATE INDEX IF NOT EXISTS idx_attendance_enrollment ON academics.student_attendance(enrollment_id);
    CREATE INDEX IF NOT EXISTS idx_attendance_date ON academics.student_attendance(attendance_date);
    CREATE INDEX IF NOT EXISTS idx_attendance_status ON academics.student_attendance(status);

    -- student_attendance_summary
    CREATE INDEX IF NOT EXISTS idx_att_summary_student ON academics.student_attendance_summary(student_id);
    CREATE INDEX IF NOT EXISTS idx_att_summary_year ON academics.student_attendance_summary(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_att_summary_term ON academics.student_attendance_summary(term_id);

    -- student_attendance_exemptions
    CREATE INDEX IF NOT EXISTS idx_att_exempt_student ON academics.student_attendance_exemptions(student_id);
    CREATE INDEX IF NOT EXISTS idx_att_exempt_dates ON academics.student_attendance_exemptions(from_date, to_date);

    -- assignments
    CREATE INDEX IF NOT EXISTS idx_assignments_section ON academics.assignments(section_id);
    CREATE INDEX IF NOT EXISTS idx_assignments_subject ON academics.assignments(subject_id);
    CREATE INDEX IF NOT EXISTS idx_assignments_teacher ON academics.assignments(teacher_id);
    CREATE INDEX IF NOT EXISTS idx_assignments_due_date ON academics.assignments(due_date);
    CREATE INDEX IF NOT EXISTS idx_assignments_not_deleted ON academics.assignments(deleted_at) WHERE deleted_at IS NULL;

    -- assignment_submissions
    CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON academics.assignment_submissions(assignment_id);
    CREATE INDEX IF NOT EXISTS idx_submissions_student ON academics.assignment_submissions(student_id);
    CREATE INDEX IF NOT EXISTS idx_submissions_status ON academics.assignment_submissions(status);

    -- assignment_grades
    CREATE INDEX IF NOT EXISTS idx_grades_submission ON academics.assignment_grades(submission_id);
    CREATE INDEX IF NOT EXISTS idx_grades_graded_by ON academics.assignment_grades(graded_by);

    -- assignment_comments
    CREATE INDEX IF NOT EXISTS idx_comments_submission ON academics.assignment_comments(submission_id);
    CREATE INDEX IF NOT EXISTS idx_comments_comment_by ON academics.assignment_comments(comment_by);

    -- exams
    CREATE INDEX IF NOT EXISTS idx_exams_year ON academics.exams(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_exams_term ON academics.exams(term_id);
    CREATE INDEX IF NOT EXISTS idx_exams_active ON academics.exams(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_exams_not_deleted ON academics.exams(deleted_at) WHERE deleted_at IS NULL;

    -- exam_schedules
    CREATE INDEX IF NOT EXISTS idx_schedules_exam ON academics.exam_schedules(exam_id);
    CREATE INDEX IF NOT EXISTS idx_schedules_subject ON academics.exam_schedules(subject_id);
    CREATE INDEX IF NOT EXISTS idx_schedules_room ON academics.exam_schedules(room_id);
    CREATE INDEX IF NOT EXISTS idx_schedules_date ON academics.exam_schedules(date);

    -- exam_results
    CREATE INDEX IF NOT EXISTS idx_results_exam ON academics.exam_results(exam_id);
    CREATE INDEX IF NOT EXISTS idx_results_enrollment ON academics.exam_results(enrollment_id);
    CREATE INDEX IF NOT EXISTS idx_results_subject ON academics.exam_results(subject_id);
    CREATE INDEX IF NOT EXISTS idx_results_exam_enrollment ON academics.exam_results(exam_id, enrollment_id);

    -- exam_grades
    CREATE INDEX IF NOT EXISTS idx_exam_grades_exam ON academics.exam_grades(exam_id);

    -- grading_policies
    CREATE INDEX IF NOT EXISTS idx_grading_policies_company ON academics.grading_policies(company_id);
    CREATE INDEX IF NOT EXISTS idx_grading_policies_default ON academics.grading_policies(is_default) WHERE is_default = true;
    CREATE INDEX IF NOT EXISTS idx_grading_policies_not_deleted ON academics.grading_policies(deleted_at) WHERE deleted_at IS NULL;

    -- grade_boundaries
    CREATE INDEX IF NOT EXISTS idx_boundaries_policy ON academics.grade_boundaries(policy_id);

    -- fee_structures
    CREATE INDEX IF NOT EXISTS idx_fee_structures_year ON academics.fee_structures(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_fee_structures_course ON academics.fee_structures(course_id);
    CREATE INDEX IF NOT EXISTS idx_fee_structures_section ON academics.fee_structures(section_id);
    CREATE INDEX IF NOT EXISTS idx_fee_structures_active ON academics.fee_structures(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_fee_structures_not_deleted ON academics.fee_structures(deleted_at) WHERE deleted_at IS NULL;

    -- fee_structure_items
    CREATE INDEX IF NOT EXISTS idx_fee_items_structure ON academics.fee_structure_items(fee_structure_id);

    -- student_fee_invoices
    CREATE INDEX IF NOT EXISTS idx_invoices_student ON academics.student_fee_invoices(student_id);
    CREATE INDEX IF NOT EXISTS idx_invoices_structure ON academics.student_fee_invoices(fee_structure_id);
    CREATE INDEX IF NOT EXISTS idx_invoices_status ON academics.student_fee_invoices(status);
    CREATE INDEX IF NOT EXISTS idx_invoices_due_date ON academics.student_fee_invoices(due_date);

    -- student_fee_invoice_items
    CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice ON academics.student_fee_invoice_items(invoice_id);

    -- student_fee_payments
    CREATE INDEX IF NOT EXISTS idx_payments_invoice ON academics.student_fee_payments(invoice_id);
    CREATE INDEX IF NOT EXISTS idx_payments_date ON academics.student_fee_payments(payment_date);
    CREATE INDEX IF NOT EXISTS idx_payments_mode ON academics.student_fee_payments(payment_mode);

    -- fee_discounts
    CREATE INDEX IF NOT EXISTS idx_discounts_student ON academics.fee_discounts(student_id);
    CREATE INDEX IF NOT EXISTS idx_discounts_valid ON academics.fee_discounts(valid_from, valid_until);

    -- fee_penalties
    CREATE INDEX IF NOT EXISTS idx_penalties_invoice ON academics.fee_penalties(invoice_id);

    -- fee_receipts
    CREATE INDEX IF NOT EXISTS idx_receipts_payment ON academics.fee_receipts(payment_id);
    CREATE INDEX IF NOT EXISTS idx_receipts_no ON academics.fee_receipts(receipt_no);

    -- library_categories
    CREATE INDEX IF NOT EXISTS idx_lib_categories_company ON academics.library_categories(company_id);
    CREATE INDEX IF NOT EXISTS idx_lib_categories_not_deleted ON academics.library_categories(deleted_at) WHERE deleted_at IS NULL;

    -- library_books
    CREATE INDEX IF NOT EXISTS idx_lib_books_company ON academics.library_books(company_id);
    CREATE INDEX IF NOT EXISTS idx_lib_books_category ON academics.library_books(category_id);
    CREATE INDEX IF NOT EXISTS idx_lib_books_title ON academics.library_books(title);
    CREATE INDEX IF NOT EXISTS idx_lib_books_author ON academics.library_books(author);
    CREATE INDEX IF NOT EXISTS idx_lib_books_isbn ON academics.library_books(isbn);
    CREATE INDEX IF NOT EXISTS idx_lib_books_not_deleted ON academics.library_books(deleted_at) WHERE deleted_at IS NULL;

    -- library_book_copies
    CREATE INDEX IF NOT EXISTS idx_lib_copies_book ON academics.library_book_copies(book_id);
    CREATE INDEX IF NOT EXISTS idx_lib_copies_accession ON academics.library_book_copies(accession_no);
    CREATE INDEX IF NOT EXISTS idx_lib_copies_status ON academics.library_book_copies(status);

    -- library_issues
    CREATE INDEX IF NOT EXISTS idx_issues_copy ON academics.library_issues(copy_id);
    CREATE INDEX IF NOT EXISTS idx_issues_student ON academics.library_issues(student_id);
    CREATE INDEX IF NOT EXISTS idx_issues_due_date ON academics.library_issues(due_date);
    CREATE INDEX IF NOT EXISTS idx_issues_status ON academics.library_issues(status);

    -- library_returns
    CREATE INDEX IF NOT EXISTS idx_returns_issue ON academics.library_returns(issue_id);

    -- library_fines
    CREATE INDEX IF NOT EXISTS idx_fines_issue ON academics.library_fines(issue_id);
    CREATE INDEX IF NOT EXISTS idx_fines_paid ON academics.library_fines(paid) WHERE paid = false;

    -- transport_routes
    CREATE INDEX IF NOT EXISTS idx_routes_company ON academics.transport_routes(company_id);
    CREATE INDEX IF NOT EXISTS idx_routes_active ON academics.transport_routes(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_routes_not_deleted ON academics.transport_routes(deleted_at) WHERE deleted_at IS NULL;

    -- transport_stops
    CREATE INDEX IF NOT EXISTS idx_stops_route ON academics.transport_stops(route_id);
    CREATE INDEX IF NOT EXISTS idx_stops_order ON academics.transport_stops(route_id, stop_order);

    -- transport_vehicles
    CREATE INDEX IF NOT EXISTS idx_vehicles_company ON academics.transport_vehicles(company_id);
    CREATE INDEX IF NOT EXISTS idx_vehicles_no ON academics.transport_vehicles(vehicle_no);
    CREATE INDEX IF NOT EXISTS idx_vehicles_active ON academics.transport_vehicles(is_active) WHERE is_active = true;
    CREATE INDEX IF NOT EXISTS idx_vehicles_not_deleted ON academics.transport_vehicles(deleted_at) WHERE deleted_at IS NULL;

    -- transport_driver_assignments
    CREATE INDEX IF NOT EXISTS idx_driver_assignments_vehicle ON academics.transport_driver_assignments(vehicle_id);
    CREATE INDEX IF NOT EXISTS idx_driver_assignments_active ON academics.transport_driver_assignments(is_active) WHERE is_active = true;

    -- student_transport_assignments
    CREATE INDEX IF NOT EXISTS idx_transport_assign_student ON academics.student_transport_assignments(student_id);
    CREATE INDEX IF NOT EXISTS idx_transport_assign_route ON academics.student_transport_assignments(route_id);
    CREATE INDEX IF NOT EXISTS idx_transport_assign_stop ON academics.student_transport_assignments(stop_id);
    CREATE INDEX IF NOT EXISTS idx_transport_assign_active ON academics.student_transport_assignments(is_active) WHERE is_active = true;

    -- notifications
    CREATE INDEX IF NOT EXISTS idx_notifications_company ON academics.notifications(company_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_type ON academics.notifications(type);
    CREATE INDEX IF NOT EXISTS idx_notifications_priority ON academics.notifications(priority);
    CREATE INDEX IF NOT EXISTS idx_notifications_created ON academics.notifications(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_notifications_not_deleted ON academics.notifications(deleted_at) WHERE deleted_at IS NULL;

    -- notification_targets
    CREATE INDEX IF NOT EXISTS idx_targets_notification ON academics.notification_targets(notification_id);
    CREATE INDEX IF NOT EXISTS idx_targets_target ON academics.notification_targets(target_type, target_entity_id);

    -- notification_reads
    CREATE INDEX IF NOT EXISTS idx_reads_notification ON academics.notification_reads(notification_id);
    CREATE INDEX IF NOT EXISTS idx_reads_user ON academics.notification_reads(user_id);

    -- student_performance_summary
    CREATE INDEX IF NOT EXISTS idx_perf_summary_student ON academics.student_performance_summary(student_id);
    CREATE INDEX IF NOT EXISTS idx_perf_summary_year ON academics.student_performance_summary(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_perf_summary_term ON academics.student_performance_summary(term_id);

    -- student_rankings
    CREATE INDEX IF NOT EXISTS idx_rankings_year ON academics.student_rankings(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_rankings_term ON academics.student_rankings(term_id);
    CREATE INDEX IF NOT EXISTS idx_rankings_rank ON academics.student_rankings(rank);

    -- class_performance_summary
    CREATE INDEX IF NOT EXISTS idx_class_perf_section ON academics.class_performance_summary(section_id);
    CREATE INDEX IF NOT EXISTS idx_class_perf_year ON academics.class_performance_summary(academic_year_id);
    CREATE INDEX IF NOT EXISTS idx_class_perf_term ON academics.class_performance_summary(term_id);

    -- academic_events
    CREATE INDEX IF NOT EXISTS idx_events_company ON academics.academic_events(company_id);
    CREATE INDEX IF NOT EXISTS idx_events_date ON academics.academic_events(event_date);

    -- student_activity_log
    CREATE INDEX IF NOT EXISTS idx_activity_log_student ON academics.student_activity_log(student_id);
    CREATE INDEX IF NOT EXISTS idx_activity_log_type ON academics.student_activity_log(activity_type);
    CREATE INDEX IF NOT EXISTS idx_activity_log_created ON academics.student_activity_log(created_at DESC);

    -- exam_result_audit
    CREATE INDEX IF NOT EXISTS idx_result_audit_result ON academics.exam_result_audit(result_id);
    CREATE INDEX IF NOT EXISTS idx_result_audit_changed_by ON academics.exam_result_audit(changed_by);

    -- fee_transaction_audit
    CREATE INDEX IF NOT EXISTS idx_fee_audit_payment ON academics.fee_transaction_audit(payment_id);
    CREATE INDEX IF NOT EXISTS idx_fee_audit_changed_by ON academics.fee_transaction_audit(changed_by);

    CREATE INDEX idx_academic_year_company_dates ON academics.academic_year(company_id, start_date, end_date) WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS academics.idempotency_keys (
        key          VARCHAR(255) PRIMARY KEY,
        response     JSONB NOT NULL,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE OR REPLACE FUNCTION academics.student_search(
        search_query TEXT,
        company_id_param UUID,
        search_type TEXT DEFAULT 'autocomplete',
        filter_status TEXT DEFAULT NULL,
        limit_count INTEGER DEFAULT 50,
        offset_count INTEGER DEFAULT 0
    )
    RETURNS TABLE(
        student_id UUID,
        first_name VARCHAR,
        last_name VARCHAR,
        admission_no VARCHAR,
        status VARCHAR,
        date_of_birth DATE,
        created_at TIMESTAMPTZ,
        relevance_score FLOAT,
        match_type TEXT
    ) AS $$
    BEGIN

        -- 🔹 AUTOCOMPLETE / SHORT SEARCH
        IF search_type = 'autocomplete' OR LENGTH(search_query) < 3 THEN
            RETURN QUERY
            SELECT
                s.student_id,
                s.first_name,
                s.last_name,
                s.admission_no,
                s.status,
                s.date_of_birth,
                s.created_at,
                GREATEST(
                    similarity(s.first_name, search_query),
                    similarity(s.last_name, search_query),
                    similarity(s.admission_no, search_query)
                )::FLOAT AS relevance_score,
                'autocomplete'::TEXT AS match_type
            FROM academics.students s
            WHERE s.company_id = company_id_param
            AND s.deleted_at IS NULL
            AND (filter_status IS NULL OR s.status = filter_status)
            AND (
                    s.first_name ILIKE '%' || search_query || '%'
                OR s.last_name ILIKE '%' || search_query || '%'
                OR s.admission_no ILIKE '%' || search_query || '%'
            )
            ORDER BY relevance_score DESC, s.first_name ASC
            LIMIT limit_count OFFSET offset_count;

        -- 🔹 FULL TEXT (ADVANCED)
        ELSE
            RETURN QUERY
            SELECT
                s.student_id,
                s.first_name,
                s.last_name,
                s.admission_no,
                s.status,
                s.date_of_birth,
                s.created_at,
                ts_rank(
                    to_tsvector('simple', s.first_name || ' ' || s.last_name || ' ' || COALESCE(s.admission_no,'')),
                    plainto_tsquery('simple', search_query)
                )::FLOAT AS relevance_score,
                'fulltext'::TEXT AS match_type
            FROM academics.students s
            WHERE s.company_id = company_id_param
            AND s.deleted_at IS NULL
            AND (filter_status IS NULL OR s.status = filter_status)
            AND to_tsvector('simple', s.first_name || ' ' || s.last_name || ' ' || COALESCE(s.admission_no,'')) 
                @@ plainto_tsquery('simple', search_query)
            ORDER BY relevance_score DESC
            LIMIT limit_count OFFSET offset_count;
        END IF;

    END;
    $$ LANGUAGE plpgsql STABLE;

    CREATE INDEX idx_students_search_tsv
    ON academics.students
    USING GIN (
        to_tsvector('simple', first_name || ' ' || last_name || ' ' || COALESCE(admission_no,''))
    )
    WHERE deleted_at IS NULL;

    CREATE INDEX idx_students_name_trgm ON academics.students USING GIN (first_name gin_trgm_ops, last_name gin_trgm_ops);

    CREATE TABLE IF NOT EXISTS outbox.events (
    event_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type VARCHAR(100) NOT NULL,
    aggregate_id   UUID,
    event_type     VARCHAR(100) NOT NULL,
    topic          VARCHAR(100) NOT NULL,        -- 🔥 NEW (CRITICAL)
    payload        JSONB NOT NULL,
    headers        JSONB,
    status         VARCHAR(20) NOT NULL DEFAULT 'pending',
    retry_count    INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at   TIMESTAMPTZ
    );
    CREATE INDEX idx_outbox_status ON outbox.events(status);
    CREATE INDEX idx_outbox_created ON outbox.events(created_at);

    -- academics.sql (add after table creation)
    CREATE UNIQUE INDEX idx_academic_year_one_current
    ON academics.academic_year(company_id)
    WHERE is_current = true AND deleted_at IS NULL;

    -- 1. Unique active enrollment per student & academic year
    CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_enrollment
    ON academics.enrollments (student_id, academic_year_id)
    WHERE status = 'active';

    CREATE INDEX IF NOT EXISTS idx_enrollment_student_active
    ON academics.enrollments(student_id)
    WHERE status = 'active';

    CREATE INDEX IF NOT EXISTS idx_enrollment_section_active
    ON academics.enrollments(section_id)
    WHERE status = 'active';




    CREATE SCHEMA IF NOT EXISTS analytics;

    -- Fact table: aggregated counts per academic year
    -- Includes metrics for attendance, curriculum, and enrollment
    CREATE TABLE IF NOT EXISTS analytics.academic_year_metrics (
        academic_year_id            UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_students              INTEGER NOT NULL DEFAULT 0,
        active_students             INTEGER NOT NULL DEFAULT 0,
        total_terms                 INTEGER NOT NULL DEFAULT 0,
        total_sections              INTEGER NOT NULL DEFAULT 0,
        total_courses               INTEGER NOT NULL DEFAULT 0,
        total_subjects              INTEGER NOT NULL DEFAULT 0,
        total_admissions            INTEGER NOT NULL DEFAULT 0,
        approved_admissions         INTEGER NOT NULL DEFAULT 0,
        pending_admissions          INTEGER NOT NULL DEFAULT 0,
        rejected_admissions         INTEGER NOT NULL DEFAULT 0,
        total_assignments           INTEGER NOT NULL DEFAULT 0,
        published_assignments       INTEGER NOT NULL DEFAULT 0,
        total_attendance_records    INTEGER NOT NULL DEFAULT 0,
        total_absent_records        INTEGER NOT NULL DEFAULT 0,
        total_late_records          INTEGER NOT NULL DEFAULT 0,
        total_half_day_records      INTEGER NOT NULL DEFAULT 0,
        total_exemptions            INTEGER NOT NULL DEFAULT 0,
        total_subject_mappings      INTEGER NOT NULL DEFAULT 0,
        courses_with_curriculum     INTEGER NOT NULL DEFAULT 0,
        total_enrollments           INTEGER NOT NULL DEFAULT 0,
        active_enrollments          INTEGER NOT NULL DEFAULT 0,
        completed_enrollments       INTEGER NOT NULL DEFAULT 0,
        withdrawn_enrollments       INTEGER NOT NULL DEFAULT 0,
        last_updated                TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_academic_year_metrics_last_updated 
        ON analytics.academic_year_metrics(last_updated);

    -- Exam metrics
    CREATE TABLE IF NOT EXISTS analytics.exam_metrics (
        academic_year_id UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_exams      INTEGER NOT NULL DEFAULT 0,
        total_schedules  INTEGER NOT NULL DEFAULT 0,
        total_results    INTEGER NOT NULL DEFAULT 0,
        total_grades     INTEGER NOT NULL DEFAULT 0,
        last_updated     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Fee metrics
    CREATE TABLE IF NOT EXISTS analytics.fee_metrics (
        academic_year_id      UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_fee_structures  INTEGER NOT NULL DEFAULT 0,
        total_invoices        INTEGER NOT NULL DEFAULT 0,
        total_payments        INTEGER NOT NULL DEFAULT 0,
        total_discounts       INTEGER NOT NULL DEFAULT 0,
        total_penalties       INTEGER NOT NULL DEFAULT 0,
        total_receipts        INTEGER NOT NULL DEFAULT 0,
        total_invoice_amount  NUMERIC(15,2) NOT NULL DEFAULT 0,
        total_paid_amount     NUMERIC(15,2) NOT NULL DEFAULT 0,
        total_discount_amount NUMERIC(15,2) NOT NULL DEFAULT 0,
        total_penalty_amount  NUMERIC(15,2) NOT NULL DEFAULT 0,
        last_updated          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Grading metrics
    CREATE TABLE IF NOT EXISTS analytics.grading_metrics (
        academic_year_id UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_policies   INTEGER NOT NULL DEFAULT 0,
        total_boundaries INTEGER NOT NULL DEFAULT 0,
        last_updated     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Guardian metrics (per academic year)
    CREATE TABLE IF NOT EXISTS analytics.guardian_metrics (
        academic_year_id        UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_guardians         INTEGER NOT NULL DEFAULT 0,
        total_primary_guardians INTEGER NOT NULL DEFAULT 0,
        last_updated            TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- Library metrics
    CREATE TABLE IF NOT EXISTS analytics.library_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_categories   INTEGER NOT NULL DEFAULT 0,
        total_books        INTEGER NOT NULL DEFAULT 0,
        total_copies       INTEGER NOT NULL DEFAULT 0,
        total_issues       INTEGER NOT NULL DEFAULT 0,
        total_returns      INTEGER NOT NULL DEFAULT 0,
        total_fines        INTEGER NOT NULL DEFAULT 0,
        total_fine_amount  NUMERIC(12,2) NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );    


    CREATE TABLE IF NOT EXISTS analytics.room_metrics (
        academic_year_id UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_rooms      INTEGER NOT NULL DEFAULT 0,
        active_rooms     INTEGER NOT NULL DEFAULT 0,
        last_updated     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.section_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_sections     INTEGER NOT NULL DEFAULT 0,
        active_sections    INTEGER NOT NULL DEFAULT 0,
        total_capacity     INTEGER NOT NULL DEFAULT 0,
        used_capacity      INTEGER NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.student_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_students     INTEGER NOT NULL DEFAULT 0,
        active_students    INTEGER NOT NULL DEFAULT 0,
        male_students      INTEGER NOT NULL DEFAULT 0,
        female_students    INTEGER NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.subject_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_subjects     INTEGER NOT NULL DEFAULT 0,
        active_subjects    INTEGER NOT NULL DEFAULT 0,
        total_credits      INTEGER NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.submission_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_submissions  INTEGER NOT NULL DEFAULT 0,
        late_submissions   INTEGER NOT NULL DEFAULT 0,
        graded_submissions INTEGER NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.teacher_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_teachers     INTEGER NOT NULL DEFAULT 0,
        active_teachers    INTEGER NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.timetable_metrics (
        academic_year_id   UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_timetables   INTEGER NOT NULL DEFAULT 0,
        active_timetables  INTEGER NOT NULL DEFAULT 0,
        total_slots        INTEGER NOT NULL DEFAULT 0,
        total_entries      INTEGER NOT NULL DEFAULT 0,
        total_changes      INTEGER NOT NULL DEFAULT 0,
        last_updated       TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analytics.transport_metrics (
        academic_year_id           UUID PRIMARY KEY REFERENCES academics.academic_year(academic_year_id) ON DELETE CASCADE,
        total_routes               INTEGER NOT NULL DEFAULT 0,
        total_stops                INTEGER NOT NULL DEFAULT 0,
        total_vehicles             INTEGER NOT NULL DEFAULT 0,
        active_vehicles            INTEGER NOT NULL DEFAULT 0,
        total_driver_assignments   INTEGER NOT NULL DEFAULT 0,
        total_student_assignments  INTEGER NOT NULL DEFAULT 0,
        last_updated               TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );


    CREATE TABLE IF NOT EXISTS academics.student_auth (
        student_auth_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id        UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
        
        -- Encrypted password fields
        password          TEXT,
        password_dek      TEXT,
        password_key_id   TEXT,
        
        -- Optional: last login, security fields
        last_login_at     TIMESTAMPTZ,
        login_attempts    INT NOT NULL DEFAULT 0,
        locked_until      TIMESTAMPTZ,
        
        -- Audit columns (consistent with other tables)
        created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by        UUID REFERENCES users(user_id),
        updated_by        UUID REFERENCES users(user_id),
        deleted_at        TIMESTAMPTZ,
        
        -- Enforce one‑to‑one relationship
        CONSTRAINT uniq_student_auth UNIQUE (student_id)
    );

    -- Index for fast lookups
    CREATE INDEX IF NOT EXISTS idx_student_auth_student_id 
        ON academics.student_auth(student_id) 
        WHERE deleted_at IS NULL;





















































-- =====================================================
-- ACADEMICS UPGRADE: Timetable Sessions & Period-wise Attendance
-- =====================================================

-- 1. ADD MISSING COLUMNS TO EXISTING TABLES
-- =====================================================

-- Student daily attendance: add source tracking (for biometric/web)
ALTER TABLE academics.student_attendance
    ADD COLUMN IF NOT EXISTS source_type VARCHAR(30),
    ADD COLUMN IF NOT EXISTS device_id   VARCHAR(256);

COMMENT ON COLUMN academics.student_attendance.source_type IS 'biometric, web, manual, classroom';
COMMENT ON COLUMN academics.student_attendance.device_id IS 'References public.attendance_devices.device_id';

-- 2. NEW TABLE: academic_session (materialised class instances)
-- =====================================================
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
    -- SNAPSHOT COLUMNS (for history safety & performance)
    section_id          UUID NOT NULL REFERENCES academics.section(section_id),
    subject_id          UUID NOT NULL REFERENCES academics.subject(subject_id),
    slot_id             UUID NOT NULL REFERENCES academics.timetable_slots(slot_id),
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID REFERENCES users(user_id),
    updated_by          UUID REFERENCES users(user_id),
    UNIQUE(timetable_entry_id, session_date)
);

-- Indexes for academic_session
CREATE INDEX idx_academic_session_section_date ON academics.academic_session(section_id, session_date);
CREATE INDEX idx_academic_session_teacher_date ON academics.academic_session(teacher_id, session_date);
CREATE INDEX idx_academic_session_subject ON academics.academic_session(subject_id);
CREATE INDEX idx_academic_session_status ON academics.academic_session(status) WHERE status = 'ongoing';

-- 3. NEW TABLE: student_session_attendance (period-wise attendance)
-- =====================================================
CREATE TABLE IF NOT EXISTS academics.student_session_attendance (
    attendance_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES academics.academic_session(session_id) ON DELETE CASCADE,
    enrollment_id   UUID NOT NULL REFERENCES academics.enrollments(enrollment_id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL CHECK (status IN ('present', 'absent', 'late', 'excused')),
    marked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    marked_by       UUID REFERENCES users(user_id),
    source_type     VARCHAR(30) NOT NULL,   -- 'web', 'biometric', 'manual', 'classroom'
    device_id       VARCHAR(256),           -- references public.attendance_devices.device_id
    is_auto         BOOLEAN DEFAULT false,  -- true = biometric auto‑mark
    remarks         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(session_id, enrollment_id)
);

-- Indexes for student_session_attendance
CREATE INDEX idx_ssa_session ON academics.student_session_attendance(session_id);
CREATE INDEX idx_ssa_enrollment ON academics.student_session_attendance(enrollment_id);
CREATE INDEX idx_ssa_session_enrollment ON academics.student_session_attendance(session_id, enrollment_id);
CREATE INDEX idx_ssa_source_type ON academics.student_session_attendance(source_type);
CREATE INDEX idx_ssa_marked_at ON academics.student_session_attendance(marked_at DESC);

-- 4. NEW TABLE: attendance_session (bulk marking control)
-- =====================================================
CREATE TABLE IF NOT EXISTS academics.attendance_session (
    session_mark_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES academics.academic_session(session_id) ON DELETE CASCADE,
    marked_by       UUID REFERENCES users(user_id),
    source_type     VARCHAR(20),
    status          VARCHAR(20) DEFAULT 'completed',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(session_id)
);

CREATE INDEX idx_attendance_session_session_id ON academics.attendance_session(session_id);

-- 5. NEW TABLE: student_biometric_mapping (link students to devices)
-- =====================================================
-- (Reuses existing public.attendance_devices – no changes to payroll/biometric tables)
CREATE TABLE IF NOT EXISTS academics.student_biometric_mapping (
    mapping_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id       UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
    company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    device_id        VARCHAR(256) NOT NULL REFERENCES public.attendance_devices(device_id) ON DELETE CASCADE,
    device_user_code VARCHAR(100) NOT NULL,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enrolled_by      UUID REFERENCES users(user_id),
    UNIQUE(company_id, device_id, device_user_code),
    UNIQUE(student_id, device_id)
);

CREATE INDEX idx_student_biometric_device ON academics.student_biometric_mapping(device_id, device_user_code) WHERE is_active = true;
CREATE INDEX idx_student_biometric_student ON academics.student_biometric_mapping(student_id) WHERE is_active = true;

-- 6. OPTIONAL BUT RECOMMENDED: student_face_embeddings (separate from employee biometrics)
-- =====================================================
CREATE TABLE IF NOT EXISTS academics.student_face_embeddings (
    embedding_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    student_id        UUID NOT NULL REFERENCES academics.students(student_id) ON DELETE CASCADE,
    company_id        UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    embedding_vector  DOUBLE PRECISION[] NOT NULL,
    model_version     VARCHAR(50) NOT NULL,
    embedding_dim     INTEGER NOT NULL CHECK (embedding_dim IN (128,512)),
    is_active         BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by        UUID REFERENCES users(user_id),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, student_id)
);

CREATE INDEX idx_student_face_embeddings_active ON academics.student_face_embeddings(company_id, is_active) WHERE is_active = true;

-- 7. ADD ANY MISSING INDEXES FOR PERFORMANCE
-- =====================================================
-- Existing table: enrollments – ensure we have index on (student_id, status)
CREATE INDEX IF NOT EXISTS idx_enrollments_student_status ON academics.enrollments(student_id, status);

-- Existing table: timetable_entries – index on (teacher_id, subject_id) for faster session generation
CREATE INDEX IF NOT EXISTS idx_timetable_entries_teacher_subject ON academics.timetable_entries(teacher_id, subject_id);

-- =====================================================
-- END OF UPGRADE SCRIPT
-- =====================================================

-- Session attendance summary per student per term/year
CREATE TABLE analytics.student_session_summary (
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

-- Daily/Weekly session metrics per section
CREATE TABLE analytics.section_session_metrics (
    section_id            UUID REFERENCES academics.section(section_id),
    session_date          DATE NOT NULL,
    total_enrolled        INTEGER NOT NULL,
    present_count         INTEGER NOT NULL,
    absent_count          INTEGER NOT NULL,
    late_count            INTEGER NOT NULL,
    marked_by_teacher     INTEGER,   -- count marked manually
    marked_by_biometric   INTEGER,   -- count auto‑marked
    PRIMARY KEY (section_id, session_date)
);

-- Teacher performance on session attendance (e.g., % of sessions where teacher marked attendance)
CREATE TABLE analytics.teacher_session_metrics (
    teacher_id            UUID REFERENCES academics.teachers(teacher_id),
    academic_year_id      UUID REFERENCES academics.academic_year(academic_year_id),
    total_sessions_taught INTEGER NOT NULL,
    sessions_marked       INTEGER NOT NULL,   -- teacher marked at least one student
    sessions_with_biometric INTEGER NOT NULL,
    last_updated          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (teacher_id, academic_year_id)
);

-- Biometric device usage analytics
CREATE TABLE analytics.biometric_usage_metrics (
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
ADD COLUMN total_sessions_generated      INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_period_attendances      INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_biometric_attendances   INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_manual_period_attendances INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_outbox_pending 
ON outbox.events(status, created_at);


