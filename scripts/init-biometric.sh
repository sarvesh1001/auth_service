#!/bin/bash
set -e

echo "🧬 Initializing biometric schema..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'

-- ============================================================
-- BIOMETRIC MODULE
-- ============================================================

CREATE SCHEMA IF NOT EXISTS biometric;

-- ============================================================
-- FACE EMBEDDINGS
-- ============================================================

CREATE TABLE IF NOT EXISTS biometric.face_embeddings (
    embedding_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    embedding_vector FLOAT8[] NOT NULL,
    model_version    VARCHAR(50) NOT NULL,
    embedding_dim    INTEGER NOT NULL CHECK (embedding_dim IN (128, 512)),
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_company_user UNIQUE (company_id, user_id),

    CONSTRAINT fk_face_embeddings_employee
        FOREIGN KEY (company_id, user_id)
        REFERENCES company_employees(company_id, user_id)
        ON DELETE CASCADE
);

-- ============================================================
-- DEVICE SYNC TRACKING
-- ============================================================

CREATE TABLE IF NOT EXISTS biometric.device_embedding_sync (
    sync_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    device_id      VARCHAR(256) NOT NULL,
    model_version  VARCHAR(50) NOT NULL,
    last_synced_at TIMESTAMPTZ,
    last_full_sync TIMESTAMPTZ,
    created_at     TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT unique_company_device UNIQUE (company_id, device_id),

    CONSTRAINT fk_device_sync_device
        FOREIGN KEY (device_id)
        REFERENCES attendance_devices(device_id)
        ON DELETE CASCADE
);

-- ============================================================
-- AUDIT LOG
-- ============================================================

CREATE TABLE IF NOT EXISTS biometric.embedding_audit_log (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL,
    user_id         UUID NOT NULL,
    action          VARCHAR(30) NOT NULL,
    model_version   VARCHAR(50),
    acted_by        UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    metadata        JSONB,

    CONSTRAINT fk_embedding_audit_employee
        FOREIGN KEY (company_id, user_id)
        REFERENCES company_employees(company_id, user_id)
        ON DELETE CASCADE
);

-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_face_embeddings_company
ON biometric.face_embeddings (company_id);

CREATE INDEX IF NOT EXISTS idx_face_embeddings_active
ON biometric.face_embeddings (company_id, is_active)
WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_face_embeddings_updated
ON biometric.face_embeddings (company_id, model_version, updated_at);

CREATE INDEX IF NOT EXISTS idx_device_embedding_sync_company
ON biometric.device_embedding_sync (company_id);

-- ============================================================
-- AUTO DEACTIVATE ON EMPLOYEE EXIT
-- ============================================================

CREATE OR REPLACE FUNCTION biometric.revoke_biometric_on_exit()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE biometric.face_embeddings
    SET is_active = false,
        updated_at = NOW()
    WHERE company_id = NEW.company_id
      AND user_id = NEW.user_id
      AND is_active = true;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_revoke_biometric_on_exit ON employee_exit;

CREATE TRIGGER trg_revoke_biometric_on_exit
AFTER UPDATE OF exit_state ON employee_exit
FOR EACH ROW
WHEN (NEW.exit_state = 'effective')
EXECUTE FUNCTION biometric.revoke_biometric_on_exit();
CREATE INDEX IF NOT EXISTS idx_face_embeddings_sync_lookup
ON biometric.face_embeddings (company_id, model_version, updated_at);



-- =============================================================================
-- Table: payroll.attendance_rule (with foreign keys)
-- =============================================================================
CREATE TABLE IF NOT EXISTS payroll.attendance_rule (
    rule_id            UUID PRIMARY KEY,
    company_id         UUID NOT NULL,
    rule_type          VARCHAR(50) NOT NULL,            -- overtime | late | absent
    calculation_type   VARCHAR(50) NOT NULL,            -- percentage | flat | multiplier
    value              NUMERIC(10,4) NOT NULL,
    based_on           VARCHAR(50),                      -- daily | hourly (nullable for flat)
    threshold_minutes  INT DEFAULT 0,                    -- for late or overtime minimum trigger
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMP NOT NULL DEFAULT now(),
    created_by         UUID,
    updated_at         TIMESTAMP,
    updated_by         UUID,

    CONSTRAINT fk_attendance_rule_company
        FOREIGN KEY (company_id) REFERENCES companies(company_id),

    CONSTRAINT fk_attendance_rule_created_by
        FOREIGN KEY (created_by) REFERENCES users(user_id),

    CONSTRAINT fk_attendance_rule_updated_by
        FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- =============================================================================
-- Table: payroll.employee_fine (with foreign keys)
-- =============================================================================
CREATE TABLE IF NOT EXISTS payroll.employee_fine (
    fine_id            UUID PRIMARY KEY,
    company_id         UUID NOT NULL,
    user_id            UUID NOT NULL,
    fine_amount        NUMERIC(12,2) NOT NULL,
    reason             TEXT NOT NULL,
    fine_date          DATE NOT NULL,
    is_processed       BOOLEAN NOT NULL DEFAULT FALSE,
    payroll_run_id     UUID,
    created_at         TIMESTAMP NOT NULL DEFAULT now(),
    created_by         UUID NOT NULL,

    CONSTRAINT fk_employee_fine_company
        FOREIGN KEY (company_id) REFERENCES companies(company_id),

    CONSTRAINT fk_employee_fine_user
        FOREIGN KEY (user_id) REFERENCES users(user_id),

    CONSTRAINT fk_employee_fine_payroll_run
        FOREIGN KEY (payroll_run_id) REFERENCES payroll.payroll_run(payroll_run_id),

    CONSTRAINT fk_employee_fine_created_by
        FOREIGN KEY (created_by) REFERENCES users(user_id)
);

-- Indexes (as originally provided)
CREATE INDEX IF NOT EXISTS idx_attendance_rule_company
    ON payroll.attendance_rule(company_id, is_active);

CREATE INDEX IF NOT EXISTS idx_employee_fine_user
    ON payroll.employee_fine(company_id, user_id, is_processed);

ALTER TABLE payroll.statutory_rule_set
ADD COLUMN deactivated_at TIMESTAMPTZ,
ADD COLUMN deactivated_by UUID;

ALTER TABLE payroll.statutory_contribution_rule
ADD CONSTRAINT no_overlapping_statutory_rules
EXCLUDE USING gist (
    company_id WITH =,
    statutory_code WITH =,
    contribution_side WITH =,
    daterange(effective_from, COALESCE(effective_to, 'infinity'), '[]') WITH &&
)
WHERE (is_active = true);
EOSQL

echo "✅ Biometric schema initialized successfully!"
