-- =====================================================
-- ACCOUNTING MODULE – FINAL PRODUCTION SCHEMA
-- with ledger core, fiscal engine, immutability, dimensions
-- =====================================================

CREATE SCHEMA IF NOT EXISTS accounting;

-- =====================================================
-- 1. CHART OF ACCOUNTS (soft delete)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.accounts (
    account_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    account_code       VARCHAR(20) NOT NULL,
    account_name       VARCHAR(255) NOT NULL,
    account_type       VARCHAR(30) NOT NULL CHECK (account_type IN (
        'asset', 'liability', 'equity', 'revenue', 'expense'
    )),
    parent_account_id  UUID,
    is_active          BOOLEAN NOT NULL DEFAULT true,
    description        TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT fk_accounts_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_accounts_parent FOREIGN KEY (parent_account_id) REFERENCES accounting.accounts(account_id),
    CONSTRAINT fk_accounts_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_accounts_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, account_code)
);

-- =====================================================
-- 2. JOURNAL ENTRIES (source linkage + idempotency)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.journal_entries (
    journal_entry_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    journal_type       VARCHAR(30) NOT NULL CHECK (journal_type IN (
        'sales', 'purchase', 'payment', 'receipt', 'general', 'contra'
    )),
    entry_date         DATE NOT NULL,
    reference          VARCHAR(100),
    description        TEXT,
    status             VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN (
        'draft', 'posted', 'reversed', 'deleted'
    )),
    reversal_of        UUID,
    source_type        VARCHAR(30),
    source_id          TEXT,                           -- ✅ changed from UUID to TEXT
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_at          TIMESTAMPTZ,
    posted_by          UUID,
    created_by         UUID,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by         UUID,
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT fk_journal_entries_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_journal_entries_reversal_of FOREIGN KEY (reversal_of) REFERENCES accounting.journal_entries(journal_entry_id),
    CONSTRAINT fk_journal_entries_posted_by FOREIGN KEY (posted_by) REFERENCES users(user_id),
    CONSTRAINT fk_journal_entries_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_journal_entries_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    CONSTRAINT unique_source UNIQUE (company_id, source_type, source_id)
);
-- =====================================================
-- 3. JOURNAL LINES (with immutability after posting)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.journal_lines (
    journal_line_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    journal_entry_id   UUID NOT NULL,
    account_id         UUID NOT NULL,
    line_number        INT NOT NULL,
    debit_amount       NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (debit_amount >= 0),
    credit_amount      NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (credit_amount >= 0),
    description        TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_journal_lines_entry FOREIGN KEY (journal_entry_id) REFERENCES accounting.journal_entries(journal_entry_id) ON DELETE CASCADE,
    CONSTRAINT fk_journal_lines_account FOREIGN KEY (account_id) REFERENCES accounting.accounts(account_id),
    CONSTRAINT check_line_amount CHECK (
        (debit_amount > 0 AND credit_amount = 0) OR
        (credit_amount > 0 AND debit_amount = 0)
    ),
    UNIQUE (journal_entry_id, line_number)
);

-- =====================================================
-- 4. LEDGER ENTRIES (SOURCE OF TRUTH)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.ledger_entries (
    ledger_entry_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id        UUID NOT NULL,
    journal_entry_id  UUID NOT NULL,
    journal_line_id   UUID NOT NULL,
    account_id        UUID NOT NULL,
    entry_date        DATE NOT NULL,
    debit_amount      NUMERIC(14,2) NOT NULL DEFAULT 0,
    credit_amount     NUMERIC(14,2) NOT NULL DEFAULT 0,
    fiscal_year       INT NOT NULL,                    -- 👈 NOW NOT NULL
    period            INT NOT NULL,                    -- 👈 NOW NOT NULL
    running_balance   NUMERIC(14,2),                   -- optional, remains nullable
    cost_center_id    UUID,
    department_id     UUID,
    is_reversal       BOOLEAN DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_le_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_le_journal FOREIGN KEY (journal_entry_id) REFERENCES accounting.journal_entries(journal_entry_id) ON DELETE CASCADE,
    CONSTRAINT fk_le_line FOREIGN KEY (journal_line_id) REFERENCES accounting.journal_lines(journal_line_id) ON DELETE CASCADE,
    CONSTRAINT fk_le_account FOREIGN KEY (account_id) REFERENCES accounting.accounts(account_id),
    CONSTRAINT unique_ledger_line UNIQUE (journal_line_id)
);
-- =====================================================
-- 5. ACCOUNT BALANCES (CACHE ONLY)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.account_balances (
    balance_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    account_id         UUID NOT NULL,
    fiscal_year        INT NOT NULL,
    period             INT NOT NULL CHECK (period BETWEEN 1 AND 12),
    opening_balance    NUMERIC(14,2) NOT NULL DEFAULT 0,
    closing_balance    NUMERIC(14,2) NOT NULL DEFAULT 0,
    is_recomputed      BOOLEAN NOT NULL DEFAULT false,
    last_computed_at   TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_balances_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_balances_account FOREIGN KEY (account_id) REFERENCES accounting.accounts(account_id),
    UNIQUE (company_id, account_id, fiscal_year, period)
);

-- =====================================================
-- 6. TAX & COMPLIANCE TABLES (unchanged, but included for completeness)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.tax_rates (
    tax_rate_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    tax_name           VARCHAR(100) NOT NULL,
    rate_percentage    NUMERIC(5,2) NOT NULL,
    effective_from     DATE NOT NULL,
    effective_to       DATE,
    is_active          BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT fk_tax_rates_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_rates_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_tax_rates_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS accounting.tax_rules (
    tax_rule_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    rule_name          VARCHAR(100) NOT NULL,
    applies_to         VARCHAR(30) NOT NULL CHECK (applies_to IN ('sales', 'purchase', 'both')),
    priority           INT NOT NULL DEFAULT 0,
    is_active          BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT fk_tax_rules_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_rules_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_tax_rules_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS accounting.tax_rule_versions (
    version_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tax_rule_id        UUID NOT NULL,
    version            INT NOT NULL,
    rule_json          JSONB NOT NULL,
    is_current         BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    CONSTRAINT fk_tax_rule_versions_rule FOREIGN KEY (tax_rule_id) REFERENCES accounting.tax_rules(tax_rule_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_rule_versions_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    UNIQUE (tax_rule_id, version)
);

CREATE TABLE IF NOT EXISTS accounting.tax_conditions (
    condition_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tax_rule_id        UUID NOT NULL,
    field_name         VARCHAR(50) NOT NULL,
    operator           VARCHAR(20) NOT NULL,
    value_text         TEXT,
    value_numeric      NUMERIC(14,2),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tax_conditions_rule FOREIGN KEY (tax_rule_id) REFERENCES accounting.tax_rules(tax_rule_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounting.tax_actions (
    action_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tax_rule_id        UUID NOT NULL,
    tax_rate_id        UUID NOT NULL,
    action_type        VARCHAR(30) NOT NULL CHECK (action_type IN ('apply_tax', 'exempt', 'reverse_charge')),
    calculation_basis  VARCHAR(30) NOT NULL DEFAULT 'line_amount' CHECK (calculation_basis IN ('line_amount', 'taxable_value')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tax_actions_rule FOREIGN KEY (tax_rule_id) REFERENCES accounting.tax_rules(tax_rule_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_actions_rate FOREIGN KEY (tax_rate_id) REFERENCES accounting.tax_rates(tax_rate_id)
);

CREATE TABLE IF NOT EXISTS accounting.tax_transactions (
    tax_transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    transaction_type   VARCHAR(30) NOT NULL CHECK (transaction_type IN ('invoice', 'payment', 'journal')),
    transaction_id     UUID NOT NULL,
    tax_rule_id        UUID,
    tax_rate_id        UUID,
    taxable_amount     NUMERIC(14,2) NOT NULL,
    tax_amount         NUMERIC(14,2) NOT NULL,
    currency           VARCHAR(3) NOT NULL DEFAULT 'USD',
    exchange_rate      NUMERIC(14,6) DEFAULT 1,
    base_currency_amount NUMERIC(14,2) GENERATED ALWAYS AS (ROUND(taxable_amount * exchange_rate, 2)) STORED,
    transaction_date   DATE NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tax_transactions_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_transactions_rule FOREIGN KEY (tax_rule_id) REFERENCES accounting.tax_rules(tax_rule_id),
    CONSTRAINT fk_tax_transactions_rate FOREIGN KEY (tax_rate_id) REFERENCES accounting.tax_rates(tax_rate_id)
);

CREATE TABLE IF NOT EXISTS accounting.tax_profiles (
    tax_profile_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    tax_regime         VARCHAR(30) NOT NULL,
    jurisdiction       VARCHAR(50) NOT NULL DEFAULT 'default',
    registration_number VARCHAR(100),
    default_tax_rate_id UUID,
    settings           JSONB,
    is_active          BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT fk_tax_profiles_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_profiles_default_rate FOREIGN KEY (default_tax_rate_id) REFERENCES accounting.tax_rates(tax_rate_id),
    CONSTRAINT fk_tax_profiles_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_tax_profiles_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, tax_regime, jurisdiction)
);

CREATE TABLE IF NOT EXISTS accounting.compliance_returns (
    return_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    return_type        VARCHAR(30) NOT NULL,
    period_start       DATE NOT NULL,
    period_end         DATE NOT NULL,
    due_date           DATE NOT NULL,
    filing_date        DATE,
    status             VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'filed', 'amended')),
    total_liability    NUMERIC(14,2) DEFAULT 0,
    total_paid         NUMERIC(14,2) DEFAULT 0,
    is_locked          BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    filed_by           UUID,
    filed_at           TIMESTAMPTZ,
    amended_from       UUID,                                      -- now present
    deleted_at         TIMESTAMPTZ,
    CONSTRAINT fk_returns_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_returns_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_returns_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    CONSTRAINT fk_returns_filed_by FOREIGN KEY (filed_by) REFERENCES users(user_id),
    CONSTRAINT fk_returns_amended_from FOREIGN KEY (amended_from) REFERENCES accounting.compliance_returns(return_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS accounting.compliance_return_lines (
    line_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id          UUID NOT NULL,
    line_type          VARCHAR(50) NOT NULL,
    tax_rate_id        UUID,
    taxable_amount     NUMERIC(14,2) NOT NULL,
    tax_amount         NUMERIC(14,2) NOT NULL,
    description        TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_return_lines_return FOREIGN KEY (return_id) REFERENCES accounting.compliance_returns(return_id) ON DELETE CASCADE,
    CONSTRAINT fk_return_lines_tax_rate FOREIGN KEY (tax_rate_id) REFERENCES accounting.tax_rates(tax_rate_id)
);

CREATE TABLE IF NOT EXISTS accounting.compliance_filings (
    filing_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id          UUID NOT NULL,
    submission_date    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledgement_no VARCHAR(100),
    filing_status      VARCHAR(20) NOT NULL DEFAULT 'submitted' CHECK (filing_status IN ('submitted', 'accepted', 'rejected', 'pending')),
    error_message      TEXT,
    metadata           JSONB,
    created_by         UUID,
    CONSTRAINT fk_filings_return FOREIGN KEY (return_id) REFERENCES accounting.compliance_returns(return_id) ON DELETE CASCADE,
    CONSTRAINT fk_filings_created_by FOREIGN KEY (created_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS accounting.compliance_audit_logs (
    audit_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    return_id          UUID,
    action             VARCHAR(50) NOT NULL,
    old_state          JSONB,
    new_state          JSONB,
    acted_by           UUID,
    acted_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address         INET,
    CONSTRAINT fk_audit_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_audit_return FOREIGN KEY (return_id) REFERENCES accounting.compliance_returns(return_id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_acted_by FOREIGN KEY (acted_by) REFERENCES users(user_id)
);

-- =====================================================
-- 7. ACCOUNTING SETTINGS (per company)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.accounting_settings (
    company_id                     UUID PRIMARY KEY,
    fiscal_year_start_month        INT NOT NULL DEFAULT 1 CHECK (fiscal_year_start_month BETWEEN 1 AND 12),
    currency_code                  VARCHAR(3) NOT NULL DEFAULT 'USD',
    tax_scheme                     VARCHAR(30) NOT NULL DEFAULT 'accrual' CHECK (tax_scheme IN ('accrual', 'cash')),
    allow_intercompany_journal     BOOLEAN NOT NULL DEFAULT false,
    auto_generate_reversals        BOOLEAN NOT NULL DEFAULT false,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by                     UUID,
    updated_by                     UUID,
    CONSTRAINT fk_settings_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_settings_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_settings_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- =====================================================
-- 8. ANALYTICS TABLES (daily aggregates, snapshots, etc.)
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.analytics_daily_account_summary (
    summary_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    account_id       UUID NOT NULL,
    date             DATE NOT NULL,
    total_debit      NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_credit     NUMERIC(14,2) NOT NULL DEFAULT 0,
    net_movement     NUMERIC(14,2) GENERATED ALWAYS AS (total_debit - total_credit) STORED,
    transaction_count INT NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ads_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_ads_account FOREIGN KEY (account_id) REFERENCES accounting.accounts(account_id),
    UNIQUE (company_id, account_id, date)
);

CREATE TABLE IF NOT EXISTS accounting.analytics_account_snapshots (
    snapshot_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    account_id       UUID NOT NULL,
    snapshot_date    DATE NOT NULL,
    balance          NUMERIC(14,2) NOT NULL,
    fiscal_year      INT,
    period           INT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_snapshot_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_snapshot_account FOREIGN KEY (account_id) REFERENCES accounting.accounts(account_id),
    UNIQUE (company_id, account_id, snapshot_date)
);

CREATE TABLE IF NOT EXISTS accounting.analytics_journal_metrics (
    metric_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    journal_type     VARCHAR(30),
    date             DATE NOT NULL,
    total_entries    INT NOT NULL DEFAULT 0,
    total_amount     NUMERIC(14,2) NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_jm_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    UNIQUE (company_id, journal_type, date)
);

CREATE TABLE IF NOT EXISTS accounting.analytics_tax_summary (
    summary_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    tax_rate_id      UUID,
    date             DATE NOT NULL,
    total_taxable    NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_tax        NUMERIC(14,2) NOT NULL DEFAULT 0,
    transaction_count INT NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tax_summary_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_summary_rate FOREIGN KEY (tax_rate_id) REFERENCES accounting.tax_rates(tax_rate_id),
    UNIQUE (company_id, tax_rate_id, date)
);

CREATE TABLE IF NOT EXISTS accounting.analytics_cashflow (
    cashflow_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    date             DATE NOT NULL,
    inflow           NUMERIC(14,2) NOT NULL DEFAULT 0,
    outflow          NUMERIC(14,2) NOT NULL DEFAULT 0,
    net_cashflow     NUMERIC(14,2) GENERATED ALWAYS AS (inflow - outflow) STORED,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_cashflow_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    UNIQUE (company_id, date)
);

-- =====================================================
-- 9. RECONCILIATION TABLES
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.reconciliation_batches (
    batch_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    reconciliation_type VARCHAR(30) NOT NULL CHECK (reconciliation_type IN ('bank', 'payment', 'ledger', 'external')),
    reference           VARCHAR(100),
    start_date          DATE,
    end_date            DATE,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    total_records       INT NOT NULL DEFAULT 0,
    matched_records     INT NOT NULL DEFAULT 0,
    unmatched_records   INT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    created_by          UUID REFERENCES users(user_id),
    CONSTRAINT fk_reconciliation_batches_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounting.reconciliation_items (
    item_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id           UUID NOT NULL,
    source_type        VARCHAR(30) NOT NULL,
    source_id          TEXT,                           -- changed from UUID to TEXT
    journal_entry_id   UUID,
    amount             NUMERIC(14,2),
    currency           VARCHAR(3) NOT NULL DEFAULT 'USD',
    transaction_date   DATE,
    match_status       VARCHAR(20) NOT NULL DEFAULT 'unmatched' CHECK (match_status IN ('matched', 'unmatched', 'partial', 'ignored')),
    match_score        NUMERIC(5,2),
    notes              TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_reconciliation_items_batch FOREIGN KEY (batch_id) REFERENCES accounting.reconciliation_batches(batch_id) ON DELETE CASCADE,
    CONSTRAINT fk_reconciliation_items_journal FOREIGN KEY (journal_entry_id) REFERENCES accounting.journal_entries(journal_entry_id)
);

CREATE TABLE IF NOT EXISTS accounting.reconciliation_differences (
    difference_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id           UUID NOT NULL,
    issue_type         VARCHAR(50) NOT NULL CHECK (issue_type IN ('missing_entry', 'amount_mismatch', 'duplicate', 'timing_difference')),
    expected_amount    NUMERIC(14,2),
    actual_amount      NUMERIC(14,2),
    source_id          TEXT,            -- changed from UUID to TEXT
    journal_entry_id   UUID,
    description        TEXT,
    resolved           BOOLEAN NOT NULL DEFAULT false,
    resolved_by        UUID REFERENCES users(user_id),
    resolved_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_reconciliation_diff_batch FOREIGN KEY (batch_id) REFERENCES accounting.reconciliation_batches(batch_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounting.reconciliation_adjustments (
    adjustment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id           UUID NOT NULL,
    journal_entry_id   UUID NOT NULL,
    reason             TEXT,
    adjustment_amount  NUMERIC(14,2),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID REFERENCES users(user_id),
    CONSTRAINT fk_reconciliation_adj_batch FOREIGN KEY (batch_id) REFERENCES accounting.reconciliation_batches(batch_id) ON DELETE CASCADE,
    CONSTRAINT fk_reconciliation_adj_journal FOREIGN KEY (journal_entry_id) REFERENCES accounting.journal_entries(journal_entry_id)
);

-- =====================================================
-- 10. RECONCILIATION ANALYTICS TABLES
-- =====================================================
CREATE TABLE IF NOT EXISTS accounting.analytics_reconciliation_batch_metrics (
    metric_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id             UUID NOT NULL UNIQUE,
    company_id           UUID NOT NULL,
    reconciliation_type  VARCHAR(30) NOT NULL,
    total_items          INT NOT NULL DEFAULT 0,
    matched_items        INT NOT NULL DEFAULT 0,
    unmatched_items      INT NOT NULL DEFAULT 0,
    ignored_items        INT NOT NULL DEFAULT 0,
    match_rate           NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_items > 0 THEN ROUND((matched_items::NUMERIC / total_items) * 100, 2) ELSE 0 END) STORED,
    started_at           TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,
    completion_duration_seconds INT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (completed_at - started_at))::INT) STORED,
    total_differences    INT NOT NULL DEFAULT 0,
    resolved_differences INT NOT NULL DEFAULT 0,
    total_adjustments    INT NOT NULL DEFAULT 0,
    adjustment_amount    NUMERIC(14,2) NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_analytics_batch_metrics_batch FOREIGN KEY (batch_id) REFERENCES accounting.reconciliation_batches(batch_id) ON DELETE CASCADE,
    CONSTRAINT fk_analytics_batch_metrics_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounting.analytics_reconciliation_daily_stats (
    stat_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    reconciliation_type  VARCHAR(30) NOT NULL,
    date                 DATE NOT NULL,
    batches_started      INT NOT NULL DEFAULT 0,
    batches_completed    INT NOT NULL DEFAULT 0,
    total_items_processed INT NOT NULL DEFAULT 0,
    total_matched        INT NOT NULL DEFAULT 0,
    total_unmatched      INT NOT NULL DEFAULT 0,
    total_ignored        INT NOT NULL DEFAULT 0,
    avg_match_rate       NUMERIC(5,2) NOT NULL DEFAULT 0,
    avg_completion_seconds INT NOT NULL DEFAULT 0,
    differences_created  INT NOT NULL DEFAULT 0,
    differences_resolved INT NOT NULL DEFAULT 0,
    adjustments_created  INT NOT NULL DEFAULT 0,
    total_adjustment_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_daily_stats_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    UNIQUE (company_id, reconciliation_type, date)
);

CREATE TABLE IF NOT EXISTS accounting.analytics_reconciliation_diff_trends (
    trend_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    batch_id             UUID,
    issue_type           VARCHAR(50) NOT NULL,
    date                 DATE NOT NULL,
    count                INT NOT NULL DEFAULT 0,
    total_expected_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_actual_amount  NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_variance       NUMERIC(14,2) GENERATED ALWAYS AS (total_expected_amount - total_actual_amount) STORED,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_diff_trends_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_diff_trends_batch FOREIGN KEY (batch_id) REFERENCES accounting.reconciliation_batches(batch_id) ON DELETE SET NULL
);

-- =====================================================
-- FUNCTIONS & TRIGGERS
-- =====================================================

-- Update updated_at column
CREATE OR REPLACE FUNCTION accounting.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach updated_at triggers to all relevant tables
CREATE TRIGGER update_accounts_updated_at BEFORE UPDATE ON accounting.accounts FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_journal_entries_updated_at BEFORE UPDATE ON accounting.journal_entries FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_journal_lines_updated_at BEFORE UPDATE ON accounting.journal_lines FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_account_balances_updated_at BEFORE UPDATE ON accounting.account_balances FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_tax_rates_updated_at BEFORE UPDATE ON accounting.tax_rates FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_tax_rules_updated_at BEFORE UPDATE ON accounting.tax_rules FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_tax_profiles_updated_at BEFORE UPDATE ON accounting.tax_profiles FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_compliance_returns_updated_at BEFORE UPDATE ON accounting.compliance_returns FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_accounting_settings_updated_at BEFORE UPDATE ON accounting.accounting_settings FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();
CREATE TRIGGER update_reconciliation_items_updated_at BEFORE UPDATE ON accounting.reconciliation_items FOR EACH ROW EXECUTE FUNCTION accounting.update_updated_at_column();

-- Fiscal year computation
CREATE OR REPLACE FUNCTION accounting.compute_fiscal_fields(p_date DATE, p_start_month INT)
RETURNS TABLE(fiscal_year INT, period INT) LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN QUERY
    SELECT
        CASE WHEN EXTRACT(MONTH FROM p_date) >= p_start_month
             THEN EXTRACT(YEAR FROM p_date)::INT
             ELSE (EXTRACT(YEAR FROM p_date) - 1)::INT
        END,
        ((EXTRACT(MONTH FROM p_date)::INT - p_start_month + 12) % 12) + 1;
END;
$$;

-- Auto‑populate fiscal fields on ledger insert
CREATE OR REPLACE FUNCTION accounting.set_ledger_fiscal_fields()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE start_month INT; fy INT; pr INT;
BEGIN
    SELECT fiscal_year_start_month INTO start_month FROM accounting.accounting_settings WHERE company_id = NEW.company_id;
    SELECT fiscal_year, period INTO fy, pr FROM accounting.compute_fiscal_fields(NEW.entry_date, start_month);
    NEW.fiscal_year := fy; NEW.period := pr;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_set_ledger_fiscal ON accounting.ledger_entries;
CREATE TRIGGER trg_set_ledger_fiscal BEFORE INSERT ON accounting.ledger_entries FOR EACH ROW EXECUTE FUNCTION accounting.set_ledger_fiscal_fields();

-- Prevent update/delete of journal lines after posting

-- Prevent update/delete of journal lines after posting (fixed for DELETE)
CREATE OR REPLACE FUNCTION accounting.prevent_update_posted_lines()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    je_status TEXT;
    je_id UUID;
BEGIN
    -- Determine the journal_entry_id based on operation
    IF TG_OP = 'DELETE' THEN
        je_id := OLD.journal_entry_id;
    ELSE
        je_id := NEW.journal_entry_id;
    END IF;

    -- Get the status of the parent journal entry
    SELECT status INTO je_status
    FROM accounting.journal_entries
    WHERE journal_entry_id = je_id;

    IF je_status = 'posted' THEN
        RAISE EXCEPTION 'Cannot modify or delete journal lines of a posted entry (JE: %)', je_id;
    END IF;

    -- Return appropriate row for the operation
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$;

-- Recreate the trigger (unchanged)
DROP TRIGGER IF EXISTS trg_no_update_posted_lines ON accounting.journal_lines;
CREATE TRIGGER trg_no_update_posted_lines
    BEFORE UPDATE OR DELETE ON accounting.journal_lines
    FOR EACH ROW
    EXECUTE FUNCTION accounting.prevent_update_posted_lines();
-- Ensure ledger entries exist before allowing post
CREATE OR REPLACE FUNCTION accounting.ensure_ledger_on_post()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE ledger_count INT;
BEGIN
    IF NEW.status = 'posted' AND (OLD.status IS DISTINCT FROM 'posted') THEN
        SELECT COUNT(*) INTO ledger_count FROM accounting.ledger_entries WHERE journal_entry_id = NEW.journal_entry_id;
        IF ledger_count = 0 THEN
            RAISE EXCEPTION 'Journal % cannot be posted: ledger_entries missing', NEW.journal_entry_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_ensure_ledger_on_post ON accounting.journal_entries;
CREATE TRIGGER trg_ensure_ledger_on_post AFTER UPDATE ON accounting.journal_entries FOR EACH ROW EXECUTE FUNCTION accounting.ensure_ledger_on_post();

-- Validate journal balance before posting (existing)
CREATE OR REPLACE FUNCTION accounting.validate_journal_before_post()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE total_debit NUMERIC; total_credit NUMERIC;
BEGIN
    IF NEW.status = 'posted' AND (OLD.status IS DISTINCT FROM 'posted') THEN
        SELECT SUM(debit_amount), SUM(credit_amount) INTO total_debit, total_credit
        FROM accounting.journal_lines WHERE journal_entry_id = NEW.journal_entry_id;
        IF total_debit IS NULL OR total_credit IS NULL OR total_debit != total_credit THEN
            RAISE EXCEPTION 'Journal % cannot be posted: not balanced (debit=%, credit=%)', NEW.journal_entry_id, COALESCE(total_debit,0), COALESCE(total_credit,0);
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_validate_journal_before_post ON accounting.journal_entries;
CREATE TRIGGER trg_validate_journal_before_post BEFORE UPDATE ON accounting.journal_entries FOR EACH ROW EXECUTE FUNCTION accounting.validate_journal_before_post();

-- Prevent deletion of posted journals
CREATE OR REPLACE FUNCTION accounting.prevent_posted_delete()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'posted' THEN
        RAISE EXCEPTION 'Cannot delete posted journal entry %', OLD.journal_entry_id;
    END IF;
    RETURN OLD;
END;
$$;
DROP TRIGGER IF EXISTS trg_no_delete_posted ON accounting.journal_entries;
CREATE TRIGGER trg_no_delete_posted BEFORE DELETE ON accounting.journal_entries FOR EACH ROW EXECUTE FUNCTION accounting.prevent_posted_delete();

-- (Optional) Ledger balance validation – deferred until end of transaction
CREATE OR REPLACE FUNCTION accounting.validate_ledger_balance()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE total_debit NUMERIC; total_credit NUMERIC;
BEGIN
    SELECT SUM(debit_amount), SUM(credit_amount) INTO total_debit, total_credit
    FROM accounting.ledger_entries WHERE journal_entry_id = NEW.journal_entry_id;
    IF NOT (total_debit = total_credit) THEN
        RAISE EXCEPTION 'Ledger imbalance for journal % (debit=%, credit=%)', NEW.journal_entry_id, total_debit, total_credit;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_validate_ledger_balance ON accounting.ledger_entries;
CREATE CONSTRAINT TRIGGER trg_validate_ledger_balance AFTER INSERT OR UPDATE ON accounting.ledger_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION accounting.validate_ledger_balance();

CREATE OR REPLACE FUNCTION accounting.update_reconciliation_batch_metrics()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO accounting.analytics_reconciliation_batch_metrics (
        batch_id, company_id, reconciliation_type,
        total_items, matched_items, unmatched_items, ignored_items,
        started_at, completed_at,
        total_differences, resolved_differences, total_adjustments, adjustment_amount
    )
    SELECT
        b.batch_id,
        b.company_id,
        b.reconciliation_type,
        COALESCE(SUM(CASE WHEN i.match_status IN ('matched', 'unmatched', 'ignored') THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN i.match_status = 'matched' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN i.match_status = 'unmatched' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN i.match_status = 'ignored' THEN 1 ELSE 0 END), 0),
        CASE WHEN b.status IN ('in_progress', 'completed') THEN LEAST(b.created_at, NOW()) ELSE NULL END,
        b.completed_at,
        (SELECT COUNT(*) FROM accounting.reconciliation_differences d WHERE d.batch_id = b.batch_id),
        (SELECT COUNT(*) FROM accounting.reconciliation_differences d WHERE d.batch_id = b.batch_id AND d.resolved = true),
        (SELECT COUNT(*) FROM accounting.reconciliation_adjustments a WHERE a.batch_id = b.batch_id),
        COALESCE((SELECT SUM(adjustment_amount) FROM accounting.reconciliation_adjustments a WHERE a.batch_id = b.batch_id), 0)
    FROM accounting.reconciliation_batches b
    LEFT JOIN accounting.reconciliation_items i ON i.batch_id = b.batch_id
    WHERE b.batch_id = NEW.batch_id
    GROUP BY b.batch_id, b.company_id, b.reconciliation_type, b.status, b.created_at, b.completed_at
    ON CONFLICT (batch_id) DO UPDATE SET
        total_items = EXCLUDED.total_items,
        matched_items = EXCLUDED.matched_items,
        unmatched_items = EXCLUDED.unmatched_items,
        ignored_items = EXCLUDED.ignored_items,
        started_at = EXCLUDED.started_at,
        completed_at = EXCLUDED.completed_at,
        total_differences = EXCLUDED.total_differences,
        resolved_differences = EXCLUDED.resolved_differences,
        total_adjustments = EXCLUDED.total_adjustments,
        adjustment_amount = EXCLUDED.adjustment_amount,
        updated_at = NOW();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION accounting.update_reconciliation_batch_metrics()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO accounting.analytics_reconciliation_batch_metrics (
        batch_id, company_id, reconciliation_type,
        total_items, matched_items, unmatched_items, ignored_items,
        started_at, completed_at,
        total_differences, resolved_differences, total_adjustments, adjustment_amount
    )
    SELECT
        b.batch_id,
        b.company_id,
        b.reconciliation_type,
        COALESCE(SUM(CASE WHEN i.match_status IN ('matched', 'unmatched', 'ignored') THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN i.match_status = 'matched' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN i.match_status = 'unmatched' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN i.match_status = 'ignored' THEN 1 ELSE 0 END), 0),
        CASE WHEN b.status IN ('in_progress', 'completed') THEN LEAST(b.created_at, NOW()) ELSE NULL END,
        b.completed_at,
        (SELECT COUNT(*) FROM accounting.reconciliation_differences d WHERE d.batch_id = b.batch_id),
        (SELECT COUNT(*) FROM accounting.reconciliation_differences d WHERE d.batch_id = b.batch_id AND d.resolved = true),
        (SELECT COUNT(*) FROM accounting.reconciliation_adjustments a WHERE a.batch_id = b.batch_id),
        COALESCE((SELECT SUM(adjustment_amount) FROM accounting.reconciliation_adjustments a WHERE a.batch_id = b.batch_id), 0)
    FROM accounting.reconciliation_batches b
    LEFT JOIN accounting.reconciliation_items i ON i.batch_id = b.batch_id
    WHERE b.batch_id = NEW.batch_id
    GROUP BY b.batch_id, b.company_id, b.reconciliation_type, b.status, b.created_at, b.completed_at
    ON CONFLICT (batch_id) DO UPDATE SET
        total_items = EXCLUDED.total_items,
        matched_items = EXCLUDED.matched_items,
        unmatched_items = EXCLUDED.unmatched_items,
        ignored_items = EXCLUDED.ignored_items,
        started_at = EXCLUDED.started_at,
        completed_at = EXCLUDED.completed_at,
        total_differences = EXCLUDED.total_differences,
        resolved_differences = EXCLUDED.resolved_differences,
        total_adjustments = EXCLUDED.total_adjustments,
        adjustment_amount = EXCLUDED.adjustment_amount,
        updated_at = NOW();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- (the exact functions are long; they are already in your original schema – we keep them unchanged)

-- =====================================================
-- INDEXES (all critical)
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_accounts_company ON accounting.accounts(company_id);
CREATE INDEX IF NOT EXISTS idx_accounts_type ON accounting.accounts(account_type);
CREATE INDEX IF NOT EXISTS idx_accounts_parent ON accounting.accounts(parent_account_id);
CREATE INDEX IF NOT EXISTS idx_accounts_deleted ON accounting.accounts(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_journal_entries_company_date ON accounting.journal_entries(company_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_journal_entries_status ON accounting.journal_entries(status);
CREATE INDEX IF NOT EXISTS idx_journal_entries_source ON accounting.journal_entries(source_type, source_id);

CREATE INDEX IF NOT EXISTS idx_journal_lines_entry ON accounting.journal_lines(journal_entry_id);
CREATE INDEX IF NOT EXISTS idx_journal_lines_account ON accounting.journal_lines(account_id);

CREATE INDEX IF NOT EXISTS idx_ledger_account_date ON accounting.ledger_entries(account_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_ledger_company_date ON accounting.ledger_entries(company_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_ledger_journal ON accounting.ledger_entries(journal_entry_id);
CREATE INDEX IF NOT EXISTS idx_ledger_fiscal_period ON accounting.ledger_entries(company_id, fiscal_year, period);
CREATE INDEX IF NOT EXISTS idx_ledger_account_fiscal ON accounting.ledger_entries(account_id, fiscal_year, period);  -- critical for balance aggregation

CREATE INDEX IF NOT EXISTS idx_account_balances_lookup ON accounting.account_balances(company_id, account_id, fiscal_year, period);
CREATE INDEX IF NOT EXISTS idx_account_balances_dirty ON accounting.account_balances(is_recomputed) WHERE is_recomputed = false;

CREATE INDEX IF NOT EXISTS idx_tax_rates_company_active ON accounting.tax_rates(company_id, is_active);
CREATE INDEX IF NOT EXISTS idx_tax_rates_effective ON accounting.tax_rates(effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_tax_rates_deleted ON accounting.tax_rates(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tax_rules_company ON accounting.tax_rules(company_id);
CREATE INDEX IF NOT EXISTS idx_tax_rules_deleted ON accounting.tax_rules(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tax_rule_versions_rule ON accounting.tax_rule_versions(tax_rule_id);
CREATE INDEX IF NOT EXISTS idx_tax_rule_versions_current ON accounting.tax_rule_versions(tax_rule_id) WHERE is_current = true;

CREATE INDEX IF NOT EXISTS idx_tax_conditions_rule ON accounting.tax_conditions(tax_rule_id);
CREATE INDEX IF NOT EXISTS idx_tax_actions_rule ON accounting.tax_actions(tax_rule_id);

CREATE INDEX IF NOT EXISTS idx_tax_transactions_company_date ON accounting.tax_transactions(company_id, transaction_date);
CREATE INDEX IF NOT EXISTS idx_tax_transactions_lookup ON accounting.tax_transactions(transaction_type, transaction_id);

CREATE INDEX IF NOT EXISTS idx_compliance_returns_company_period ON accounting.compliance_returns(company_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_compliance_returns_status ON accounting.compliance_returns(status);
CREATE INDEX IF NOT EXISTS idx_compliance_returns_deleted ON accounting.compliance_returns(deleted_at) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_compliance_return_lines_return ON accounting.compliance_return_lines(return_id);
CREATE INDEX IF NOT EXISTS idx_compliance_filings_return ON accounting.compliance_filings(return_id);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_return ON accounting.compliance_audit_logs(return_id);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_company ON accounting.compliance_audit_logs(company_id);

CREATE INDEX IF NOT EXISTS idx_analytics_daily_company_date ON accounting.analytics_daily_account_summary(company_id, date);
CREATE INDEX IF NOT EXISTS idx_analytics_snapshots_company_date ON accounting.analytics_account_snapshots(company_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_analytics_journal_metrics_company_date ON accounting.analytics_journal_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_analytics_tax_summary_company_date ON accounting.analytics_tax_summary(company_id, date);
CREATE INDEX IF NOT EXISTS idx_analytics_cashflow_company_date ON accounting.analytics_cashflow(company_id, date);

CREATE INDEX IF NOT EXISTS idx_recon_batches_company ON accounting.reconciliation_batches(company_id);
CREATE INDEX IF NOT EXISTS idx_recon_batches_status ON accounting.reconciliation_batches(status);
CREATE INDEX IF NOT EXISTS idx_recon_batches_type ON accounting.reconciliation_batches(reconciliation_type);
CREATE INDEX IF NOT EXISTS idx_recon_items_batch ON accounting.reconciliation_items(batch_id);
CREATE INDEX IF NOT EXISTS idx_recon_items_status ON accounting.reconciliation_items(match_status);
CREATE INDEX IF NOT EXISTS idx_recon_items_journal ON accounting.reconciliation_items(journal_entry_id);
CREATE INDEX IF NOT EXISTS idx_recon_items_source ON accounting.reconciliation_items(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_recon_diff_batch ON accounting.reconciliation_differences(batch_id);
CREATE INDEX IF NOT EXISTS idx_recon_diff_resolved ON accounting.reconciliation_differences(resolved) WHERE resolved = false;
CREATE INDEX IF NOT EXISTS idx_recon_adj_batch ON accounting.reconciliation_adjustments(batch_id);

CREATE INDEX IF NOT EXISTS idx_analytics_batch_metrics_company ON accounting.analytics_reconciliation_batch_metrics(company_id);
CREATE INDEX IF NOT EXISTS idx_analytics_batch_metrics_type ON accounting.analytics_reconciliation_batch_metrics(reconciliation_type);
CREATE INDEX IF NOT EXISTS idx_analytics_batch_metrics_completed ON accounting.analytics_reconciliation_batch_metrics(completed_at) WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytics_daily_stats_company_date ON accounting.analytics_reconciliation_daily_stats(company_id, date);
CREATE INDEX IF NOT EXISTS idx_analytics_daily_stats_type_date ON accounting.analytics_reconciliation_daily_stats(reconciliation_type, date);
CREATE INDEX IF NOT EXISTS idx_analytics_diff_trends_company_date ON accounting.analytics_reconciliation_diff_trends(company_id, date);
CREATE INDEX IF NOT EXISTS idx_analytics_diff_trends_issue_type ON accounting.analytics_reconciliation_diff_trends(issue_type);

-- =====================================================
-- INITIAL DEFAULT ACCOUNTING SETTINGS
-- =====================================================
INSERT INTO accounting.accounting_settings (company_id, fiscal_year_start_month, currency_code, created_by)
SELECT company_id, 4, 'USD', NULL FROM companies
ON CONFLICT (company_id) DO NOTHING;


CREATE TABLE accounting.processed_events (
    event_id        TEXT NOT NULL,
    consumer_group  VARCHAR(100) NOT NULL,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, consumer_group)
);
CREATE INDEX idx_processed_events_consumer 
ON accounting.processed_events(consumer_group);



-- Table for period locking (prevents posting to closed periods)
CREATE TABLE IF NOT EXISTS accounting.period_locks (
    lock_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    fiscal_year      INT NOT NULL,
    period           INT NOT NULL CHECK (period BETWEEN 1 AND 12),
    is_locked        BOOLEAN NOT NULL DEFAULT false,
    locked_at        TIMESTAMPTZ,
    locked_by        UUID REFERENCES users(user_id),
    reason           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, fiscal_year, period)
);

-- Indexes for period_locks
CREATE INDEX IF NOT EXISTS idx_period_locks_company ON accounting.period_locks(company_id);
CREATE INDEX IF NOT EXISTS idx_period_locks_locked ON accounting.period_locks(is_locked) WHERE is_locked = true;
CREATE INDEX IF NOT EXISTS idx_period_locks_fiscal_period ON accounting.period_locks(fiscal_year, period);

-- Fast lookup index for accounts by ID and type (critical for rule engine)
CREATE INDEX IF NOT EXISTS idx_accounts_id_type ON accounting.accounts(account_id, account_type);


CREATE OR REPLACE FUNCTION accounting.check_period_lock()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM accounting.period_locks
        WHERE company_id = NEW.company_id
          AND fiscal_year = NEW.fiscal_year
          AND period = NEW.period
          AND is_locked = true
    ) THEN
        RAISE EXCEPTION 'Cannot insert ledger entry for locked period %-% (company %)', 
                        NEW.fiscal_year, NEW.period, NEW.company_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_check_period_lock
BEFORE INSERT ON accounting.ledger_entries
FOR EACH ROW
EXECUTE FUNCTION accounting.check_period_lock();


ALTER TABLE accounting.reconciliation_batches
ADD COLUMN failure_reason TEXT;






ALTER TABLE accounting.journal_entries 
ALTER COLUMN source_id TYPE TEXT;