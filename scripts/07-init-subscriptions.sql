    -- =====================================================
    -- SUBSCRIPTION SCHEMA (Modular, Optimized)
    -- =====================================================

    DROP SCHEMA IF EXISTS subscription CASCADE;
    CREATE SCHEMA subscription;

    -- -----------------------------------------------------
    -- LOOKUPS
    -- -----------------------------------------------------

    CREATE TABLE subscription.plan_type (
        plan_type_id SMALLINT PRIMARY KEY,
        code         VARCHAR(30) NOT NULL UNIQUE,
        name         VARCHAR(100) NOT NULL
    );

    INSERT INTO subscription.plan_type (plan_type_id, code, name) VALUES
        (1, 'recurring', 'Recurring'),
        (2, 'one_time', 'One‑Time'),
        (3, 'usage_based', 'Usage‑Based'),
        (4, 'contract', 'Contract')
    ON CONFLICT (plan_type_id) DO NOTHING;

    CREATE TABLE subscription.billing_frequency (
        frequency_id SMALLINT PRIMARY KEY,
        code         VARCHAR(20) NOT NULL UNIQUE,
        name         VARCHAR(50) NOT NULL
    );

    INSERT INTO subscription.billing_frequency (frequency_id, code, name) VALUES
        (1, 'daily', 'Daily'),
        (2, 'weekly', 'Weekly'),
        (3, 'monthly', 'Monthly'),
        (4, 'quarterly', 'Quarterly'),
        (5, 'half_yearly', 'Half‑Yearly'),
        (6, 'yearly', 'Yearly')
    ON CONFLICT (frequency_id) DO NOTHING;

    CREATE TABLE subscription.pricing_model (
        model_id SMALLINT PRIMARY KEY,
        code     VARCHAR(30) NOT NULL UNIQUE,
        name     VARCHAR(100) NOT NULL
    );

    INSERT INTO subscription.pricing_model (model_id, code, name) VALUES
        (1, 'flat', 'Flat'),
        (2, 'per_user', 'Per User'),
        (3, 'per_seat', 'Per Seat'),
        (4, 'per_visit', 'Per Visit'),
        (5, 'per_usage', 'Per Usage'),
        (6, 'tiered', 'Tiered'),
        (7, 'metered', 'Metered')
    ON CONFLICT (model_id) DO NOTHING;

    CREATE TABLE subscription.statuses (
        status_id SMALLINT PRIMARY KEY,
        code      VARCHAR(30) NOT NULL,
        category  VARCHAR(30) NOT NULL,
        name      VARCHAR(100) NOT NULL,
        UNIQUE (code, category)
    );

    INSERT INTO subscription.statuses (status_id, code, category, name) VALUES
        (1, 'active', 'subscription', 'Active'),
        (2, 'paused', 'subscription', 'Paused'),
        (3, 'expired', 'subscription', 'Expired'),
        (4, 'cancelled', 'subscription', 'Cancelled'),
        (5, 'trial', 'subscription', 'Trial'),
        (6, 'pending', 'subscription', 'Pending'),
        (7, 'active', 'item', 'Active'),
        (8, 'inactive', 'item', 'Inactive')
    ON CONFLICT (status_id) DO NOTHING;

    -- -----------------------------------------------------
    -- POLICIES (Configurable Business Rules)
    -- -----------------------------------------------------

    CREATE TABLE subscription.proration_policies (
        proration_policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name                VARCHAR(100) NOT NULL,
        upgrade_type        VARCHAR(20) NOT NULL CHECK (upgrade_type IN ('charge_difference', 'refund', 'credit_note')),
        downgrade_type      VARCHAR(20) NOT NULL CHECK (downgrade_type IN ('credit_next', 'refund', 'none')),
        is_active           BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        UNIQUE (company_id, name)
    );

    CREATE TABLE subscription.billing_policies (
        billing_policy_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name                VARCHAR(100) NOT NULL,
        frequency_id        SMALLINT NOT NULL REFERENCES subscription.billing_frequency(frequency_id),
        billing_interval    INT NOT NULL DEFAULT 1,   -- e.g., 1 month, 2 weeks
        model_id            SMALLINT NOT NULL REFERENCES subscription.pricing_model(model_id),
        advance_days        INT NOT NULL DEFAULT 0,
        is_active           BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        UNIQUE (company_id, name)
    );

    CREATE TABLE subscription.renewal_policies (
        renewal_policy_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name                VARCHAR(100) NOT NULL,
        auto_renew          BOOLEAN NOT NULL DEFAULT true,
        grace_days          INT NOT NULL DEFAULT 0,
        late_fee_percent    NUMERIC(5,2) DEFAULT 0,
        notice_days         INT NOT NULL DEFAULT 0,
        is_active           BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        UNIQUE (company_id, name)
    );

    CREATE TABLE subscription.pause_policies (
        pause_policy_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name                VARCHAR(100) NOT NULL,
        max_pause_days      INT NOT NULL DEFAULT 0,
        allowed_reasons     TEXT[] NOT NULL DEFAULT '{}',
        freeze_days         INT NOT NULL DEFAULT 0,
        is_active           BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        UNIQUE (company_id, name)
    );

    -- -----------------------------------------------------
    -- FEATURES & PLANS
    -- -----------------------------------------------------

    CREATE TABLE subscription.feature_registry (
        feature_key       VARCHAR(100) PRIMARY KEY,
        module            VARCHAR(50) NOT NULL,
        feature_group     VARCHAR(50),
        permission_scope  VARCHAR(50),
        description       TEXT,
        default_limit     NUMERIC(14,4),
        depends_on        VARCHAR(100)[] DEFAULT '{}',
        version           INT NOT NULL DEFAULT 1,
        is_active         BOOLEAN NOT NULL DEFAULT true,
        created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE subscription.plans (
        plan_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name                VARCHAR(255) NOT NULL,
        plan_type_id        SMALLINT NOT NULL REFERENCES subscription.plan_type(plan_type_id),
        description         TEXT,
        billing_policy_id   UUID NOT NULL REFERENCES subscription.billing_policies(billing_policy_id) ON DELETE RESTRICT,
        renewal_policy_id   UUID NOT NULL REFERENCES subscription.renewal_policies(renewal_policy_id) ON DELETE RESTRICT,
        pause_policy_id     UUID NOT NULL REFERENCES subscription.pause_policies(pause_policy_id) ON DELETE RESTRICT,
        proration_policy_id UUID NOT NULL REFERENCES subscription.proration_policies(proration_policy_id) ON DELETE RESTRICT,
        duration_days       INT NOT NULL DEFAULT 365,
        cancellation_policy TEXT,
        metadata            JSONB,
        is_active           BOOLEAN NOT NULL DEFAULT true,
        version             INT NOT NULL DEFAULT 1,
        published_at        TIMESTAMPTZ,
        published_by        UUID REFERENCES users(user_id) ON DELETE SET NULL,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        UNIQUE (company_id, name)
    );

    CREATE TABLE subscription.plan_items (
        plan_item_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        plan_id             UUID NOT NULL REFERENCES subscription.plans(plan_id) ON DELETE CASCADE,
        item_type           VARCHAR(20) NOT NULL CHECK (item_type IN ('base','addon','benefit','discount','tax')),
        name                VARCHAR(255) NOT NULL,
        description         TEXT,
        feature_key         VARCHAR(100) REFERENCES subscription.feature_registry(feature_key) ON DELETE SET NULL,
        billing_policy_id   UUID REFERENCES subscription.billing_policies(billing_policy_id) ON DELETE SET NULL,
        price               NUMERIC(14,2) NOT NULL DEFAULT 0,
        currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
        effective_from      DATE NOT NULL DEFAULT CURRENT_DATE,
        effective_to        DATE,
        is_mandatory        BOOLEAN NOT NULL DEFAULT false,
        is_active           BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ
    );

    CREATE TABLE subscription.entitlements (
        entitlement_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        plan_item_id        UUID NOT NULL REFERENCES subscription.plan_items(plan_item_id) ON DELETE CASCADE,
        feature_key         VARCHAR(100) NOT NULL REFERENCES subscription.feature_registry(feature_key) ON DELETE CASCADE,
        limit_value         NUMERIC(14,4),
        limit_period        VARCHAR(20) CHECK (limit_period IN ('day','week','month','year','lifetime')) DEFAULT 'month',
        is_enabled          BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (plan_item_id, feature_key)
    );

    CREATE TABLE subscription.benefits (
        benefit_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        plan_item_id        UUID NOT NULL REFERENCES subscription.plan_items(plan_item_id) ON DELETE CASCADE,
        benefit_type        VARCHAR(50) NOT NULL CHECK (benefit_type IN ('discount','freebie','access','service','other')),
        benefit_description TEXT,
        value               JSONB NOT NULL,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
quantity
    CREATE TABLE subscription.addons (
        addon_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        name                VARCHAR(255) NOT NULL,
        description         TEXT,
        billing_policy_id   UUID NOT NULL REFERENCES subscription.billing_policies(billing_policy_id) ON DELETE RESTRICT,
        price               NUMERIC(14,2) NOT NULL,
        currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
        is_active           BOOLEAN NOT NULL DEFAULT true,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        UNIQUE (company_id, name)
    );

    -- -----------------------------------------------------
    -- SUBSCRIPTIONS (CORE)
    -- -----------------------------------------------------

    CREATE TABLE subscription.subscriptions (
        subscription_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        customer_id         UUID NOT NULL,                         -- references sales.customers (no FK)
        plan_id             UUID NOT NULL REFERENCES subscription.plans(plan_id) ON DELETE RESTRICT,
        status_id           SMALLINT NOT NULL REFERENCES subscription.statuses(status_id) DEFAULT 1,
        start_date          DATE NOT NULL DEFAULT CURRENT_DATE,
        end_date            DATE,
        trial_end           DATE,
        billing_start       DATE NOT NULL,
        auto_renew          BOOLEAN NOT NULL DEFAULT true,
        pause_reason        TEXT,
        cancellation_reason TEXT,
        cancelled_at        TIMESTAMPTZ,
        contract_number     VARCHAR(100) UNIQUE,
        signed_at           TIMESTAMPTZ,
        terms_version       VARCHAR(20),
        signed_document_key TEXT,
        current_invoice_id  UUID,                                 -- references sales.invoices (no FK)
        last_invoice_id     UUID,
        next_invoice_id     UUID,
        coupon_id           UUID,                                 -- references sales.coupons (no FK)
        version             INT NOT NULL DEFAULT 1,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at          TIMESTAMPTZ,
        sales_order_id      UUID,                                 -- references sales.orders (no FK)
        schedule_id         UUID,                                 -- external scheduling module
        workflow_id         UUID,                                 -- external workflow module
        notification_pref_id UUID                                 -- external notification module
    );

    COMMENT ON COLUMN subscription.subscriptions.customer_id IS 'Customer from sales.customers (application‑enforced)';
    COMMENT ON COLUMN subscription.subscriptions.schedule_id IS 'External scheduling module reference';
    COMMENT ON COLUMN subscription.subscriptions.workflow_id IS 'External workflow module reference';
    COMMENT ON COLUMN subscription.subscriptions.notification_pref_id IS 'External notification preference reference';

    -- -----------------------------------------------------
    -- SUBSCRIPTION ITEMS
    -- -----------------------------------------------------

    CREATE TABLE subscription.subscription_items (
        sub_item_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
        plan_item_id        UUID NOT NULL REFERENCES subscription.plan_items(plan_item_id) ON DELETE RESTRICT,
        addon_id            UUID REFERENCES subscription.addons(addon_id) ON DELETE SET NULL,
        quantity            NUMERIC(14,4) NOT NULL DEFAULT 1,
        unit_price          NUMERIC(14,2) NOT NULL,
        total_price         NUMERIC(14,2) GENERATED ALWAYS AS (quantity * unit_price) STORED,
        currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
        status_id           SMALLINT NOT NULL REFERENCES subscription.statuses(status_id) DEFAULT 7,
        start_date          DATE NOT NULL DEFAULT CURRENT_DATE,
        end_date            DATE,
        metadata            JSONB,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        product_id          UUID                                 -- references sales.products (no FK)
    );

    COMMENT ON COLUMN subscription.subscription_items.product_id IS 'Reference to the Sales product for this line item (pricing source)';

    -- -----------------------------------------------------
    -- VERSIONS & TIMELINE
    -- -----------------------------------------------------

    CREATE TABLE subscription.subscription_versions (
        version_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
        version_number      INT NOT NULL,
        snapshot            JSONB NOT NULL,
        reason              TEXT,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE subscription.subscription_timeline (
        timeline_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
        event_type          VARCHAR(50) NOT NULL,
        old_status_id       SMALLINT REFERENCES subscription.statuses(status_id),
        new_status_id       SMALLINT REFERENCES subscription.statuses(status_id),
        performed_by        UUID REFERENCES users(user_id) ON DELETE SET NULL,
        metadata            JSONB,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- -----------------------------------------------------
    -- USAGE TRACKING
    -- -----------------------------------------------------

    CREATE TABLE subscription.usages (
        usage_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_item_id UUID NOT NULL REFERENCES subscription.subscription_items(sub_item_id) ON DELETE CASCADE,
        feature_key         VARCHAR(100) NOT NULL REFERENCES subscription.feature_registry(feature_key),
        quantity_used       NUMERIC(14,4) NOT NULL,
        period_start        DATE NOT NULL,
        period_end          DATE NOT NULL,
        recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        source_type         VARCHAR(50),
        source_id           UUID,
        created_by          UUID REFERENCES users(user_id) ON DELETE SET NULL
    );

    CREATE VIEW subscription.usage_remaining AS
    SELECT
        si.sub_item_id,
        si.subscription_id,
        si.plan_item_id,
        e.feature_key,
        e.limit_value AS total_allowed,
        COALESCE(SUM(u.quantity_used), 0) AS used,
        (e.limit_value - COALESCE(SUM(u.quantity_used), 0)) AS remaining
    FROM subscription.subscription_items si
    JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
    JOIN subscription.entitlements e ON pi.plan_item_id = e.plan_item_id
    LEFT JOIN subscription.usages u ON u.subscription_item_id = si.sub_item_id
        AND u.feature_key = e.feature_key
        AND u.period_start = DATE_TRUNC('month', CURRENT_DATE)
    WHERE si.status_id = 7
    GROUP BY si.sub_item_id, si.subscription_id, si.plan_item_id, e.feature_key, e.limit_value;

    -- -----------------------------------------------------
    -- TRIALS
    -- -----------------------------------------------------

    CREATE TABLE subscription.trials (
        trial_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_id   UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
        started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        ended_at          TIMESTAMPTZ,
        trial_days        INT NOT NULL,
        features_enabled  JSONB NOT NULL DEFAULT '{}',
        usage_consumed    JSONB NOT NULL DEFAULT '{}',
        status            VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','expired','converted','cancelled')),
        created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    -- -----------------------------------------------------
    -- CROSS-MODULE MAPPING (Lightweight)
    -- -----------------------------------------------------

    CREATE TABLE subscription.subscription_invoice_item_map (
        map_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_item_id  UUID NOT NULL REFERENCES subscription.subscription_items(sub_item_id) ON DELETE CASCADE,
        invoice_item_id       UUID NOT NULL,                       -- references sales.invoice_items (no FK)
        allocated_quantity    NUMERIC(14,4) NOT NULL DEFAULT 1,
        created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (subscription_item_id, invoice_item_id)
    );

    CREATE TABLE subscription.subscription_session_map (
        map_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subscription_id       UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
        session_type          VARCHAR(50) NOT NULL,
        session_id            UUID NOT NULL,
        created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (session_type, session_id)
    );

    CREATE TABLE subscription.usage_attendance_link (
        link_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        usage_id              UUID NOT NULL REFERENCES subscription.usages(usage_id) ON DELETE CASCADE,
        attendance_event_id   UUID NOT NULL,                       -- references attendance.attendance_events (no FK)
        created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (usage_id, attendance_event_id)
    );

    -- -----------------------------------------------------
    -- AUDIT
    -- -----------------------------------------------------


    -- -----------------------------------------------------
    -- INDEXES
    -- -----------------------------------------------------

    CREATE INDEX idx_sub_plans_company ON subscription.plans(company_id);
    CREATE INDEX idx_sub_plans_type ON subscription.plans(plan_type_id);
    CREATE INDEX idx_sub_plans_deleted ON subscription.plans(deleted_at) WHERE deleted_at IS NOT NULL;

    CREATE INDEX idx_sub_plan_items_plan ON subscription.plan_items(plan_id);
    CREATE INDEX idx_sub_plan_items_feature ON subscription.plan_items(feature_key);
    CREATE INDEX idx_sub_plan_items_effective ON subscription.plan_items(effective_from, effective_to);

    CREATE INDEX idx_sub_entitlements_plan_item ON subscription.entitlements(plan_item_id);
    CREATE INDEX idx_sub_entitlements_feature ON subscription.entitlements(feature_key);

    CREATE INDEX idx_sub_subscriptions_company ON subscription.subscriptions(company_id);
    CREATE INDEX idx_sub_subscriptions_customer ON subscription.subscriptions(customer_id);
    CREATE INDEX idx_sub_subscriptions_plan ON subscription.subscriptions(plan_id);
    CREATE INDEX idx_sub_subscriptions_status ON subscription.subscriptions(status_id) WHERE status_id = 1;
    CREATE INDEX idx_sub_subscriptions_dates ON subscription.subscriptions(start_date, end_date);
    CREATE INDEX idx_sub_subscriptions_contract ON subscription.subscriptions(contract_number) WHERE contract_number IS NOT NULL;
    CREATE INDEX idx_sub_subscriptions_sales_order ON subscription.subscriptions(sales_order_id);
    CREATE INDEX idx_sub_subscriptions_schedule ON subscription.subscriptions(schedule_id);
    CREATE INDEX idx_sub_subscriptions_workflow ON subscription.subscriptions(workflow_id);

    CREATE INDEX idx_sub_items_subscription ON subscription.subscription_items(subscription_id);
    CREATE INDEX idx_sub_items_plan_item ON subscription.subscription_items(plan_item_id);
    CREATE INDEX idx_sub_items_status ON subscription.subscription_items(status_id);
    CREATE INDEX idx_sub_items_product ON subscription.subscription_items(product_id);

    CREATE INDEX idx_sub_versions_subscription ON subscription.subscription_versions(subscription_id);
    CREATE INDEX idx_sub_timeline_subscription ON subscription.subscription_timeline(subscription_id);
    CREATE INDEX idx_sub_timeline_event ON subscription.subscription_timeline(event_type);
    CREATE INDEX idx_sub_usages_sub_item ON subscription.usages(subscription_item_id);
    CREATE INDEX idx_sub_usages_period ON subscription.usages(period_start, period_end);
    CREATE INDEX idx_sub_inv_map_sub_item ON subscription.subscription_invoice_item_map(subscription_item_id);
    CREATE INDEX idx_sub_inv_map_inv_item ON subscription.subscription_invoice_item_map(invoice_item_id);
    CREATE INDEX idx_sub_session_map_sub ON subscription.subscription_session_map(subscription_id);
    CREATE INDEX idx_sub_session_map_session ON subscription.subscription_session_map(session_type, session_id);
    CREATE INDEX idx_usage_attendance_usage ON subscription.usage_attendance_link(usage_id);
    CREATE INDEX idx_usage_attendance_event ON subscription.usage_attendance_link(attendance_event_id);

    -- -----------------------------------------------------
    -- TRIGGERS FOR updated_at
    -- -----------------------------------------------------

    CREATE OR REPLACE FUNCTION subscription.update_updated_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    DO $$
    DECLARE
        tables TEXT[] := ARRAY[
            'proration_policies', 'billing_policies', 'renewal_policies', 'pause_policies',
            'plans', 'plan_items', 'entitlements', 'benefits', 'addons',
            'subscriptions', 'subscription_items', 'trials'
        ];
        t TEXT;
    BEGIN
        FOREACH t IN ARRAY tables
        LOOP
            EXECUTE format('
                CREATE TRIGGER update_%s_updated_at
                BEFORE UPDATE ON subscription.%I
                FOR EACH ROW EXECUTE FUNCTION subscription.update_updated_at_column()
            ', t, t);
        END LOOP;
    END;
    $$;

    -- -----------------------------------------------------
    -- ANALYTICS (Simplified Fact Tables)
    -- -----------------------------------------------------

    CREATE SCHEMA IF NOT EXISTS subscription_analytics;

    CREATE TABLE subscription_analytics.subscription_fact (
        fact_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id        UUID NOT NULL,
        subscription_id   UUID NOT NULL,
        event_date        TIMESTAMPTZ NOT NULL,
        event_type        VARCHAR(50) NOT NULL,   -- 'created', 'status_change', 'renewed', 'cancelled', etc.
        plan_id           UUID,
        customer_id       UUID,
        old_status_id     SMALLINT,
        new_status_id     SMALLINT,
        mrr_change        NUMERIC(14,2),
        metadata          JSONB,
        created_at        TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE subscription_analytics.usage_fact (
        fact_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id        UUID NOT NULL,
        subscription_item_id UUID NOT NULL,
        feature_key       VARCHAR(100) NOT NULL,
        quantity          NUMERIC(14,4) NOT NULL,
        usage_date        DATE NOT NULL,
        created_at        TIMESTAMPTZ DEFAULT NOW()
    );
    -- Plan versions (snapshots for publishing/rollback)
    CREATE TABLE subscription.plan_versions (
        version_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id      UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
        plan_id         UUID NOT NULL REFERENCES subscription.plans(plan_id) ON DELETE CASCADE,
        version_number  INT NOT NULL,
        snapshot        JSONB NOT NULL,               -- full plan configuration
        is_published    BOOLEAN NOT NULL DEFAULT false,
        published_at    TIMESTAMPTZ,
        published_by    UUID REFERENCES users(user_id) ON DELETE SET NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        deleted_at      TIMESTAMPTZ,
        UNIQUE(company_id, plan_id, version_number)
    );

    CREATE INDEX idx_plan_versions_plan ON subscription.plan_versions(plan_id);
    CREATE INDEX idx_plan_versions_published ON subscription.plan_versions(is_published) WHERE is_published = true;
    CREATE INDEX idx_plan_versions_deleted ON subscription.plan_versions(deleted_at) WHERE deleted_at IS NOT NULL;
    -- Indexes for analytics
    CREATE INDEX idx_sub_fact_company_date ON subscription_analytics.subscription_fact(company_id, event_date);
    CREATE INDEX idx_sub_fact_subscription ON subscription_analytics.subscription_fact(subscription_id);
    CREATE INDEX idx_usage_fact_company_date ON subscription_analytics.usage_fact(company_id, usage_date);
    CREATE INDEX idx_usage_fact_sub_item ON subscription_analytics.usage_fact(subscription_item_id);

    -- -----------------------------------------------------
    -- END SCRIPT
    -- -----------------------------------------------------

    -- subscription_analytics.daily_subscription_metrics
    CREATE TABLE subscription_analytics.daily_subscription_metrics (
        company_id           UUID NOT NULL,
        date                 DATE NOT NULL,
        new_subscriptions    INT NOT NULL DEFAULT 0,
        active_subscriptions INT NOT NULL DEFAULT 0,
        cancelled_subscriptions INT NOT NULL DEFAULT 0,
        expired_subscriptions INT NOT NULL DEFAULT 0,
        paused_subscriptions INT NOT NULL DEFAULT 0,
        trial_starts         INT NOT NULL DEFAULT 0,
        trial_conversions    INT NOT NULL DEFAULT 0,
        trial_expirations    INT NOT NULL DEFAULT 0,
        mrr                  NUMERIC(14,2) NOT NULL DEFAULT 0,
        arr                  NUMERIC(14,2) NOT NULL DEFAULT 0,
        updated_at           TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, date)
    );

    -- subscription_analytics.daily_plan_metrics
    CREATE TABLE subscription_analytics.daily_plan_metrics (
        company_id     UUID NOT NULL,
        plan_id        UUID NOT NULL,
        date           DATE NOT NULL,
        active_count   INT NOT NULL DEFAULT 0,
        new_count      INT NOT NULL DEFAULT 0,
        mrr            NUMERIC(14,2) NOT NULL DEFAULT 0,
        arr            NUMERIC(14,2) NOT NULL DEFAULT 0,
        updated_at     TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, plan_id, date)
    );


    CREATE TABLE subscription_analytics.addon_usage_fact (
        fact_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id        UUID NOT NULL,
        addon_id          UUID NOT NULL,
        subscription_id   UUID NOT NULL,
        quantity          NUMERIC(14,4) NOT NULL,
        usage_date        DATE NOT NULL,
        created_at        TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_addon_usage_fact_company_date ON subscription_analytics.addon_usage_fact(company_id, usage_date);
    CREATE INDEX idx_addon_usage_fact_addon ON subscription_analytics.addon_usage_fact(addon_id);

    -- subscription_analytics.daily_addon_metrics
    CREATE TABLE subscription_analytics.daily_addon_metrics (
        company_id     UUID NOT NULL,
        addon_id       UUID NOT NULL,
        date           DATE NOT NULL,
        active_count   INT NOT NULL DEFAULT 0,      -- number of subscriptions with this addon active on that day
        new_count      INT NOT NULL DEFAULT 0,      -- new subscriptions that attached this addon on that day
        revenue        NUMERIC(14,2) NOT NULL DEFAULT 0, -- total revenue from this addon (sum of unit_price * quantity)
        mrr            NUMERIC(14,2) NOT NULL DEFAULT 0, -- monthly recurring revenue contribution
        arr            NUMERIC(14,2) NOT NULL DEFAULT 0, -- annualised MRR
        updated_at     TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, addon_id, date)
    );

    CREATE INDEX idx_daily_addon_metrics_company_date ON subscription_analytics.daily_addon_metrics(company_id, date);
    CREATE INDEX idx_daily_addon_metrics_addon ON subscription_analytics.daily_addon_metrics(addon_id);


    -- subscription_analytics.benefit_usage_fact
    -- Records each subscription benefit usage event (e.g., when a benefit is attached to a subscription)
    CREATE TABLE subscription_analytics.benefit_usage_fact (
        fact_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id        UUID NOT NULL,
        benefit_id        UUID NOT NULL,          -- references subscription.benefits(benefit_id) but no FK
        subscription_id   UUID NOT NULL,
        benefit_type      VARCHAR(50) NOT NULL,   -- denormalized for quick querying
        quantity          NUMERIC(14,4) NOT NULL, -- typically 1, but can be extended
        usage_date        DATE NOT NULL,          -- day the benefit became active/used
        created_at        TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_benefit_usage_fact_company_date ON subscription_analytics.benefit_usage_fact(company_id, usage_date);
    CREATE INDEX idx_benefit_usage_fact_benefit ON subscription_analytics.benefit_usage_fact(benefit_id);
    CREATE INDEX idx_benefit_usage_fact_subscription ON subscription_analytics.benefit_usage_fact(subscription_id);

    -- subscription_analytics.daily_benefit_metrics
    -- Aggregated daily metrics per benefit (active counts, new attachments, etc.)
    CREATE TABLE subscription_analytics.daily_benefit_metrics (
        company_id     UUID NOT NULL,
        benefit_id     UUID NOT NULL,
        date           DATE NOT NULL,
        active_count   INT NOT NULL DEFAULT 0,      -- number of subscriptions with this benefit active on that day
        new_count      INT NOT NULL DEFAULT 0,      -- new subscriptions that attached this benefit on that day
        -- Optionally add revenue impact if benefit is discount-based:
        -- total_discount NUMERIC(14,2) NOT NULL DEFAULT 0,
        updated_at     TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, benefit_id, date)
    );

    CREATE INDEX idx_daily_benefit_metrics_company_date ON subscription_analytics.daily_benefit_metrics(company_id, date);
    CREATE INDEX idx_daily_benefit_metrics_benefit ON subscription_analytics.daily_benefit_metrics(benefit_id);



    -- -----------------------------------------------------
    -- BILLING POLICY ANALYTICS
    -- -----------------------------------------------------

    -- subscription_analytics.billing_policy_usage_fact
    -- Records each time a billing policy is referenced by a plan or addon.
    -- This can be used to track policy adoption over time.
    CREATE TABLE subscription_analytics.billing_policy_usage_fact (
        fact_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id           UUID NOT NULL,
        billing_policy_id    UUID NOT NULL,
        entity_type          VARCHAR(20) NOT NULL,      -- 'plan' or 'addon'
        entity_id            UUID NOT NULL,             -- plan_id or addon_id
        usage_date           DATE NOT NULL,             -- day the association became active
        created_at           TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_bp_usage_fact_company_date ON subscription_analytics.billing_policy_usage_fact(company_id, usage_date);
    CREATE INDEX idx_bp_usage_fact_policy ON subscription_analytics.billing_policy_usage_fact(billing_policy_id);
    CREATE INDEX idx_bp_usage_fact_entity ON subscription_analytics.billing_policy_usage_fact(entity_type, entity_id);

    -- subscription_analytics.daily_billing_policy_metrics
    -- Aggregated daily metrics per billing policy:
    --   - active_count: number of active plans/addons using this policy on that day
    --   - new_count: number of new associations created on that day
    --   - (optional) revenue: total revenue from subscriptions using this policy – can be derived later
    CREATE TABLE subscription_analytics.daily_billing_policy_metrics (
        company_id           UUID NOT NULL,
        billing_policy_id    UUID NOT NULL,
        date                 DATE NOT NULL,
        active_count         INT NOT NULL DEFAULT 0,
        new_count            INT NOT NULL DEFAULT 0,
        -- revenue              NUMERIC(14,2) NOT NULL DEFAULT 0,  -- uncomment if you want to track revenue
        updated_at           TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, billing_policy_id, date)
    );

    CREATE INDEX idx_daily_bp_metrics_company_date ON subscription_analytics.daily_billing_policy_metrics(company_id, date);
    CREATE INDEX idx_daily_bp_metrics_policy ON subscription_analytics.daily_billing_policy_metrics(billing_policy_id);


    -- Records each plan that uses a renewal policy.
    -- Inserted when a plan is created or its renewal_policy_id changes.
    CREATE TABLE subscription_analytics.renewal_policy_usage_fact (
        fact_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id           UUID NOT NULL,
        renewal_policy_id    UUID NOT NULL,
        plan_id              UUID NOT NULL,             -- the plan that references this policy
        usage_date           DATE NOT NULL,             -- day the association became active (plan.published_at or created_at)
        created_at           TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_rp_usage_fact_company_date ON subscription_analytics.renewal_policy_usage_fact(company_id, usage_date);
    CREATE INDEX idx_rp_usage_fact_policy ON subscription_analytics.renewal_policy_usage_fact(renewal_policy_id);
    CREATE INDEX idx_rp_usage_fact_plan ON subscription_analytics.renewal_policy_usage_fact(plan_id);


    -- subscription_analytics.daily_renewal_policy_metrics
    -- Daily aggregates per renewal policy:
    --   active_count: number of active plans using this policy on that day
    --   new_count:    number of new plans that started using this policy on that day
    --   (optional) plans_count: total plans referencing it (including inactive) – can be derived
    CREATE TABLE subscription_analytics.daily_renewal_policy_metrics (
        company_id           UUID NOT NULL,
        renewal_policy_id    UUID NOT NULL,
        date                 DATE NOT NULL,
        active_count         INT NOT NULL DEFAULT 0,
        new_count            INT NOT NULL DEFAULT 0,
        -- Optionally add revenue impact if you want to track MRR from plans using this policy
        -- mrr                  NUMERIC(14,2) NOT NULL DEFAULT 0,
        updated_at           TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, renewal_policy_id, date)
    );

    CREATE INDEX idx_daily_rp_metrics_company_date ON subscription_analytics.daily_renewal_policy_metrics(company_id, date);
    CREATE INDEX idx_daily_rp_metrics_policy ON subscription_analytics.daily_renewal_policy_metrics(renewal_policy_id);



    -- =====================================================
    -- PAUSE POLICY ANALYTICS
    -- =====================================================

    -- -----------------------------------------------------------------
    -- pause_policy_usage_fact
    -- Records each plan's association with a pause policy.
    -- Inserted when a plan is created, published, or its pause_policy_id changes.
    -- -----------------------------------------------------------------
    CREATE TABLE subscription_analytics.pause_policy_usage_fact (
        fact_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id           UUID NOT NULL,
        pause_policy_id      UUID NOT NULL,          -- references subscription.pause_policies(pause_policy_id)
        entity_type          VARCHAR(20) NOT NULL,   -- only 'plan' for now (could be extended)
        entity_id            UUID NOT NULL,          -- plan_id
        usage_date           DATE NOT NULL,          -- the day the association became active (plan.published_at or created_at)
        created_at           TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_pause_usage_fact_company_date ON subscription_analytics.pause_policy_usage_fact(company_id, usage_date);
    CREATE INDEX idx_pause_usage_fact_policy ON subscription_analytics.pause_policy_usage_fact(pause_policy_id);
    CREATE INDEX idx_pause_usage_fact_entity ON subscription_analytics.pause_policy_usage_fact(entity_type, entity_id);

    -- -----------------------------------------------------------------
    -- daily_pause_policy_metrics
    -- Daily aggregated metrics per pause policy:
    --   - active_count: number of active plans using this policy on that day
    --   - new_count:    number of plans that started using this policy on that day
    --   - paused_subscriptions_count: number of subscriptions currently paused that use this policy
    --   - pause_events_count: number of pause events (transitions to paused status) on that day
    --   - resume_events_count: number of resume events (transitions from paused to active) on that day
    --   - avg_pause_duration_days: average pause duration for pauses that ended on that day (can be computed, but we store it for quick access)
    -- -----------------------------------------------------------------
    CREATE TABLE subscription_analytics.daily_pause_policy_metrics (
        company_id                  UUID NOT NULL,
        pause_policy_id             UUID NOT NULL,
        date                        DATE NOT NULL,
        active_count                INT NOT NULL DEFAULT 0,      -- plans using this policy that are active on the day
        new_count                   INT NOT NULL DEFAULT 0,      -- plans that newly associated with this policy on that day
        paused_subscriptions_count  INT NOT NULL DEFAULT 0,      -- subscriptions in paused status using this policy
        pause_events_count          INT NOT NULL DEFAULT 0,      -- number of pause transitions (status -> paused) on that day
        resume_events_count         INT NOT NULL DEFAULT 0,      -- number of resume transitions (paused -> active) on that day
        avg_pause_duration_days     NUMERIC(8,2) DEFAULT 0,      -- average duration of pauses that ended on that day
        updated_at                  TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, pause_policy_id, date)
    );

    CREATE INDEX idx_daily_pause_metrics_company_date ON subscription_analytics.daily_pause_policy_metrics(company_id, date);
    CREATE INDEX idx_daily_pause_metrics_policy ON subscription_analytics.daily_pause_policy_metrics(pause_policy_id);

    -- -----------------------------------------------------------------
    -- (Optional) pause_event_fact – for fine‑grained pause analytics
    -- This fact records each individual pause event per subscription.
    -- Can be used to populate daily aggregates and support deeper analysis.
    -- -----------------------------------------------------------------
    CREATE TABLE subscription_analytics.pause_event_fact (
        fact_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id           UUID NOT NULL,
        subscription_id      UUID NOT NULL,          -- references subscription.subscriptions(subscription_id)
        pause_policy_id      UUID NOT NULL,          -- references subscription.pause_policies(pause_policy_id)
        pause_reason         TEXT,                   -- reason used (from subscription.pause_reason)
        pause_start_date     DATE NOT NULL,          -- when the subscription transitioned to paused
        pause_end_date       DATE,                   -- when it resumed/expired/cancelled (if known)
        pause_duration_days  INT,                    -- computed as pause_end_date - pause_start_date (if ended)
        created_at           TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_pause_event_fact_company_date ON subscription_analytics.pause_event_fact(company_id, pause_start_date);
    CREATE INDEX idx_pause_event_fact_subscription ON subscription_analytics.pause_event_fact(subscription_id);
    CREATE INDEX idx_pause_event_fact_policy ON subscription_analytics.pause_event_fact(pause_policy_id);



    -- =====================================================
    -- ENTITLEMENT ANALYTICS
    -- =====================================================

    -- -----------------------------------------------------------------
    -- entitlement_usage_fact
    -- Records each time a subscription is granted an entitlement
    -- (i.e., when a subscription item is created, refreshed, or upgraded).
    -- This allows tracking which features are active for which subscriptions
    -- on any given day.
    -- -----------------------------------------------------------------
    CREATE TABLE subscription_analytics.entitlement_usage_fact (
        fact_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id        UUID NOT NULL,
        subscription_id   UUID NOT NULL,          -- references subscription.subscriptions
        plan_item_id      UUID NOT NULL,          -- references subscription.plan_items
        feature_key       VARCHAR(100) NOT NULL,  -- denormalized for quick querying
        limit_value       NUMERIC(14,4),          -- the limit granted (if any)
        limit_period      VARCHAR(20),            -- 'day','week','month','year','lifetime'
        is_enabled        BOOLEAN NOT NULL,       -- whether the entitlement is enabled
        grant_date        DATE NOT NULL,          -- the day the entitlement became active for the subscription
        created_at        TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_ent_usage_fact_company_date ON subscription_analytics.entitlement_usage_fact(company_id, grant_date);
    CREATE INDEX idx_ent_usage_fact_subscription ON subscription_analytics.entitlement_usage_fact(subscription_id);
    CREATE INDEX idx_ent_usage_fact_feature ON subscription_analytics.entitlement_usage_fact(feature_key);
    CREATE INDEX idx_ent_usage_fact_plan_item ON subscription_analytics.entitlement_usage_fact(plan_item_id);

    -- -----------------------------------------------------------------
    -- daily_entitlement_metrics
    -- Daily aggregated metrics per feature (or per feature + company).
    -- Counts active subscriptions that have the entitlement enabled,
    -- and the number of new grants on that day.
    -- Optionally, we could track average limit values, but that's less common.
    -- -----------------------------------------------------------------
    CREATE TABLE subscription_analytics.daily_entitlement_metrics (
        company_id        UUID NOT NULL,
        feature_key       VARCHAR(100) NOT NULL,
        date              DATE NOT NULL,
        active_count      INT NOT NULL DEFAULT 0,      -- subscriptions with this entitlement enabled on that day
        new_count         INT NOT NULL DEFAULT 0,      -- subscriptions that newly received this entitlement on that day
        -- optional: average limit value (if you want to track trends)
        -- avg_limit_value  NUMERIC(14,4),
        updated_at        TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, feature_key, date)
    );

    CREATE INDEX idx_daily_ent_metrics_company_date ON subscription_analytics.daily_entitlement_metrics(company_id, date);
    CREATE INDEX idx_daily_ent_metrics_feature ON subscription_analytics.daily_entitlement_metrics(feature_key);

    -- -----------------------------------------------------------------
    -- (Optional) entitlement_limit_fact – to track limit changes over time
    -- This would record every change to an entitlement's limit (e.g., when a plan is updated).
    -- It can help analyze how limits are adjusted.
    -- -----------------------------------------------------------------
    CREATE TABLE subscription_analytics.entitlement_limit_fact (
        fact_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id        UUID NOT NULL,
        plan_item_id      UUID NOT NULL,
        feature_key       VARCHAR(100) NOT NULL,
        old_limit_value   NUMERIC(14,4),
        new_limit_value   NUMERIC(14,4),
        old_limit_period  VARCHAR(20),
        new_limit_period  VARCHAR(20),
        effective_date    DATE NOT NULL,
        created_at        TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_ent_limit_fact_company_date ON subscription_analytics.entitlement_limit_fact(company_id, effective_date);
    CREATE INDEX idx_ent_limit_fact_feature ON subscription_analytics.entitlement_limit_fact(feature_key);
    CREATE INDEX idx_ent_limit_fact_plan_item ON subscription_analytics.entitlement_limit_fact(plan_item_id);


    CREATE TABLE subscription_analytics.plan_change_fact (
        fact_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id             UUID NOT NULL,
        subscription_id        UUID NOT NULL,          -- references subscription.subscriptions
        old_plan_id            UUID NOT NULL,          -- plan before change
        new_plan_id            UUID NOT NULL,          -- plan after change
        change_type            VARCHAR(20) NOT NULL,   -- 'upgrade', 'downgrade', 'lateral'
        change_date            DATE NOT NULL,          -- day the change became effective
        old_plan_version       INT,                    -- optional: version before
        new_plan_version       INT,                    -- optional: version after
        mrr_delta              NUMERIC(14,2),          -- if MRR changed, record the delta
        performed_by           UUID,                   -- user who initiated change
        reason                 TEXT,                   -- optional reason
        created_at             TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX idx_pcf_company_date ON subscription_analytics.plan_change_fact(company_id, change_date);
    CREATE INDEX idx_pcf_subscription ON subscription_analytics.plan_change_fact(subscription_id);
    CREATE INDEX idx_pcf_old_plan ON subscription_analytics.plan_change_fact(old_plan_id);
    CREATE INDEX idx_pcf_new_plan ON subscription_analytics.plan_change_fact(new_plan_id);

    CREATE TABLE subscription_analytics.daily_plan_change_metrics (
        company_id               UUID NOT NULL,
        plan_id                  UUID NOT NULL,           -- the plan being measured (can be old or new)
        date                     DATE NOT NULL,
        upgrade_in_count         INT NOT NULL DEFAULT 0,  -- subscriptions that moved TO this plan via upgrade
        upgrade_out_count        INT NOT NULL DEFAULT 0,  -- subscriptions that moved FROM this plan via upgrade
        downgrade_in_count       INT NOT NULL DEFAULT 0,  -- subscriptions that moved TO this plan via downgrade
        downgrade_out_count      INT NOT NULL DEFAULT 0,  -- subscriptions that moved FROM this plan via downgrade
        lateral_in_count         INT NOT NULL DEFAULT 0,  -- subscriptions that moved TO this plan via lateral change
        lateral_out_count        INT NOT NULL DEFAULT 0,  -- subscriptions that moved FROM this plan via lateral change
        net_change               INT NOT NULL DEFAULT 0,  -- (incoming - outgoing) for all change types combined
        updated_at               TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (company_id, plan_id, date)
    );

    CREATE INDEX idx_dpcm_company_date ON subscription_analytics.daily_plan_change_metrics(company_id, date);
    CREATE INDEX idx_dpcm_plan ON subscription_analytics.daily_plan_change_metrics(plan_id);



    ALTER TABLE subscription.billing_frequency ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE subscription.pricing_model       ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE subscription.plan_type           ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE subscription.statuses            ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();


ALTER TABLE subscription.billing_policies 
ADD CONSTRAINT billing_policies_advance_days_check 
CHECK (advance_days >= 0);
CREATE UNIQUE INDEX idx_unique_company_plan_name 
ON subscription.plans (company_id, name) 
WHERE deleted_at IS NULL;

 ALTER TABLE subscription.benefits
 ADD CONSTRAINT benefits_plan_item_type_value_unique
UNIQUE (plan_item_id, benefit_type, value);
 an index to speed up the duplicate check
CREATE INDEX idx_benefits_plan_item_type_value
ON subscription.benefits (plan_item_id, benefit_type, value);
ALTER TABLE

-- Optional: create an index to speed up the duplicate check
CREATE INDEX idx_benefits_plan_item_type_value
auth_service-# ON subscription.benefits (plan_item_id, benefit_type, value);
CREATE INDEX
ALTER TABLE subscription.plan_items ADD COLUMN company_id UUID;
ALTER TABLE subscription.plan_items ADD COLUMN tax_rate NUMERIC(10,2);
ALTER TABLE subscription.plan_items ADD COLUMN product_id UUID;
ALTER TABLE subscription.plan_items ADD COLUMN metadata JSONB;


