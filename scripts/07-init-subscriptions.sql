-- =====================================================
-- Subscription Module Schema v2.0 (Enterprise Edition)
-- Fixed: usage_remaining view uses entitlements.limit_value
-- =====================================================
CREATE SCHEMA IF NOT EXISTS subscription;

-- ----------------------------------------------
-- 1. Lookup Tables (Replace CHECK Enums)
-- ----------------------------------------------

CREATE TABLE IF NOT EXISTS subscription.business_models (
    business_model_id SMALLINT PRIMARY KEY,
    code              VARCHAR(30) NOT NULL UNIQUE,
    name              VARCHAR(100) NOT NULL
);
INSERT INTO subscription.business_models (business_model_id, code, name) VALUES
    (1, 'membership', 'Membership'),
    (2, 'recurring_product', 'Recurring Product'),
    (3, 'recurring_service', 'Recurring Service'),
    (4, 'usage_based', 'Usage Based'),
    (5, 'rental', 'Rental'),
    (6, 'contract', 'Contract'),
    (7, 'course', 'Course'),
    (8, 'seat_license', 'Seat License'),
    (9, 'insurance', 'Insurance'),
    (10, 'leasing', 'Leasing'),
    (99, 'custom', 'Custom')
ON CONFLICT (business_model_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS subscription.billing_types (
    billing_type_id SMALLINT PRIMARY KEY,
    code            VARCHAR(30) NOT NULL UNIQUE,
    name            VARCHAR(100) NOT NULL
);
INSERT INTO subscription.billing_types (billing_type_id, code, name) VALUES
    (1, 'monthly', 'Monthly'),
    (2, 'quarterly', 'Quarterly'),
    (3, 'half_yearly', 'Half Yearly'),
    (4, 'yearly', 'Yearly'),
    (5, 'weekly', 'Weekly'),
    (6, 'daily', 'Daily'),
    (7, 'usage_based', 'Usage Based'),
    (8, 'per_session', 'Per Session'),
    (9, 'per_visit', 'Per Visit'),
    (10, 'per_delivery', 'Per Delivery'),
    (11, 'per_seat', 'Per Seat'),
    (12, 'per_user', 'Per User')
ON CONFLICT (billing_type_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS subscription.subscriber_types (
    subscriber_type_id SMALLINT PRIMARY KEY,
    code               VARCHAR(30) NOT NULL UNIQUE,
    name               VARCHAR(100) NOT NULL
);
INSERT INTO subscription.subscriber_types (subscriber_type_id, code, name) VALUES
    (1, 'customer', 'Customer (Sales)'),
    (2, 'student', 'Student (Academics)'),
    (3, 'employee', 'Employee (HR)'),
    (4, 'vendor', 'Vendor'),
    (5, 'company', 'Company / Corporate'),
    (6, 'parent', 'Parent / Guardian')
ON CONFLICT (subscriber_type_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS subscription.schedule_types (
    schedule_type_id SMALLINT PRIMARY KEY,
    code             VARCHAR(30) NOT NULL UNIQUE,
    name             VARCHAR(100) NOT NULL
);
INSERT INTO subscription.schedule_types (schedule_type_id, code, name) VALUES
    (1, 'class', 'Class'),
    (2, 'appointment', 'Appointment'),
    (3, 'meeting', 'Meeting'),
    (4, 'delivery', 'Delivery'),
    (5, 'visit', 'Home Visit'),
    (6, 'workshop', 'Workshop'),
    (7, 'event', 'Event'),
    (8, 'service', 'Service Visit'),
    (9, 'maintenance', 'Maintenance Visit')
ON CONFLICT (schedule_type_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS subscription.providers (
    provider_id SMALLINT PRIMARY KEY,
    code        VARCHAR(30) NOT NULL UNIQUE,
    name        VARCHAR(100) NOT NULL
);
INSERT INTO subscription.providers (provider_id, code, name) VALUES
    (1, 'zoom', 'Zoom'),
    (2, 'google_meet', 'Google Meet'),
    (3, 'microsoft_teams', 'Microsoft Teams'),
    (4, 'youtube_live', 'YouTube Live'),
    (5, 'custom', 'Custom URL')
ON CONFLICT (provider_id) DO NOTHING;

-- Fixed unique constraint: (code, category)
CREATE TABLE IF NOT EXISTS subscription.statuses (
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

-- ----------------------------------------------
-- 2. Policy Tables
-- ----------------------------------------------

CREATE TABLE IF NOT EXISTS subscription.proration_policies (
    proration_policy_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    name                  VARCHAR(100) NOT NULL,
    upgrade_type          VARCHAR(20) NOT NULL CHECK (upgrade_type IN ('charge_difference', 'refund', 'credit_note')),
    downgrade_type        VARCHAR(20) NOT NULL CHECK (downgrade_type IN ('credit_next', 'refund', 'none')),
    is_active             BOOLEAN NOT NULL DEFAULT true,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at            TIMESTAMPTZ,
    UNIQUE (company_id, name)
);

CREATE TABLE IF NOT EXISTS subscription.billing_policies (
    billing_policy_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    name                VARCHAR(100) NOT NULL,
    billing_type_id     SMALLINT NOT NULL REFERENCES subscription.billing_types(billing_type_id),
    billing_frequency   INT,
    advance_days        INT NOT NULL DEFAULT 0,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,
    UNIQUE (company_id, name)
);

CREATE TABLE IF NOT EXISTS subscription.renewal_policies (
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

CREATE TABLE IF NOT EXISTS subscription.pause_policies (
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

-- ----------------------------------------------
-- 3. Core Feature Registry
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.feature_registry (
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

-- ----------------------------------------------
-- 4. Plans
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.plans (
    plan_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    business_model_id   SMALLINT NOT NULL REFERENCES subscription.business_models(business_model_id),
    description         TEXT,
    billing_policy_id   UUID NOT NULL REFERENCES subscription.billing_policies(billing_policy_id) ON DELETE RESTRICT,
    renewal_policy_id   UUID NOT NULL REFERENCES subscription.renewal_policies(renewal_policy_id) ON DELETE RESTRICT,
    pause_policy_id     UUID NOT NULL REFERENCES subscription.pause_policies(pause_policy_id) ON DELETE RESTRICT,
    proration_policy_id UUID NOT NULL REFERENCES subscription.proration_policies(proration_policy_id) ON DELETE RESTRICT,
    duration_days       INT NOT NULL DEFAULT 365,
    cancellation_policy TEXT,
    metadata            JSONB,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,
    UNIQUE (company_id, name)
);

-- ----------------------------------------------
-- 5. Plan Items
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.plan_items (
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
COMMENT ON TABLE subscription.plan_items IS 'Line items of a plan – replaces price/currency/joining_fee/deposit on plan.';

-- ----------------------------------------------
-- 6. Entitlements
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.entitlements (
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
COMMENT ON TABLE subscription.entitlements IS 'Capabilities and limits granted by a specific plan item.';

-- ----------------------------------------------
-- 7. Benefits
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.benefits (
    benefit_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_item_id        UUID NOT NULL REFERENCES subscription.plan_items(plan_item_id) ON DELETE CASCADE,
    benefit_type        VARCHAR(50) NOT NULL CHECK (benefit_type IN ('discount','freebie','access','service','other')),
    benefit_description TEXT,
    value               JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE subscription.benefits IS 'Perks attached to a specific plan item (e.g. 10% discount).';

-- ----------------------------------------------
-- 8. Add-ons
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.addons (
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

-- ----------------------------------------------
-- 9. Subscriptions
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.subscriptions (
    subscription_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    subscriber_type_id  SMALLINT NOT NULL REFERENCES subscription.subscriber_types(subscriber_type_id),
    subscriber_id       UUID NOT NULL,
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
    current_invoice_id  UUID,
    last_invoice_id     UUID,
    next_invoice_id     UUID,
    coupon_id           UUID,
    version             INT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);
COMMENT ON TABLE subscription.subscriptions IS 'Generic subscription holding a plan for any subscriber type.';

-- ----------------------------------------------
-- 10. Subscription Items
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.subscription_items (
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
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE subscription.subscription_items IS 'All charges (base plan, addons, benefits) actually applied to a subscription.';

-- ----------------------------------------------
-- 11. Subscription Versions
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.subscription_versions (
    version_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
    version_number      INT NOT NULL,
    snapshot            JSONB NOT NULL,
    reason              TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE subscription.subscription_versions IS 'Historical snapshots of subscription state (critical for invoicing).';

-- ----------------------------------------------
-- 12. Subscription Timeline
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.subscription_timeline (
    timeline_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
    event_type          VARCHAR(50) NOT NULL,
    old_status_id       SMALLINT REFERENCES subscription.statuses(status_id),
    new_status_id       SMALLINT REFERENCES subscription.statuses(status_id),
    performed_by        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    metadata            JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE subscription.subscription_timeline IS 'Explicit state transition log (more structured than generic audit).';

-- ----------------------------------------------
-- 13. Usage Logs & Remaining View (FIXED)
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.usages (
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

-- Corrected view: uses entitlements.limit_value and joins usages on both sub_item and feature_key
CREATE OR REPLACE VIEW subscription.usage_remaining AS
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

-- ----------------------------------------------
-- 14. Resource Assignments
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.resource_assignments (
    assignment_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
    resource_type       VARCHAR(50) NOT NULL,
    resource_id         UUID NOT NULL,
    allocation_strategy VARCHAR(20) NOT NULL DEFAULT 'exclusive' CHECK (allocation_strategy IN ('exclusive','shared','rotating','priority')),
    assigned_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_until      TIMESTAMPTZ,
    status_id           SMALLINT NOT NULL REFERENCES subscription.statuses(status_id) DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------
-- 15. Schedules
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.schedules (
    schedule_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
    schedule_type_id    SMALLINT NOT NULL REFERENCES subscription.schedule_types(schedule_type_id),
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    start_time          TIMESTAMPTZ NOT NULL,
    end_time            TIMESTAMPTZ NOT NULL,
    location            VARCHAR(255),
    status_id           SMALLINT NOT NULL REFERENCES subscription.statuses(status_id) DEFAULT 1,
    recurrence_rule     VARCHAR(100),
    recurrence_end      TIMESTAMPTZ,
    metadata            JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);

-- ----------------------------------------------
-- 16. Online Sessions
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.online_sessions (
    session_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id         UUID NOT NULL REFERENCES subscription.schedules(schedule_id) ON DELETE CASCADE,
    provider_id         SMALLINT NOT NULL REFERENCES subscription.providers(provider_id),
    meeting_url         TEXT NOT NULL,
    recording_url       TEXT,
    notes               TEXT,
    attachment_keys     TEXT[],
    chat_log            JSONB,
    resources           JSONB,
    host_user_id        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------
-- 17. Waitlists
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.waitlists (
    waitlist_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    schedule_id         UUID NOT NULL REFERENCES subscription.schedules(schedule_id) ON DELETE CASCADE,
    subscriber_type_id  SMALLINT NOT NULL REFERENCES subscription.subscriber_types(subscriber_type_id),
    subscriber_id       UUID NOT NULL,
    status_id           SMALLINT NOT NULL REFERENCES subscription.statuses(status_id) DEFAULT 1,
    registered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    position            INT,
    notified_at         TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE subscription.waitlists IS 'Queue for a specific scheduled session (e.g. a full yoga class).';

-- ----------------------------------------------
-- 18. Workflows
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.workflows (
    workflow_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    workflow_name       VARCHAR(100) NOT NULL,
    trigger_event       VARCHAR(50) NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (company_id, workflow_name)
);

CREATE TABLE IF NOT EXISTS subscription.workflow_steps (
    step_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id         UUID NOT NULL REFERENCES subscription.workflows(workflow_id) ON DELETE CASCADE,
    step_order          INT NOT NULL,
    step_type           VARCHAR(30) NOT NULL,
    config              JSONB NOT NULL,
    depends_on_step     UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE subscription.workflow_steps IS 'Explicit, queryable workflow steps (replaces JSON array).';

-- ----------------------------------------------
-- 19. Notification Preferences
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.notification_preferences (
    pref_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
    channel             VARCHAR(20) NOT NULL CHECK (channel IN ('email','sms','whatsapp','push')),
    event_type          VARCHAR(50) NOT NULL,
    is_enabled          BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (subscription_id, channel, event_type)
);

-- ----------------------------------------------
-- 20. General Audit Log
-- ----------------------------------------------
CREATE TABLE IF NOT EXISTS subscription.audit_logs (
    audit_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscription.subscriptions(subscription_id) ON DELETE CASCADE,
    action              VARCHAR(50) NOT NULL,
    old_state           JSONB,
    new_state           JSONB,
    performed_by        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    performed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address          INET,
    user_agent          TEXT
);

-- ----------------------------------------------
-- Indexes
-- ----------------------------------------------
CREATE INDEX idx_sub_plans_company ON subscription.plans(company_id);
CREATE INDEX idx_sub_plans_business_model ON subscription.plans(business_model_id);
CREATE INDEX idx_sub_plans_deleted ON subscription.plans(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE INDEX idx_sub_plan_items_plan ON subscription.plan_items(plan_id);
CREATE INDEX idx_sub_plan_items_feature ON subscription.plan_items(feature_key);
CREATE INDEX idx_sub_plan_items_effective ON subscription.plan_items(effective_from, effective_to);

CREATE INDEX idx_sub_entitlements_plan_item ON subscription.entitlements(plan_item_id);
CREATE INDEX idx_sub_entitlements_feature ON subscription.entitlements(feature_key);

CREATE INDEX idx_sub_subscriptions_company ON subscription.subscriptions(company_id);
CREATE INDEX idx_sub_subscriptions_subscriber ON subscription.subscriptions(subscriber_type_id, subscriber_id);
CREATE INDEX idx_sub_subscriptions_plan ON subscription.subscriptions(plan_id);
CREATE INDEX idx_sub_subscriptions_status ON subscription.subscriptions(status_id) WHERE status_id = 1;
CREATE INDEX idx_sub_subscriptions_dates ON subscription.subscriptions(start_date, end_date);
CREATE INDEX idx_sub_subscriptions_contract ON subscription.subscriptions(contract_number) WHERE contract_number IS NOT NULL;

CREATE INDEX idx_sub_items_subscription ON subscription.subscription_items(subscription_id);
CREATE INDEX idx_sub_items_plan_item ON subscription.subscription_items(plan_item_id);
CREATE INDEX idx_sub_items_status ON subscription.subscription_items(status_id);

CREATE INDEX idx_sub_versions_subscription ON subscription.subscription_versions(subscription_id);

CREATE INDEX idx_sub_timeline_subscription ON subscription.subscription_timeline(subscription_id);
CREATE INDEX idx_sub_timeline_event ON subscription.subscription_timeline(event_type);

CREATE INDEX idx_sub_usages_sub_item ON subscription.usages(subscription_item_id);
CREATE INDEX idx_sub_usages_period ON subscription.usages(period_start, period_end);

CREATE INDEX idx_sub_resource_sub ON subscription.resource_assignments(subscription_id);
CREATE INDEX idx_sub_resource_type ON subscription.resource_assignments(resource_type, resource_id);
CREATE INDEX idx_sub_resource_status ON subscription.resource_assignments(status_id);

CREATE INDEX idx_sub_schedules_sub ON subscription.schedules(subscription_id);
CREATE INDEX idx_sub_schedules_time ON subscription.schedules(start_time, end_time);
CREATE INDEX idx_sub_schedules_type ON subscription.schedules(schedule_type_id);
CREATE INDEX idx_sub_schedules_status ON subscription.schedules(status_id);

CREATE INDEX idx_sub_online_sessions_schedule ON subscription.online_sessions(schedule_id);

CREATE INDEX idx_sub_waitlists_schedule ON subscription.waitlists(schedule_id);
CREATE INDEX idx_sub_waitlists_subscriber ON subscription.waitlists(subscriber_type_id, subscriber_id);
CREATE INDEX idx_sub_waitlists_status ON subscription.waitlists(status_id);

CREATE INDEX idx_sub_workflows_company ON subscription.workflows(company_id);
CREATE INDEX idx_sub_workflows_event ON subscription.workflows(trigger_event);
CREATE INDEX idx_sub_workflow_steps_workflow ON subscription.workflow_steps(workflow_id);

CREATE INDEX idx_sub_notification_prefs_sub ON subscription.notification_preferences(subscription_id);

CREATE INDEX idx_sub_audit_sub ON subscription.audit_logs(subscription_id);
CREATE INDEX idx_sub_audit_performed_at ON subscription.audit_logs(performed_at DESC);

-- ----------------------------------------------
-- Update Triggers
-- ----------------------------------------------
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
        'plans', 'plan_items', 'entitlements', 'benefits', 'addons',
        'subscriptions', 'subscription_items', 'resource_assignments',
        'schedules', 'online_sessions', 'waitlists', 'workflows',
        'notification_preferences', 'billing_policies', 'renewal_policies',
        'pause_policies', 'proration_policies'
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



CREATE TABLE IF NOT EXISTS subscription.trials (
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

CREATE INDEX idx_trials_subscription ON subscription.trials(subscription_id);
CREATE INDEX idx_trials_status ON subscription.trials(status);

CREATE TRIGGER update_trials_updated_at
BEFORE UPDATE ON subscription.trials
FOR EACH ROW EXECUTE FUNCTION subscription.update_updated_at_column();