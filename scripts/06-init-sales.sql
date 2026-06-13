-- =====================================================
-- COMPLETE SALES MODULE SCHEMA (DIRECT CREATION)
-- No ALTER statements – everything created in final form
-- =====================================================

-- Ensure required schemas exist
CREATE SCHEMA IF NOT EXISTS sales;
CREATE SCHEMA IF NOT EXISTS sales_analytics;

-- =====================================================
-- ENUMS
-- =====================================================
CREATE TYPE sales.order_status AS ENUM ('draft', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded');
CREATE TYPE sales.invoice_status AS ENUM ('draft', 'issued', 'paid', 'overdue', 'cancelled', 'credited');
CREATE TYPE sales.payment_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'refunded', 'partially_refunded');
CREATE TYPE sales.payment_method AS ENUM ('cash', 'card', 'bank_transfer', 'digital_wallet', 'coupon', 'other');
CREATE TYPE sales.discount_type AS ENUM ('percentage', 'fixed_amount', 'buy_x_get_y');
CREATE TYPE sales.quote_status AS ENUM ('draft', 'sent', 'accepted', 'rejected', 'expired', 'converted');
CREATE TYPE sales.commission_base_type AS ENUM ('revenue', 'profit', 'order_total');
CREATE TYPE sales.credit_note_status AS ENUM ('draft', 'issued', 'partially_used', 'fully_used', 'voided');

-- =====================================================
-- PAYMENT TERMS (created before customers)
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.payment_terms (
    term_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL,
    code            VARCHAR(50) NOT NULL,
    term_name       VARCHAR(100) NOT NULL,
    description     TEXT,
    due_days        INT NOT NULL,
    discount_percent NUMERIC(5,2) DEFAULT 0,
    discount_days   INT DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,
    updated_by      UUID,
    CONSTRAINT fk_payment_terms_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_payment_terms_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_payment_terms_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, code),
    UNIQUE (company_id, term_name)
);

-- =====================================================
-- CUSTOMERS (with encryption fields for PII)
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.customers (
    customer_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    customer_code        VARCHAR(50) NOT NULL,
    name                 VARCHAR(255) NOT NULL,
    email                TEXT,
    email_dek            TEXT,
    email_key_id         TEXT,
    phone                TEXT,
    phone_dek            TEXT,
    phone_key_id         TEXT,
    tax_id               TEXT,
    tax_id_dek           TEXT,
    tax_id_key_id        TEXT,
    billing_address      TEXT,
    billing_address_dek  TEXT,
    billing_address_key_id TEXT,
    shipping_address     TEXT,
    shipping_address_dek TEXT,
    shipping_address_key_id TEXT,
    credit_limit         NUMERIC(14,2) DEFAULT 0,
    is_active            BOOLEAN NOT NULL DEFAULT true,
    payment_term_id      UUID NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_customers_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_customers_payment_term FOREIGN KEY (payment_term_id) REFERENCES sales.payment_terms(term_id) ON DELETE SET NULL,
    CONSTRAINT fk_customers_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_customers_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, customer_code)
);

-- =====================================================
-- PRODUCTS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.products (
    product_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    sku                 VARCHAR(100) NOT NULL,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    unit_price          NUMERIC(14,4) NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    inventory_item_id   UUID NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID,
    updated_by          UUID,
    CONSTRAINT fk_products_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_products_inventory_item FOREIGN KEY (inventory_item_id) REFERENCES items(item_id) ON DELETE SET NULL,
    CONSTRAINT fk_products_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_products_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, sku)
);

-- =====================================================
-- SALES REPS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.sales_reps (
    sales_rep_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    user_id          UUID NOT NULL,
    code             VARCHAR(50) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    -- Encrypted email fields
    email            TEXT,                     -- kept for backward compatibility, can be dropped later
    email_dek        TEXT,
    email_key_id     TEXT,
    email_hash       VARCHAR(64),              -- SHA‑256 of plain email (for uniqueness & search)
    -- Encrypted phone fields
    phone            TEXT,              -- kept for backward compatibility
    phone_dek        TEXT,
    phone_key_id     TEXT,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_sales_reps_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_sales_reps_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_sales_reps_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_sales_reps_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, code),
    -- Email uniqueness is enforced via hash
    CONSTRAINT uniq_sales_reps_email_hash UNIQUE (company_id, email_hash)
);

-- Index for fast email lookup (when plain email is not stored)
CREATE INDEX idx_sales_reps_email_hash ON sales.sales_reps (company_id, email_hash) WHERE email_hash IS NOT NULL;
-- =====================================================
-- ORDERS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.orders (
    order_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    customer_id        UUID NOT NULL,
    order_number       VARCHAR(50) NOT NULL,
    external_ref       VARCHAR(100),
    order_date         DATE NOT NULL,
    status             sales.order_status NOT NULL DEFAULT 'draft',
    currency           VARCHAR(3) NOT NULL DEFAULT 'USD',
    subtotal           NUMERIC(14,4) NOT NULL DEFAULT 0,
    discount_total     NUMERIC(14,4) NOT NULL DEFAULT 0,
    tax_total          NUMERIC(14,4) NOT NULL DEFAULT 0,
    grand_total        NUMERIC(14,4) GENERATED ALWAYS AS (subtotal - discount_total + tax_total) STORED,
    notes              TEXT,
    shipping_address   JSONB,
    billing_address    JSONB,
    sales_rep_id       UUID NULL,
    confirmed_at       TIMESTAMPTZ,
    shipped_at         TIMESTAMPTZ,
    delivered_at       TIMESTAMPTZ,
    cancelled_at       TIMESTAMPTZ,
    cancellation_reason TEXT,
    credit_hold        BOOLEAN DEFAULT false,
    credit_status      VARCHAR(20) DEFAULT 'approved',   -- 'pending', 'approved', 'rejected', 'hold'
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    CONSTRAINT fk_orders_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id),
    CONSTRAINT fk_orders_sales_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE SET NULL,
    CONSTRAINT fk_orders_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_orders_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, order_number)
);

-- =====================================================
-- ORDER ITEMS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.order_items (
    order_item_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id             UUID NOT NULL,
    product_id           UUID NOT NULL,
    product_name_snapshot VARCHAR(255) NOT NULL,
    quantity             NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price           NUMERIC(14,4) NOT NULL,
    discount_amount      NUMERIC(14,4) DEFAULT 0,
    tax_amount           NUMERIC(14,4) DEFAULT 0,
    total_price          NUMERIC(14,4) GENERATED ALWAYS AS ((unit_price * quantity) - discount_amount + tax_amount) STORED,
    metadata             JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES sales.orders(order_id) ON DELETE CASCADE,
    CONSTRAINT fk_order_items_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id)
);

-- =====================================================
-- INVOICES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.invoices (
    invoice_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    order_id             UUID,
    customer_id          UUID NOT NULL,
    invoice_number       VARCHAR(50) NOT NULL,
    external_ref         VARCHAR(100),
    invoice_date         DATE NOT NULL,
    due_date             DATE NOT NULL,
    status               sales.invoice_status NOT NULL DEFAULT 'draft',
    currency             VARCHAR(3) NOT NULL DEFAULT 'USD',
    exchange_rate        NUMERIC(14,6) DEFAULT 1,
    subtotal             NUMERIC(14,4) NOT NULL DEFAULT 0,
    discount_total       NUMERIC(14,4) NOT NULL DEFAULT 0,
    tax_total            NUMERIC(14,4) NOT NULL DEFAULT 0,
    grand_total          NUMERIC(14,4) GENERATED ALWAYS AS (subtotal - discount_total + tax_total) STORED,
    amount_paid          NUMERIC(14,4) NOT NULL DEFAULT 0,
    amount_due           NUMERIC(14,4) NOT NULL DEFAULT 0,
    notes                TEXT,
    is_locked            BOOLEAN DEFAULT false,
    sales_rep_id         UUID NULL,
    payment_term_name    VARCHAR(100),
    payment_due_days     INT,
    early_discount_percent NUMERIC(5,2) DEFAULT 0,
    early_discount_days  INT DEFAULT 0,
    issued_at            TIMESTAMPTZ,
    paid_at              TIMESTAMPTZ,
    cancelled_at         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_invoices_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_invoices_order FOREIGN KEY (order_id) REFERENCES sales.orders(order_id) ON DELETE SET NULL,
    CONSTRAINT fk_invoices_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id),
    CONSTRAINT fk_invoices_sales_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE SET NULL,
    CONSTRAINT fk_invoices_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_invoices_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, invoice_number)
);

-- =====================================================
-- INVOICE ITEMS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.invoice_items (
    invoice_item_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id           UUID NOT NULL,
    product_id           UUID,
    product_name_snapshot VARCHAR(255) NOT NULL,
    quantity             NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price           NUMERIC(14,4) NOT NULL,
    discount_amount      NUMERIC(14,4) DEFAULT 0,
    tax_amount           NUMERIC(14,4) DEFAULT 0,
    total_price          NUMERIC(14,4) GENERATED ALWAYS AS ((unit_price * quantity) - discount_amount + tax_amount) STORED,
    metadata             JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_invoice_items_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE CASCADE,
    CONSTRAINT fk_invoice_items_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id) ON DELETE SET NULL
);

-- =====================================================
-- PAYMENTS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.payments (
    payment_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    payment_number       VARCHAR(50) NOT NULL,
    external_ref         VARCHAR(100),
    payment_date         DATE NOT NULL,
    amount               NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    payment_method       sales.payment_method NOT NULL,
    status               sales.payment_status NOT NULL DEFAULT 'pending',
    exchange_rate        NUMERIC(14,6) DEFAULT 1,
    reference            VARCHAR(100),
    gateway_response     JSONB,
    failure_reason       TEXT,
    completed_at         TIMESTAMPTZ,
    refunded_amount      NUMERIC(14,4) DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_payments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_payments_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_payments_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, payment_number)
);

-- =====================================================
-- PAYMENT ALLOCATIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.payment_allocations (
    allocation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_id           UUID NOT NULL,
    invoice_id           UUID NOT NULL,
    amount               NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_alloc_payment FOREIGN KEY (payment_id) REFERENCES sales.payments(payment_id) ON DELETE CASCADE,
    CONSTRAINT fk_alloc_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE CASCADE
);

-- =====================================================
-- RETURNS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.returns (
    return_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    order_id             UUID NOT NULL,
    invoice_id           UUID,
    credit_note_id       UUID,
    return_number        VARCHAR(50) NOT NULL,
    return_date          DATE NOT NULL,
    reason               TEXT,
    status               VARCHAR(20) NOT NULL DEFAULT 'pending',
    total_refund         NUMERIC(14,4) NOT NULL DEFAULT 0,
    approved_at          TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_returns_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_returns_order FOREIGN KEY (order_id) REFERENCES sales.orders(order_id),
    CONSTRAINT fk_returns_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE SET NULL,
    CONSTRAINT fk_returns_credit_note FOREIGN KEY (credit_note_id) REFERENCES sales.invoices(invoice_id) ON DELETE SET NULL,
    CONSTRAINT fk_returns_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_returns_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, return_number)
);

-- =====================================================
-- RETURN ITEMS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.return_items (
    return_item_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id            UUID NOT NULL,
    order_item_id        UUID,
    product_id           UUID NOT NULL,
    product_name_snapshot VARCHAR(255) NOT NULL,
    quantity             NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price           NUMERIC(14,4) NOT NULL,
    refund_amount        NUMERIC(14,4) NOT NULL,
    reason               TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    CONSTRAINT fk_return_items_return FOREIGN KEY (return_id) REFERENCES sales.returns(return_id) ON DELETE CASCADE,
    CONSTRAINT fk_return_items_order_item FOREIGN KEY (order_item_id) REFERENCES sales.order_items(order_item_id) ON DELETE SET NULL,
    CONSTRAINT fk_return_items_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id),
    CONSTRAINT fk_return_items_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- PAYMENT REFUNDS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.payment_refunds (
    refund_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL,
    payment_id     UUID NOT NULL,
    return_id      UUID NULL,                         -- column added directly
    amount         NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    reason         TEXT NOT NULL,
    gateway_ref    VARCHAR(100),
    status         VARCHAR(20) NOT NULL DEFAULT 'pending',
    refunded_by    UUID,
    completed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_refunds_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_refunds_payment FOREIGN KEY (payment_id) REFERENCES sales.payments(payment_id) ON DELETE CASCADE,
    CONSTRAINT fk_payment_refunds_return FOREIGN KEY (return_id) REFERENCES sales.returns(return_id) ON DELETE SET NULL,
    CONSTRAINT fk_refunds_user FOREIGN KEY (refunded_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- COUPONS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.coupons (
    coupon_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    code                 VARCHAR(100) NOT NULL,
    discount_type        sales.discount_type NOT NULL,
    discount_value       NUMERIC(14,4) NOT NULL,
    max_discount_amount  NUMERIC(14,4),
    start_date           TIMESTAMPTZ NOT NULL,
    end_date             TIMESTAMPTZ NOT NULL,
    usage_limit          INT,
    per_user_limit       INT DEFAULT 1,
    min_order_amount     NUMERIC(14,4),
    applicable_items     JSONB,
    is_active            BOOLEAN NOT NULL DEFAULT true,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_coupons_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_coupons_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_coupons_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, code)
);

-- =====================================================
-- COUPON USAGES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.coupon_usages (
    usage_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_id            UUID NOT NULL,
    customer_id          UUID NOT NULL,
    order_id             UUID NOT NULL,
    discount_amount      NUMERIC(14,4) NOT NULL,
    used_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_coupon_usage_coupon FOREIGN KEY (coupon_id) REFERENCES sales.coupons(coupon_id),
    CONSTRAINT fk_coupon_usage_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id),
    CONSTRAINT fk_coupon_usage_order FOREIGN KEY (order_id) REFERENCES sales.orders(order_id),
    UNIQUE (coupon_id, customer_id, order_id)
);

-- =====================================================
-- PROMOTIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.promotions (
    promotion_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    name                 VARCHAR(255) NOT NULL,
    description          TEXT,
    start_date           TIMESTAMPTZ NOT NULL,
    end_date             TIMESTAMPTZ NOT NULL,
    is_active            BOOLEAN NOT NULL DEFAULT true,
    priority             INT DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_promotions_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_promotions_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_promotions_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- PROMOTION RULES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.promotion_rules (
    rule_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    promotion_id         UUID NOT NULL,
    rule_type            VARCHAR(50) NOT NULL,
    rule_config          JSONB NOT NULL,
    discount_type        sales.discount_type NOT NULL,
    discount_value       NUMERIC(14,4) NOT NULL,
    max_discount         NUMERIC(14,4),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_promotion_rules_promotion FOREIGN KEY (promotion_id) REFERENCES sales.promotions(promotion_id) ON DELETE CASCADE
);

-- =====================================================
-- AUTOMATIC DISCOUNTS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.automatic_discounts (
    auto_discount_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL,
    name                  VARCHAR(255) NOT NULL,
    description           TEXT,
    discount_type         sales.discount_type NOT NULL,
    discount_value        NUMERIC(14,4) NOT NULL,
    max_discount_amount   NUMERIC(14,4),
    min_order_amount      NUMERIC(14,4),
    applicable_products   JSONB,
    start_date            TIMESTAMPTZ NOT NULL,
    end_date              TIMESTAMPTZ NOT NULL,
    is_active             BOOLEAN NOT NULL DEFAULT true,
    priority              INT NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            UUID,
    updated_by            UUID,
    CONSTRAINT fk_auto_discount_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_auto_discount_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_auto_discount_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- DISCOUNT STACKING RULES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.discount_stacking_rules (
    rule_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL,
    rule_name             VARCHAR(100) NOT NULL,
    is_active             BOOLEAN NOT NULL DEFAULT true,
    primary_discount_type VARCHAR(30) NOT NULL,
    primary_discount_id   UUID NOT NULL,
    allowed_types         JSONB NOT NULL,
    max_total_discount    NUMERIC(14,4),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            UUID,
    updated_by            UUID,
    CONSTRAINT fk_stacking_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_stacking_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_stacking_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE(company_id, primary_discount_type, primary_discount_id)
);

-- =====================================================
-- DISCOUNT EXCLUSIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.discount_exclusions (
    exclusion_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL,
    discount_type_a       VARCHAR(30) NOT NULL,
    discount_id_a         UUID NOT NULL,
    discount_type_b       VARCHAR(30) NOT NULL,
    discount_id_b         UUID NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            UUID,
    CONSTRAINT fk_exclusion_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_exclusion_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE(company_id, discount_type_a, discount_id_a, discount_type_b, discount_id_b)
);

-- =====================================================
-- DISCOUNT PRIORITIES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.discount_priorities (
    priority_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL,
    discount_type         VARCHAR(30) NOT NULL,
    discount_id           UUID,
    priority              INT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            UUID,
    updated_by            UUID,
    CONSTRAINT fk_priority_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_priority_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_priority_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE(company_id, discount_type, discount_id)
);

-- =====================================================
-- DISCOUNT APPLICATIONS (includes automatic discounts)
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.discount_applications (
    application_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    order_id             UUID,
    invoice_id           UUID,
    discount_type        VARCHAR(50) NOT NULL,
    discount_id          UUID,
    auto_discount_id     UUID,
    discount_name        VARCHAR(255),
    amount               NUMERIC(14,4) NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_discount_applications_order FOREIGN KEY (order_id) REFERENCES sales.orders(order_id) ON DELETE CASCADE,
    CONSTRAINT fk_discount_applications_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE CASCADE,
    CONSTRAINT fk_discount_app_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_discount_app_auto FOREIGN KEY (auto_discount_id) REFERENCES sales.automatic_discounts(auto_discount_id) ON DELETE SET NULL,
    CHECK ((order_id IS NOT NULL AND invoice_id IS NULL) OR (order_id IS NULL AND invoice_id IS NOT NULL)),
    CHECK ((discount_id IS NOT NULL AND auto_discount_id IS NULL) OR (discount_id IS NULL AND auto_discount_id IS NOT NULL))
);

-- =====================================================
-- TAX SNAPSHOTS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.tax_snapshots (
    tax_snapshot_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    entity_type          VARCHAR(20) NOT NULL,
    entity_id            UUID NOT NULL,
    line_id              UUID,
    tax_rate_id          UUID,
    tax_name             VARCHAR(100),
    tax_percentage       NUMERIC(5,2),
    taxable_amount       NUMERIC(14,4) NOT NULL,
    tax_amount           NUMERIC(14,4) NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tax_snapshots_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE
);

-- =====================================================
-- QUOTES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.quotes (
    quote_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    customer_id          UUID NOT NULL,
    quote_number         VARCHAR(50) NOT NULL,
    revision             INT NOT NULL DEFAULT 1,
    quote_date           DATE NOT NULL,
    expiry_date          DATE,
    status               sales.quote_status NOT NULL DEFAULT 'draft',
    currency             VARCHAR(3) NOT NULL DEFAULT 'USD',
    subtotal             NUMERIC(14,4) NOT NULL DEFAULT 0,
    discount_total       NUMERIC(14,4) NOT NULL DEFAULT 0,
    tax_total            NUMERIC(14,4) NOT NULL DEFAULT 0,
    grand_total          NUMERIC(14,4) GENERATED ALWAYS AS (subtotal - discount_total + tax_total) STORED,
    notes                TEXT,
    converted_order_id   UUID NULL,
    sales_rep_id         UUID NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_quotes_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_quotes_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id),
    CONSTRAINT fk_quotes_converted_order FOREIGN KEY (converted_order_id) REFERENCES sales.orders(order_id) ON DELETE SET NULL,
    CONSTRAINT fk_quotes_sales_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE SET NULL,
    CONSTRAINT fk_quotes_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_quotes_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, quote_number, revision)
);

-- =====================================================
-- QUOTE ITEMS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.quote_items (
    quote_item_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    quote_id             UUID NOT NULL,
    product_id           UUID NOT NULL,
    product_name_snapshot VARCHAR(255) NOT NULL,
    quantity             NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price           NUMERIC(14,4) NOT NULL,
    discount_amount      NUMERIC(14,4) DEFAULT 0,
    tax_amount           NUMERIC(14,4) DEFAULT 0,
    total_price          NUMERIC(14,4) GENERATED ALWAYS AS ((unit_price * quantity) - discount_amount + tax_amount) STORED,
    metadata             JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_quote_items_quote FOREIGN KEY (quote_id) REFERENCES sales.quotes(quote_id) ON DELETE CASCADE,
    CONSTRAINT fk_quote_items_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id)
);

-- =====================================================
-- SALES REP COMMISSIONS (legacy)
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.sales_rep_commissions (
    commission_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    sales_rep_id         UUID NOT NULL,
    effective_from       DATE NOT NULL,
    effective_to         DATE,
    commission_rate      NUMERIC(5,2) NOT NULL,
    applies_to           sales.commission_base_type NOT NULL,
    product_id           UUID NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,
    CONSTRAINT fk_commissions_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_commissions_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE CASCADE,
    CONSTRAINT fk_commissions_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id) ON DELETE SET NULL,
    CONSTRAINT fk_commissions_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_commissions_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT chk_commission_rate CHECK (commission_rate >= 0 AND commission_rate <= 100),
    CONSTRAINT chk_commission_dates CHECK (effective_to IS NULL OR effective_to >= effective_from)
);

-- =====================================================
-- CREDIT CHECK HISTORY
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.credit_check_history (
    credit_history_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    customer_id          UUID NOT NULL,
    action_type          VARCHAR(30) NOT NULL,
    previous_limit       NUMERIC(14,2),
    new_limit            NUMERIC(14,2),
    previous_outstanding NUMERIC(14,2),
    new_outstanding      NUMERIC(14,2),
    reason               TEXT,
    approved_by          UUID,
    created_by           UUID,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_credit_history_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_credit_history_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id) ON DELETE CASCADE,
    CONSTRAINT fk_credit_history_approved_by FOREIGN KEY (approved_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_credit_history_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- CREDIT NOTES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.credit_notes (
    credit_note_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    customer_id         UUID NOT NULL,
    credit_note_number  VARCHAR(50) NOT NULL,
    invoice_id          UUID,
    return_id           UUID,
    issue_date          DATE NOT NULL,
    status              sales.credit_note_status NOT NULL DEFAULT 'draft',
    currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
    subtotal            NUMERIC(14,4) NOT NULL,
    tax_total           NUMERIC(14,4) NOT NULL,
    total_amount        NUMERIC(14,4) NOT NULL,
    amount_applied      NUMERIC(14,4) NOT NULL DEFAULT 0,
    remaining_amount    NUMERIC(14,4) GENERATED ALWAYS AS (total_amount - amount_applied) STORED,
    reason              TEXT,
    notes               TEXT,
    issued_at           TIMESTAMPTZ,
    voided_at           TIMESTAMPTZ,
    void_reason         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID,
    updated_by          UUID,
    CONSTRAINT fk_credit_notes_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_credit_notes_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id),
    CONSTRAINT fk_credit_notes_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE SET NULL,
    CONSTRAINT fk_credit_notes_return FOREIGN KEY (return_id) REFERENCES sales.returns(return_id) ON DELETE SET NULL,
    CONSTRAINT fk_credit_notes_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_credit_notes_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, credit_note_number)
);

-- =====================================================
-- CREDIT NOTE ITEMS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.credit_note_items (
    credit_note_item_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credit_note_id        UUID NOT NULL,
    invoice_item_id       UUID,
    product_id            UUID,
    product_name_snapshot VARCHAR(255) NOT NULL,
    quantity              NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price            NUMERIC(14,4) NOT NULL,
    tax_rate              NUMERIC(5,2),
    tax_amount            NUMERIC(14,4) DEFAULT 0,
    line_amount           NUMERIC(14,4) NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            UUID,
    CONSTRAINT fk_credit_items_credit_note FOREIGN KEY (credit_note_id) REFERENCES sales.credit_notes(credit_note_id) ON DELETE CASCADE,
    CONSTRAINT fk_credit_items_invoice_item FOREIGN KEY (invoice_item_id) REFERENCES sales.invoice_items(invoice_item_id) ON DELETE SET NULL,
    CONSTRAINT fk_credit_items_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id) ON DELETE SET NULL,
    CONSTRAINT fk_credit_items_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- CREDIT NOTE APPLICATIONS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.credit_note_applications (
    application_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credit_note_id  UUID NOT NULL,
    invoice_id      UUID NOT NULL,
    amount          NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_cn_app_credit_note FOREIGN KEY (credit_note_id) REFERENCES sales.credit_notes(credit_note_id) ON DELETE CASCADE,
    CONSTRAINT fk_cn_app_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE CASCADE,
    CONSTRAINT fk_cn_applied_by FOREIGN KEY (applied_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- SALES TARGETS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.sales_targets (
    target_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL,
    sales_rep_id    UUID NOT NULL,
    period_start    DATE NOT NULL,
    period_end      DATE NOT NULL,
    target_amount   NUMERIC(14,2) NOT NULL,
    currency        VARCHAR(3) NOT NULL DEFAULT 'USD',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,
    updated_by      UUID,
    CONSTRAINT fk_targets_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_targets_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE CASCADE,
    CONSTRAINT fk_targets_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_targets_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE(company_id, sales_rep_id, period_start, period_end)
);

-- =====================================================
-- COMMISSION PLANS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.commission_plans (
    plan_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    code             VARCHAR(50) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_commission_plans_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_commission_plans_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_commission_plans_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE(company_id, code)
);

-- =====================================================
-- COMMISSION RULES
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.commission_rules (
    rule_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    plan_id          UUID NOT NULL,
    rule_type        VARCHAR(20) NOT NULL, -- 'flat','tiered','product','category'
    applies_to       sales.commission_base_type NOT NULL,
    product_id       UUID,
    tier_min         NUMERIC(14,4),
    tier_max         NUMERIC(14,4),
    rate             NUMERIC(14,4) NOT NULL,
    is_percentage    BOOLEAN NOT NULL DEFAULT true,
    priority         INT NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_commission_rules_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_commission_rules_plan FOREIGN KEY (plan_id) REFERENCES sales.commission_plans(plan_id) ON DELETE CASCADE,
    CONSTRAINT fk_commission_rules_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id) ON DELETE SET NULL,
    CONSTRAINT fk_commission_rules_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_commission_rules_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- SALES COMMISSIONS (actual earned)
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.sales_commissions (
    commission_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL,
    sales_rep_id       UUID NOT NULL,
    reference_type     VARCHAR(20) NOT NULL, -- 'order','invoice','payment'
    reference_id       UUID NOT NULL,
    commission_base    NUMERIC(14,4) NOT NULL,
    commission_rate    NUMERIC(14,4) NOT NULL,
    commission_amount  NUMERIC(14,4) NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'pending',
    earned_at          TIMESTAMPTZ NOT NULL,
    paid_at            TIMESTAMPTZ,
    approved_at        TIMESTAMPTZ,
    rejected_at        TIMESTAMPTZ,
    reject_reason      TEXT,
    notes              TEXT,
    rule_id            UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    CONSTRAINT fk_sales_commissions_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_sales_commissions_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE CASCADE,
    CONSTRAINT fk_sales_commissions_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_sales_commissions_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_sales_commissions_rule FOREIGN KEY (rule_id) REFERENCES sales.commission_rules(rule_id) ON DELETE SET NULL,
    UNIQUE(company_id, reference_type, reference_id)
);

-- =====================================================
-- SALES REP COMMISSION ASSIGNMENTS
-- =====================================================
CREATE TABLE IF NOT EXISTS sales.sales_rep_commission_assignments (
    assignment_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    sales_rep_id     UUID NOT NULL,
    plan_id          UUID NOT NULL,
    effective_from   DATE NOT NULL,
    effective_to     DATE,
    assigned_by      UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_assignments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_assignments_rep FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE CASCADE,
    CONSTRAINT fk_assignments_plan FOREIGN KEY (plan_id) REFERENCES sales.commission_plans(plan_id) ON DELETE CASCADE,
    CONSTRAINT fk_assignments_assigned_by FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- =====================================================
-- FUNCTIONS & TRIGGERS
-- =====================================================
CREATE OR REPLACE FUNCTION sales.update_invoice_paid_amount()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE sales.invoices
    SET amount_paid = COALESCE(
        (SELECT SUM(pa.amount) FROM sales.payment_allocations pa
         JOIN sales.payments p ON pa.payment_id = p.payment_id
         WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'),
        0
    ),
    amount_due = grand_total - COALESCE(
        (SELECT SUM(pa.amount) FROM sales.payment_allocations pa
         JOIN sales.payments p ON pa.payment_id = p.payment_id
         WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'),
        0
    ),
    status = CASE
        WHEN COALESCE((SELECT SUM(pa.amount) FROM sales.payment_allocations pa
                       JOIN sales.payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) >= grand_total THEN 'paid'
        WHEN COALESCE((SELECT SUM(pa.amount) FROM sales.payment_allocations pa
                       JOIN sales.payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) > 0 THEN 'issued'
        ELSE status
    END,
    paid_at = CASE
        WHEN COALESCE((SELECT SUM(pa.amount) FROM sales.payment_allocations pa
                       JOIN sales.payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) >= grand_total THEN NOW()
        ELSE paid_at
    END,
    updated_at = NOW()
    WHERE invoice_id = NEW.invoice_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- Generic updated_at function
CREATE OR REPLACE FUNCTION sales.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_customers_updated_at BEFORE UPDATE ON sales.customers FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON sales.products FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON sales.orders FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_invoices_updated_at BEFORE UPDATE ON sales.invoices FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_payments_updated_at BEFORE UPDATE ON sales.payments FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_returns_updated_at BEFORE UPDATE ON sales.returns FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_coupons_updated_at BEFORE UPDATE ON sales.coupons FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_promotions_updated_at BEFORE UPDATE ON sales.promotions FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_payment_terms_updated_at BEFORE UPDATE ON sales.payment_terms FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_quotes_updated_at BEFORE UPDATE ON sales.quotes FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_sales_reps_updated_at BEFORE UPDATE ON sales.sales_reps FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_commissions_updated_at BEFORE UPDATE ON sales.sales_rep_commissions FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_auto_discount_updated_at BEFORE UPDATE ON sales.automatic_discounts FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_stacking_updated_at BEFORE UPDATE ON sales.discount_stacking_rules FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_priority_updated_at BEFORE UPDATE ON sales.discount_priorities FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_payment_refunds_updated_at BEFORE UPDATE ON sales.payment_refunds FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_commission_plans_updated_at BEFORE UPDATE ON sales.commission_plans FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_commission_rules_updated_at BEFORE UPDATE ON sales.commission_rules FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_sales_commissions_updated_at BEFORE UPDATE ON sales.sales_commissions FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();

-- Trigger for invoice paid amount
CREATE TRIGGER trg_update_invoice_paid_amount
    AFTER INSERT OR UPDATE ON sales.payment_allocations
    FOR EACH ROW
    EXECUTE FUNCTION sales.update_invoice_paid_amount();

-- =====================================================
-- ANALYTICS TABLES
-- =====================================================

-- Daily sales snapshot
CREATE TABLE IF NOT EXISTS sales_analytics.daily_sales (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    total_orders INT DEFAULT 0,
    total_invoices INT DEFAULT 0,
    total_revenue DECIMAL(14,4) DEFAULT 0,
    total_discounts DECIMAL(14,4) DEFAULT 0,
    total_tax DECIMAL(14,4) DEFAULT 0,
    total_payments DECIMAL(14,4) DEFAULT 0,
    unique_customers INT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Customer lifetime metrics
CREATE TABLE IF NOT EXISTS sales_analytics.customer_metrics (
    customer_id UUID PRIMARY KEY,
    company_id UUID NOT NULL,
    first_order_date DATE,
    last_order_date DATE,
    total_orders INT DEFAULT 0,
    total_invoices INT DEFAULT 0,
    total_spent DECIMAL(14,4) DEFAULT 0,
    total_payments DECIMAL(14,4) DEFAULT 0,
    average_order_value DECIMAL(14,4) DEFAULT 0,
    lifetime_value DECIMAL(14,4) DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Product sales fact table
CREATE TABLE IF NOT EXISTS sales_analytics.product_sales_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    product_id UUID NOT NULL,
    date DATE NOT NULL,
    quantity_sold DECIMAL(14,4) DEFAULT 0,
    revenue DECIMAL(14,4) DEFAULT 0,
    discount_applied DECIMAL(14,4) DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Daily unique customers
CREATE TABLE IF NOT EXISTS sales_analytics.daily_unique_customers (
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    customer_id UUID NOT NULL,
    PRIMARY KEY (company_id, date, customer_id)
);

-- Auto discount unique customers
CREATE TABLE IF NOT EXISTS sales_analytics.auto_discount_unique_customers (
    company_id       UUID NOT NULL,
    auto_discount_id UUID NOT NULL,
    date             DATE NOT NULL,
    customer_id      UUID NOT NULL,
    PRIMARY KEY (company_id, auto_discount_id, date, customer_id)
);

-- Product returns fact
CREATE TABLE IF NOT EXISTS sales_analytics.product_returns_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    product_id UUID NOT NULL,
    date DATE NOT NULL,
    quantity_returned NUMERIC(14,4) NOT NULL,
    refund_amount NUMERIC(14,4) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, product_id, date)
);

-- Payment term performance
CREATE TABLE IF NOT EXISTS sales_analytics.payment_term_performance (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    payment_term_id UUID NOT NULL,
    date DATE NOT NULL,
    total_invoices INT NOT NULL DEFAULT 0,
    total_invoice_amount DECIMAL(14,4) NOT NULL DEFAULT 0,
    paid_on_time_count INT NOT NULL DEFAULT 0,
    paid_late_count INT NOT NULL DEFAULT 0,
    early_discount_eligible_count INT NOT NULL DEFAULT 0,
    early_discount_taken_count INT NOT NULL DEFAULT 0,
    early_discount_amount DECIMAL(14,4) NOT NULL DEFAULT 0,
    average_days_to_pay DECIMAL(10,2) DEFAULT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, payment_term_id, date)
);

-- Order status history
CREATE TABLE IF NOT EXISTS sales_analytics.order_status_history (
    history_id     BIGSERIAL PRIMARY KEY,
    order_id       UUID NOT NULL,
    company_id     UUID NOT NULL,
    status         sales.order_status NOT NULL,
    entered_at     TIMESTAMPTZ NOT NULL,
    exited_at      TIMESTAMPTZ,
    duration_seconds BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (exited_at - entered_at))) STORED,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Order item analytics
CREATE TABLE IF NOT EXISTS sales_analytics.order_item_analytics (
    id                 BIGSERIAL PRIMARY KEY,
    order_item_id      UUID NOT NULL,
    order_id           UUID NOT NULL,
    company_id         UUID NOT NULL,
    product_id         UUID NOT NULL,
    quantity           DECIMAL(14,4) NOT NULL,
    unit_price         DECIMAL(14,4) NOT NULL,
    discount_amount    DECIMAL(14,4) DEFAULT 0,
    tax_amount         DECIMAL(14,4) DEFAULT 0,
    total_line_amount  DECIMAL(14,4) NOT NULL,
    cogs_per_unit      DECIMAL(14,4),
    profit             DECIMAL(14,4) GENERATED ALWAYS AS (total_line_amount - (quantity * cogs_per_unit)) STORED,
    order_date         DATE NOT NULL,
    created_at         TIMESTAMPTZ DEFAULT NOW()
);

-- Sales rep performance
CREATE TABLE IF NOT EXISTS sales_analytics.sales_rep_performance (
    id                  BIGSERIAL PRIMARY KEY,
    company_id          UUID NOT NULL,
    sales_rep_id        UUID NOT NULL,
    date                DATE NOT NULL,
    total_orders        INT DEFAULT 0,
    total_revenue       DECIMAL(14,4) DEFAULT 0,
    average_order_value DECIMAL(14,4) DEFAULT 0,
    total_commission    DECIMAL(14,4) DEFAULT 0,
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, sales_rep_id, date)
);

-- Order cancellation reasons
CREATE TABLE IF NOT EXISTS sales_analytics.order_cancellation_reasons (
    id                BIGSERIAL PRIMARY KEY,
    order_id          UUID NOT NULL,
    company_id        UUID NOT NULL,
    cancellation_reason TEXT NOT NULL,
    cancelled_by      UUID,
    cancelled_at      TIMESTAMPTZ NOT NULL,
    order_status_before_cancel sales.order_status,
    order_total_before_cancel DECIMAL(14,4)
);

-- Fulfillment metrics
CREATE TABLE IF NOT EXISTS sales_analytics.fulfillment_metrics (
    id                    BIGSERIAL PRIMARY KEY,
    order_id              UUID NOT NULL,
    company_id            UUID NOT NULL,
    confirmed_at          TIMESTAMPTZ,
    shipped_at            TIMESTAMPTZ,
    delivered_at          TIMESTAMPTZ,
    confirmation_to_ship_hours DECIMAL(10,2) GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (shipped_at - confirmed_at))/3600) STORED,
    ship_to_delivery_hours     DECIMAL(10,2) GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (delivered_at - shipped_at))/3600) STORED,
    carrier              VARCHAR(100),
    tracking_number      VARCHAR(100),
    shipping_address_region VARCHAR(100),
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(order_id)
);

-- Order hourly sales
CREATE TABLE IF NOT EXISTS sales_analytics.order_hourly_sales (
    id               BIGSERIAL PRIMARY KEY,
    company_id       UUID NOT NULL,
    hour_bucket      TIMESTAMPTZ NOT NULL,
    total_orders     INT DEFAULT 0,
    total_revenue    DECIMAL(14,4) DEFAULT 0,
    unique_customers INT DEFAULT 0,
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, hour_bucket)
);

-- Daily quote metrics
CREATE TABLE IF NOT EXISTS sales_analytics.daily_quote_metrics (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    total_quotes_created INT DEFAULT 0,
    total_quote_value DECIMAL(14,4) DEFAULT 0,
    total_quotes_converted INT DEFAULT 0,
    converted_value DECIMAL(14,4) DEFAULT 0,
    conversion_rate DECIMAL(5,2) GENERATED ALWAYS AS (
        CASE WHEN total_quotes_created > 0 
             THEN (total_quotes_converted::DECIMAL / total_quotes_created) * 100 
             ELSE 0 
        END
    ) STORED,
    average_quote_value DECIMAL(14,4) GENERATED ALWAYS AS (
        CASE WHEN total_quotes_created > 0 
             THEN total_quote_value / total_quotes_created 
             ELSE 0 
        END
    ) STORED,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Quote status history
CREATE TABLE IF NOT EXISTS sales_analytics.quote_status_history (
    history_id BIGSERIAL PRIMARY KEY,
    quote_id UUID NOT NULL,
    company_id UUID NOT NULL,
    status sales.quote_status NOT NULL,
    entered_at TIMESTAMPTZ NOT NULL,
    exited_at TIMESTAMPTZ,
    duration_seconds BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (exited_at - entered_at))) STORED,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Quote conversion facts
CREATE TABLE IF NOT EXISTS sales_analytics.quote_conversion_facts (
    id BIGSERIAL PRIMARY KEY,
    quote_id UUID NOT NULL,
    order_id UUID NOT NULL,
    company_id UUID NOT NULL,
    customer_id UUID NOT NULL,
    quote_value_at_conversion DECIMAL(14,4) NOT NULL,
    order_value_at_conversion DECIMAL(14,4) NOT NULL,
    conversion_time_seconds INT NOT NULL,
    quote_expiry_days INT,
    used_coupon_ids UUID[],
    sales_rep_id UUID,
    converted_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(quote_id, order_id)
);

-- Quote item analytics
CREATE TABLE IF NOT EXISTS sales_analytics.quote_item_analytics (
    id BIGSERIAL PRIMARY KEY,
    quote_item_id UUID NOT NULL,
    quote_id UUID NOT NULL,
    company_id UUID NOT NULL,
    product_id UUID NOT NULL,
    quantity DECIMAL(14,4) NOT NULL,
    unit_price DECIMAL(14,4) NOT NULL,
    discount_amount DECIMAL(14,4) DEFAULT 0,
    tax_amount DECIMAL(14,4) DEFAULT 0,
    total_line_amount DECIMAL(14,4) GENERATED ALWAYS AS (
        (unit_price * quantity) - discount_amount + tax_amount
    ) STORED,
    quote_date DATE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(quote_item_id)
);

-- Invoice status history
CREATE TABLE IF NOT EXISTS sales_analytics.invoice_status_history (
    history_id     BIGSERIAL PRIMARY KEY,
    invoice_id     UUID NOT NULL,
    company_id     UUID NOT NULL,
    status         sales.invoice_status NOT NULL,
    entered_at     TIMESTAMPTZ NOT NULL,
    exited_at      TIMESTAMPTZ,
    duration_seconds BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (exited_at - entered_at))) STORED,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Invoice item analytics
CREATE TABLE IF NOT EXISTS sales_analytics.invoice_item_analytics (
    id                 BIGSERIAL PRIMARY KEY,
    invoice_item_id    UUID NOT NULL,
    invoice_id         UUID NOT NULL,
    company_id         UUID NOT NULL,
    product_id         UUID NOT NULL,
    quantity           DECIMAL(14,4) NOT NULL,
    unit_price         DECIMAL(14,4) NOT NULL,
    discount_amount    DECIMAL(14,4) DEFAULT 0,
    tax_amount         DECIMAL(14,4) DEFAULT 0,
    total_line_amount  DECIMAL(14,4) NOT NULL,
    invoice_date       DATE NOT NULL,
    created_at         TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(invoice_item_id)
);

-- Daily invoice metrics
CREATE TABLE IF NOT EXISTS sales_analytics.daily_invoice_metrics (
    id                         BIGSERIAL PRIMARY KEY,
    company_id                 UUID NOT NULL,
    date                       DATE NOT NULL,
    total_invoices_issued      INT DEFAULT 0,
    total_invoices_paid        INT DEFAULT 0,
    total_invoices_overdue     INT DEFAULT 0,
    total_invoices_cancelled   INT DEFAULT 0,
    total_invoice_value_issued DECIMAL(14,4) DEFAULT 0,
    total_paid_value           DECIMAL(14,4) DEFAULT 0,
    total_overdue_value        DECIMAL(14,4) DEFAULT 0,
    early_discount_taken_count INT DEFAULT 0,
    early_discount_amount      DECIMAL(14,4) DEFAULT 0,
    avg_days_to_payment        DECIMAL(10,2),
    updated_at                 TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Invoice aging snapshot
CREATE TABLE IF NOT EXISTS sales_analytics.invoice_aging_snapshot (
    snapshot_id          BIGSERIAL PRIMARY KEY,
    company_id           UUID NOT NULL,
    snapshot_date        DATE NOT NULL,
    bucket_0_30_days     DECIMAL(14,4) DEFAULT 0,
    bucket_31_60_days    DECIMAL(14,4) DEFAULT 0,
    bucket_61_90_days    DECIMAL(14,4) DEFAULT 0,
    bucket_over_90_days  DECIMAL(14,4) DEFAULT 0,
    total_outstanding    DECIMAL(14,4) DEFAULT 0,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, snapshot_date)
);

-- Payment method daily
CREATE TABLE IF NOT EXISTS sales_analytics.payment_method_daily (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    payment_method sales.payment_method NOT NULL,
    payment_count INT DEFAULT 0,
    total_amount DECIMAL(14,4) DEFAULT 0,
    average_amount DECIMAL(14,4) GENERATED ALWAYS AS (
        CASE WHEN payment_count > 0 THEN total_amount / payment_count ELSE 0 END
    ) STORED,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date, payment_method)
);

-- Refund metrics
CREATE TABLE IF NOT EXISTS sales_analytics.refund_metrics (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    refund_count INT DEFAULT 0,
    total_refund_amount DECIMAL(14,4) DEFAULT 0,
    average_refund_amount DECIMAL(14,4) GENERATED ALWAYS AS (
        CASE WHEN refund_count > 0 THEN total_refund_amount / refund_count ELSE 0 END
    ) STORED,
    partial_refund_count INT DEFAULT 0,
    full_refund_count INT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Payment aging snapshot
CREATE TABLE IF NOT EXISTS sales_analytics.payment_aging_snapshot (
    snapshot_id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    snapshot_date DATE NOT NULL,
    bucket_0_30_days DECIMAL(14,4) DEFAULT 0,
    bucket_31_60_days DECIMAL(14,4) DEFAULT 0,
    bucket_61_90_days DECIMAL(14,4) DEFAULT 0,
    bucket_over_90_days DECIMAL(14,4) DEFAULT 0,
    total_unallocated DECIMAL(14,4) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, snapshot_date)
);

-- Collection efficiency
CREATE TABLE IF NOT EXISTS sales_analytics.collection_efficiency (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    days_sales_outstanding DECIMAL(10,2) DEFAULT NULL,
    collection_rate DECIMAL(5,2) DEFAULT NULL,
    total_receivables DECIMAL(14,4) DEFAULT 0,
    collected_amount DECIMAL(14,4) DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Automatic discount metrics
CREATE TABLE IF NOT EXISTS sales_analytics.automatic_discount_metrics (
    id                    BIGSERIAL PRIMARY KEY,
    company_id            UUID NOT NULL,
    auto_discount_id      UUID NOT NULL,
    date                  DATE NOT NULL,
    times_applied         INT NOT NULL DEFAULT 0,
    total_discount_amount NUMERIC(14,4) NOT NULL DEFAULT 0,
    total_order_value     NUMERIC(14,4) NOT NULL DEFAULT 0,
    unique_customers      INT NOT NULL DEFAULT 0,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, auto_discount_id, date)
);

-- Discount stacking usage
CREATE TABLE IF NOT EXISTS sales_analytics.discount_stacking_usage (
    id                    BIGSERIAL PRIMARY KEY,
    company_id            UUID NOT NULL,
    rule_id               UUID NOT NULL,
    date                  DATE NOT NULL,
    times_used            INT NOT NULL DEFAULT 0,
    total_combined_discount NUMERIC(14,4) NOT NULL DEFAULT 0,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, rule_id, date)
);

-- Coupon usage fact
CREATE TABLE sales_analytics.coupon_usage_fact (
    id              BIGSERIAL PRIMARY KEY,
    company_id      UUID NOT NULL,
    coupon_id       UUID NOT NULL,
    entity_type     VARCHAR(20) NOT NULL,       -- 'order', 'invoice', 'quote'
    entity_id       UUID NOT NULL,
    customer_id     UUID,
    discount_amount DECIMAL(14,4) NOT NULL,
    order_subtotal  DECIMAL(14,4),
    used_at         TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, coupon_id, entity_type, entity_id)
);

-- Daily coupon metrics
CREATE TABLE sales_analytics.daily_coupon_metrics (
    id                  BIGSERIAL PRIMARY KEY,
    company_id          UUID NOT NULL,
    coupon_id           UUID NOT NULL,
    date                DATE NOT NULL,
    times_applied       INT NOT NULL DEFAULT 0,
    total_discount_amount DECIMAL(14,4) NOT NULL DEFAULT 0,
    total_order_value   DECIMAL(14,4) NOT NULL DEFAULT 0,
    unique_customers    INT NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, coupon_id, date)
);

-- Customer coupon usage
CREATE TABLE sales_analytics.customer_coupon_usage (
    company_id      UUID NOT NULL,
    coupon_id       UUID NOT NULL,
    customer_id     UUID NOT NULL,
    usage_count     INT NOT NULL DEFAULT 0,
    total_discount  DECIMAL(14,4) NOT NULL DEFAULT 0,
    first_used_at   TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    PRIMARY KEY (company_id, coupon_id, customer_id)
);

-- Coupon redemption rate daily
CREATE TABLE sales_analytics.coupon_redemption_rate_daily (
    id                  BIGSERIAL PRIMARY KEY,
    company_id          UUID NOT NULL,
    coupon_id           UUID NOT NULL,
    date                DATE NOT NULL,
    total_issued        INT,
    times_used          INT NOT NULL DEFAULT 0,
    total_available     INT,
    redemption_rate     DECIMAL(5,2),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, coupon_id, date)
);

-- Coupon performance summary
CREATE TABLE sales_analytics.coupon_performance_summary (
    coupon_id           UUID PRIMARY KEY,
    company_id          UUID NOT NULL,
    total_times_used    BIGINT NOT NULL DEFAULT 0,
    total_discount_given DECIMAL(14,4) NOT NULL DEFAULT 0,
    avg_discount_per_use DECIMAL(14,4),
    unique_customers    INT NOT NULL DEFAULT 0,
    last_used_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Promotion usage fact
CREATE TABLE sales_analytics.promotion_usage_fact (
    id              BIGSERIAL PRIMARY KEY,
    company_id      UUID NOT NULL,
    promotion_id    UUID NOT NULL,
    entity_type     VARCHAR(20) NOT NULL,
    entity_id       UUID NOT NULL,
    customer_id     UUID,
    discount_amount DECIMAL(14,4) NOT NULL,
    order_subtotal  DECIMAL(14,4),
    used_at         TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, promotion_id, entity_type, entity_id)
);

-- Daily promotion metrics
CREATE TABLE sales_analytics.daily_promotion_metrics (
    id                  BIGSERIAL PRIMARY KEY,
    company_id          UUID NOT NULL,
    promotion_id        UUID NOT NULL,
    date                DATE NOT NULL,
    times_applied       INT NOT NULL DEFAULT 0,
    total_discount_amount DECIMAL(14,4) NOT NULL DEFAULT 0,
    total_order_value   DECIMAL(14,4) NOT NULL DEFAULT 0,
    unique_customers    INT NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, promotion_id, date)
);

-- Daily promotion unique customers
CREATE TABLE sales_analytics.daily_promotion_unique_customers (
    company_id      UUID NOT NULL,
    promotion_id    UUID NOT NULL,
    date            DATE NOT NULL,
    customer_id     UUID NOT NULL,
    PRIMARY KEY (company_id, promotion_id, date, customer_id)
);

-- Promotion performance summary
CREATE TABLE sales_analytics.promotion_performance_summary (
    promotion_id            UUID PRIMARY KEY,
    company_id              UUID NOT NULL,
    total_times_used        BIGINT NOT NULL DEFAULT 0,
    total_discount_given    DECIMAL(14,4) NOT NULL DEFAULT 0,
    avg_discount_per_use    DECIMAL(14,4),
    unique_customers        INT NOT NULL DEFAULT 0,
    last_used_at            TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- Customer promotion usage
CREATE TABLE sales_analytics.customer_promotion_usage (
    company_id      UUID NOT NULL,
    promotion_id    UUID NOT NULL,
    customer_id     UUID NOT NULL,
    usage_count     INT NOT NULL DEFAULT 0,
    total_discount  DECIMAL(14,4) NOT NULL DEFAULT 0,
    first_used_at   TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    PRIMARY KEY (company_id, promotion_id, customer_id)
);

-- Promotion redemption rate daily
CREATE TABLE sales_analytics.promotion_redemption_rate_daily (
    id                  BIGSERIAL PRIMARY KEY,
    company_id          UUID NOT NULL,
    promotion_id        UUID NOT NULL,
    date                DATE NOT NULL,
    total_available     INT,
    times_used          INT NOT NULL DEFAULT 0,
    redemption_rate     DECIMAL(5,2),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, promotion_id, date)
);

-- Promotion unique customers (global)
CREATE TABLE sales_analytics.promotion_unique_customers (
    company_id   UUID NOT NULL,
    promotion_id UUID NOT NULL,
    customer_id  UUID NOT NULL,
    PRIMARY KEY (company_id, promotion_id, customer_id)
);

-- Daily return metrics
CREATE TABLE sales_analytics.daily_return_metrics (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    total_returns_requested INT DEFAULT 0,
    total_returns_approved INT DEFAULT 0,
    total_returns_completed INT DEFAULT 0,
    total_returns_rejected INT DEFAULT 0,
    total_refund_amount DECIMAL(14,4) DEFAULT 0,
    total_credit_note_amount DECIMAL(14,4) DEFAULT 0,
    unique_customers INT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Return reason fact
CREATE TABLE sales_analytics.return_reason_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    return_id UUID NOT NULL,
    return_item_id UUID NOT NULL,
    reason_code VARCHAR(100),
    reason_text TEXT,
    product_id UUID,
    quantity_returned DECIMAL(14,4),
    refund_amount DECIMAL(14,4),
    return_date DATE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Return processing time fact
CREATE TABLE sales_analytics.return_processing_time_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    return_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL,
    entered_at TIMESTAMPTZ NOT NULL,
    exited_at TIMESTAMPTZ,
    duration_seconds BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (exited_at - entered_at))) STORED,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Credit note fact
CREATE TABLE sales_analytics.credit_note_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    credit_note_id UUID NOT NULL,
    return_id UUID,
    issued_date DATE NOT NULL,
    issued_amount DECIMAL(14,4) NOT NULL,
    applied_amount DECIMAL(14,4) DEFAULT 0,
    applied_to_invoice_id UUID,
    applied_date DATE,
    status VARCHAR(20) DEFAULT 'issued',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Refund fact
CREATE TABLE sales_analytics.refund_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    refund_id UUID NOT NULL,
    return_id UUID NOT NULL,
    payment_id UUID NOT NULL,
    amount DECIMAL(14,4) NOT NULL,
    refund_date DATE NOT NULL,
    refund_method sales.payment_method,
    status VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Return product category fact
CREATE TABLE sales_analytics.return_product_category_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    category_id UUID,
    category_name VARCHAR(255),
    return_date DATE NOT NULL,
    quantity_returned DECIMAL(14,4),
    refund_amount DECIMAL(14,4),
    unique_returns INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Daily return unique customers
CREATE TABLE sales_analytics.daily_return_unique_customers (
    company_id UUID NOT NULL,
    date DATE NOT NULL,
    customer_id UUID NOT NULL,
    PRIMARY KEY (company_id, date, customer_id)
);

-- Sales rep target achievement
CREATE TABLE sales_analytics.sales_rep_target_achievement (
    id                 BIGSERIAL PRIMARY KEY,
    company_id         UUID NOT NULL,
    sales_rep_id       UUID NOT NULL,
    period_start       DATE NOT NULL,
    period_end         DATE NOT NULL,
    target_amount      DECIMAL(14,2) NOT NULL,
    actual_revenue     DECIMAL(14,2) NOT NULL DEFAULT 0,
    achievement_pct    DECIMAL(5,2) GENERATED ALWAYS AS (
        CASE WHEN target_amount > 0 
             THEN (actual_revenue / target_amount) * 100 
             ELSE 0 
        END
    ) STORED,
    currency           VARCHAR(3) NOT NULL DEFAULT 'USD',
    created_at         TIMESTAMPTZ DEFAULT NOW(),
    updated_at         TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, sales_rep_id, period_start, period_end)
);

-- Sales rep commission fact (with plan_id and rule_id included directly)
CREATE TABLE sales_analytics.sales_rep_commission_fact (
    id                BIGSERIAL PRIMARY KEY,
    company_id        UUID NOT NULL,
    sales_rep_id      UUID NOT NULL,
    entity_type       VARCHAR(20) NOT NULL,
    entity_id         UUID NOT NULL,
    commission_base   DECIMAL(14,4) NOT NULL,
    commission_rate   DECIMAL(5,2) NOT NULL,
    commission_amount DECIMAL(14,4) NOT NULL,
    earned_at         TIMESTAMPTZ NOT NULL,
    paid_at           TIMESTAMPTZ,
    plan_id           UUID,
    rule_id           UUID,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, entity_type, entity_id)
);

-- Sales rep leaderboard snapshot
CREATE TABLE sales_analytics.sales_rep_leaderboard_snapshot (
    id                BIGSERIAL PRIMARY KEY,
    company_id        UUID NOT NULL,
    snapshot_date     DATE NOT NULL,
    period_start      DATE NOT NULL,
    period_end        DATE NOT NULL,
    sales_rep_id      UUID NOT NULL,
    rank              INT NOT NULL,
    revenue           DECIMAL(14,4) NOT NULL,
    orders_count      INT NOT NULL,
    average_deal      DECIMAL(14,4) NOT NULL,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, snapshot_date, sales_rep_id)
);

-- Commission plan daily
CREATE TABLE sales_analytics.commission_plan_daily (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    date DATE NOT NULL,
    total_commissions_earned DECIMAL(14,4) NOT NULL DEFAULT 0,
    total_commissions_paid DECIMAL(14,4) NOT NULL DEFAULT 0,
    commission_count INT NOT NULL DEFAULT 0,
    average_rate DECIMAL(10,2) NOT NULL DEFAULT 0,
    unique_sales_reps INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, plan_id, date)
);

-- Commission rule fact
CREATE TABLE sales_analytics.commission_rule_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    rule_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    date DATE NOT NULL,
    times_applied INT NOT NULL DEFAULT 0,
    total_commission_base DECIMAL(14,4) NOT NULL DEFAULT 0,
    total_commission_amount DECIMAL(14,4) NOT NULL DEFAULT 0,
    avg_rate DECIMAL(10,2) NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, rule_id, date)
);

CREATE TABLE sales_analytics.commission_assignment_fact (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    sales_rep_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    assigned_at DATE NOT NULL,
    removed_at DATE,
    duration_days INT,   -- not generated; compute as COALESCE(removed_at, CURRENT_DATE) - assigned_at in queries
    assigned_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
-- Commission lifecycle
CREATE TABLE sales_analytics.commission_lifecycle (
    commission_id UUID PRIMARY KEY,
    company_id UUID NOT NULL,
    sales_rep_id UUID NOT NULL,
    reference_type VARCHAR(20) NOT NULL,
    reference_id UUID NOT NULL,
    earned_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    approval_delay_hours DECIMAL(10,2) GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (approved_at - earned_at))/3600) STORED,
    payment_delay_hours DECIMAL(10,2) GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (paid_at - approved_at))/3600) STORED,
    current_status VARCHAR(20) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Commission forecast snapshot
CREATE TABLE sales_analytics.commission_forecast_snapshot (
    id BIGSERIAL PRIMARY KEY,
    company_id UUID NOT NULL,
    snapshot_date DATE NOT NULL,
    sales_rep_id UUID NOT NULL,
    expected_commission_from_open_orders DECIMAL(14,4) DEFAULT 0,
    expected_commission_from_open_invoices DECIMAL(14,4) DEFAULT 0,
    total_expected_commission DECIMAL(14,4) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, snapshot_date, sales_rep_id)
);

-- Credit check fact
CREATE TABLE IF NOT EXISTS sales_analytics.credit_check_fact (
    id               BIGSERIAL PRIMARY KEY,
    company_id       UUID NOT NULL,
    customer_id      UUID NOT NULL,
    check_id         UUID,
    check_type       VARCHAR(20) NOT NULL,
    result           VARCHAR(20) NOT NULL,
    requested_amount DECIMAL(14,4) NOT NULL,
    current_limit    DECIMAL(14,2) NOT NULL,
    current_outstanding DECIMAL(14,4) NOT NULL,
    available_credit DECIMAL(14,4) NOT NULL,
    reason           TEXT,
    checked_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Daily credit metrics
CREATE TABLE IF NOT EXISTS sales_analytics.daily_credit_metrics (
    id                         BIGSERIAL PRIMARY KEY,
    company_id                 UUID NOT NULL,
    date                       DATE NOT NULL,
    total_checks               INT DEFAULT 0,
    checks_passed              INT DEFAULT 0,
    checks_failed              INT DEFAULT 0,
    total_order_value_checked  DECIMAL(14,4) DEFAULT 0,
    total_invoice_value_checked DECIMAL(14,4) DEFAULT 0,
    avg_available_credit       DECIMAL(14,4) DEFAULT 0,
    avg_credit_utilization     DECIMAL(5,2) DEFAULT 0,
    updated_at                 TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date)
);

-- Credit hold fact
CREATE TABLE IF NOT EXISTS sales_analytics.credit_hold_fact (
    id              BIGSERIAL PRIMARY KEY,
    order_id        UUID NOT NULL,
    company_id      UUID NOT NULL,
    customer_id     UUID NOT NULL,
    hold_started_at TIMESTAMPTZ NOT NULL,
    hold_ended_at   TIMESTAMPTZ,
    duration_seconds BIGINT GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (hold_ended_at - hold_started_at))) STORED,
    reason          TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(order_id, hold_started_at)
);

-- Credit limit change fact
CREATE TABLE IF NOT EXISTS sales_analytics.credit_limit_change_fact (
    id               BIGSERIAL PRIMARY KEY,
    company_id       UUID NOT NULL,
    customer_id      UUID NOT NULL,
    previous_limit   DECIMAL(14,2) NOT NULL,
    new_limit        DECIMAL(14,2) NOT NULL,
    change_amount    DECIMAL(14,2) GENERATED ALWAYS AS (new_limit - previous_limit) STORED,
    change_reason    TEXT,
    changed_by       UUID,
    changed_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Customer credit daily snapshot
CREATE TABLE IF NOT EXISTS sales_analytics.customer_credit_daily_snapshot (
    snapshot_id      BIGSERIAL PRIMARY KEY,
    company_id       UUID NOT NULL,
    customer_id      UUID NOT NULL,
    snapshot_date    DATE NOT NULL,
    credit_limit     DECIMAL(14,2) NOT NULL,
    outstanding_balance DECIMAL(14,4) NOT NULL,
    available_credit DECIMAL(14,4) NOT NULL,
    utilization_pct  DECIMAL(5,2) GENERATED ALWAYS AS (
        CASE WHEN credit_limit > 0 THEN (outstanding_balance / credit_limit) * 100 ELSE 0 END
    ) STORED,
    is_suspended     BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, customer_id, snapshot_date)
);

-- =====================================================
-- INDEXES FOR ANALYTICS TABLES
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_daily_sales_company_date ON sales_analytics.daily_sales(company_id, date);
CREATE INDEX IF NOT EXISTS idx_product_sales_company_date ON sales_analytics.product_sales_fact(company_id, date);
CREATE INDEX IF NOT EXISTS idx_customer_metrics_company ON sales_analytics.customer_metrics(company_id);
CREATE INDEX IF NOT EXISTS idx_payment_term_performance_company_date ON sales_analytics.payment_term_performance(company_id, date);
CREATE INDEX IF NOT EXISTS idx_order_status_history_order ON sales_analytics.order_status_history(order_id);
CREATE INDEX IF NOT EXISTS idx_order_status_history_company ON sales_analytics.order_status_history(company_id, entered_at);
CREATE INDEX IF NOT EXISTS idx_order_item_analytics_order ON sales_analytics.order_item_analytics(order_id);
CREATE INDEX IF NOT EXISTS idx_order_item_analytics_product ON sales_analytics.order_item_analytics(product_id, order_date);
CREATE INDEX IF NOT EXISTS idx_sales_rep_performance_rep ON sales_analytics.sales_rep_performance(sales_rep_id, date);
CREATE INDEX IF NOT EXISTS idx_order_cancellation_reasons ON sales_analytics.order_cancellation_reasons(company_id, cancelled_at);
CREATE INDEX IF NOT EXISTS idx_hourly_sales_company ON sales_analytics.order_hourly_sales(company_id, hour_bucket);
CREATE INDEX IF NOT EXISTS idx_daily_quote_metrics_company_date ON sales_analytics.daily_quote_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_quote_status_history_quote ON sales_analytics.quote_status_history(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_status_history_company ON sales_analytics.quote_status_history(company_id, entered_at);
CREATE INDEX IF NOT EXISTS idx_quote_conversion_quote ON sales_analytics.quote_conversion_facts(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_conversion_order ON sales_analytics.quote_conversion_facts(order_id);
CREATE INDEX IF NOT EXISTS idx_quote_conversion_company ON sales_analytics.quote_conversion_facts(company_id, converted_at);
CREATE INDEX IF NOT EXISTS idx_quote_item_analytics_quote ON sales_analytics.quote_item_analytics(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_item_analytics_product ON sales_analytics.quote_item_analytics(product_id, quote_date);
CREATE INDEX IF NOT EXISTS idx_quote_item_analytics_company ON sales_analytics.quote_item_analytics(company_id, quote_date);
CREATE INDEX IF NOT EXISTS idx_invoice_status_history_invoice ON sales_analytics.invoice_status_history(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_status_history_company ON sales_analytics.invoice_status_history(company_id, entered_at);
CREATE INDEX IF NOT EXISTS idx_invoice_item_analytics_invoice ON sales_analytics.invoice_item_analytics(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_item_analytics_product ON sales_analytics.invoice_item_analytics(product_id, invoice_date);
CREATE INDEX IF NOT EXISTS idx_invoice_item_analytics_company ON sales_analytics.invoice_item_analytics(company_id, invoice_date);
CREATE INDEX IF NOT EXISTS idx_daily_invoice_metrics_company_date ON sales_analytics.daily_invoice_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_payment_method_daily_company_date ON sales_analytics.payment_method_daily(company_id, date);
CREATE INDEX IF NOT EXISTS idx_refund_metrics_company_date ON sales_analytics.refund_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_payment_aging_company_date ON sales_analytics.payment_aging_snapshot(company_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_collection_efficiency_company_date ON sales_analytics.collection_efficiency(company_id, date);
CREATE INDEX IF NOT EXISTS idx_auto_discount_metrics_company_date ON sales_analytics.automatic_discount_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_auto_discount_metrics_discount ON sales_analytics.automatic_discount_metrics(auto_discount_id);
CREATE INDEX IF NOT EXISTS idx_stacking_usage_rule ON sales_analytics.discount_stacking_usage(rule_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_fact_company_date ON sales_analytics.coupon_usage_fact(company_id, used_at);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_fact_coupon ON sales_analytics.coupon_usage_fact(coupon_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usage_fact_customer ON sales_analytics.coupon_usage_fact(customer_id);
CREATE INDEX IF NOT EXISTS idx_daily_coupon_metrics_company_date ON sales_analytics.daily_coupon_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_daily_coupon_metrics_coupon ON sales_analytics.daily_coupon_metrics(coupon_id);
CREATE INDEX IF NOT EXISTS idx_customer_coupon_usage_customer ON sales_analytics.customer_coupon_usage(customer_id);
CREATE INDEX IF NOT EXISTS idx_promotion_usage_fact_company_date ON sales_analytics.promotion_usage_fact(company_id, used_at);
CREATE INDEX IF NOT EXISTS idx_promotion_usage_fact_promotion ON sales_analytics.promotion_usage_fact(promotion_id);
CREATE INDEX IF NOT EXISTS idx_promotion_usage_fact_customer ON sales_analytics.promotion_usage_fact(customer_id);
CREATE INDEX IF NOT EXISTS idx_daily_promotion_metrics_company_date ON sales_analytics.daily_promotion_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_daily_promotion_metrics_promotion ON sales_analytics.daily_promotion_metrics(promotion_id);
CREATE INDEX IF NOT EXISTS idx_promotion_performance_company ON sales_analytics.promotion_performance_summary(company_id);
CREATE INDEX IF NOT EXISTS idx_customer_promotion_usage_customer ON sales_analytics.customer_promotion_usage(customer_id);
CREATE INDEX IF NOT EXISTS idx_daily_return_metrics_company_date ON sales_analytics.daily_return_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_return_reason_fact_company_date ON sales_analytics.return_reason_fact(company_id, return_date);
CREATE INDEX IF NOT EXISTS idx_return_reason_fact_reason ON sales_analytics.return_reason_fact(reason_code);
CREATE INDEX IF NOT EXISTS idx_return_processing_time_return ON sales_analytics.return_processing_time_fact(return_id);
CREATE INDEX IF NOT EXISTS idx_return_processing_time_status ON sales_analytics.return_processing_time_fact(status);
CREATE INDEX IF NOT EXISTS idx_credit_note_fact_company_date ON sales_analytics.credit_note_fact(company_id, issued_date);
CREATE INDEX IF NOT EXISTS idx_credit_note_fact_return ON sales_analytics.credit_note_fact(return_id);
CREATE INDEX IF NOT EXISTS idx_refund_fact_return ON sales_analytics.refund_fact(return_id);
CREATE INDEX IF NOT EXISTS idx_refund_fact_company_date ON sales_analytics.refund_fact(company_id, refund_date);
CREATE INDEX IF NOT EXISTS idx_target_achievement_rep ON sales_analytics.sales_rep_target_achievement(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_target_achievement_period ON sales_analytics.sales_rep_target_achievement(period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_target_achievement_company ON sales_analytics.sales_rep_target_achievement(company_id);
CREATE INDEX IF NOT EXISTS idx_commission_fact_rep ON sales_analytics.sales_rep_commission_fact(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_commission_fact_earned ON sales_analytics.sales_rep_commission_fact(earned_at);
CREATE INDEX IF NOT EXISTS idx_commission_fact_paid ON sales_analytics.sales_rep_commission_fact(paid_at);
CREATE INDEX IF NOT EXISTS idx_commission_fact_plan ON sales_analytics.sales_rep_commission_fact(plan_id);
CREATE INDEX IF NOT EXISTS idx_commission_fact_rule ON sales_analytics.sales_rep_commission_fact(rule_id);
CREATE INDEX IF NOT EXISTS idx_leaderboard_snapshot_company_date ON sales_analytics.sales_rep_leaderboard_snapshot(company_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_leaderboard_snapshot_rep ON sales_analytics.sales_rep_leaderboard_snapshot(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_commission_plan_daily_company_date ON sales_analytics.commission_plan_daily(company_id, date);
CREATE INDEX IF NOT EXISTS idx_commission_rule_fact_plan ON sales_analytics.commission_rule_fact(plan_id);
CREATE INDEX IF NOT EXISTS idx_assignment_fact_rep ON sales_analytics.commission_assignment_fact(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_assignment_fact_plan ON sales_analytics.commission_assignment_fact(plan_id);
CREATE INDEX IF NOT EXISTS idx_commission_lifecycle_status ON sales_analytics.commission_lifecycle(current_status);
CREATE INDEX IF NOT EXISTS idx_commission_forecast_rep ON sales_analytics.commission_forecast_snapshot(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_credit_check_fact_company_date ON sales_analytics.credit_check_fact(company_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_credit_check_fact_customer ON sales_analytics.credit_check_fact(customer_id);
CREATE INDEX IF NOT EXISTS idx_credit_check_fact_result ON sales_analytics.credit_check_fact(result);
CREATE INDEX IF NOT EXISTS idx_daily_credit_metrics_company_date ON sales_analytics.daily_credit_metrics(company_id, date);
CREATE INDEX IF NOT EXISTS idx_credit_hold_fact_order ON sales_analytics.credit_hold_fact(order_id);
CREATE INDEX IF NOT EXISTS idx_credit_hold_fact_company_date ON sales_analytics.credit_hold_fact(company_id, hold_started_at);
CREATE INDEX IF NOT EXISTS idx_credit_hold_fact_customer ON sales_analytics.credit_hold_fact(customer_id);
CREATE INDEX IF NOT EXISTS idx_credit_limit_change_company ON sales_analytics.credit_limit_change_fact(company_id, changed_at);
CREATE INDEX IF NOT EXISTS idx_credit_limit_change_customer ON sales_analytics.credit_limit_change_fact(customer_id);
CREATE INDEX IF NOT EXISTS idx_customer_credit_snapshot_company_date ON sales_analytics.customer_credit_daily_snapshot(company_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_customer_credit_snapshot_customer ON sales_analytics.customer_credit_daily_snapshot(customer_id);

-- =====================================================
-- MATERIALIZED VIEW: Current customer credit status
-- =====================================================
CREATE MATERIALIZED VIEW sales_analytics.current_customer_credit AS
SELECT
    c.customer_id,
    c.company_id,
    COALESCE(c.credit_limit, 0) AS credit_limit,
    COALESCE(SUM(i.amount_due), 0) AS outstanding_balance,
    COALESCE(c.credit_limit, 0) - COALESCE(SUM(i.amount_due), 0) AS available_credit,
    CASE WHEN COALESCE(c.credit_limit, 0) > 0
         THEN (COALESCE(SUM(i.amount_due), 0) / c.credit_limit) * 100
         ELSE 0
    END AS utilization_pct,
    EXISTS (
        SELECT 1 FROM sales.credit_check_history h
        WHERE h.customer_id = c.customer_id
          AND h.action_type = 'suspend'
          AND h.created_at > COALESCE(
              (SELECT MAX(created_at) FROM sales.credit_check_history
               WHERE customer_id = c.customer_id AND action_type = 'restore'),
              '0001-01-01'
          )
    ) AS is_suspended
FROM sales.customers c
LEFT JOIN sales.invoices i ON i.customer_id = c.customer_id AND i.status NOT IN ('paid', 'cancelled')
GROUP BY c.customer_id, c.company_id, c.credit_limit;

CREATE UNIQUE INDEX idx_current_credit_customer ON sales_analytics.current_customer_credit(customer_id);
CREATE INDEX idx_current_credit_company ON sales_analytics.current_customer_credit(company_id);

-- =====================================================
-- ADDITIONAL INDEXES (from original script)
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_customers_company ON sales.customers(company_id);
CREATE INDEX IF NOT EXISTS idx_customers_code ON sales.customers(company_id, customer_code);
CREATE INDEX IF NOT EXISTS idx_customers_payment_term ON sales.customers(payment_term_id);
CREATE INDEX IF NOT EXISTS idx_products_company ON sales.products(company_id);
CREATE INDEX IF NOT EXISTS idx_products_inventory_item ON sales.products(inventory_item_id) WHERE inventory_item_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_payment_terms_company ON sales.payment_terms(company_id);
CREATE INDEX IF NOT EXISTS idx_payment_terms_code ON sales.payment_terms(company_id, code);
CREATE INDEX IF NOT EXISTS idx_sales_reps_company ON sales.sales_reps(company_id);
CREATE INDEX IF NOT EXISTS idx_sales_reps_user ON sales.sales_reps(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_orders_external_ref ON sales.orders (company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_orders_company ON sales.orders(company_id);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON sales.orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_date ON sales.orders(order_date);
CREATE INDEX IF NOT EXISTS idx_orders_status ON sales.orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_number ON sales.orders(company_id, order_number);
CREATE INDEX IF NOT EXISTS idx_orders_ext ON sales.orders(company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_orders_sales_rep ON sales.orders(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON sales.order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_order_items_product ON sales.order_items(product_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_invoices_external_ref ON sales.invoices (company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_invoices_company ON sales.invoices(company_id);
CREATE INDEX IF NOT EXISTS idx_invoices_customer ON sales.invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_order ON sales.invoices(order_id);
CREATE INDEX IF NOT EXISTS idx_invoices_date ON sales.invoices(invoice_date);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON sales.invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_due ON sales.invoices(due_date) WHERE status NOT IN ('paid', 'cancelled');
CREATE INDEX IF NOT EXISTS idx_invoices_ext ON sales.invoices(company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_invoices_sales_rep ON sales.invoices(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice ON sales.invoice_items(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_items_product ON sales.invoice_items(product_id) WHERE product_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_payments_external_ref ON sales.payments (company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_payments_company ON sales.payments(company_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON sales.payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_date ON sales.payments(payment_date);
CREATE INDEX IF NOT EXISTS idx_payments_ext ON sales.payments(company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_payment_allocations_payment ON sales.payment_allocations(payment_id);
CREATE INDEX IF NOT EXISTS idx_payment_allocations_invoice ON sales.payment_allocations(invoice_id);
CREATE INDEX IF NOT EXISTS idx_payment_refunds_payment ON sales.payment_refunds(payment_id);
CREATE INDEX IF NOT EXISTS idx_payment_refunds_status ON sales.payment_refunds(status);
CREATE INDEX IF NOT EXISTS idx_payment_refunds_date ON sales.payment_refunds(created_at);
CREATE INDEX IF NOT EXISTS idx_payment_refunds_return ON sales.payment_refunds(return_id);
CREATE INDEX IF NOT EXISTS idx_returns_company ON sales.returns(company_id);
CREATE INDEX IF NOT EXISTS idx_returns_order ON sales.returns(order_id);
CREATE INDEX IF NOT EXISTS idx_returns_status ON sales.returns(status);
CREATE INDEX IF NOT EXISTS idx_return_items_return ON sales.return_items(return_id);
CREATE INDEX IF NOT EXISTS idx_return_items_product ON sales.return_items(product_id);
CREATE INDEX IF NOT EXISTS idx_coupons_company ON sales.coupons(company_id);
CREATE INDEX IF NOT EXISTS idx_coupons_code ON sales.coupons(code);
CREATE INDEX IF NOT EXISTS idx_coupons_dates ON sales.coupons(start_date, end_date) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_coupon_usages_coupon ON sales.coupon_usages(coupon_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usages_customer ON sales.coupon_usages(customer_id);
CREATE INDEX IF NOT EXISTS idx_promotions_company ON sales.promotions(company_id);
CREATE INDEX IF NOT EXISTS idx_promotions_dates ON sales.promotions(start_date, end_date) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_promotion_rules_promotion ON sales.promotion_rules(promotion_id);
CREATE INDEX IF NOT EXISTS idx_auto_discount_company ON sales.automatic_discounts(company_id);
CREATE INDEX IF NOT EXISTS idx_auto_discount_dates ON sales.automatic_discounts(start_date, end_date) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_auto_discount_priority ON sales.automatic_discounts(company_id, priority);
CREATE INDEX IF NOT EXISTS idx_stacking_primary ON sales.discount_stacking_rules(company_id, primary_discount_type, primary_discount_id);
CREATE INDEX IF NOT EXISTS idx_stacking_active ON sales.discount_stacking_rules(company_id, is_active);
CREATE INDEX IF NOT EXISTS idx_exclusion_pair ON sales.discount_exclusions(company_id, discount_type_a, discount_id_a);
CREATE INDEX IF NOT EXISTS idx_priority_company_type ON sales.discount_priorities(company_id, discount_type);
CREATE INDEX IF NOT EXISTS idx_priority_value ON sales.discount_priorities(company_id, priority);
CREATE INDEX IF NOT EXISTS idx_discount_applications_order ON sales.discount_applications(order_id) WHERE order_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_discount_applications_invoice ON sales.discount_applications(invoice_id) WHERE invoice_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tax_snapshots_entity ON sales.tax_snapshots(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_tax_snapshots_line ON sales.tax_snapshots(line_id) WHERE line_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tax_snapshots_company ON sales.tax_snapshots(company_id);
CREATE INDEX IF NOT EXISTS idx_quotes_company ON sales.quotes(company_id);
CREATE INDEX IF NOT EXISTS idx_quotes_customer ON sales.quotes(customer_id);
CREATE INDEX IF NOT EXISTS idx_quotes_status ON sales.quotes(status);
CREATE INDEX IF NOT EXISTS idx_quotes_date ON sales.quotes(quote_date);
CREATE INDEX IF NOT EXISTS idx_quotes_converted_order ON sales.quotes(converted_order_id);
CREATE INDEX IF NOT EXISTS idx_quotes_sales_rep ON sales.quotes(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_quotes_expiry ON sales.quotes(expiry_date) WHERE expiry_date IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_quote_items_quote ON sales.quote_items(quote_id);
CREATE INDEX IF NOT EXISTS idx_quote_items_product ON sales.quote_items(product_id);
CREATE INDEX IF NOT EXISTS idx_commissions_rep ON sales.sales_rep_commissions(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_commissions_product ON sales.sales_rep_commissions(product_id) WHERE product_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_commissions_date ON sales.sales_rep_commissions(effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_commissions_rate ON sales.sales_rep_commissions(commission_rate);
CREATE INDEX IF NOT EXISTS idx_credit_history_customer ON sales.credit_check_history(customer_id);
CREATE INDEX IF NOT EXISTS idx_credit_history_action ON sales.credit_check_history(action_type);
CREATE INDEX IF NOT EXISTS idx_credit_history_date ON sales.credit_check_history(created_at);
CREATE INDEX IF NOT EXISTS idx_credit_history_created_by ON sales.credit_check_history(created_by);
CREATE INDEX IF NOT EXISTS idx_credit_notes_company ON sales.credit_notes(company_id);
CREATE INDEX IF NOT EXISTS idx_credit_notes_customer ON sales.credit_notes(customer_id);
CREATE INDEX IF NOT EXISTS idx_credit_notes_invoice ON sales.credit_notes(invoice_id);
CREATE INDEX IF NOT EXISTS idx_credit_notes_return ON sales.credit_notes(return_id);
CREATE INDEX IF NOT EXISTS idx_credit_notes_status ON sales.credit_notes(status);
CREATE INDEX IF NOT EXISTS idx_credit_notes_issue_date ON sales.credit_notes(issue_date);
CREATE INDEX IF NOT EXISTS idx_credit_items_credit_note ON sales.credit_note_items(credit_note_id);
CREATE INDEX IF NOT EXISTS idx_credit_items_product ON sales.credit_note_items(product_id);
CREATE INDEX IF NOT EXISTS idx_cn_app_credit_note ON sales.credit_note_applications(credit_note_id);
CREATE INDEX IF NOT EXISTS idx_cn_app_invoice ON sales.credit_note_applications(invoice_id);
CREATE INDEX IF NOT EXISTS idx_sales_targets_rep ON sales.sales_targets(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_sales_targets_period ON sales.sales_targets(period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_commission_plans_company ON sales.commission_plans(company_id);
CREATE INDEX IF NOT EXISTS idx_commission_plans_dates ON sales.commission_plans(effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_commission_rules_plan ON sales.commission_rules(plan_id);
CREATE INDEX IF NOT EXISTS idx_commission_rules_product ON sales.commission_rules(product_id);
CREATE INDEX IF NOT EXISTS idx_sales_commissions_rep ON sales.sales_commissions(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_sales_commissions_reference ON sales.sales_commissions(reference_type, reference_id);
CREATE INDEX IF NOT EXISTS idx_sales_commissions_status ON sales.sales_commissions(status);
CREATE INDEX IF NOT EXISTS idx_sales_commissions_earned ON sales.sales_commissions(earned_at);
CREATE INDEX IF NOT EXISTS idx_assignments_rep ON sales.sales_rep_commission_assignments(sales_rep_id);
CREATE INDEX IF NOT EXISTS idx_assignments_dates ON sales.sales_rep_commission_assignments(effective_from, effective_to);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_customers_email ON sales.customers (company_id, email) WHERE email IS NOT NULL;

-- =====================================================
-- END OF SCRIPT
-- =====================================================


-- Add email_hash column
ALTER TABLE sales.customers ADD COLUMN email_hash VARCHAR(64);

-- Create unique index (ignoring NULLs for customers without email)
CREATE UNIQUE INDEX uniq_customers_email_hash ON sales.customers (company_id, email_hash) WHERE email_hash IS NOT NULL;

-- 1. Drop the broken generated column (cannot alter expression directly)
ALTER TABLE sales.order_items DROP COLUMN total_price;

-- 2. Re‑add it with COALESCE to handle NULLs
ALTER TABLE sales.order_items ADD COLUMN total_price NUMERIC(14,4) GENERATED ALWAYS AS (
    (unit_price * quantity) - COALESCE(discount_amount, 0) + COALESCE(tax_amount, 0)
) STORED;
ALTER TABLE sales_analytics.product_sales_fact
ADD CONSTRAINT product_sales_fact_company_product_date_unique
UNIQUE (company_id, product_id, date);


-- Step 1: Add column with default 0
ALTER TABLE sales.order_items 
ADD COLUMN quantity_invoiced NUMERIC(14,4) NOT NULL DEFAULT 0;

-- Step 2: Add check constraint (cannot invoice more than ordered)
ALTER TABLE sales.order_items 
ADD CONSTRAINT chk_quantity_invoiced 
CHECK (quantity_invoiced <= quantity AND quantity_invoiced >= 0);

-- Step 3: (Optional) Add an index for faster lookups
CREATE INDEX idx_order_items_invoiced ON sales.order_items(order_id, product_id) 
WHERE quantity_invoiced < quantity;



-- 1. order_item_analytics: unique on order_item_id
ALTER TABLE sales_analytics.order_item_analytics
ADD CONSTRAINT order_item_analytics_order_item_id_unique UNIQUE (order_item_id);

-- 2. order_hourly_sales: unique on (company_id, hour_bucket)
ALTER TABLE sales_analytics.order_hourly_sales
ADD CONSTRAINT order_hourly_sales_company_hour_unique UNIQUE (company_id, hour_bucket);

-- 3. fulfillment_metrics: unique on order_id
ALTER TABLE sales_analytics.fulfillment_metrics
ADD CONSTRAINT fulfillment_metrics_order_id_unique UNIQUE (order_id);

-- 4. product_sales_fact: you already added a unique constraint in the script:
--    ALTER TABLE sales_analytics.product_sales_fact
--    ADD CONSTRAINT product_sales_fact_company_product_date_unique UNIQUE (company_id, product_id, date);
--    If that failed, double‑check it exists. Otherwise run:
ALTER TABLE sales_analytics.product_sales_fact
ADD CONSTRAINT product_sales_fact_company_product_date_unique UNIQUE (company_id, product_id, date);


-- Add order_item_id column (nullable, because draft invoices from scratch won't have it)
ALTER TABLE sales.invoice_items 
ADD COLUMN order_item_id UUID NULL;

-- Add foreign key constraint (optional but recommended)
ALTER TABLE sales.invoice_items 
ADD CONSTRAINT fk_invoice_items_order_item 
FOREIGN KEY (order_item_id) REFERENCES sales.order_items(order_item_id) ON DELETE SET NULL;

-- Create index for faster lookups
CREATE INDEX idx_invoice_items_order_item ON sales.invoice_items(order_item_id);


ALTER TABLE sales.order_items 
ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();CREATE TRIGGER update_order_items_updated_at 
BEFORE UPDATE ON sales.order_items 
FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();

CREATE TABLE IF NOT EXISTS sales_analytics.commission_plan_unique_reps (
    company_id   UUID NOT NULL,
    plan_id      UUID NOT NULL,
    date         DATE NOT NULL,
    sales_rep_id UUID NOT NULL,
    PRIMARY KEY (company_id, plan_id, date, sales_rep_id)
);

ALTER TABLE sales.coupons ADD COLUMN deleted_at TIMESTAMPTZ;
CREATE INDEX idx_coupons_deleted_at ON sales.coupons(deleted_at) WHERE deleted_at IS NOT NULL;

ALTER TABLE sales.customers 
ADD COLUMN sales_rep_id UUID NULL;

ALTER TABLE sales.customers 
ADD CONSTRAINT fk_customers_sales_rep 
FOREIGN KEY (sales_rep_id) REFERENCES sales.sales_reps(sales_rep_id) ON DELETE SET NULL;

CREATE INDEX idx_customers_sales_rep ON sales.customers(sales_rep_id);

ALTER TABLE sales.promotions ADD COLUMN stacking_type VARCHAR(20) NOT NULL DEFAULT 'stackable';
ALTER TABLE sales.promotions ADD CONSTRAINT chk_stacking_type CHECK (stacking_type IN ('stackable', 'exclusive', 'none'));

-- If coupons also support stacking_type:
ALTER TABLE sales.coupons ADD COLUMN stacking_type VARCHAR(20) NOT NULL DEFAULT 'stackable';
ALTER TABLE sales.coupons ADD CONSTRAINT chk_coupon_stacking_type CHECK (stacking_type IN ('stackable', 'exclusive', 'none'));


ALTER TABLE sales.coupon_usages ADD CONSTRAINT uniq_coupon_order UNIQUE (coupon_id, order_id);
