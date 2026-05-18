-- =====================================================
-- SALES MODULE SCHEMA (MODULAR + ENCRYPTION)
-- =====================================================

-- Ensure the sales schema exists
CREATE SCHEMA IF NOT EXISTS sales;

-- -----------------------------------------------------
-- ENUMS (schema qualified)
-- -----------------------------------------------------
CREATE TYPE sales.order_status AS ENUM ('draft', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded');
CREATE TYPE sales.invoice_status AS ENUM ('draft', 'issued', 'paid', 'overdue', 'cancelled', 'credited');
CREATE TYPE sales.payment_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'refunded', 'partially_refunded');
CREATE TYPE sales.payment_method AS ENUM ('cash', 'card', 'bank_transfer', 'digital_wallet', 'coupon', 'other');
CREATE TYPE sales.discount_type AS ENUM ('percentage', 'fixed_amount', 'buy_x_get_y');

-- -----------------------------------------------------
-- CUSTOMERS (with encryption for PII)
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS sales.customers (
    customer_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    customer_code        VARCHAR(50) NOT NULL,
    name                 VARCHAR(255) NOT NULL,

    -- Encrypted fields (pattern: field, field_dek, field_key_id)
    email                TEXT,
    email_dek            TEXT,
    email_key_id         TEXT,

    phone                TEXT,
    phone_dek            TEXT,
    phone_key_id         TEXT,

    tax_id               TEXT,
    tax_id_dek           TEXT,
    tax_id_key_id        TEXT,

    billing_address      TEXT,               -- JSONB originally, but encrypted as TEXT
    billing_address_dek  TEXT,
    billing_address_key_id TEXT,

    shipping_address     TEXT,
    shipping_address_dek TEXT,
    shipping_address_key_id TEXT,

    credit_limit         NUMERIC(14,2) DEFAULT 0,
    is_active            BOOLEAN NOT NULL DEFAULT true,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by           UUID,
    updated_by           UUID,

    CONSTRAINT fk_customers_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_customers_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_customers_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, customer_code)
);

-- Unique index on email (encrypted, but unique on the encrypted value)
-- Since email is encrypted, uniqueness must be enforced on the decrypted value via application logic.
-- We only create an index for search performance on the encrypted column (optional).
CREATE UNIQUE INDEX IF NOT EXISTS uniq_customers_email
    ON sales.customers (company_id, email)
    WHERE email IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_customers_company ON sales.customers(company_id);
CREATE INDEX IF NOT EXISTS idx_customers_code ON sales.customers(company_id, customer_code);

-- -----------------------------------------------------
-- PRODUCTS (Sales own product master – modular)
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS sales.products (
    product_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    sku                 VARCHAR(100) NOT NULL,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    unit_price          NUMERIC(14,4) NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    inventory_item_id   UUID NULL,                     -- links to items.item_id if Inventory module is installed
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

CREATE INDEX IF NOT EXISTS idx_products_company ON sales.products(company_id);
CREATE INDEX IF NOT EXISTS idx_products_inventory_item ON sales.products(inventory_item_id) WHERE inventory_item_id IS NOT NULL;

-- -----------------------------------------------------
-- ORDERS (with idempotency external_ref)
-- -----------------------------------------------------
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
    confirmed_at       TIMESTAMPTZ,
    shipped_at         TIMESTAMPTZ,
    delivered_at       TIMESTAMPTZ,
    cancelled_at       TIMESTAMPTZ,
    cancellation_reason TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID,
    updated_by         UUID,
    CONSTRAINT fk_orders_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES sales.customers(customer_id),
    CONSTRAINT fk_orders_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_orders_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, order_number)
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_orders_external_ref
    ON sales.orders (company_id, external_ref)
    WHERE external_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_orders_company ON sales.orders(company_id);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON sales.orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_date ON sales.orders(order_date);
CREATE INDEX IF NOT EXISTS idx_orders_status ON sales.orders(status);

-- -----------------------------------------------------
-- ORDER ITEMS
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_order_items_order ON sales.order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_order_items_product ON sales.order_items(product_id);

-- -----------------------------------------------------
-- INVOICES
-- -----------------------------------------------------
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
    CONSTRAINT fk_invoices_created_by FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_invoices_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL,
    UNIQUE (company_id, invoice_number)
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_invoices_external_ref
    ON sales.invoices (company_id, external_ref)
    WHERE external_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_invoices_company ON sales.invoices(company_id);
CREATE INDEX IF NOT EXISTS idx_invoices_customer ON sales.invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_order ON sales.invoices(order_id);
CREATE INDEX IF NOT EXISTS idx_invoices_date ON sales.invoices(invoice_date);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON sales.invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_due ON sales.invoices(due_date) WHERE status NOT IN ('paid', 'cancelled');

-- -----------------------------------------------------
-- INVOICE ITEMS
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice ON sales.invoice_items(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invoice_items_product ON sales.invoice_items(product_id) WHERE product_id IS NOT NULL;

-- -----------------------------------------------------
-- PAYMENTS
-- -----------------------------------------------------
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

CREATE UNIQUE INDEX IF NOT EXISTS uniq_payments_external_ref
    ON sales.payments (company_id, external_ref)
    WHERE external_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_payments_company ON sales.payments(company_id);
CREATE INDEX IF NOT EXISTS idx_payments_status ON sales.payments(status);
CREATE INDEX IF NOT EXISTS idx_payments_date ON sales.payments(payment_date);

-- -----------------------------------------------------
-- PAYMENT ALLOCATIONS
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS sales.payment_allocations (
    allocation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_id           UUID NOT NULL,
    invoice_id           UUID NOT NULL,
    amount               NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_alloc_payment FOREIGN KEY (payment_id) REFERENCES sales.payments(payment_id) ON DELETE CASCADE,
    CONSTRAINT fk_alloc_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_payment_allocations_payment ON sales.payment_allocations(payment_id);
CREATE INDEX IF NOT EXISTS idx_payment_allocations_invoice ON sales.payment_allocations(invoice_id);

-- -----------------------------------------------------
-- RETURNS
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_returns_company ON sales.returns(company_id);
CREATE INDEX IF NOT EXISTS idx_returns_order ON sales.returns(order_id);
CREATE INDEX IF NOT EXISTS idx_returns_status ON sales.returns(status);

-- -----------------------------------------------------
-- RETURN ITEMS
-- -----------------------------------------------------
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
    CONSTRAINT fk_return_items_return FOREIGN KEY (return_id) REFERENCES sales.returns(return_id) ON DELETE CASCADE,
    CONSTRAINT fk_return_items_order_item FOREIGN KEY (order_item_id) REFERENCES sales.order_items(order_item_id) ON DELETE SET NULL,
    CONSTRAINT fk_return_items_product FOREIGN KEY (product_id) REFERENCES sales.products(product_id)
);

CREATE INDEX IF NOT EXISTS idx_return_items_return ON sales.return_items(return_id);
CREATE INDEX IF NOT EXISTS idx_return_items_product ON sales.return_items(product_id);

-- -----------------------------------------------------
-- COUPONS
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_coupons_company ON sales.coupons(company_id);
CREATE INDEX IF NOT EXISTS idx_coupons_code ON sales.coupons(code);
CREATE INDEX IF NOT EXISTS idx_coupons_dates ON sales.coupons(start_date, end_date) WHERE is_active = true;

-- -----------------------------------------------------
-- COUPON USAGES
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_coupon_usages_coupon ON sales.coupon_usages(coupon_id);
CREATE INDEX IF NOT EXISTS idx_coupon_usages_customer ON sales.coupon_usages(customer_id);

-- -----------------------------------------------------
-- PROMOTIONS
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_promotions_company ON sales.promotions(company_id);
CREATE INDEX IF NOT EXISTS idx_promotions_dates ON sales.promotions(start_date, end_date) WHERE is_active = true;

-- -----------------------------------------------------
-- PROMOTION RULES
-- -----------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_promotion_rules_promotion ON sales.promotion_rules(promotion_id);

-- -----------------------------------------------------
-- DISCOUNT APPLICATIONS
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS sales.discount_applications (
    application_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id             UUID,
    invoice_id           UUID,
    discount_type        VARCHAR(50) NOT NULL,
    discount_id          UUID,
    discount_name        VARCHAR(255),
    amount               NUMERIC(14,4) NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_discount_applications_order FOREIGN KEY (order_id) REFERENCES sales.orders(order_id) ON DELETE CASCADE,
    CONSTRAINT fk_discount_applications_invoice FOREIGN KEY (invoice_id) REFERENCES sales.invoices(invoice_id) ON DELETE CASCADE,
    CHECK ((order_id IS NOT NULL AND invoice_id IS NULL) OR (order_id IS NULL AND invoice_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_discount_applications_order ON sales.discount_applications(order_id) WHERE order_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_discount_applications_invoice ON sales.discount_applications(invoice_id) WHERE invoice_id IS NOT NULL;

-- -----------------------------------------------------
-- TAX SNAPSHOTS
-- -----------------------------------------------------
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
    -- optional FK to accounting.tax_rates if that schema exists
);

CREATE INDEX IF NOT EXISTS idx_tax_snapshots_entity ON sales.tax_snapshots(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_tax_snapshots_line ON sales.tax_snapshots(line_id) WHERE line_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tax_snapshots_company ON sales.tax_snapshots(company_id);

-- =====================================================
-- TRIGGERS & FUNCTIONS
-- =====================================================
CREATE OR REPLACE FUNCTION sales.update_invoice_paid_amount()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE sales.invoices
    SET amount_paid = COALESCE(
        (SELECT SUM(amount) FROM sales.payment_allocations pa
         JOIN sales.payments p ON pa.payment_id = p.payment_id
         WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'),
        0
    ),
    amount_due = grand_total - COALESCE(
        (SELECT SUM(amount) FROM sales.payment_allocations pa
         JOIN sales.payments p ON pa.payment_id = p.payment_id
         WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'),
        0
    ),
    status = CASE
        WHEN COALESCE((SELECT SUM(amount) FROM sales.payment_allocations pa
                       JOIN sales.payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) >= grand_total THEN 'paid'
        WHEN COALESCE((SELECT SUM(amount) FROM sales.payment_allocations pa
                       JOIN sales.payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) > 0 THEN 'issued'
        ELSE status
    END,
    paid_at = CASE
        WHEN COALESCE((SELECT SUM(amount) FROM sales.payment_allocations pa
                       JOIN sales.payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) >= grand_total THEN NOW()
        ELSE paid_at
    END,
    updated_at = NOW()
    WHERE invoice_id = NEW.invoice_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_invoice_paid_amount
    AFTER INSERT OR UPDATE ON sales.payment_allocations
    FOR EACH ROW
    EXECUTE FUNCTION sales.update_invoice_paid_amount();

CREATE OR REPLACE FUNCTION sales.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_customers_updated_at BEFORE UPDATE ON sales.customers FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON sales.products FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON sales.orders FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_invoices_updated_at BEFORE UPDATE ON sales.invoices FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_payments_updated_at BEFORE UPDATE ON sales.payments FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_returns_updated_at BEFORE UPDATE ON sales.returns FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_coupons_updated_at BEFORE UPDATE ON sales.coupons FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();
CREATE TRIGGER update_promotions_updated_at BEFORE UPDATE ON sales.promotions FOR EACH ROW EXECUTE FUNCTION sales.update_updated_at_column();

-- =====================================================
-- ADDITIONAL INDEXES (not already covered)
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_orders_number ON sales.orders(company_id, order_number);
CREATE INDEX IF NOT EXISTS idx_orders_ext ON sales.orders(company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_invoices_ext ON sales.invoices(company_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_payments_ext ON sales.payments(company_id, external_ref) WHERE external_ref IS NOT NULL;