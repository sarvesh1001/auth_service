-- =====================================================
-- SALES MODULE SCHEMA (ENTERPRISE READY)
-- =====================================================

-- -----------------------------------------------------
-- ENUMS
-- -----------------------------------------------------
CREATE TYPE order_status AS ENUM ('draft', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded');
CREATE TYPE invoice_status AS ENUM ('draft', 'issued', 'paid', 'overdue', 'cancelled', 'credited');
CREATE TYPE payment_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'refunded', 'partially_refunded');
CREATE TYPE payment_method AS ENUM ('cash', 'card', 'bank_transfer', 'digital_wallet', 'coupon', 'other');
CREATE TYPE discount_type AS ENUM ('percentage', 'fixed_amount', 'buy_x_get_y');

-- -----------------------------------------------------
-- CUSTOMERS
-- -----------------------------------------------------
CREATE TABLE customers (
    customer_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    customer_code    VARCHAR(50) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    email            VARCHAR(255),
    phone            VARCHAR(50),
    tax_id           VARCHAR(100),
    billing_address  JSONB,
    shipping_address JSONB,
    credit_limit     NUMERIC(14,2) DEFAULT 0,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_customers_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_customers_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_customers_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, customer_code),
    UNIQUE (company_id, email)
);

CREATE UNIQUE INDEX uniq_customers_active_email
ON customers (company_id, email)
WHERE email IS NOT NULL;

-- -----------------------------------------------------
-- ORDERS (with idempotency external_ref)
-- -----------------------------------------------------
CREATE TABLE orders (
    order_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    customer_id      UUID NOT NULL,
    order_number     VARCHAR(50) NOT NULL,
    external_ref     VARCHAR(100),
    order_date       DATE NOT NULL,
    status           order_status NOT NULL DEFAULT 'draft',
    currency         VARCHAR(3) NOT NULL DEFAULT 'USD',
    subtotal         NUMERIC(14,4) NOT NULL DEFAULT 0,
    discount_total   NUMERIC(14,4) NOT NULL DEFAULT 0,
    tax_total        NUMERIC(14,4) NOT NULL DEFAULT 0,
    grand_total      NUMERIC(14,4) GENERATED ALWAYS AS (subtotal - discount_total + tax_total) STORED,
    notes            TEXT,
    shipping_address JSONB,
    billing_address  JSONB,
    confirmed_at     TIMESTAMPTZ,
    shipped_at       TIMESTAMPTZ,
    delivered_at     TIMESTAMPTZ,
    cancelled_at     TIMESTAMPTZ,
    cancellation_reason TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_orders_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    CONSTRAINT fk_orders_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_orders_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, order_number)
);

CREATE UNIQUE INDEX uniq_orders_external_ref
ON orders (company_id, external_ref)
WHERE external_ref IS NOT NULL;

-- -----------------------------------------------------
-- ORDER ITEMS
-- -----------------------------------------------------
CREATE TABLE order_items (
    order_item_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id         UUID NOT NULL,
    item_id          UUID NOT NULL,
    item_name_snapshot VARCHAR(255) NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price       NUMERIC(14,4) NOT NULL,
    discount_amount  NUMERIC(14,4) DEFAULT 0,
    tax_amount       NUMERIC(14,4) DEFAULT 0,
    total_price      NUMERIC(14,4) GENERATED ALWAYS AS ((unit_price * quantity) - discount_amount + tax_amount) STORED,
    metadata         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
    CONSTRAINT fk_order_items_item FOREIGN KEY (item_id) REFERENCES items(item_id)
);

-- -----------------------------------------------------
-- INVOICES (with idempotency, locking, exchange rate)
-- -----------------------------------------------------
CREATE TABLE invoices (
    invoice_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    order_id         UUID,
    customer_id      UUID NOT NULL,
    invoice_number   VARCHAR(50) NOT NULL,
    external_ref     VARCHAR(100),
    invoice_date     DATE NOT NULL,
    due_date         DATE NOT NULL,
    status           invoice_status NOT NULL DEFAULT 'draft',
    currency         VARCHAR(3) NOT NULL DEFAULT 'USD',
    exchange_rate    NUMERIC(14,6) DEFAULT 1,
    subtotal         NUMERIC(14,4) NOT NULL DEFAULT 0,
    discount_total   NUMERIC(14,4) NOT NULL DEFAULT 0,
    tax_total        NUMERIC(14,4) NOT NULL DEFAULT 0,
    grand_total      NUMERIC(14,4) GENERATED ALWAYS AS (subtotal - discount_total + tax_total) STORED,
    amount_paid      NUMERIC(14,4) NOT NULL DEFAULT 0,
    amount_due       NUMERIC(14,4) NOT NULL DEFAULT 0,   -- now a regular column
    notes            TEXT,
    is_locked        BOOLEAN DEFAULT false,
    issued_at        TIMESTAMPTZ,
    paid_at          TIMESTAMPTZ,
    cancelled_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_invoices_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_invoices_order FOREIGN KEY (order_id) REFERENCES orders(order_id),
    CONSTRAINT fk_invoices_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    CONSTRAINT fk_invoices_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_invoices_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, invoice_number)
);

CREATE UNIQUE INDEX uniq_invoices_external_ref
ON invoices (company_id, external_ref)
WHERE external_ref IS NOT NULL;

-- -----------------------------------------------------
-- INVOICE ITEMS
-- -----------------------------------------------------
CREATE TABLE invoice_items (
    invoice_item_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id       UUID NOT NULL,
    item_id          UUID,
    item_name_snapshot VARCHAR(255) NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price       NUMERIC(14,4) NOT NULL,
    discount_amount  NUMERIC(14,4) DEFAULT 0,
    tax_amount       NUMERIC(14,4) DEFAULT 0,
    total_price      NUMERIC(14,4) GENERATED ALWAYS AS ((unit_price * quantity) - discount_amount + tax_amount) STORED,
    metadata         JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_invoice_items_invoice FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id) ON DELETE CASCADE,
    CONSTRAINT fk_invoice_items_item FOREIGN KEY (item_id) REFERENCES items(item_id)
);

-- -----------------------------------------------------
-- PAYMENTS (no direct invoice_id, use allocations)
-- -----------------------------------------------------
CREATE TABLE payments (
    payment_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    payment_number   VARCHAR(50) NOT NULL,
    external_ref     VARCHAR(100),
    payment_date     DATE NOT NULL,
    amount           NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    payment_method   payment_method NOT NULL,
    status           payment_status NOT NULL DEFAULT 'pending',
    exchange_rate    NUMERIC(14,6) DEFAULT 1,
    reference        VARCHAR(100),
    gateway_response JSONB,
    failure_reason   TEXT,
    completed_at     TIMESTAMPTZ,
    refunded_amount  NUMERIC(14,4) DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_payments_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_payments_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_payments_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, payment_number)
);

CREATE UNIQUE INDEX uniq_payments_external_ref
ON payments (company_id, external_ref)
WHERE external_ref IS NOT NULL;

-- -----------------------------------------------------
-- PAYMENT ALLOCATIONS
-- -----------------------------------------------------
CREATE TABLE payment_allocations (
    allocation_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_id       UUID NOT NULL,
    invoice_id       UUID NOT NULL,
    amount           NUMERIC(14,4) NOT NULL CHECK (amount > 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_alloc_payment FOREIGN KEY (payment_id) REFERENCES payments(payment_id) ON DELETE CASCADE,
    CONSTRAINT fk_alloc_invoice FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id)
);

-- -----------------------------------------------------
-- RETURNS (with credit note linkage)
-- -----------------------------------------------------
CREATE TABLE returns (
    return_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    order_id         UUID NOT NULL,
    invoice_id       UUID,
    credit_note_id   UUID,
    return_number    VARCHAR(50) NOT NULL,
    return_date      DATE NOT NULL,
    reason           TEXT,
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    total_refund     NUMERIC(14,4) NOT NULL DEFAULT 0,
    approved_at      TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_returns_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_returns_order FOREIGN KEY (order_id) REFERENCES orders(order_id),
    CONSTRAINT fk_returns_invoice FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id),
    CONSTRAINT fk_returns_credit_note FOREIGN KEY (credit_note_id) REFERENCES invoices(invoice_id),
    CONSTRAINT fk_returns_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_returns_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, return_number)
);

-- -----------------------------------------------------
-- RETURN ITEMS
-- -----------------------------------------------------
CREATE TABLE return_items (
    return_item_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    return_id        UUID NOT NULL,
    order_item_id    UUID,
    item_id          UUID NOT NULL,
    item_name_snapshot VARCHAR(255) NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    unit_price       NUMERIC(14,4) NOT NULL,
    refund_amount    NUMERIC(14,4) NOT NULL,
    reason           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_return_items_return FOREIGN KEY (return_id) REFERENCES returns(return_id) ON DELETE CASCADE,
    CONSTRAINT fk_return_items_order_item FOREIGN KEY (order_item_id) REFERENCES order_items(order_item_id),
    CONSTRAINT fk_return_items_item FOREIGN KEY (item_id) REFERENCES items(item_id)
);

-- -----------------------------------------------------
-- COUPONS
-- -----------------------------------------------------
CREATE TABLE coupons (
    coupon_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    code             VARCHAR(100) NOT NULL,
    discount_type    discount_type NOT NULL,
    discount_value   NUMERIC(14,4) NOT NULL,
    max_discount_amount NUMERIC(14,4),
    start_date       TIMESTAMPTZ NOT NULL,
    end_date         TIMESTAMPTZ NOT NULL,
    usage_limit      INT,
    per_user_limit   INT DEFAULT 1,
    min_order_amount NUMERIC(14,4),
    applicable_items JSONB,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_coupons_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_coupons_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_coupons_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, code)
);

-- -----------------------------------------------------
-- COUPON USAGES
-- -----------------------------------------------------
CREATE TABLE coupon_usages (
    usage_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_id        UUID NOT NULL,
    customer_id      UUID NOT NULL,
    order_id         UUID NOT NULL,
    discount_amount  NUMERIC(14,4) NOT NULL,
    used_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_coupon_usage_coupon FOREIGN KEY (coupon_id) REFERENCES coupons(coupon_id),
    CONSTRAINT fk_coupon_usage_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id),
    CONSTRAINT fk_coupon_usage_order FOREIGN KEY (order_id) REFERENCES orders(order_id),
    UNIQUE (coupon_id, customer_id, order_id)
);

-- -----------------------------------------------------
-- PROMOTIONS
-- -----------------------------------------------------
CREATE TABLE promotions (
    promotion_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    start_date       TIMESTAMPTZ NOT NULL,
    end_date         TIMESTAMPTZ NOT NULL,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    priority         INT DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_promotions_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_promotions_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_promotions_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- -----------------------------------------------------
-- PROMOTION RULES
-- -----------------------------------------------------
CREATE TABLE promotion_rules (
    rule_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    promotion_id     UUID NOT NULL,
    rule_type        VARCHAR(50) NOT NULL,
    rule_config      JSONB NOT NULL,
    discount_type    discount_type NOT NULL,
    discount_value   NUMERIC(14,4) NOT NULL,
    max_discount     NUMERIC(14,4),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_promotion_rules_promotion FOREIGN KEY (promotion_id) REFERENCES promotions(promotion_id) ON DELETE CASCADE
);

-- -----------------------------------------------------
-- DISCOUNT APPLICATIONS
-- -----------------------------------------------------
CREATE TABLE discount_applications (
    application_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id         UUID,
    invoice_id       UUID,
    discount_type    VARCHAR(50) NOT NULL,
    discount_id      UUID,
    discount_name    VARCHAR(255),
    amount           NUMERIC(14,4) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_discount_applications_order FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
    CONSTRAINT fk_discount_applications_invoice FOREIGN KEY (invoice_id) REFERENCES invoices(invoice_id) ON DELETE CASCADE,
    CHECK ((order_id IS NOT NULL AND invoice_id IS NULL) OR (order_id IS NULL AND invoice_id IS NOT NULL))
);

-- -----------------------------------------------------
-- TAX SNAPSHOTS
-- -----------------------------------------------------
CREATE TABLE tax_snapshots (
    tax_snapshot_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    entity_type      VARCHAR(20) NOT NULL,
    entity_id        UUID NOT NULL,
    line_id          UUID,
    tax_rate_id      UUID,
    tax_name         VARCHAR(100),
    tax_percentage   NUMERIC(5,2),
    taxable_amount   NUMERIC(14,4) NOT NULL,
    tax_amount       NUMERIC(14,4) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_tax_snapshots_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_tax_snapshots_rate FOREIGN KEY (tax_rate_id) REFERENCES accounting.tax_rates(tax_rate_id)
);

-- =====================================================
-- TRIGGERS & FUNCTIONS
-- =====================================================
CREATE OR REPLACE FUNCTION update_invoice_paid_amount()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE invoices
    SET amount_paid = COALESCE(
        (SELECT SUM(amount) FROM payment_allocations pa
         JOIN payments p ON pa.payment_id = p.payment_id
         WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'),
        0
    ),
    amount_due = grand_total - COALESCE(   -- new line
        (SELECT SUM(amount) FROM payment_allocations pa
         JOIN payments p ON pa.payment_id = p.payment_id
         WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'),
        0
    ),
    status = CASE
        WHEN COALESCE((SELECT SUM(amount) FROM payment_allocations pa
                       JOIN payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) >= grand_total THEN 'paid'
        WHEN COALESCE((SELECT SUM(amount) FROM payment_allocations pa
                       JOIN payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) > 0 THEN 'issued'
        ELSE status
    END,
    paid_at = CASE
        WHEN COALESCE((SELECT SUM(amount) FROM payment_allocations pa
                       JOIN payments p ON pa.payment_id = p.payment_id
                       WHERE pa.invoice_id = NEW.invoice_id AND p.status = 'completed'), 0) >= grand_total THEN NOW()
        ELSE paid_at
    END,
    updated_at = NOW()
    WHERE invoice_id = NEW.invoice_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_invoice_paid_amount
    AFTER INSERT OR UPDATE ON payment_allocations
    FOR EACH ROW
    EXECUTE FUNCTION update_invoice_paid_amount();

-- =====================================================
-- INDEXES
-- =====================================================
CREATE INDEX idx_customers_company ON customers(company_id);
CREATE INDEX idx_customers_email ON customers(email) WHERE email IS NOT NULL;
CREATE INDEX idx_customers_code ON customers(company_id, customer_code);

CREATE INDEX idx_orders_company ON orders(company_id);
CREATE INDEX idx_orders_customer ON orders(customer_id);
CREATE INDEX idx_orders_date ON orders(order_date);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_number ON orders(company_id, order_number);
CREATE INDEX idx_orders_ext ON orders(company_id, external_ref) WHERE external_ref IS NOT NULL;

CREATE INDEX idx_order_items_order ON order_items(order_id);
CREATE INDEX idx_order_items_item ON order_items(item_id);

CREATE INDEX idx_invoices_company ON invoices(company_id);
CREATE INDEX idx_invoices_customer ON invoices(customer_id);
CREATE INDEX idx_invoices_order ON invoices(order_id);
CREATE INDEX idx_invoices_date ON invoices(invoice_date);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_invoices_due ON invoices(due_date) WHERE status NOT IN ('paid', 'cancelled');
CREATE INDEX idx_invoices_ext ON invoices(company_id, external_ref) WHERE external_ref IS NOT NULL;

CREATE INDEX idx_invoice_items_invoice ON invoice_items(invoice_id);

CREATE INDEX idx_payments_company ON payments(company_id);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_date ON payments(payment_date);
CREATE INDEX idx_payments_ext ON payments(company_id, external_ref) WHERE external_ref IS NOT NULL;

CREATE INDEX idx_payment_allocations_payment ON payment_allocations(payment_id);
CREATE INDEX idx_payment_allocations_invoice ON payment_allocations(invoice_id);

CREATE INDEX idx_returns_company ON returns(company_id);
CREATE INDEX idx_returns_order ON returns(order_id);
CREATE INDEX idx_returns_status ON returns(status);

CREATE INDEX idx_return_items_return ON return_items(return_id);

CREATE INDEX idx_coupons_company ON coupons(company_id);
CREATE INDEX idx_coupons_code ON coupons(code);
CREATE INDEX idx_coupons_dates ON coupons(start_date, end_date) WHERE is_active = true;

CREATE INDEX idx_coupon_usages_coupon ON coupon_usages(coupon_id);
CREATE INDEX idx_coupon_usages_customer ON coupon_usages(customer_id);

CREATE INDEX idx_promotions_company ON promotions(company_id);
CREATE INDEX idx_promotions_dates ON promotions(start_date, end_date) WHERE is_active = true;

CREATE INDEX idx_promotion_rules_promotion ON promotion_rules(promotion_id);

CREATE INDEX idx_discount_applications_order ON discount_applications(order_id) WHERE order_id IS NOT NULL;
CREATE INDEX idx_discount_applications_invoice ON discount_applications(invoice_id) WHERE invoice_id IS NOT NULL;

CREATE INDEX idx_tax_snapshots_entity ON tax_snapshots(entity_type, entity_id);
CREATE INDEX idx_tax_snapshots_line ON tax_snapshots(line_id) WHERE line_id IS NOT NULL;
CREATE INDEX idx_tax_snapshots_company ON tax_snapshots(company_id);

-- =====================================================
-- UPDATED AT TRIGGERS
-- =====================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_customers_updated_at BEFORE UPDATE ON customers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_invoices_updated_at BEFORE UPDATE ON invoices FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_payments_updated_at BEFORE UPDATE ON payments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_returns_updated_at BEFORE UPDATE ON returns FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_coupons_updated_at BEFORE UPDATE ON coupons FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_promotions_updated_at BEFORE UPDATE ON promotions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


