-- =====================================================
-- INVENTORY MANAGEMENT SCHEMA (PRODUCTION READY)
-- =====================================================

-- -----------------------------------------------------
-- ENUMS
-- -----------------------------------------------------
CREATE TYPE item_type AS ENUM ('raw_material', 'finished_good', 'sub_assembly', 'consumable', 'service');
CREATE TYPE movement_type AS ENUM ('purchase_in', 'sales_out', 'production_in', 'return_in', 'return_out', 'adjustment_in', 'adjustment_out', 'transfer');
CREATE TYPE valuation_method AS ENUM ('fifo', 'lifo', 'weighted_average', 'standard_cost');

-- -----------------------------------------------------
-- ITEMS
-- -----------------------------------------------------
CREATE TABLE items (
    item_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    sku              VARCHAR(100) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    item_type        item_type NOT NULL,
    unit_of_measure  VARCHAR(20) NOT NULL,
    valuation_method valuation_method NOT NULL DEFAULT 'weighted_average',
    standard_cost    NUMERIC(14,4) DEFAULT 0,
    selling_price    NUMERIC(14,4) DEFAULT 0,
    reorder_level    NUMERIC(14,4) DEFAULT 0,
    reorder_quantity NUMERIC(14,4) DEFAULT 0,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_items_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_items_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_items_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, sku)
);

-- -----------------------------------------------------
-- WAREHOUSES
-- -----------------------------------------------------
CREATE TABLE warehouses (
    warehouse_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    code             VARCHAR(50) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    location         TEXT,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_warehouses_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_warehouses_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_warehouses_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, code)
);

-- -----------------------------------------------------
-- BATCHES
-- -----------------------------------------------------
CREATE TABLE batches (
    batch_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    item_id          UUID NOT NULL,
    batch_number     VARCHAR(100) NOT NULL,
    supplier_batch   VARCHAR(100),
    manufactured_date DATE,
    expiry_date      DATE,
    received_date    DATE,
    quantity         NUMERIC(14,4) NOT NULL,
    remaining_qty    NUMERIC(14,4) NOT NULL,
    cost_per_unit    NUMERIC(14,4) NOT NULL,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_batches_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_batches_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_batches_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_batches_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, item_id, batch_number)
);

-- -----------------------------------------------------
-- STOCK BALANCES
-- -----------------------------------------------------
CREATE TABLE stock_balances (
    stock_balance_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    warehouse_id     UUID NOT NULL,
    item_id          UUID NOT NULL,
    batch_id         UUID,
    quantity_on_hand NUMERIC(14,4) NOT NULL DEFAULT 0,
    reserved_qty     NUMERIC(14,4) NOT NULL DEFAULT 0,
    available_qty    NUMERIC(14,4) GENERATED ALWAYS AS (quantity_on_hand - reserved_qty) STORED,
    last_movement_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_stock_balances_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_stock_balances_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_stock_balances_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_stock_balances_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    UNIQUE (company_id, warehouse_id, item_id, batch_id)
);

-- -----------------------------------------------------
-- STOCK MOVEMENTS
-- -----------------------------------------------------
CREATE TABLE stock_movements (
    movement_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    movement_type    movement_type NOT NULL,
    reference_type   VARCHAR(50),
    reference_id     UUID,
    movement_date    DATE NOT NULL,
    warehouse_id     UUID NOT NULL,
    from_warehouse_id UUID,
    item_id          UUID NOT NULL,
    batch_id         UUID,
    quantity_in      NUMERIC(14,4) NOT NULL DEFAULT 0,
    quantity_out     NUMERIC(14,4) NOT NULL DEFAULT 0,
    unit_cost        NUMERIC(14,4) NOT NULL,
    total_cost       NUMERIC(14,4) GENERATED ALWAYS AS (
        CASE 
            WHEN quantity_in > 0 THEN quantity_in * unit_cost
            ELSE quantity_out * unit_cost
        END
    ) STORED,
    reason           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    CONSTRAINT fk_movements_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_movements_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_movements_from_warehouse FOREIGN KEY (from_warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_movements_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_movements_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_movements_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT check_qty_direction CHECK (
        (quantity_in > 0 AND quantity_out = 0) OR
        (quantity_out > 0 AND quantity_in = 0)
    ),
    CONSTRAINT unique_movement_source UNIQUE (
        company_id, reference_type, reference_id, item_id, warehouse_id, batch_id
    )
);

-- -----------------------------------------------------
-- STOCK LEDGER (FIFO layers) - ADDED warehouse_id
-- -----------------------------------------------------
CREATE TABLE stock_ledger (
    ledger_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    warehouse_id     UUID,                              -- NEW column
    item_id          UUID NOT NULL,
    batch_id         UUID,
    movement_id      UUID NOT NULL,
    transaction_date DATE NOT NULL,
    quantity_in      NUMERIC(14,4) DEFAULT 0,
    quantity_out     NUMERIC(14,4) DEFAULT 0,
    unit_cost        NUMERIC(14,4) NOT NULL,
    running_balance  NUMERIC(14,4) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ledger_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_ledger_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),  -- NEW FK
    CONSTRAINT fk_ledger_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_ledger_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_ledger_movement FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id)
);

-- -----------------------------------------------------
-- STOCK ALLOCATIONS
-- -----------------------------------------------------
CREATE TABLE stock_allocations (
    allocation_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    movement_id      UUID NOT NULL,
    source_ledger_id UUID NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL,
    unit_cost        NUMERIC(14,4) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_allocations_movement FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id),
    CONSTRAINT fk_allocations_source_ledger FOREIGN KEY (source_ledger_id) REFERENCES stock_ledger(ledger_id),
    CONSTRAINT check_allocation_quantity CHECK (quantity > 0)
);

-- -----------------------------------------------------
-- RESERVATIONS - ADDED status CHECK constraint
-- -----------------------------------------------------
CREATE TABLE reservations (
    reservation_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    reservation_type VARCHAR(50) NOT NULL,
    reference_id     UUID NOT NULL,
    warehouse_id     UUID NOT NULL,
    item_id          UUID NOT NULL,
    batch_id         UUID,
    quantity         NUMERIC(14,4) NOT NULL,
    status           VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ,
    created_by       UUID,
    fulfilled_at     TIMESTAMPTZ,
    cancelled_at     TIMESTAMPTZ,
    CONSTRAINT fk_reservations_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_reservations_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_reservations_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_reservations_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_reservations_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT check_reservation_positive CHECK (quantity > 0),
    CONSTRAINT check_reservation_status CHECK (status IN ('active', 'fulfilled', 'cancelled'))  -- NEW constraint
);

-- -----------------------------------------------------
-- BILL OF MATERIALS (BOM)
-- -----------------------------------------------------
CREATE TABLE boms (
    bom_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    product_item_id  UUID NOT NULL,
    bom_code         VARCHAR(100) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    version          INT NOT NULL DEFAULT 1,
    quantity         NUMERIC(14,4) NOT NULL DEFAULT 1,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    CONSTRAINT fk_boms_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_boms_product FOREIGN KEY (product_item_id) REFERENCES items(item_id),
    CONSTRAINT fk_boms_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_boms_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, product_item_id, version)
);

CREATE TABLE bom_items (
    bom_item_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bom_id           UUID NOT NULL,
    component_item_id UUID NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL,
    scrap_percentage NUMERIC(5,2) DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_bom_items_bom FOREIGN KEY (bom_id) REFERENCES boms(bom_id) ON DELETE CASCADE,
    CONSTRAINT fk_bom_items_component FOREIGN KEY (component_item_id) REFERENCES items(item_id)
);

-- -----------------------------------------------------
-- VALUATION SNAPSHOTS
-- -----------------------------------------------------
CREATE TABLE inventory_valuations (
    valuation_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    valuation_date   DATE NOT NULL,
    item_id          UUID NOT NULL,
    warehouse_id     UUID,
    quantity         NUMERIC(14,4) NOT NULL,
    unit_cost        NUMERIC(14,4) NOT NULL,
    total_value      NUMERIC(14,4) GENERATED ALWAYS AS (quantity * unit_cost) STORED,
    valuation_method valuation_method NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_valuations_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_valuations_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_valuations_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
);

-- =====================================================
-- TRIGGER: update stock_balances
-- =====================================================
CREATE OR REPLACE FUNCTION update_stock_balance_on_movement()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO stock_balances (
        company_id, warehouse_id, item_id, batch_id,
        quantity_on_hand, last_movement_at
    )
    VALUES (
        NEW.company_id,
        NEW.warehouse_id,
        NEW.item_id,
        NEW.batch_id,
        (NEW.quantity_in - NEW.quantity_out),
        NEW.movement_date
    )
    ON CONFLICT (company_id, warehouse_id, item_id, batch_id)
    DO UPDATE
    SET quantity_on_hand = stock_balances.quantity_on_hand + (EXCLUDED.quantity_on_hand),
        last_movement_at = EXCLUDED.last_movement_at,
        updated_at = NOW();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_stock_balance
    AFTER INSERT ON stock_movements
    FOR EACH ROW
    EXECUTE FUNCTION update_stock_balance_on_movement();

-- =====================================================
-- INDEXES (performance)
-- =====================================================
CREATE INDEX idx_items_company_sku ON items(company_id, sku);
CREATE INDEX idx_items_type ON items(item_type);
CREATE INDEX idx_warehouses_company_code ON warehouses(company_id, code);
CREATE INDEX idx_batches_item ON batches(item_id);
CREATE INDEX idx_batches_expiry ON batches(expiry_date) WHERE expiry_date IS NOT NULL;
CREATE INDEX idx_stock_balances_lookup ON stock_balances(company_id, warehouse_id, item_id, batch_id);
CREATE INDEX idx_stock_balances_available ON stock_balances(company_id, item_id) WHERE available_qty > 0;
CREATE INDEX idx_movements_reference ON stock_movements(reference_type, reference_id);
CREATE INDEX idx_movements_date ON stock_movements(movement_date);
CREATE INDEX idx_ledger_item ON stock_ledger(item_id, transaction_date);
CREATE INDEX idx_ledger_warehouse ON stock_ledger(warehouse_id);  -- NEW index for warehouse
CREATE INDEX idx_allocations_movement ON stock_allocations(movement_id);
CREATE INDEX idx_allocations_source ON stock_allocations(source_ledger_id);
CREATE INDEX idx_reservations_active ON reservations(company_id, warehouse_id, item_id) WHERE status = 'active';
CREATE INDEX idx_boms_product ON boms(product_item_id, is_active);
CREATE INDEX idx_valuations_date ON inventory_valuations(valuation_date);