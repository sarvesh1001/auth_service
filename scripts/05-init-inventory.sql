-- =====================================================
-- INVENTORY MANAGEMENT SCHEMA (v7 – production-grade uniqueness)
-- =====================================================

-- ENUMS
DO $$ BEGIN
    CREATE TYPE item_type AS ENUM ('raw_material', 'finished_good', 'sub_assembly', 'consumable', 'service');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE movement_type AS ENUM ('purchase_in', 'sales_out', 'production_in', 'return_in', 'return_out', 'adjustment_in', 'adjustment_out','production_out', 'transfer' , 'production_scrap');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE valuation_method AS ENUM ('fifo', 'lifo', 'weighted_average', 'standard_cost');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE fulfillment_policy AS ENUM (
        'inventory_required',
        'allow_backorder',
        'made_to_order',
        'dropship',
        'service_only',
        'digital_delivery',
        'external_vendor'
    );
EXCEPTION WHEN duplicate_object THEN null;
END $$;

-- ITEMS
CREATE TABLE IF NOT EXISTS items (
    item_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    sku              VARCHAR(100) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT,
    item_type        item_type NOT NULL,
    unit_of_measure  VARCHAR(20) NOT NULL,
    valuation_method valuation_method NOT NULL DEFAULT 'weighted_average',
    standard_cost    NUMERIC(14,4) DEFAULT 0 CHECK (standard_cost >= 0),
    selling_price    NUMERIC(14,4) DEFAULT 0,
    reorder_level    NUMERIC(14,4) DEFAULT 0 CHECK (reorder_level >= 0),
    reorder_quantity NUMERIC(14,4) DEFAULT 0,
    is_active        BOOLEAN NOT NULL DEFAULT true,
    last_reordered_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    updated_by       UUID,
    track_inventory  BOOLEAN NOT NULL DEFAULT true,
    allow_negative_stock BOOLEAN NOT NULL DEFAULT false,
    is_sellable      BOOLEAN NOT NULL DEFAULT true,
    is_purchasable   BOOLEAN NOT NULL DEFAULT true,
    requires_shipping BOOLEAN NOT NULL DEFAULT true,
    is_batch_tracked BOOLEAN NOT NULL DEFAULT false,
    is_serial_tracked BOOLEAN NOT NULL DEFAULT false,
    fulfillment_policy fulfillment_policy NOT NULL DEFAULT 'inventory_required',
    CONSTRAINT fk_items_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_items_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_items_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    UNIQUE (company_id, sku)
);

-- INVENTORY LOCATIONS
CREATE TABLE IF NOT EXISTS inventory_locations (
    location_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    location_type VARCHAR(50),
    parent_location_id UUID,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_inv_location_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_inv_location_parent FOREIGN KEY (parent_location_id) REFERENCES inventory_locations(location_id) ON DELETE SET NULL,
    UNIQUE(company_id, code)
);

-- WAREHOUSES
CREATE TABLE IF NOT EXISTS warehouses (
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
    is_default       BOOLEAN NOT NULL DEFAULT false,
    location_id      UUID,
    warehouse_type   VARCHAR(50),
    allow_negative_stock BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT fk_warehouses_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_warehouses_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_warehouses_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    CONSTRAINT fk_warehouse_location FOREIGN KEY (location_id) REFERENCES inventory_locations(location_id) ON DELETE SET NULL,
    UNIQUE (company_id, code)
);

-- BATCHES
CREATE TABLE IF NOT EXISTS batches (
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

-- STOCK BALANCES (with proper uniqueness)
CREATE TABLE IF NOT EXISTS stock_balances (
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
    CONSTRAINT fk_stock_balances_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id) ON DELETE SET NULL
);

-- Partial unique indexes replacing the old non-unique idx_stock_balances_lookup.
-- These enable the ON CONFLICT behaviour for both batch‑tracked and non‑batch items.
CREATE UNIQUE INDEX IF NOT EXISTS stock_balances_batch_unique
    ON stock_balances (company_id, warehouse_id, item_id, batch_id)
    WHERE batch_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS stock_balances_nobatch_unique
    ON stock_balances (company_id, warehouse_id, item_id)
    WHERE batch_id IS NULL;

-- Additional performance index for available stock queries
CREATE INDEX IF NOT EXISTS idx_stock_balances_available
    ON stock_balances(company_id, item_id) WHERE available_qty > 0;

-- STOCK MOVEMENTS
CREATE TABLE IF NOT EXISTS stock_movements (
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
    unit_cost        NUMERIC(14,4) NOT NULL CHECK (unit_cost >= 0),
    total_cost       NUMERIC(14,4) GENERATED ALWAYS AS (CASE WHEN quantity_in > 0 THEN quantity_in * unit_cost ELSE quantity_out * unit_cost END) STORED,
    reason           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    status           VARCHAR(20) NOT NULL DEFAULT 'posted',
    reservation_id   UUID,
    shipment_id      UUID,
    transfer_order_id UUID,
    CONSTRAINT fk_movements_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_movements_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_movements_from_warehouse FOREIGN KEY (from_warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_movements_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_movements_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id) ON DELETE SET NULL,
    CONSTRAINT fk_movements_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT check_qty_direction CHECK ((quantity_in > 0 AND quantity_out = 0) OR (quantity_out > 0 AND quantity_in = 0)),
    CONSTRAINT unique_movement_source UNIQUE (company_id, reference_type, reference_id, item_id, warehouse_id, batch_id),
    CONSTRAINT chk_stock_movement_status CHECK (status IN ('draft', 'reserved', 'pending', 'posted', 'cancelled'))
);

-- STOCK LEDGER
CREATE TABLE IF NOT EXISTS stock_ledger (
    ledger_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    warehouse_id     UUID,
    item_id          UUID NOT NULL,
    batch_id         UUID,
    movement_id      UUID NOT NULL,
    transaction_date DATE NOT NULL,
    quantity_in      NUMERIC(14,4) DEFAULT 0,
    quantity_out     NUMERIC(14,4) DEFAULT 0,
    unit_cost        NUMERIC(14,4) NOT NULL,
    running_balance  NUMERIC(14,4) NOT NULL,
    remaining_quantity NUMERIC(14,4),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_ledger_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_ledger_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id) ON DELETE SET NULL,
    CONSTRAINT fk_ledger_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_ledger_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id) ON DELETE SET NULL,
    CONSTRAINT fk_ledger_movement FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id) ON DELETE CASCADE
);

-- STOCK ALLOCATIONS
CREATE TABLE IF NOT EXISTS stock_allocations (
    allocation_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    movement_id      UUID NOT NULL,
    source_ledger_id UUID NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL,
    unit_cost        NUMERIC(14,4) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_allocations_movement FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id) ON DELETE CASCADE,
    CONSTRAINT fk_allocations_source_ledger FOREIGN KEY (source_ledger_id) REFERENCES stock_ledger(ledger_id),
    CONSTRAINT check_allocation_quantity CHECK (quantity > 0)
);

-- RESERVATIONS
CREATE TABLE IF NOT EXISTS reservations (
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
    fulfilled_quantity NUMERIC(14,4) DEFAULT 0,
    CONSTRAINT fk_reservations_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_reservations_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_reservations_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_reservations_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id) ON DELETE SET NULL,
    CONSTRAINT fk_reservations_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT check_reservation_positive CHECK (quantity > 0),
    CONSTRAINT reservations_status_check CHECK (status IN ('active', 'partially_fulfilled', 'fulfilled', 'cancelled', 'expired'))
);

-- FULFILLMENT ORDERS
CREATE TABLE IF NOT EXISTS fulfillment_orders (
    fulfillment_order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    reference_type VARCHAR(50) NOT NULL,
    reference_id UUID NOT NULL,
    warehouse_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_fulfillment_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_fulfillment_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
);

CREATE TABLE IF NOT EXISTS fulfillment_order_items (
    fulfillment_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fulfillment_order_id UUID NOT NULL,
    item_id UUID NOT NULL,
    ordered_qty NUMERIC(14,4) NOT NULL,
    fulfilled_qty NUMERIC(14,4) NOT NULL DEFAULT 0,
    backordered_qty NUMERIC(14,4) NOT NULL DEFAULT 0,
    CONSTRAINT fk_fulfillment_item_order FOREIGN KEY (fulfillment_order_id) REFERENCES fulfillment_orders(fulfillment_order_id) ON DELETE CASCADE,
    CONSTRAINT fk_fulfillment_item_item FOREIGN KEY (item_id) REFERENCES items(item_id)
);

-- SHIPMENTS
CREATE TABLE IF NOT EXISTS shipments (
    shipment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    fulfillment_order_id UUID NOT NULL,
    warehouse_id UUID NOT NULL,
    shipment_number VARCHAR(100) NOT NULL,
    shipment_status VARCHAR(20) NOT NULL DEFAULT 'draft',
    shipped_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_shipment_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_shipment_fulfillment FOREIGN KEY (fulfillment_order_id) REFERENCES fulfillment_orders(fulfillment_order_id),
    CONSTRAINT fk_shipment_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
);

CREATE TABLE IF NOT EXISTS shipment_items (
    shipment_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shipment_id UUID NOT NULL,
    fulfillment_item_id UUID NOT NULL,
    quantity_shipped NUMERIC(14,4) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_shipment_items_shipment FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id) ON DELETE CASCADE,
    CONSTRAINT fk_shipment_items_fulfillment_item FOREIGN KEY (fulfillment_item_id) REFERENCES fulfillment_order_items(fulfillment_item_id),
    CONSTRAINT check_shipment_quantity_positive CHECK (quantity_shipped > 0)
);

-- TRANSFER ORDERS
CREATE TABLE IF NOT EXISTS stock_transfer_orders (
    transfer_order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    transfer_number VARCHAR(100) NOT NULL,
    from_warehouse_id UUID NOT NULL,
    to_warehouse_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    dispatched_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_transfer_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_transfer_from_wh FOREIGN KEY (from_warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_transfer_to_wh FOREIGN KEY (to_warehouse_id) REFERENCES warehouses(warehouse_id)
);

CREATE TABLE IF NOT EXISTS stock_transfer_items (
    transfer_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_order_id UUID NOT NULL,
    item_id UUID NOT NULL,
    quantity NUMERIC(14,4) NOT NULL,
    CONSTRAINT fk_transfer_item_order FOREIGN KEY (transfer_order_id) REFERENCES stock_transfer_orders(transfer_order_id) ON DELETE CASCADE,
    CONSTRAINT fk_transfer_item_item FOREIGN KEY (item_id) REFERENCES items(item_id)
);

-- BOM
CREATE TABLE IF NOT EXISTS boms (
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

CREATE TABLE IF NOT EXISTS bom_items (
    bom_item_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bom_id           UUID NOT NULL,
    component_item_id UUID NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL CHECK (quantity > 0),
    scrap_percentage NUMERIC(5,2) DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_bom_items_bom FOREIGN KEY (bom_id) REFERENCES boms(bom_id) ON DELETE CASCADE,
    CONSTRAINT fk_bom_items_component FOREIGN KEY (component_item_id) REFERENCES items(item_id),
    CONSTRAINT bom_items_bom_id_component_item_id_key UNIQUE (bom_id, component_item_id),
    CONSTRAINT bom_items_scrap_nonnegative CHECK (scrap_percentage >= 0)
);

-- PRODUCTION ORDERS
CREATE TABLE IF NOT EXISTS production_orders (
    production_order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    order_number        VARCHAR(100) NOT NULL,
    product_item_id     UUID NOT NULL,
    bom_id              UUID NOT NULL,
    planned_quantity    NUMERIC(14,4) NOT NULL,
    produced_quantity   NUMERIC(14,4) NOT NULL DEFAULT 0,
    status              VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'released', 'started', 'completed', 'cancelled')),
    planned_start_date  DATE,
    planned_end_date    DATE,
    actual_start_time   TIMESTAMPTZ,
    actual_end_time     TIMESTAMPTZ,
    warehouse_id        UUID NOT NULL,
    created_by          UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_reference_type VARCHAR(50),
    source_reference_id   UUID,
    CONSTRAINT fk_prod_orders_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_prod_orders_product FOREIGN KEY (product_item_id) REFERENCES items(item_id),
    CONSTRAINT fk_prod_orders_bom FOREIGN KEY (bom_id) REFERENCES boms(bom_id),
    CONSTRAINT fk_prod_orders_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_prod_orders_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    UNIQUE (company_id, order_number)
);

CREATE TABLE IF NOT EXISTS production_order_components (
    component_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    production_order_id UUID NOT NULL,
    item_id             UUID NOT NULL,
    batch_id            UUID,
    planned_quantity    NUMERIC(14,4) NOT NULL,
    actual_quantity     NUMERIC(14,4) NOT NULL DEFAULT 0,
    movement_id         UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_prod_comp_order FOREIGN KEY (production_order_id) REFERENCES production_orders(production_order_id) ON DELETE CASCADE,
    CONSTRAINT fk_prod_comp_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_prod_comp_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_prod_comp_movement FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id)
);

CREATE TABLE IF NOT EXISTS production_metrics (
    metric_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL,
    date                 DATE NOT NULL,
    product_item_id      UUID NOT NULL,
    total_produced_qty   NUMERIC(14,4) NOT NULL DEFAULT 0,
    total_consumed_raw_qty NUMERIC(14,4) NOT NULL DEFAULT 0,
    efficiency           NUMERIC(5,2),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_prod_metrics_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_prod_metrics_product FOREIGN KEY (product_item_id) REFERENCES items(item_id),
    UNIQUE (company_id, date, product_item_id)
);

-- SERIAL NUMBERS
CREATE TABLE IF NOT EXISTS serial_numbers (
    serial_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    item_id UUID NOT NULL,
    serial_number VARCHAR(255) NOT NULL,
    warehouse_id UUID,
    batch_id UUID,
    status VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, serial_number),
    CONSTRAINT fk_serial_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_serial_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_serial_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_serial_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);

CREATE TABLE IF NOT EXISTS serial_number_transactions (
    transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_id UUID NOT NULL,
    company_id UUID NOT NULL,
    movement_id UUID,
    from_warehouse_id UUID,
    to_warehouse_id UUID,
    from_batch_id UUID,
    to_batch_id UUID,
    old_status VARCHAR(20),
    new_status VARCHAR(20),
    transaction_type VARCHAR(50) NOT NULL,
    transaction_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    notes TEXT,
    CONSTRAINT fk_serial_txn_serial FOREIGN KEY (serial_id) REFERENCES serial_numbers(serial_id) ON DELETE CASCADE,
    CONSTRAINT fk_serial_txn_movement FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id) ON DELETE SET NULL,
    CONSTRAINT fk_serial_txn_from_wh FOREIGN KEY (from_warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_serial_txn_to_wh FOREIGN KEY (to_warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_serial_txn_from_batch FOREIGN KEY (from_batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_serial_txn_to_batch FOREIGN KEY (to_batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_serial_txn_created_by FOREIGN KEY (created_by) REFERENCES users(user_id)
);

-- CYCLE COUNTS
CREATE TABLE IF NOT EXISTS inventory_cycle_counts (
    cycle_count_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    warehouse_id UUID NOT NULL,
    item_id UUID,
    location_id UUID,
    count_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'planned',
    scheduled_date DATE,
    counted_by UUID,
    counted_at TIMESTAMPTZ,
    expected_quantity NUMERIC(14,4),
    actual_quantity NUMERIC(14,4),
    variance NUMERIC(14,4) GENERATED ALWAYS AS (actual_quantity - expected_quantity) STORED,
    adjustment_movement_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_cycle_count_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_cycle_count_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_cycle_count_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_cycle_count_location FOREIGN KEY (location_id) REFERENCES inventory_locations(location_id),
    CONSTRAINT fk_cycle_count_counted_by FOREIGN KEY (counted_by) REFERENCES users(user_id),
    CONSTRAINT fk_cycle_count_adjustment FOREIGN KEY (adjustment_movement_id) REFERENCES stock_movements(movement_id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cycle_counts_unique_item_schedule
ON inventory_cycle_counts (company_id, warehouse_id, item_id, scheduled_date)
WHERE item_id IS NOT NULL;

-- PICKING LISTS
CREATE TABLE IF NOT EXISTS picking_lists (
    picking_list_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    fulfillment_order_id UUID NOT NULL,
    warehouse_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'created',
    assigned_to UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    picked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT fk_picking_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_picking_fulfillment FOREIGN KEY (fulfillment_order_id) REFERENCES fulfillment_orders(fulfillment_order_id) ON DELETE CASCADE,
    CONSTRAINT fk_picking_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_picking_assigned_to FOREIGN KEY (assigned_to) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS picking_list_items (
    picking_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    picking_list_id UUID NOT NULL,
    fulfillment_item_id UUID NOT NULL,
    ordered_qty NUMERIC(14,4) NOT NULL,
    picked_qty NUMERIC(14,4) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_picking_item_list FOREIGN KEY (picking_list_id) REFERENCES picking_lists(picking_list_id) ON DELETE CASCADE,
    CONSTRAINT fk_picking_item_fulfillment_item FOREIGN KEY (fulfillment_item_id) REFERENCES fulfillment_order_items(fulfillment_item_id)
);

-- PACKING LISTS
CREATE TABLE IF NOT EXISTS packing_lists (
    packing_list_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    shipment_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'created',
    packed_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    packed_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT fk_packing_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_packing_shipment FOREIGN KEY (shipment_id) REFERENCES shipments(shipment_id) ON DELETE CASCADE,
    CONSTRAINT fk_packing_packed_by FOREIGN KEY (packed_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS packing_list_items (
    packing_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    packing_list_id UUID NOT NULL,
    shipment_item_id UUID NOT NULL,
    packed_qty NUMERIC(14,4) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_packing_item_list FOREIGN KEY (packing_list_id) REFERENCES packing_lists(packing_list_id) ON DELETE CASCADE,
    CONSTRAINT fk_packing_item_shipment_item FOREIGN KEY (shipment_item_id) REFERENCES shipment_items(shipment_item_id)
);

-- INVENTORY VALUATIONS
CREATE TABLE IF NOT EXISTS inventory_valuations (
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
    CONSTRAINT fk_valuations_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id) ON DELETE SET NULL
);

-- ANALYTICS TABLES
CREATE TABLE IF NOT EXISTS daily_inventory_snapshot (
    snapshot_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    snapshot_date    DATE NOT NULL,
    warehouse_id     UUID,
    item_id          UUID NOT NULL,
    batch_id         UUID,
    quantity_on_hand NUMERIC(14,4) NOT NULL,
    reserved_qty     NUMERIC(14,4) NOT NULL DEFAULT 0,
    available_qty    NUMERIC(14,4) NOT NULL,
    unit_cost        NUMERIC(14,4) NOT NULL,
    total_value      NUMERIC(14,4) GENERATED ALWAYS AS (quantity_on_hand * unit_cost) STORED,
    days_of_stock    NUMERIC(10,2),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_snapshot_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_snapshot_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_snapshot_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_snapshot_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);

CREATE TABLE IF NOT EXISTS inventory_aging (
    aging_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    snapshot_date    DATE NOT NULL,
    warehouse_id     UUID NOT NULL,
    item_id          UUID NOT NULL,
    batch_id         UUID NOT NULL,
    days_in_stock    INT NOT NULL,
    aging_bucket     VARCHAR(20) NOT NULL,
    quantity         NUMERIC(14,4) NOT NULL,
    unit_cost        NUMERIC(14,4) NOT NULL,
    total_value      NUMERIC(14,4) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_aging_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_aging_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_aging_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_aging_batch FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);

CREATE TABLE IF NOT EXISTS inventory_turnover_metrics (
    turnover_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    year_month       DATE NOT NULL,
    warehouse_id     UUID,
    item_id          UUID NOT NULL,
    total_consumed_qty NUMERIC(14,4) NOT NULL,
    total_consumed_value NUMERIC(14,4) NOT NULL,
    avg_inventory_qty   NUMERIC(14,4) NOT NULL,
    turnover_ratio   NUMERIC(10,2) GENERATED ALWAYS AS (CASE WHEN avg_inventory_qty > 0 THEN total_consumed_qty / avg_inventory_qty ELSE 0 END) STORED,
    days_inventory   NUMERIC(10,2),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_turnover_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_turnover_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_turnover_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    UNIQUE (company_id, year_month, warehouse_id, item_id)
);

CREATE TABLE IF NOT EXISTS abc_classification (
    classification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    classification_date DATE NOT NULL,
    item_id          UUID NOT NULL,
    warehouse_id     UUID,
    annual_consumption_value NUMERIC(14,4) NOT NULL,
    cumulative_percent NUMERIC(5,2) NOT NULL,
    abc_class        CHAR(1) NOT NULL CHECK (abc_class IN ('A', 'B', 'C')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_abc_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_abc_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_abc_item FOREIGN KEY (item_id) REFERENCES items(item_id)
);

CREATE TABLE IF NOT EXISTS demand_history (
    demand_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    demand_date      DATE NOT NULL,
    item_id          UUID NOT NULL,
    warehouse_id     UUID,
    quantity_demanded NUMERIC(14,4) NOT NULL,
    quantity_shipped  NUMERIC(14,4),
    backorder_qty     NUMERIC(14,4) DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_demand_company FOREIGN KEY (company_id) REFERENCES companies(company_id),
    CONSTRAINT fk_demand_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_demand_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id)
);

CREATE TABLE IF NOT EXISTS movement_daily_summary (
    summary_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    date                DATE NOT NULL,
    warehouse_id        UUID,
    item_id             UUID NOT NULL,
    movement_type       VARCHAR(50) NOT NULL,
    total_quantity_in   NUMERIC(14,4) DEFAULT 0,
    total_quantity_out  NUMERIC(14,4) DEFAULT 0,
    transaction_count   INT DEFAULT 0,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(company_id, date, warehouse_id, item_id, movement_type)
);

-- REORDER ORDERS
CREATE TABLE IF NOT EXISTS reorder_orders (
    reorder_order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL,
    item_id          UUID NOT NULL,
    warehouse_id     UUID NOT NULL,
    requested_qty    NUMERIC(14,4) NOT NULL,
    status           VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'ordered', 'cancelled' , 'received')),
    source           VARCHAR(20) NOT NULL DEFAULT 'auto',
    reference_type   VARCHAR(50),
    reference_id     UUID,
    generated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       UUID,
    CONSTRAINT fk_reorder_company FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_reorder_item FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_reorder_warehouse FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id),
    CONSTRAINT fk_reorder_created_by FOREIGN KEY (created_by) REFERENCES users(user_id)
);

-- =====================================================
-- ADDITIONAL INDEXES
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_items_company_sku ON items(company_id, sku);
CREATE INDEX IF NOT EXISTS idx_items_type ON items(item_type);
CREATE INDEX IF NOT EXISTS idx_items_fulfillment_policy ON items(fulfillment_policy);
CREATE INDEX IF NOT EXISTS idx_warehouses_company_code ON warehouses(company_id, code);
CREATE INDEX IF NOT EXISTS idx_inventory_locations_parent ON inventory_locations(parent_location_id);
CREATE INDEX IF NOT EXISTS idx_batches_item ON batches(item_id);
CREATE INDEX IF NOT EXISTS idx_batches_expiry ON batches(expiry_date) WHERE expiry_date IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_movements_reference ON stock_movements(reference_type, reference_id);
CREATE INDEX IF NOT EXISTS idx_movements_date ON stock_movements(movement_date);
CREATE INDEX IF NOT EXISTS idx_ledger_item ON stock_ledger(item_id, transaction_date);
CREATE INDEX IF NOT EXISTS idx_ledger_warehouse ON stock_ledger(warehouse_id);
CREATE INDEX IF NOT EXISTS idx_allocations_movement ON stock_allocations(movement_id);
CREATE INDEX IF NOT EXISTS idx_allocations_source ON stock_allocations(source_ledger_id);
CREATE INDEX IF NOT EXISTS idx_reservations_active ON reservations(company_id, warehouse_id, item_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_boms_product ON boms(product_item_id, is_active);
CREATE INDEX IF NOT EXISTS idx_valuations_date ON inventory_valuations(valuation_date);
CREATE INDEX IF NOT EXISTS idx_snapshot_date_company ON daily_inventory_snapshot(snapshot_date, company_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_item_date ON daily_inventory_snapshot(item_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_snapshot_warehouse ON daily_inventory_snapshot(warehouse_id);
CREATE INDEX IF NOT EXISTS idx_aging_snapshot ON inventory_aging(snapshot_date, company_id);
CREATE INDEX IF NOT EXISTS idx_aging_bucket ON inventory_aging(aging_bucket, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_turnover_month ON inventory_turnover_metrics(year_month, company_id);
CREATE INDEX IF NOT EXISTS idx_abc_date_class ON abc_classification(classification_date, abc_class);
CREATE INDEX IF NOT EXISTS idx_abc_item ON abc_classification(item_id, classification_date);
CREATE INDEX IF NOT EXISTS idx_demand_item_date ON demand_history(item_id, demand_date);
CREATE INDEX IF NOT EXISTS idx_demand_warehouse ON demand_history(warehouse_id);
CREATE INDEX IF NOT EXISTS idx_movement_analytics ON movement_daily_summary(company_id, date);
CREATE INDEX IF NOT EXISTS idx_prod_orders_company_status ON production_orders(company_id, status);
CREATE INDEX IF NOT EXISTS idx_prod_orders_product ON production_orders(product_item_id);
CREATE INDEX IF NOT EXISTS idx_prod_orders_dates ON production_orders(planned_start_date, planned_end_date);
CREATE INDEX IF NOT EXISTS idx_prod_comp_order ON production_order_components(production_order_id);
CREATE INDEX IF NOT EXISTS idx_prod_comp_item ON production_order_components(item_id);
CREATE INDEX IF NOT EXISTS idx_prod_metrics_date ON production_metrics(date);
CREATE INDEX IF NOT EXISTS idx_prod_metrics_product ON production_metrics(product_item_id);
CREATE INDEX IF NOT EXISTS idx_reorder_orders_pending ON reorder_orders(company_id, status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_reorder_orders_item ON reorder_orders(item_id, warehouse_id);
CREATE INDEX IF NOT EXISTS idx_fulfillment_orders_reference ON fulfillment_orders(reference_type, reference_id);
CREATE INDEX IF NOT EXISTS idx_shipments_status ON shipments(shipment_status);
CREATE INDEX IF NOT EXISTS idx_shipment_items_shipment ON shipment_items(shipment_id);
CREATE INDEX IF NOT EXISTS idx_stock_transfer_orders_status ON stock_transfer_orders(status);
CREATE INDEX IF NOT EXISTS idx_serial_numbers_item ON serial_numbers(item_id);
CREATE INDEX IF NOT EXISTS idx_serial_txn_serial ON serial_number_transactions(serial_id);
CREATE INDEX IF NOT EXISTS idx_serial_txn_movement ON serial_number_transactions(movement_id);
CREATE INDEX IF NOT EXISTS idx_cycle_counts_warehouse ON inventory_cycle_counts(warehouse_id);
CREATE INDEX IF NOT EXISTS idx_cycle_counts_status ON inventory_cycle_counts(status);
CREATE INDEX IF NOT EXISTS idx_picking_lists_fulfillment ON picking_lists(fulfillment_order_id);
CREATE INDEX IF NOT EXISTS idx_picking_lists_status ON picking_lists(status);
CREATE INDEX IF NOT EXISTS idx_packing_lists_shipment ON packing_lists(shipment_id);
CREATE INDEX IF NOT EXISTS idx_packing_lists_status ON packing_lists(status);


-- Add warehouse_id column (required, with foreign key)
ALTER TABLE inventory_locations 
ADD COLUMN warehouse_id UUID NOT NULL,
ADD CONSTRAINT fk_inv_location_warehouse 
    FOREIGN KEY (warehouse_id) REFERENCES warehouses(warehouse_id) ON DELETE RESTRICT;

-- Drop the old warehouse‑location assignment table if it exists
DROP TABLE IF EXISTS warehouse_locations;

-- Unique constraint: code must be unique per company + warehouse
ALTER TABLE inventory_locations 
DROP CONSTRAINT inventory_locations_company_id_code_key,
ADD CONSTRAINT unique_location_code_per_warehouse 
    UNIQUE (company_id, code, warehouse_id);






-- =====================================================
-- VENDORS & PURCHASE ORDERS (for reorder integration)
-- =====================================================

CREATE TABLE IF NOT EXISTS vendors (
    vendor_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,

    -- Business identifiers (not encrypted – searchable)
    vendor_code        VARCHAR(50) NOT NULL,
    vendor_name        VARCHAR(255) NOT NULL,
    vendor_type        VARCHAR(50),   -- e.g., 'raw_material', 'service', 'logistics'

    -- Encrypted contact fields (pattern: field, field_dek, field_key_id)
    contact_person     TEXT,
    contact_person_dek TEXT,
    contact_person_key_id TEXT,

    phone              TEXT,
    phone_dek          TEXT,
    phone_key_id       TEXT,

    email              TEXT,
    email_dek          TEXT,
    email_key_id       TEXT,

    address            TEXT,
    address_dek        TEXT,
    address_key_id     TEXT,

    -- Bank details (generic, no country‑specific assumptions)
    bank_account_no    TEXT,
    bank_account_no_dek TEXT,
    bank_account_no_key_id TEXT,

    bank_routing_code  TEXT,                -- BIC/SWIFT or local routing number
    bank_routing_code_dek TEXT,
    bank_routing_code_key_id TEXT,

    bank_name          TEXT,
    bank_name_dek      TEXT,
    bank_name_key_id   TEXT,

    -- Operational
    is_active          BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID REFERENCES users(user_id),
    updated_by         UUID REFERENCES users(user_id),
    deleted_at         TIMESTAMPTZ,

    UNIQUE (company_id, vendor_code)
);

CREATE INDEX idx_vendors_company_code ON vendors(company_id, vendor_code) WHERE deleted_at IS NULL;
CREATE INDEX idx_vendors_name ON vendors(vendor_name) WHERE deleted_at IS NULL;


CREATE TABLE IF NOT EXISTS vendor_tax_identifiers (
    tax_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id          UUID NOT NULL REFERENCES vendors(vendor_id) ON DELETE CASCADE,
    tax_type           VARCHAR(50) NOT NULL,   -- 'GST', 'VAT', 'PAN', 'EIN', 'NIF', etc.
    tax_number         TEXT,
    tax_number_dek     TEXT,
    tax_number_key_id  TEXT,
    is_primary         BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by         UUID REFERENCES users(user_id),
    UNIQUE(vendor_id, tax_type)
);

CREATE INDEX idx_vendor_tax_vendor ON vendor_tax_identifiers(vendor_id);


CREATE TABLE IF NOT EXISTS purchase_orders (
    purchase_order_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    po_number           VARCHAR(100) NOT NULL,
    vendor_id           UUID NOT NULL REFERENCES vendors(vendor_id),
    order_date          DATE NOT NULL,
    expected_delivery_date DATE,
    status              VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','submitted','approved','ordered','partially_received','received','cancelled')),
    total_amount        NUMERIC(14,4),
    currency            VARCHAR(3) DEFAULT 'USD',
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID REFERENCES users(user_id),
    updated_by          UUID REFERENCES users(user_id),
    UNIQUE(company_id, po_number)
);

CREATE INDEX idx_purchase_orders_company ON purchase_orders(company_id);
CREATE INDEX idx_purchase_orders_vendor ON purchase_orders(vendor_id);
CREATE INDEX idx_purchase_orders_status ON purchase_orders(status);
CREATE INDEX idx_purchase_orders_date ON purchase_orders(order_date);



CREATE TABLE IF NOT EXISTS purchase_order_items (
    po_item_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purchase_order_id   UUID NOT NULL REFERENCES purchase_orders(purchase_order_id) ON DELETE CASCADE,
    item_id             UUID NOT NULL REFERENCES items(item_id),
    quantity_ordered    NUMERIC(14,4) NOT NULL,
    quantity_received   NUMERIC(14,4) NOT NULL DEFAULT 0,
    unit_cost           NUMERIC(14,4) NOT NULL,
    total_line          NUMERIC(14,4) GENERATED ALWAYS AS (quantity_ordered * unit_cost) STORED,
    received_date       DATE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(purchase_order_id, item_id)
);

CREATE INDEX idx_po_items_order ON purchase_order_items(purchase_order_id);
CREATE INDEX idx_po_items_item ON purchase_order_items(item_id);


CREATE TABLE IF NOT EXISTS purchase_order_receipts (
    receipt_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purchase_order_id   UUID NOT NULL REFERENCES purchase_orders(purchase_order_id) ON DELETE CASCADE,
    po_item_id          UUID NOT NULL REFERENCES purchase_order_items(po_item_id) ON DELETE CASCADE,
    receipt_date        DATE NOT NULL,
    quantity_received   NUMERIC(14,4) NOT NULL,
    unit_cost           NUMERIC(14,4) NOT NULL,          -- could include freight/insurance share
    warehouse_id        UUID NOT NULL REFERENCES warehouses(warehouse_id),
    batch_id            UUID REFERENCES batches(batch_id), -- if batch‑tracked
    movement_id         UUID REFERENCES stock_movements(movement_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID REFERENCES users(user_id)
);

CREATE INDEX idx_po_receipts_order ON purchase_order_receipts(purchase_order_id);
CREATE INDEX idx_po_receipts_item ON purchase_order_receipts(po_item_id);

CREATE TABLE item_vendors (
    item_id    UUID NOT NULL REFERENCES items(item_id),
    vendor_id  UUID NOT NULL REFERENCES vendors(vendor_id),
    is_default BOOLEAN NOT NULL DEFAULT false,
    lead_time  INT,   -- days
    unit_cost  NUMERIC(14,4),
    PRIMARY KEY (item_id, vendor_id)
);

ALTER TABLE purchase_orders
ADD COLUMN deleted_at TIMESTAMPTZ;

-- Drop the existing unique constraint
ALTER TABLE purchase_orders DROP CONSTRAINT purchase_orders_company_id_po_number_key;

-- Create a partial unique index that ignores soft‑deleted rows
CREATE UNIQUE INDEX idx_purchase_orders_unique_active
ON purchase_orders (company_id, po_number)
WHERE deleted_at IS NULL;




-- =====================================================================
-- PRODUCTION ORDER COMPONENT CONSUMPTIONS (with company_id)
-- =====================================================================
CREATE TABLE IF NOT EXISTS production_order_component_consumptions (
    consumption_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,                         -- multi‑tenant
    component_id        UUID NOT NULL,
    production_order_id UUID NOT NULL,
    item_id             UUID NOT NULL,
    batch_id            UUID,
    quantity_consumed   NUMERIC(14,4) NOT NULL CHECK (quantity_consumed > 0),
    movement_id         UUID NOT NULL UNIQUE,
    consumed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID,
    notes               TEXT,

    CONSTRAINT fk_consumption_company 
        FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_consumption_component 
        FOREIGN KEY (component_id) REFERENCES production_order_components(component_id) ON DELETE CASCADE,
    CONSTRAINT fk_consumption_order 
        FOREIGN KEY (production_order_id) REFERENCES production_orders(production_order_id) ON DELETE CASCADE,
    CONSTRAINT fk_consumption_item 
        FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_consumption_batch 
        FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_consumption_movement 
        FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id) ON DELETE RESTRICT,
    CONSTRAINT fk_consumption_created_by 
        FOREIGN KEY (created_by) REFERENCES users(user_id)
);

CREATE INDEX idx_consumption_company ON production_order_component_consumptions(company_id);
CREATE INDEX idx_consumption_component ON production_order_component_consumptions(component_id);
CREATE INDEX idx_consumption_order ON production_order_component_consumptions(production_order_id);
CREATE INDEX idx_consumption_movement ON production_order_component_consumptions(movement_id);

-- =====================================================================
-- PRODUCTION ORDER SCRAP (with company_id)
-- =====================================================================
CREATE TABLE IF NOT EXISTS production_order_scrap (
    scrap_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID NOT NULL,
    production_order_id UUID NOT NULL,
    component_id        UUID,
    item_id             UUID NOT NULL,
    batch_id            UUID,
    scrap_quantity      NUMERIC(14,4) NOT NULL CHECK (scrap_quantity > 0),
    movement_id         UUID NOT NULL UNIQUE,
    reason              TEXT,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID,

    CONSTRAINT fk_scrap_company 
        FOREIGN KEY (company_id) REFERENCES companies(company_id) ON DELETE CASCADE,
    CONSTRAINT fk_scrap_order 
        FOREIGN KEY (production_order_id) REFERENCES production_orders(production_order_id) ON DELETE CASCADE,
    CONSTRAINT fk_scrap_component 
        FOREIGN KEY (component_id) REFERENCES production_order_components(component_id) ON DELETE SET NULL,
    CONSTRAINT fk_scrap_item 
        FOREIGN KEY (item_id) REFERENCES items(item_id),
    CONSTRAINT fk_scrap_batch 
        FOREIGN KEY (batch_id) REFERENCES batches(batch_id),
    CONSTRAINT fk_scrap_movement 
        FOREIGN KEY (movement_id) REFERENCES stock_movements(movement_id) ON DELETE RESTRICT,
    CONSTRAINT fk_scrap_created_by 
        FOREIGN KEY (created_by) REFERENCES users(user_id)
);

CREATE INDEX idx_scrap_company ON production_order_scrap(company_id);
CREATE INDEX idx_scrap_order ON production_order_scrap(production_order_id);
CREATE INDEX idx_scrap_movement ON production_order_scrap(movement_id);

-- Add the new movement type (if not already present)
ALTER TYPE movement_type ADD VALUE IF NOT EXISTS 'production_scrap';

ALTER TABLE production_order_components DROP COLUMN IF EXISTS actual_quantity;
ALTER TABLE production_order_components DROP CONSTRAINT IF EXISTS fk_prod_comp_movement;
ALTER TABLE production_order_components DROP COLUMN IF EXISTS movement_id;
-- Remove redundant columns from production_order_components
ALTER TABLE production_order_components 
    DROP COLUMN IF EXISTS actual_quantity,
    DROP CONSTRAINT IF EXISTS fk_prod_comp_movement,
    DROP COLUMN IF EXISTS movement_id;