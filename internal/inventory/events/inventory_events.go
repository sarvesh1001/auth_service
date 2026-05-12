package events

import "time"

const (
	TopicInventoryEvents         = "inventory-events"
	EventWarehouseCreated        = "inventory.warehouse.created"
	EventWarehouseUpdated        = "inventory.warehouse.updated"
	EventWarehouseDeleted        = "inventory.warehouse.deleted"
	EventBOMCreated              = "bom.created"
	EventBOMUpdated              = "bom.updated"
	EventBOMDeleted              = "bom.deleted"
	EventFulfillmentOrderCreated = "inventory.fulfillment_order.created"
	EventShipmentCreated         = "inventory.shipment.created"
	EventShipmentShipped         = "inventory.shipment.shipped"
	EventShipmentDelivered       = "inventory.shipment.delivered"
	EventLocationCreated         = "inventory.location.created"
	EventLocationUpdated         = "inventory.location.updated"
	EventLocationDeleted         = "inventory.location.deleted"
	EventSerialNumbersRegistered = "inventory.serial.registered"
	EventShipmentItemCreated     = "inventory.shipment_item.created"
	EventSerialNumberTransaction = "inventory.serial.transaction"
	EventCycleCountCreated       = "inventory.cycle_count.created"
	EventCycleCountStarted       = "inventory.cycle_count.started"
	EventCycleCountCompleted     = "inventory.cycle_count.completed"
	EventCycleCountCancelled     = "inventory.cycle_count.cancelled"
	EventCycleCountAdjusted      = "inventory.cycle_count.adjusted"
	EventPickingListCreated      = "inventory.picking_list.created"
	EventPickingListCompleted    = "inventory.picking_list.completed"
	EventPackingListCreated      = "inventory.packing_list.created"
	EventPackingListPacked       = "inventory.packing_list.packed"
	EventPackingListVerified     = "inventory.packing_list.verified"
	EventPackingListCompleted    = "inventory.packing_list.completed"
	EventDigitalDeliveryRequired = "inventory.digital_delivery.required"
	EventExternalVendorRequired  = "inventory.external_vendor.required"

	EventShipmentUpdated               = "inventory.shipment.updated"
	EventShipmentCancelled             = "inventory.shipment.cancelled"
	EventReservationPartiallyFulfilled = "inventory.reservation.partially_fulfilled"

	// Item events
	EventItemCreated          = "inventory.item.created"
	EventItemUpdated          = "inventory.item.updated"
	EventItemDeleted          = "inventory.item.deleted"
	EventDropshipRequired     = "inventory.dropship.required"
	EventFulfillmentBackorder = "inventory.fulfillment.backorder"

	// Stock movement events
	EventMovementCreated   = "inventory.movement.created"
	EventMovementCancelled = "inventory.movement.cancelled"

	// Batch events
	EventBatchCreated  = "inventory.batch.created"
	EventBatchAdjusted = "inventory.batch.adjusted"

	// Stock balance events (for analytics)
	EventStockChanged         = "inventory.stock.changed"
	EventReservationCreated   = "inventory.reservation.created"
	EventReservationFulfilled = "inventory.reservation.fulfilled"
)

type ItemPayload struct {
	ItemID    string `json:"item_id"`
	CompanyID string `json:"company_id"`
	SKU       string `json:"sku"`
	Name      string `json:"name"`
	ItemType  string `json:"item_type"`
	IsActive  bool   `json:"is_active"`
}

type MovementPayload struct {
	MovementID   string    `json:"movement_id"`
	CompanyID    string    `json:"company_id"`
	MovementType string    `json:"movement_type"`
	ItemID       string    `json:"item_id"`
	WarehouseID  string    `json:"warehouse_id"`
	QuantityIn   float64   `json:"quantity_in"`
	QuantityOut  float64   `json:"quantity_out"`
	UnitCost     float64   `json:"unit_cost"`
	MovementDate time.Time `json:"movement_date"`
}

type StockChangePayload struct {
	CompanyID    string    `json:"company_id"`
	ItemID       string    `json:"item_id"`
	WarehouseID  string    `json:"warehouse_id"`
	BatchID      *string   `json:"batch_id,omitempty"`
	OldAvailable float64   `json:"old_available"`
	NewAvailable float64   `json:"new_available"`
	Delta        float64   `json:"delta"`
	Timestamp    time.Time `json:"timestamp"`
}

const (
	// Production events
	EventProductionOrderCreated   = "inventory.production.created"
	EventProductionOrderReleased  = "inventory.production.released"
	EventProductionOrderStarted   = "inventory.production.started"
	EventProductionOrderCompleted = "inventory.production.completed"
	EventProductionOrderCancelled = "inventory.production.cancelled"
	EventReorderCreated           = "inventory.reorder.created"
	EventReservationCancelled     = "inventory.reservation.cancelled"
	EventReservationExpired       = "inventory.reservation.expired"
)

type ProductionOrderPayload struct {
	ProductionOrderID string    `json:"production_order_id"`
	CompanyID         string    `json:"company_id"`
	OrderNumber       string    `json:"order_number"`
	ProductItemID     string    `json:"product_item_id"`
	BOMID             string    `json:"bom_id"`
	PlannedQuantity   float64   `json:"planned_quantity"`
	ProducedQuantity  float64   `json:"produced_quantity"`
	Status            string    `json:"status"`
	WarehouseID       string    `json:"warehouse_id"`
	CompletedAt       time.Time `json:"completed_at,omitempty"`
}
type ReorderPayload struct {
	ReorderOrderID string    `json:"reorder_order_id"`
	CompanyID      string    `json:"company_id"`
	ItemID         string    `json:"item_id"`
	WarehouseID    string    `json:"warehouse_id"`
	RequestedQty   float64   `json:"requested_qty"`
	Status         string    `json:"status"`
	Source         string    `json:"source"`
	GeneratedAt    time.Time `json:"generated_at"`
}
type ReservationPayload struct {
	ReservationID   string     `json:"reservation_id"`
	CompanyID       string     `json:"company_id"`
	ReservationType string     `json:"reservation_type"`
	ReferenceID     string     `json:"reference_id"`
	WarehouseID     string     `json:"warehouse_id"`
	ItemID          string     `json:"item_id"`
	BatchID         *string    `json:"batch_id,omitempty"`
	Quantity        float64    `json:"quantity"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

type BOMPayload struct {
	BOMID         string  `json:"bomId"`
	CompanyID     string  `json:"companyId"`
	ProductItemID string  `json:"productItemId"`
	BOMCode       string  `json:"bomCode"`
	Name          string  `json:"name"`
	Version       int     `json:"version"`
	Quantity      float64 `json:"quantity"`
	IsActive      bool    `json:"isActive"`
}

const (
	EventTransferOrderCreated    = "inventory.transfer_order.created"
	EventTransferOrderDispatched = "inventory.transfer_order.dispatched"
	EventTransferOrderReceived   = "inventory.transfer_order.received"
	EventTransferOrderCancelled  = "inventory.transfer_order.cancelled"
)

type TransferOrderPayload struct {
	TransferOrderID string     `json:"transfer_order_id"`
	CompanyID       string     `json:"company_id"`
	TransferNumber  string     `json:"transfer_number"`
	FromWarehouseID string     `json:"from_warehouse_id"`
	ToWarehouseID   string     `json:"to_warehouse_id"`
	Status          string     `json:"status"`
	DispatchedAt    *time.Time `json:"dispatched_at,omitempty"`
	ReceivedAt      *time.Time `json:"received_at,omitempty"`
}
