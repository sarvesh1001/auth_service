package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// DailyInventorySnapshot – already correct
type DailyInventorySnapshot struct {
	SnapshotID     uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"snapshotId"`
	CompanyID      uuid.UUID        `gorm:"type:uuid;not null;index:idx_snapshot_date_company,priority:2;index:idx_snapshot_company" json:"companyId"`
	SnapshotDate   time.Time        `gorm:"type:date;not null;index:idx_snapshot_date_company,priority:1;index:idx_snapshot_item_date,priority:2" json:"snapshotDate"`
	WarehouseID    *uuid.UUID       `gorm:"type:uuid;index:idx_snapshot_warehouse" json:"warehouseId,omitempty"`
	ItemID         uuid.UUID        `gorm:"type:uuid;not null;index:idx_snapshot_item_date,priority:1" json:"itemId"`
	BatchID        *uuid.UUID       `gorm:"type:uuid" json:"batchId,omitempty"`
	QuantityOnHand decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"quantityOnHand"`
	ReservedQty    decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"reservedQty"`
	AvailableQty   decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"availableQty"`
	UnitCost       decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	TotalValue     decimal.Decimal  `gorm:"->;type:numeric(14,4);generated:always" json:"totalValue"`
	DaysOfStock    *decimal.Decimal `gorm:"type:numeric(10,2)" json:"daysOfStock,omitempty"`
	CreatedAt      time.Time        `gorm:"default:now()" json:"createdAt"`
}

func (DailyInventorySnapshot) TableName() string { return "daily_inventory_snapshot" }

// InventoryAging – corrected
type InventoryAging struct {
	AgingID      uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"agingId"`
	CompanyID    uuid.UUID       `gorm:"type:uuid;not null;index:idx_aging_snapshot,priority:2" json:"companyId"`
	SnapshotDate time.Time       `gorm:"type:date;not null;index:idx_aging_snapshot,priority:1;index:idx_aging_bucket,priority:2" json:"snapshotDate"`
	WarehouseID  uuid.UUID       `gorm:"type:uuid;not null;index" json:"warehouseId"`
	ItemID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"itemId"`
	BatchID      uuid.UUID       `gorm:"type:uuid;not null;index" json:"batchId"`
	DaysInStock  int             `gorm:"not null" json:"daysInStock"`
	AgingBucket  string          `gorm:"type:varchar(20);not null;index:idx_aging_bucket,priority:1" json:"agingBucket"`
	Quantity     decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UnitCost     decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"unitCost"`
	TotalValue   decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"totalValue"`
	CreatedAt    time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (InventoryAging) TableName() string { return "inventory_aging" }

// InventoryTurnoverMetrics – corrected
type InventoryTurnoverMetrics struct {
	TurnoverID         uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"turnoverId"`
	CompanyID          uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_unique_turnover,priority:1;index:idx_turnover_month,priority:2" json:"companyId"`
	YearMonth          time.Time        `gorm:"type:date;not null;uniqueIndex:idx_unique_turnover,priority:2;index:idx_turnover_month,priority:1" json:"yearMonth"`
	WarehouseID        *uuid.UUID       `gorm:"type:uuid;uniqueIndex:idx_unique_turnover,priority:3" json:"warehouseId,omitempty"`
	ItemID             uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_unique_turnover,priority:4" json:"itemId"`
	TotalConsumedQty   decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"totalConsumedQty"`
	TotalConsumedValue decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"totalConsumedValue"`
	AvgInventoryQty    decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"avgInventoryQty"`
	TurnoverRatio      decimal.Decimal  `gorm:"->;type:numeric(10,2);generated:always" json:"turnoverRatio"`
	DaysInventory      *decimal.Decimal `gorm:"type:numeric(10,2)" json:"daysInventory,omitempty"`
	CreatedAt          time.Time        `gorm:"default:now()" json:"createdAt"`
}

func (InventoryTurnoverMetrics) TableName() string { return "inventory_turnover_metrics" }

// ABCClassification – corrected
type ABCClassification struct {
	ClassificationID       uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"classificationId"`
	CompanyID              uuid.UUID       `gorm:"type:uuid;not null;index:idx_abc_date_class,priority:2;index:idx_abc_item,priority:2" json:"companyId"`
	ClassificationDate     time.Time       `gorm:"type:date;not null;index:idx_abc_date_class,priority:1;index:idx_abc_item,priority:1" json:"classificationDate"`
	ItemID                 uuid.UUID       `gorm:"type:uuid;not null;index:idx_abc_item,priority:1" json:"itemId"`
	WarehouseID            *uuid.UUID      `gorm:"type:uuid" json:"warehouseId,omitempty"`
	AnnualConsumptionValue decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"annualConsumptionValue"`
	CumulativePercent      decimal.Decimal `gorm:"type:numeric(5,2);not null" json:"cumulativePercent"`
	ABCClass               string          `gorm:"type:char(1);not null;check:abc_class IN ('A','B','C');index:idx_abc_date_class,priority:3" json:"abcClass"`
	CreatedAt              time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (ABCClassification) TableName() string { return "abc_classification" }

// DemandHistory – corrected
type DemandHistory struct {
	DemandID         uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"demandId"`
	CompanyID        uuid.UUID        `gorm:"type:uuid;not null;index:idx_demand_item_date,priority:2;index:idx_demand_warehouse,priority:2" json:"companyId"`
	DemandDate       time.Time        `gorm:"type:date;not null;index:idx_demand_item_date,priority:1" json:"demandDate"`
	ItemID           uuid.UUID        `gorm:"type:uuid;not null;index:idx_demand_item_date,priority:1" json:"itemId"`
	WarehouseID      *uuid.UUID       `gorm:"type:uuid;index:idx_demand_warehouse,priority:1" json:"warehouseId,omitempty"`
	QuantityDemanded decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"quantityDemanded"`
	QuantityShipped  *decimal.Decimal `gorm:"type:numeric(14,4)" json:"quantityShipped,omitempty"`
	BackorderQty     decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"backorderQty"`
	CreatedAt        time.Time        `gorm:"default:now()" json:"createdAt"`
}

func (DemandHistory) TableName() string { return "demand_history" }

// MovementDailySummary – corrected
type MovementDailySummary struct {
	SummaryID        uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"summaryId"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_unique_movement_summary,priority:1;index:idx_movement_analytics,priority:1" json:"companyId"`
	Date             time.Time       `gorm:"type:date;not null;uniqueIndex:idx_unique_movement_summary,priority:2;index:idx_movement_analytics,priority:2" json:"date"`
	WarehouseID      *uuid.UUID      `gorm:"type:uuid" json:"warehouseId,omitempty"`
	ItemID           uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_unique_movement_summary,priority:4" json:"itemId"`
	MovementType     string          `gorm:"type:varchar(50);not null;uniqueIndex:idx_unique_movement_summary,priority:5" json:"movementType"`
	TotalQuantityIn  decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalQuantityIn"`
	TotalQuantityOut decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"totalQuantityOut"`
	TransactionCount int             `gorm:"not null;default:0" json:"transactionCount"`
	CreatedAt        time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt        time.Time       `gorm:"not null;default:now()" json:"updatedAt"`
}

func (MovementDailySummary) TableName() string { return "movement_daily_summary" }
