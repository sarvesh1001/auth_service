package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProductionOrder represents a manufacturing order to produce a finished good.
type ProductionOrder struct {
	ProductionOrderID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"productionOrderId"`
	CompanyID         uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	OrderNumber       string          `gorm:"type:varchar(100);not null" json:"orderNumber"`
	ProductItemID     uuid.UUID       `gorm:"type:uuid;not null" json:"productItemId"`
	BOMID             uuid.UUID       `gorm:"type:uuid;not null" json:"bomId"`
	PlannedQuantity   decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"plannedQuantity"`
	ProducedQuantity  decimal.Decimal `gorm:"type:numeric(14,4);not null;default:0" json:"producedQuantity"`
	Status            string          `gorm:"type:varchar(20);not null;default:'draft'" json:"status"`
	PlannedStartDate  *time.Time      `gorm:"type:date" json:"plannedStartDate,omitempty"`
	PlannedEndDate    *time.Time      `gorm:"type:date" json:"plannedEndDate,omitempty"`
	ActualStartTime   *time.Time      `gorm:"type:timestamptz" json:"actualStartTime,omitempty"`
	ActualEndTime     *time.Time      `gorm:"type:timestamptz" json:"actualEndTime,omitempty"`
	WarehouseID       uuid.UUID       `gorm:"type:uuid;not null" json:"warehouseId"`
	CreatedBy         *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	CreatedAt         time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt         time.Time       `gorm:"not null;default:now()" json:"updatedAt"`

	// New fields for make-to-order linking
	SourceReferenceType *string    `gorm:"type:varchar(50)" json:"sourceReferenceType,omitempty"`
	SourceReferenceID   *uuid.UUID `gorm:"type:uuid" json:"sourceReferenceId,omitempty"`
}

func (ProductionOrder) TableName() string {
	return "production_orders"
}

type ProductionOrderComponent struct {
	ComponentID       uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"componentId"`
	ProductionOrderID uuid.UUID       `gorm:"type:uuid;not null" json:"productionOrderId"`
	ItemID            uuid.UUID       `gorm:"type:uuid;not null" json:"itemId"`
	BatchID           *uuid.UUID      `gorm:"type:uuid" json:"batchId,omitempty"`
	PlannedQuantity   decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"plannedQuantity"`
	// ActualQuantity removed – actual consumption is tracked in production_order_component_consumptions table
	CreatedAt time.Time `gorm:"not null;default:now()" json:"createdAt"`
}

func (ProductionOrderComponent) TableName() string {
	return "production_order_components"
}

// ProductionMetric stores daily KPIs for production analytics.
type ProductionMetric struct {
	MetricID            uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"metricId"`
	CompanyID           uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_unique_prod_metric,priority:1" json:"companyId"`
	Date                time.Time        `gorm:"type:date;not null;uniqueIndex:idx_unique_prod_metric,priority:2" json:"date"`
	ProductItemID       uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_unique_prod_metric,priority:3" json:"productItemId"`
	TotalProducedQty    decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"totalProducedQty"`
	TotalConsumedRawQty decimal.Decimal  `gorm:"type:numeric(14,4);not null;default:0" json:"totalConsumedRawQty"`
	Efficiency          *decimal.Decimal `gorm:"type:numeric(5,2)" json:"efficiency,omitempty"`
	CreatedAt           time.Time        `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt           time.Time        `gorm:"not null;default:now()" json:"updatedAt"`
}

func (ProductionMetric) TableName() string {
	return "production_metrics"
}
