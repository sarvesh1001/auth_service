package models

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"auth-service/internal/subscription/models/enums"
)

type SubscriptionItem struct {
	SubItemID      uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"subItemId"`
	SubscriptionID uuid.UUID       `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	PlanItemID     uuid.UUID       `gorm:"type:uuid;not null" json:"planItemId"`
	AddonID        *uuid.UUID      `gorm:"type:uuid" json:"addonId,omitempty"`
	Quantity       decimal.Decimal `gorm:"type:numeric(14,4);not null;default:1" json:"quantity"`
	UnitPrice      decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"unitPrice"`
	TotalPrice     decimal.Decimal `gorm:"->" json:"totalPrice"` // generated column (quantity * unit_price)
	Currency       string          `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	Status         enums.ItemStatus `gorm:"type:varchar(20);not null;default:'active'" json:"status"`
	StartDate      time.Time       `gorm:"type:date;not null;default:CURRENT_DATE" json:"startDate"`
	EndDate        *time.Time      `gorm:"type:date" json:"endDate,omitempty"`
	Metadata       JSONB           `gorm:"type:jsonb" json:"metadata,omitempty"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	ProductID      *uuid.UUID      `gorm:"type:uuid" json:"productId,omitempty"` // reference to sales.products
}
