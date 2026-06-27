package models

import (
	"time"

	"gorm.io/datatypes"

	"github.com/google/uuid"
)

type SubscriptionItem struct {
	SubItemID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID      `gorm:"type:uuid;not null;index"`
	PlanItemID     uuid.UUID      `gorm:"type:uuid;not null"`
	AddonID        *uuid.UUID     `gorm:"type:uuid"`
	Quantity       float64        `gorm:"type:numeric(14,4);not null;default:1"`
	UnitPrice      float64        `gorm:"type:numeric(14,2);not null"`
	TotalPrice     float64        `gorm:"type:numeric(14,2);generated:always as (quantity * unit_price) stored"`
	Currency       string         `gorm:"size:3;not null;default:'USD'"`
	StatusID       int16          `gorm:"not null;default:7;index"`
	StartDate      time.Time      `gorm:"type:date;not null;default:now()"`
	EndDate        *time.Time     `gorm:"type:date"`
	Metadata       datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`
	UpdatedAt      time.Time      `gorm:"not null;default:now()"`

	// relationships
	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	PlanItem     PlanItem     `gorm:"foreignKey:PlanItemID"`
	Addon        *Addon       `gorm:"foreignKey:AddonID"`
	Status       Status       `gorm:"foreignKey:StatusID"`
	Usages       []Usage      `gorm:"foreignKey:SubscriptionItemID"`
}

func (SubscriptionItem) TableName() string { return "subscription_items" }
