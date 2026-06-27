package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PlanItem struct {
	PlanItemID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	PlanID          uuid.UUID      `gorm:"type:uuid;not null;index"`
	ItemType        string         `gorm:"size:20;not null;check:item_type IN ('base','addon','benefit','discount','tax')"`
	Name            string         `gorm:"size:255;not null"`
	Description     *string        `gorm:"type:text"`
	FeatureKey      *string        `gorm:"size:100"`
	BillingPolicyID *uuid.UUID     `gorm:"type:uuid"`
	Price           float64        `gorm:"type:numeric(14,2);not null;default:0"`
	Currency        string         `gorm:"size:3;not null;default:'USD'"`
	EffectiveFrom   time.Time      `gorm:"type:date;not null;default:now()"`
	EffectiveTo     *time.Time     `gorm:"type:date"`
	IsMandatory     bool           `gorm:"not null;default:false"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	// relationships
	Plan          Plan            `gorm:"foreignKey:PlanID"`
	Feature       *FeatureRegistry `gorm:"foreignKey:FeatureKey"`
	BillingPolicy *BillingPolicy  `gorm:"foreignKey:BillingPolicyID"`
	Entitlements  []Entitlement   `gorm:"foreignKey:PlanItemID"`
	Benefits      []Benefit       `gorm:"foreignKey:PlanItemID"`
}

func (PlanItem) TableName() string { return "plan_items" }
