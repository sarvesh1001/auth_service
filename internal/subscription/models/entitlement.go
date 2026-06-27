package models

import (
	"time"

	"github.com/google/uuid"
)

type Entitlement struct {
	EntitlementID uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	PlanItemID    uuid.UUID  `gorm:"type:uuid;not null;index"`
	FeatureKey    string     `gorm:"size:100;not null"`
	LimitValue    *float64   `gorm:"type:numeric(14,4)"`
	LimitPeriod   *string    `gorm:"size:20;check:limit_period IN ('day','week','month','year','lifetime')"`
	IsEnabled     bool       `gorm:"not null;default:true"`
	CreatedAt     time.Time  `gorm:"not null;default:now()"`
	UpdatedAt     time.Time  `gorm:"not null;default:now()"`

	// relationships
	PlanItem PlanItem        `gorm:"foreignKey:PlanItemID"`
	Feature  FeatureRegistry `gorm:"foreignKey:FeatureKey"`
}

func (Entitlement) TableName() string { return "entitlements" }
