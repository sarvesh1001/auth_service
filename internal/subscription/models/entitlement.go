package models

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"auth-service/internal/subscription/models/enums"
)

type Entitlement struct {
	EntitlementID uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"entitlementId"`
	PlanItemID    uuid.UUID          `gorm:"type:uuid;not null;index" json:"planItemId"`
	FeatureKey    string             `gorm:"type:varchar(100);not null" json:"featureKey"`
	LimitValue    *decimal.Decimal   `gorm:"type:numeric(14,4)" json:"limitValue,omitempty"`
	LimitPeriod   enums.LimitPeriod  `gorm:"type:varchar(20);default:'month'" json:"limitPeriod,omitempty"`
	IsEnabled     bool               `gorm:"not null;default:true" json:"isEnabled"`
	CreatedAt     time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt     time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
}
