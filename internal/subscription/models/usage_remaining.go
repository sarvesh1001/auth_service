package models

import (
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// UsageRemaining is a view model, not persisted.
type UsageRemaining struct {
	SubItemID     uuid.UUID        `gorm:"column:sub_item_id" json:"subItemId"`
	SubscriptionID uuid.UUID       `gorm:"column:subscription_id" json:"subscriptionId"`
	PlanItemID    uuid.UUID        `gorm:"column:plan_item_id" json:"planItemId"`
	FeatureKey    string           `gorm:"column:feature_key" json:"featureKey"`
	TotalAllowed  *decimal.Decimal `gorm:"column:total_allowed" json:"totalAllowed,omitempty"`
	Used          decimal.Decimal  `gorm:"column:used" json:"used"`
	Remaining     decimal.Decimal  `gorm:"column:remaining" json:"remaining"`
}
