// FILE: models/feature_registry.go

package models

import (
	"time"

	"github.com/shopspring/decimal"
)

type FeatureRegistry struct {
	FeatureKey      string           `gorm:"type:varchar(100);primaryKey" json:"featureKey"`
	Module          string           `gorm:"type:varchar(50);not null" json:"module"`
	FeatureGroup    *string          `gorm:"type:varchar(50)" json:"featureGroup,omitempty"`
	PermissionScope *string          `gorm:"type:varchar(50)" json:"permissionScope,omitempty"`
	Description     *string          `gorm:"type:text" json:"description,omitempty"`
	DefaultLimit    *decimal.Decimal `gorm:"type:numeric(14,4)" json:"defaultLimit,omitempty"`
	DependsOn       []string         `gorm:"type:varchar(100)[]" json:"dependsOn,omitempty"` // PostgreSQL array
	Version         int              `gorm:"not null;default:1" json:"version"`
	IsActive        bool             `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time        `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time        `gorm:"autoUpdateTime" json:"updatedAt"`
}
