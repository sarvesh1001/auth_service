package models

import (
	"time"
)

type FeatureRegistry struct {
	FeatureKey      string    `gorm:"primaryKey;size:100"`
	Module          string    `gorm:"size:50;not null"`
	FeatureGroup    *string   `gorm:"size:50"`
	PermissionScope *string   `gorm:"size:50"`
	Description     *string   `gorm:"type:text"`
	DefaultLimit    *float64  `gorm:"type:numeric(14,4)"`
	DependsOn       []string  `gorm:"type:varchar(100)[];not null;default:'{}'"` // changed
	Version         int       `gorm:"not null;default:1"`
	IsActive        bool      `gorm:"not null;default:true"`
	CreatedAt       time.Time `gorm:"not null;default:now()"`
	UpdatedAt       time.Time `gorm:"not null;default:now()"`
}

func (FeatureRegistry) TableName() string { return "feature_registry" }
