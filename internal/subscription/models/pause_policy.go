package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PausePolicy struct {
	PausePolicyID  uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID      uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name           string         `gorm:"size:100;not null"`
	MaxPauseDays   int            `gorm:"not null;default:0"`
	AllowedReasons []string       `gorm:"type:text[];not null;default:'{}'"` // changed
	FreezeDays     int            `gorm:"not null;default:0"`
	IsActive       bool           `gorm:"not null;default:true"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`
	UpdatedAt      time.Time      `gorm:"not null;default:now()"`
	DeletedAt      gorm.DeletedAt `gorm:"index"`
	Company        Company        `gorm:"foreignKey:CompanyID"`
}

func (PausePolicy) TableName() string { return "pause_policies" }
