package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProrationPolicy struct {
	ProrationPolicyID uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name              string         `gorm:"size:100;not null"`
	UpgradeType       string         `gorm:"size:20;not null;check:upgrade_type IN ('charge_difference','refund','credit_note')"`
	DowngradeType     string         `gorm:"size:20;not null;check:downgrade_type IN ('credit_next','refund','none')"`
	IsActive          bool           `gorm:"not null;default:true"`
	CreatedAt         time.Time      `gorm:"not null;default:now()"`
	UpdatedAt         time.Time      `gorm:"not null;default:now()"`
	DeletedAt         gorm.DeletedAt `gorm:"index"`

	// relationships
	Company Company `gorm:"foreignKey:CompanyID"`
}

func (ProrationPolicy) TableName() string { return "proration_policies" }
