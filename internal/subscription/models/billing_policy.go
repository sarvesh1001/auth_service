package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BillingPolicy struct {
	BillingPolicyID  uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID        uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name             string         `gorm:"size:100;not null"`
	BillingTypeID    int16          `gorm:"not null"`
	BillingFrequency *int           `gorm:"default:null"`
	AdvanceDays      int            `gorm:"not null;default:0"`
	IsActive         bool           `gorm:"not null;default:true"`
	CreatedAt        time.Time      `gorm:"not null;default:now()"`
	UpdatedAt        time.Time      `gorm:"not null;default:now()"`
	DeletedAt        gorm.DeletedAt `gorm:"index"`

	// relationships
	Company     Company      `gorm:"foreignKey:CompanyID"`
	BillingType BillingType  `gorm:"foreignKey:BillingTypeID"`
}

func (BillingPolicy) TableName() string { return "billing_policies" }
