package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Addon struct {
	AddonID         uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name            string         `gorm:"size:255;not null"`
	Description     *string        `gorm:"type:text"`
	BillingPolicyID uuid.UUID      `gorm:"type:uuid;not null"`
	Price           float64        `gorm:"type:numeric(14,2);not null"`
	Currency        string         `gorm:"size:3;not null;default:'USD'"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	Company       Company       `gorm:"foreignKey:CompanyID"`
	BillingPolicy BillingPolicy `gorm:"foreignKey:BillingPolicyID"`
}

func (Addon) TableName() string { return "addons" }
