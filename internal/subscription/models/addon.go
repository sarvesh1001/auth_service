package models

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Addon struct {
	AddonID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"addonId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	Name            string          `gorm:"type:varchar(255);not null" json:"name"`
	Description     *string         `gorm:"type:text" json:"description,omitempty"`
	BillingPolicyID uuid.UUID       `gorm:"type:uuid;not null" json:"billingPolicyId"`
	Price           decimal.Decimal `gorm:"type:numeric(14,2);not null" json:"price"`
	Currency        string          `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	IsActive        bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt       *time.Time      `gorm:"index" json:"deletedAt,omitempty"`
}
