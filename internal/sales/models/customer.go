package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes" // recommended for JSONB
)

type Customer struct {
	CustomerID      uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"customerId"`
	CompanyID       uuid.UUID        `gorm:"type:uuid;not null" json:"companyId"`
	CustomerCode    string           `gorm:"type:varchar(50);not null;uniqueIndex:idx_customer_code" json:"customerCode"`
	Name            string           `gorm:"type:varchar(255);not null" json:"name"`
	Email           *string          `gorm:"type:varchar(255)" json:"email,omitempty"`
	Phone           *string          `gorm:"type:varchar(50)" json:"phone,omitempty"`
	TaxID           *string          `gorm:"type:varchar(100)" json:"taxId,omitempty"`
	BillingAddress  datatypes.JSON   `gorm:"type:jsonb" json:"billingAddress,omitempty"`
	ShippingAddress datatypes.JSON   `gorm:"type:jsonb" json:"shippingAddress,omitempty"`
	CreditLimit     *decimal.Decimal `gorm:"type:numeric(14,2);default:0" json:"creditLimit,omitempty"`
	IsActive        bool             `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time        `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time        `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy       *uuid.UUID       `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy       *uuid.UUID       `gorm:"type:uuid" json:"updatedBy,omitempty"`
}

// If you prefer to keep your own JSONB type, define it once in a shared package.
// Here we use datatypes.JSON from GORM.
// JSONB is a helper type for PostgreSQL jsonb; you can use datatypes.JSON from gorm.io/datatypes
type JSONB map[string]interface{}
