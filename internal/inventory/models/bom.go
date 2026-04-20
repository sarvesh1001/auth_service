package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type BOM struct {
	BOMID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"bomId"`
	CompanyID     uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	ProductItemID uuid.UUID       `gorm:"type:uuid;not null" json:"productItemId"`
	BOMCode       string          `gorm:"type:varchar(100);not null" json:"bomCode"`
	Name          string          `gorm:"type:varchar(255);not null" json:"name"`
	Version       int             `gorm:"not null;default:1" json:"version"`
	Quantity      decimal.Decimal `gorm:"type:numeric(14,4);not null;default:1" json:"quantity"`
	IsActive      bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt     time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt     time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy     *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy     *uuid.UUID      `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
