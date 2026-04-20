package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type TaxSnapshot struct {
	TaxSnapshotID uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"taxSnapshotId"`
	CompanyID     uuid.UUID        `gorm:"type:uuid;not null" json:"companyId"`
	EntityType    string           `gorm:"type:varchar(20);not null" json:"entityType"`
	EntityID      uuid.UUID        `gorm:"type:uuid;not null" json:"entityId"`
	LineID        *uuid.UUID       `gorm:"type:uuid" json:"lineId,omitempty"`
	TaxRateID     *uuid.UUID       `gorm:"type:uuid" json:"taxRateId,omitempty"`
	TaxName       *string          `gorm:"type:varchar(100)" json:"taxName,omitempty"`
	TaxPercentage *decimal.Decimal `gorm:"type:numeric(5,2)" json:"taxPercentage,omitempty"`
	TaxableAmount decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"taxableAmount"`
	TaxAmount     decimal.Decimal  `gorm:"type:numeric(14,4);not null" json:"taxAmount"`
	CreatedAt     time.Time        `gorm:"not null;default:now()" json:"createdAt"`
}
