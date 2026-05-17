// models/vendor_tax_identifier.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type VendorTaxIdentifier struct {
	TaxID     uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"taxId"`
	VendorID  uuid.UUID `gorm:"type:uuid;not null" json:"vendorId"`
	TaxType   string    `gorm:"type:varchar(50);not null" json:"taxType"`
	TaxNumber string    `json:"taxNumber"` // plaintext
	// Encrypted columns
	TaxNumberEnc   string     `gorm:"column:tax_number"`
	TaxNumberDEK   string     `gorm:"column:tax_number_dek"`
	TaxNumberKeyID string     `gorm:"column:tax_number_key_id"`
	IsPrimary      bool       `gorm:"not null;default:false" json:"isPrimary"`
	CreatedAt      time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	CreatedBy      *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
}

func (VendorTaxIdentifier) TableName() string { return "vendor_tax_identifiers" }
