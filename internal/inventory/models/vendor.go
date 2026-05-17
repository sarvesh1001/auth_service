// models/vendor.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type Vendor struct {
	VendorID   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"vendorId"`
	CompanyID  uuid.UUID `gorm:"type:uuid;not null" json:"companyId"`
	VendorCode string    `gorm:"type:varchar(50);not null" json:"vendorCode"`
	VendorName string    `gorm:"type:varchar(255);not null" json:"vendorName"`
	VendorType *string   `gorm:"type:varchar(50)" json:"vendorType,omitempty"`

	// Encrypted fields (plaintext will be stored in these variables for app use)
	ContactPerson   string `json:"contactPerson,omitempty"`
	Phone           string `json:"phone,omitempty"`
	Email           string `json:"email,omitempty"`
	Address         string `json:"address,omitempty"`
	BankAccountNo   string `json:"bankAccountNo,omitempty"`
	BankRoutingCode string `json:"bankRoutingCode,omitempty"`
	BankName        string `json:"bankName,omitempty"`

	// Database encrypted columns (for GORM or manual mapping)
	ContactPersonEnc   string `gorm:"column:contact_person"`
	ContactPersonDEK   string `gorm:"column:contact_person_dek"`
	ContactPersonKeyID string `gorm:"column:contact_person_key_id"`

	PhoneEnc   string `gorm:"column:phone"`
	PhoneDEK   string `gorm:"column:phone_dek"`
	PhoneKeyID string `gorm:"column:phone_key_id"`

	EmailEnc   string `gorm:"column:email"`
	EmailDEK   string `gorm:"column:email_dek"`
	EmailKeyID string `gorm:"column:email_key_id"`

	AddressEnc   string `gorm:"column:address"`
	AddressDEK   string `gorm:"column:address_dek"`
	AddressKeyID string `gorm:"column:address_key_id"`

	BankAccountEnc   string `gorm:"column:bank_account_no"`
	BankAccountDEK   string `gorm:"column:bank_account_no_dek"`
	BankAccountKeyID string `gorm:"column:bank_account_no_key_id"`

	BankRoutingEnc   string `gorm:"column:bank_routing_code"`
	BankRoutingDEK   string `gorm:"column:bank_routing_code_dek"`
	BankRoutingKeyID string `gorm:"column:bank_routing_code_key_id"`

	BankNameEnc   string `gorm:"column:bank_name"`
	BankNameDEK   string `gorm:"column:bank_name_dek"`
	BankNameKeyID string `gorm:"column:bank_name_key_id"`

	IsActive  bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
	DeletedAt *time.Time `gorm:"type:timestamptz" json:"deletedAt,omitempty"`
}

func (Vendor) TableName() string { return "vendors" }
