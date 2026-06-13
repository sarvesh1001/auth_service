package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Customer struct {
	CustomerID   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"customerId"`
	CompanyID    uuid.UUID `gorm:"type:uuid;not null;index" json:"companyId"`
	CustomerCode string    `gorm:"type:varchar(50);not null;uniqueIndex" json:"customerCode"`
	Name         string    `gorm:"type:varchar(255);not null" json:"name"`

	// Encrypted fields – store ciphertext + metadata
	EmailEncrypted *string `gorm:"column:email;type:text" json:"-"`
	EmailDEK       *string `gorm:"column:email_dek;type:text" json:"-"`
	EmailKeyID     *string `gorm:"column:email_key_id;type:text" json:"-"`
	EmailHash      *string `gorm:"column:email_hash;type:varchar(64)" json:"-"`

	PhoneEncrypted *string `gorm:"column:phone;type:text" json:"-"`
	PhoneDEK       *string `gorm:"column:phone_dek;type:text" json:"-"`
	PhoneKeyID     *string `gorm:"column:phone_key_id;type:text" json:"-"`

	TaxIDEncrypted *string `gorm:"column:tax_id;type:text" json:"-"`
	TaxIDDEK       *string `gorm:"column:tax_id_dek;type:text" json:"-"`
	TaxIDKeyID     *string `gorm:"column:tax_id_key_id;type:text" json:"-"`

	BillingAddressEncrypted *string `gorm:"column:billing_address;type:text" json:"-"`
	BillingAddressDEK       *string `gorm:"column:billing_address_dek;type:text" json:"-"`
	BillingAddressKeyID     *string `gorm:"column:billing_address_key_id;type:text" json:"-"`

	ShippingAddressEncrypted *string `gorm:"column:shipping_address;type:text" json:"-"`
	ShippingAddressDEK       *string `gorm:"column:shipping_address_dek;type:text" json:"-"`
	ShippingAddressKeyID     *string `gorm:"column:shipping_address_key_id;type:text" json:"-"`

	// Plaintext fields for API (not stored in DB)
	Email           *string `gorm:"-" json:"email,omitempty"`
	Phone           *string `gorm:"-" json:"phone,omitempty"`
	TaxID           *string `gorm:"-" json:"taxId,omitempty"`
	BillingAddress  *string `gorm:"-" json:"billingAddress,omitempty"`
	ShippingAddress *string `gorm:"-" json:"shippingAddress,omitempty"`

	CreditLimit   *decimal.Decimal `gorm:"type:numeric(14,2);default:0" json:"creditLimit,omitempty"`
	PaymentTermID *uuid.UUID       `gorm:"type:uuid;index" json:"paymentTermId,omitempty"`
	SalesRepID    *uuid.UUID       `gorm:"type:uuid;index" json:"salesRepId,omitempty"` // NEW
	IsActive      bool             `gorm:"not null;default:true" json:"isActive"`
	CreatedAt     time.Time        `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt     time.Time        `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy     *uuid.UUID       `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy     *uuid.UUID       `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
