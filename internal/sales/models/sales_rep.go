package models

import (
	"time"

	"github.com/google/uuid"
)

type SalesRep struct {
	SalesRepID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"salesRepId"`
	CompanyID  uuid.UUID `gorm:"type:uuid;not null;index" json:"companyId"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index" json:"userId"`
	Code       string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_sales_rep_code" json:"code"`
	Name       string    `gorm:"type:varchar(255);not null" json:"name"`

	// -----------------------------------------------------------------
	// Plain fields for API input/output (never stored)
	// -----------------------------------------------------------------
	Email *string `gorm:"-" json:"email,omitempty"`
	Phone *string `gorm:"-" json:"phone,omitempty"`

	// -----------------------------------------------------------------
	// Encrypted storage fields (mapped to database columns)
	// -----------------------------------------------------------------
	// Email encryption
	EmailEncrypted *string `gorm:"column:email;type:text" json:"-"`
	EmailDEK       *string `gorm:"column:email_dek;type:text" json:"-"`
	EmailKeyID     *string `gorm:"column:email_key_id;type:text" json:"-"`
	EmailHash      *string `gorm:"column:email_hash;type:varchar(64)" json:"-"`

	// Phone encryption
	PhoneEncrypted *string `gorm:"column:phone;type:varchar(50)" json:"-"`
	PhoneDEK       *string `gorm:"column:phone_dek;type:text" json:"-"`
	PhoneKeyID     *string `gorm:"column:phone_key_id;type:text" json:"-"`

	// -----------------------------------------------------------------
	// Standard fields
	// -----------------------------------------------------------------
	IsActive  bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
