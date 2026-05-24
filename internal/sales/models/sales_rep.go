package models

import (
	"time"

	"github.com/google/uuid"
)

type SalesRep struct {
	SalesRepID uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"salesRepId"`
	CompanyID  uuid.UUID  `gorm:"type:uuid;not null;index" json:"companyId"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index" json:"userId"`
	Code       string     `gorm:"type:varchar(50);not null;uniqueIndex:idx_sales_rep_code" json:"code"`
	Name       string     `gorm:"type:varchar(255);not null" json:"name"`
	Email      *string    `gorm:"type:varchar(255)" json:"email,omitempty"`
	Phone      *string    `gorm:"type:varchar(50)" json:"phone,omitempty"`
	IsActive   bool       `gorm:"not null;default:true" json:"isActive"`
	CreatedAt  time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt  time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy  *uuid.UUID `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy  *uuid.UUID `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
