package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PaymentTerm struct {
	TermID          uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"termId"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	Code            string          `gorm:"type:varchar(50);not null;uniqueIndex:unique_payment_terms_code,priority:2" json:"code"`
	TermName        string          `gorm:"type:varchar(100);not null;uniqueIndex:unique_payment_terms_name,priority:2" json:"termName"`
	Description     *string         `gorm:"type:text" json:"description,omitempty"`
	DueDays         int             `gorm:"not null" json:"dueDays"`
	DiscountPercent decimal.Decimal `gorm:"type:numeric(5,2);default:0" json:"discountPercent"`
	DiscountDays    int             `gorm:"default:0" json:"discountDays"`
	IsActive        bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy       *uuid.UUID      `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy       *uuid.UUID      `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
