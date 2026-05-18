package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Payment struct {
	PaymentID       uuid.UUID           `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"paymentId"`
	CompanyID       uuid.UUID           `gorm:"type:uuid;not null;index" json:"companyId"`
	PaymentNumber   string              `gorm:"type:varchar(50);not null;uniqueIndex" json:"paymentNumber"`
	ExternalRef     *string             `gorm:"type:varchar(100)" json:"externalRef,omitempty"`
	PaymentDate     time.Time           `gorm:"type:date;not null" json:"paymentDate"`
	Amount          decimal.Decimal     `gorm:"type:numeric(14,4);not null;check:amount > 0" json:"amount"`
	PaymentMethod   enums.PaymentMethod `gorm:"type:payment_method;not null" json:"paymentMethod"`
	Status          enums.PaymentStatus `gorm:"type:payment_status;not null;default:'pending';check:status IN ('pending','processing','completed','failed','refunded','partially_refunded')" json:"status"`
	ExchangeRate    *decimal.Decimal    `gorm:"type:numeric(14,6);default:1" json:"exchangeRate,omitempty"`
	Reference       *string             `gorm:"type:varchar(100)" json:"reference,omitempty"`
	GatewayResponse JSONB               `gorm:"type:jsonb" json:"gatewayResponse,omitempty"`
	FailureReason   *string             `gorm:"type:text" json:"failureReason,omitempty"`
	CompletedAt     *time.Time          `gorm:"type:timestamptz" json:"completedAt,omitempty"`
	RefundedAmount  decimal.Decimal     `gorm:"type:numeric(14,4);default:0" json:"refundedAmount"` // NOT a pointer
	CreatedAt       time.Time           `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time           `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy       *uuid.UUID          `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy       *uuid.UUID          `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
