package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PaymentRefund struct {
	RefundID    uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"refundId"`
	CompanyID   uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	PaymentID   uuid.UUID       `gorm:"type:uuid;not null;index" json:"paymentId"`
	ReturnID    *uuid.UUID      `gorm:"type:uuid;index" json:"returnId,omitempty"` // added to link refund to return
	Amount      decimal.Decimal `gorm:"type:numeric(14,4);not null;check:amount > 0" json:"amount"`
	Reason      string          `gorm:"type:text;not null" json:"reason"`
	GatewayRef  *string         `gorm:"type:varchar(100)" json:"gatewayRef,omitempty"`
	Status      string          `gorm:"type:varchar(20);not null;default:'pending'" json:"status"`
	RefundedBy  *uuid.UUID      `gorm:"type:uuid" json:"refundedBy,omitempty"`
	CompletedAt *time.Time      `gorm:"type:timestamptz" json:"completedAt,omitempty"`
	CreatedAt   time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt   time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
}
