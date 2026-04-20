package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PaymentAllocation struct {
	AllocationID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"allocationId"`
	PaymentID    uuid.UUID       `gorm:"type:uuid;not null" json:"paymentId"`
	InvoiceID    uuid.UUID       `gorm:"type:uuid;not null" json:"invoiceId"`
	Amount       decimal.Decimal `gorm:"type:numeric(14,4);not null;check:amount > 0" json:"amount"`
	CreatedAt    time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
