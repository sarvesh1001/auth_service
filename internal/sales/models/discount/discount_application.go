package discount

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DiscountApplication struct {
	ApplicationID uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"applicationId"`
	OrderID       *uuid.UUID      `gorm:"type:uuid" json:"orderId,omitempty"`
	InvoiceID     *uuid.UUID      `gorm:"type:uuid" json:"invoiceId,omitempty"`
	DiscountType  string          `gorm:"type:varchar(50);not null" json:"discountType"`
	DiscountID    *uuid.UUID      `gorm:"type:uuid" json:"discountId,omitempty"`
	DiscountName  *string         `gorm:"type:varchar(255)" json:"discountName,omitempty"`
	Amount        decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"amount"`
	CreatedAt     time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
