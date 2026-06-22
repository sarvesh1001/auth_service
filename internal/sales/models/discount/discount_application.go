package discount

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DiscountApplication struct {
	ApplicationID  uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"applicationId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null;index" json:"companyId"`
	OrderID        *uuid.UUID      `gorm:"type:uuid" json:"orderId,omitempty"`
	InvoiceID      *uuid.UUID      `gorm:"type:uuid" json:"invoiceId,omitempty"`
	CustomerID     *uuid.UUID      `gorm:"type:uuid;index" json:"customerId,omitempty"` // NEW
	DiscountType   string          `gorm:"type:varchar(50);not null" json:"discountType"`
	DiscountID     *uuid.UUID      `gorm:"type:uuid" json:"discountId,omitempty"`
	AutoDiscountID *uuid.UUID      `gorm:"type:uuid" json:"autoDiscountId,omitempty"`
	DiscountName   *string         `gorm:"type:varchar(255)" json:"discountName,omitempty"`
	Amount         decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"amount"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}

func (DiscountApplication) TableName() string {
	return "sales.discount_applications"
}
