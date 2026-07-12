package models

import (
	"time"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type SubscriptionInvoiceItemMap struct {
	MapID               uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"mapId"`
	SubscriptionItemID  uuid.UUID       `gorm:"type:uuid;not null;index" json:"subscriptionItemId"`
	InvoiceItemID       uuid.UUID       `gorm:"type:uuid;not null;index" json:"invoiceItemId"` // sales.invoice_items
	AllocatedQuantity   decimal.Decimal `gorm:"type:numeric(14,4);not null;default:1" json:"allocatedQuantity"`
	CreatedAt           time.Time       `gorm:"not null;default:now()" json:"createdAt"`
}
