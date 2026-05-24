// FILE: internal/sales/models/sales_analytics/invoice_status_history.go

package sales_analytics

import (
	"time"

	"github.com/google/uuid"

	"auth-service/internal/sales/models/enums"
)

type InvoiceStatusHistory struct {
	HistoryID       int64               `gorm:"primaryKey;autoIncrement" json:"historyId"`
	InvoiceID       uuid.UUID           `gorm:"type:uuid;not null;index" json:"invoiceId"`
	CompanyID       uuid.UUID           `gorm:"type:uuid;not null;index" json:"companyId"`
	Status          enums.InvoiceStatus `gorm:"type:sales.invoice_status;not null" json:"status"`
	EnteredAt       time.Time           `gorm:"type:timestamptz;not null" json:"enteredAt"`
	ExitedAt        *time.Time          `gorm:"type:timestamptz" json:"exitedAt,omitempty"`
	DurationSeconds int64               `gorm:"->" json:"durationSeconds"` // computed
	CreatedAt       time.Time           `gorm:"default:now()" json:"createdAt"`
}

func (InvoiceStatusHistory) TableName() string {
	return "sales_analytics.invoice_status_history"
}
