package sales_analytics

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
)

// QuoteStatusHistory tracks the time spent in each quote status.
type QuoteStatusHistory struct {
	HistoryID       int64             `gorm:"primaryKey;autoIncrement" json:"historyId"`
	QuoteID         uuid.UUID         `gorm:"type:uuid;not null;index" json:"quoteId"`
	CompanyID       uuid.UUID         `gorm:"type:uuid;not null;index" json:"companyId"`
	Status          enums.QuoteStatus `gorm:"type:sales.quote_status;not null" json:"status"`
	EnteredAt       time.Time         `gorm:"type:timestamptz;not null" json:"enteredAt"`
	ExitedAt        *time.Time        `gorm:"type:timestamptz" json:"exitedAt,omitempty"`
	DurationSeconds int64             `gorm:"->" json:"durationSeconds"` // generated column
	CreatedAt       time.Time         `gorm:"default:now()" json:"createdAt"`
}

func (QuoteStatusHistory) TableName() string {
	return "sales_analytics.quote_status_history"
}
