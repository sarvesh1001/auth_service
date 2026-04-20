package analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type JournalMetric struct {
	MetricID     uuid.UUID       `db:"metric_id" json:"metric_id"`
	CompanyID    uuid.UUID       `db:"company_id" json:"company_id"`
	JournalType  *string         `db:"journal_type" json:"journal_type,omitempty"`
	Date         time.Time       `db:"date" json:"date"`
	TotalEntries int             `db:"total_entries" json:"total_entries"`
	TotalAmount  decimal.Decimal `db:"total_amount" json:"total_amount"`
	CreatedAt    time.Time       `db:"created_at" json:"created_at"`
}
