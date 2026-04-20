package analytics

import (
	"time"

	"github.com/google/uuid"
)

type ReconciliationDiffTrends struct {
	TrendID   uuid.UUID  `db:"trend_id" json:"trend_id"`
	CompanyID uuid.UUID  `db:"company_id" json:"company_id"`
	BatchID   *uuid.UUID `db:"batch_id" json:"batch_id,omitempty"`
	IssueType string     `db:"issue_type" json:"issue_type"`
	Date      time.Time  `db:"date" json:"date"`

	Count               int     `db:"count" json:"count"`
	TotalExpectedAmount float64 `db:"total_expected_amount" json:"total_expected_amount"`
	TotalActualAmount   float64 `db:"total_actual_amount" json:"total_actual_amount"`
	TotalVariance       float64 `db:"total_variance" json:"total_variance"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
