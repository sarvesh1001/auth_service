package analytics

import (
	"time"

	"github.com/google/uuid"
)

type ReconciliationDailyStats struct {
	StatID             uuid.UUID `db:"stat_id" json:"stat_id"`
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	ReconciliationType string    `db:"reconciliation_type" json:"reconciliation_type"`
	Date               time.Time `db:"date" json:"date"`

	BatchesStarted   int `db:"batches_started" json:"batches_started"`
	BatchesCompleted int `db:"batches_completed" json:"batches_completed"`

	TotalItemsProcessed int `db:"total_items_processed" json:"total_items_processed"`
	TotalMatched        int `db:"total_matched" json:"total_matched"`
	TotalUnmatched      int `db:"total_unmatched" json:"total_unmatched"`
	TotalIgnored        int `db:"total_ignored" json:"total_ignored"`

	AvgMatchRate         float64 `db:"avg_match_rate" json:"avg_match_rate"`
	AvgCompletionSeconds int     `db:"avg_completion_seconds" json:"avg_completion_seconds"`

	DifferencesCreated    int     `db:"differences_created" json:"differences_created"`
	DifferencesResolved   int     `db:"differences_resolved" json:"differences_resolved"`
	AdjustmentsCreated    int     `db:"adjustments_created" json:"adjustments_created"`
	TotalAdjustmentAmount float64 `db:"total_adjustment_amount" json:"total_adjustment_amount"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}
