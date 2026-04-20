package analytics

import (
	"time"

	"github.com/google/uuid"
)

type ReconciliationBatchMetrics struct {
	MetricID           uuid.UUID `db:"metric_id" json:"metric_id"`
	BatchID            uuid.UUID `db:"batch_id" json:"batch_id"`
	CompanyID          uuid.UUID `db:"company_id" json:"company_id"`
	ReconciliationType string    `db:"reconciliation_type" json:"reconciliation_type"`

	TotalItems     int     `db:"total_items" json:"total_items"`
	MatchedItems   int     `db:"matched_items" json:"matched_items"`
	UnmatchedItems int     `db:"unmatched_items" json:"unmatched_items"`
	IgnoredItems   int     `db:"ignored_items" json:"ignored_items"`
	MatchRate      float64 `db:"match_rate" json:"match_rate"`

	StartedAt                 *time.Time `db:"started_at" json:"started_at,omitempty"`
	CompletedAt               *time.Time `db:"completed_at" json:"completed_at,omitempty"`
	CompletionDurationSeconds *int       `db:"completion_duration_seconds" json:"completion_duration_seconds,omitempty"`

	TotalDifferences    int     `db:"total_differences" json:"total_differences"`
	ResolvedDifferences int     `db:"resolved_differences" json:"resolved_differences"`
	TotalAdjustments    int     `db:"total_adjustments" json:"total_adjustments"`
	AdjustmentAmount    float64 `db:"adjustment_amount" json:"adjustment_amount"` // decimal stored as float64 in JSON

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}
