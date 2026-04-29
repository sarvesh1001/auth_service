// FILE: ./models/reconciliation_batch.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type ReconciliationBatch struct {
	BatchID            uuid.UUID  `db:"batch_id" json:"batch_id"`
	CompanyID          uuid.UUID  `db:"company_id" json:"company_id"`
	ReconciliationType string     `db:"reconciliation_type" json:"reconciliation_type"` // bank, payment, ledger, external
	Reference          *string    `db:"reference" json:"reference,omitempty"`
	StartDate          *time.Time `db:"start_date" json:"start_date,omitempty"`
	EndDate            *time.Time `db:"end_date" json:"end_date,omitempty"`
	Status             string     `db:"status" json:"status"` // pending, in_progress, completed, failed
	TotalRecords       int        `db:"total_records" json:"total_records"`
	MatchedRecords     int        `db:"matched_records" json:"matched_records"`
	FailureReason      *string    `db:"failure_reason" json:"failure_reason,omitempty"`
	UnmatchedRecords   int        `db:"unmatched_records" json:"unmatched_records"`
	CreatedAt          time.Time  `db:"created_at" json:"created_at"`
	CompletedAt        *time.Time `db:"completed_at" json:"completed_at,omitempty"`
	CreatedBy          *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
}
