package events

import "time"

const (
	EventReconciliationBatchCreated      = "reconciliation.batch.created"
	EventReconciliationBatchCompleted    = "reconciliation.batch.completed"
	EventReconciliationAutoMatched       = "reconciliation.auto.matched"
	EventReconciliationDifferenceCreated = "reconciliation.difference.created"
)

type ReconciliationBatchPayload struct {
	BatchID            string    `json:"batch_id"`
	CompanyID          string    `json:"company_id"`
	ReconciliationType string    `json:"reconciliation_type"`
	Status             string    `json:"status"`
	TotalRecords       int       `json:"total_records"`
	MatchedRecords     int       `json:"matched_records,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	CompletedAt        time.Time `json:"completed_at,omitempty"`
}

type ReconciliationAutoMatchPayload struct {
	BatchID         string `json:"batch_id"`
	MatchedCount    int    `json:"matched_count"`
	TotalCandidates int    `json:"total_candidates"`
	Threshold       string `json:"threshold"`
}

type ReconciliationDifferencePayload struct {
	DifferenceID   string `json:"difference_id"`
	BatchID        string `json:"batch_id"`
	IssueType      string `json:"issue_type"`
	ExpectedAmount string `json:"expected_amount"`
	ActualAmount   string `json:"actual_amount"`
	Resolved       bool   `json:"resolved"`
}
