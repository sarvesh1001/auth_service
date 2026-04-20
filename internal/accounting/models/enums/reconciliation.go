// FILE: ./models/enums/reconciliation.go
package enums

const (
	ReconciliationTypeBank     = "bank"
	ReconciliationTypePayment  = "payment"
	ReconciliationTypeLedger   = "ledger"
	ReconciliationTypeExternal = "external"
)

var ValidReconciliationTypes = []string{
	ReconciliationTypeBank, ReconciliationTypePayment,
	ReconciliationTypeLedger, ReconciliationTypeExternal,
}

const (
	ReconciliationStatusPending    = "pending"
	ReconciliationStatusInProgress = "in_progress"
	ReconciliationStatusCompleted  = "completed"
	ReconciliationStatusFailed     = "failed"
)

var ValidReconciliationStatuses = []string{
	ReconciliationStatusPending, ReconciliationStatusInProgress,
	ReconciliationStatusCompleted, ReconciliationStatusFailed,
}

const (
	MatchStatusMatched   = "matched"
	MatchStatusUnmatched = "unmatched"
	MatchStatusPartial   = "partial"
	MatchStatusIgnored   = "ignored"
)

var ValidMatchStatuses = []string{
	MatchStatusMatched, MatchStatusUnmatched, MatchStatusPartial, MatchStatusIgnored,
}

const (
	IssueTypeMissingEntry     = "missing_entry"
	IssueTypeAmountMismatch   = "amount_mismatch"
	IssueTypeDuplicate        = "duplicate"
	IssueTypeTimingDifference = "timing_difference"
)

var ValidIssueTypes = []string{
	IssueTypeMissingEntry, IssueTypeAmountMismatch,
	IssueTypeDuplicate, IssueTypeTimingDifference,
}
