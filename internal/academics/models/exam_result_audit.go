package models

import (
	"time"

	"github.com/google/uuid"
)

// ChangeType defines the type of change made to an exam result.
type ChangeType string

const (
	ChangeInsert ChangeType = "insert"
	ChangeUpdate ChangeType = "update"
	ChangeDelete ChangeType = "delete"
)

// ExamResultAudit tracks changes to exam results.
type ExamResultAudit struct {
	AuditID    uuid.UUID  `json:"audit_id"`
	ResultID   uuid.UUID  `json:"result_id"`
	ChangedBy  uuid.UUID  `json:"changed_by"`
	ChangeType ChangeType `json:"change_type"`
	OldMarks   *float64   `json:"old_marks,omitempty"`
	NewMarks   *float64   `json:"new_marks,omitempty"`
	ChangedAt  time.Time  `json:"changed_at"`
}
