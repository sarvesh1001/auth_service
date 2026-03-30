package models

import (
	"time"

	"github.com/google/uuid"
)

type IssueStatus string

const (
	IssueStatusIssued   IssueStatus = "issued"
	IssueStatusReturned IssueStatus = "returned"
	IssueStatusOverdue  IssueStatus = "overdue"
	IssueStatusLost     IssueStatus = "lost"
)

func IsValidIssueStatus(s string) bool {
	switch IssueStatus(s) {
	case IssueStatusIssued, IssueStatusReturned, IssueStatusOverdue, IssueStatusLost:
		return true
	default:
		return false
	}
}

type LibraryIssue struct {
	IssueID      uuid.UUID   `json:"issue_id"`
	CopyID       uuid.UUID   `json:"copy_id"`
	StudentID    uuid.UUID   `json:"student_id"`
	IssueDate    time.Time   `json:"issue_date"`
	DueDate      time.Time   `json:"due_date"`
	ReturnedDate *time.Time  `json:"returned_date,omitempty"`
	Status       IssueStatus `json:"status"`
	IssuedBy     *uuid.UUID  `json:"issued_by,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	CreatedBy    *uuid.UUID  `json:"created_by,omitempty"`
}
