package models

import (
	"time"

	"github.com/google/uuid"
)

type SubmissionStatus string

const (
	SubmissionSubmitted SubmissionStatus = "submitted"
	SubmissionLate      SubmissionStatus = "late"
	SubmissionGraded    SubmissionStatus = "graded"
	SubmissionReturned  SubmissionStatus = "returned"
)

type AssignmentSubmission struct {
	SubmissionID   uuid.UUID        `json:"submission_id"`
	AssignmentID   uuid.UUID        `json:"assignment_id"`
	StudentID      uuid.UUID        `json:"student_id"`
	SubmissionDate time.Time        `json:"submission_date"`
	FileURL        string           `json:"file_url,omitempty"`
	Remarks        string           `json:"remarks,omitempty"`
	Status         SubmissionStatus `json:"status"`
	MarksObtained  *float64         `json:"marks_obtained,omitempty"`
	Feedback       string           `json:"feedback,omitempty"`
	GradedBy       *uuid.UUID       `json:"graded_by,omitempty"`
	GradedAt       *time.Time       `json:"graded_at,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	// CreatedBy removed – student is identified via student_id
}
