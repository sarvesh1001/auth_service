package models

import (
	"time"

	"github.com/google/uuid"
)

type AdmissionStatus string

const (
	AdmissionStatusPending  AdmissionStatus = "pending"
	AdmissionStatusApproved AdmissionStatus = "approved"
	AdmissionStatusRejected AdmissionStatus = "rejected"
)

// IsValidAdmissionStatus checks if a string is a valid admission status.
func IsValidAdmissionStatus(s string) bool {
	switch AdmissionStatus(s) {
	case AdmissionStatusPending, AdmissionStatusApproved, AdmissionStatusRejected:
		return true
	default:
		return false
	}
}

type Admission struct {
	AdmissionID     uuid.UUID       `json:"admission_id"`
	StudentID       uuid.UUID       `json:"student_id"`
	AcademicYearID  uuid.UUID       `json:"academic_year_id"`
	AdmissionDate   time.Time       `json:"admission_date"`
	ClassAppliedFor string          `json:"class_applied_for,omitempty"`
	AdmissionStatus AdmissionStatus `json:"admission_status"`
	Remarks         string          `json:"remarks,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	CreatedBy       *uuid.UUID      `json:"created_by,omitempty"`
}
