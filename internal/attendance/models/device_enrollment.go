package models

import (
	"time"

	"github.com/google/uuid"
)

type DeviceEnrollment struct {
	MappingID         uuid.UUID  `json:"mapping_id" db:"mapping_id"`
	CompanyID         uuid.UUID  `json:"company_id" db:"company_id"`
	SubjectType       string     `json:"subject_type" db:"subject_type"`
	SubjectID         uuid.UUID  `json:"subject_id" db:"subject_id"`
	DeviceID          string     `json:"device_id" db:"device_id"`
	SourceType        string     `json:"source_type" db:"source_type"`
	DeviceUserCode    string     `json:"device_user_code" db:"device_user_code"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	EnrollmentVersion int        `json:"enrollment_version" db:"enrollment_version"`
	EnrolledAt        time.Time  `json:"enrolled_at" db:"enrolled_at"`
	UnenrolledAt      *time.Time `json:"unenrolled_at,omitempty" db:"unenrolled_at"`
	RevokedReason     *string    `json:"revoked_reason,omitempty" db:"revoked_reason"`
	RevokedBy         *uuid.UUID `json:"revoked_by,omitempty" db:"revoked_by"`
	CreatedBy         *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}
