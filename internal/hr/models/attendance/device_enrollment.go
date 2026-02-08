package attendance

import (
	"time"

	"github.com/google/uuid"
)

// UserDeviceIdentifier represents the enrollment of a user to a device
type UserDeviceIdentifier struct {
	MappingID         uuid.UUID  `json:"mapping_id" db:"mapping_id"`
	CompanyID         uuid.UUID  `json:"company_id" db:"company_id"`
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	DeviceID          string     `json:"device_id" db:"device_id"`
	SourceType        string     `json:"source_type" db:"source_type"`
	DeviceUserCode    string     `json:"device_user_code" db:"device_user_code"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	EnrollmentVersion int        `json:"enrollment_version" db:"enrollment_version"`
	EnrolledAt        time.Time  `json:"enrolled_at" db:"enrolled_at"`
	UnenrolledAt      *time.Time `json:"unenrolled_at,omitempty" db:"unenrolled_at"`
	RevokedReason     *string    `json:"revoked_reason,omitempty" db:"revoked_reason"`
	RevokedBy         *uuid.UUID // ✅ ADD
	CreatedBy         *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// DeviceEnrollmentRequest represents a request to enroll a user
type DeviceEnrollmentRequest struct {
	UserID         uuid.UUID `json:"user_id"`
	DeviceUserCode string    `json:"device_user_code"`
	SourceType     string    `json:"source_type"`
}

// DeviceEnrollmentRevokeRequest represents a request to revoke enrollment
type DeviceEnrollmentRevokeRequest struct {
	DeviceUserCode string `json:"device_user_code"`
	SourceType     string `json:"source_type"` // ✅ REQUIRED
	Reason         string `json:"reason"`
}

// DeviceEnrollmentResponse represents enrollment response
type DeviceEnrollmentResponse struct {
	MappingID      uuid.UUID `json:"mapping_id"`
	UserID         uuid.UUID `json:"user_id"`
	DeviceID       string    `json:"device_id"`
	DeviceUserCode string    `json:"device_user_code"`
	SourceType     string    `json:"source_type"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	EnrolledBy     uuid.UUID `json:"enrolled_by"`
}
