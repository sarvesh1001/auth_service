// models/student_biometric_mapping.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// StudentBiometricMapping links a student to a biometric device user code.
type StudentBiometricMapping struct {
	MappingID      uuid.UUID  `json:"mapping_id"`
	StudentID      uuid.UUID  `json:"student_id"`
	CompanyID      uuid.UUID  `json:"company_id"`
	DeviceID       string     `json:"device_id"` // references public.attendance_devices.device_id
	DeviceUserCode string     `json:"device_user_code"`
	IsActive       bool       `json:"is_active"`
	EnrolledAt     time.Time  `json:"enrolled_at"`
	EnrolledBy     *uuid.UUID `json:"enrolled_by,omitempty"`
}
