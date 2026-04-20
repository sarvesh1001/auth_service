// models/student_session_attendance.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type SessionAttendanceStatus string

const (
	SessionPresent SessionAttendanceStatus = "present"
	SessionAbsent  SessionAttendanceStatus = "absent"
	SessionLate    SessionAttendanceStatus = "late"
	SessionExcused SessionAttendanceStatus = "excused"
)

// StudentSessionAttendance represents period-wise attendance per student.
type StudentSessionAttendance struct {
	AttendanceID uuid.UUID               `json:"attendance_id"`
	SessionID    uuid.UUID               `json:"session_id"`
	EnrollmentID uuid.UUID               `json:"enrollment_id"`
	Status       SessionAttendanceStatus `json:"status"`
	MarkedAt     time.Time               `json:"marked_at"`
	MarkedBy     *uuid.UUID              `json:"marked_by,omitempty"`
	SourceType   AttendanceSourceType    `json:"source_type"` // web, biometric, manual, classroom
	DeviceID     *string                 `json:"device_id,omitempty"`
	IsAuto       bool                    `json:"is_auto"` // true = biometric auto-mark
	Remarks      string                  `json:"remarks,omitempty"`
	CreatedAt    time.Time               `json:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at"`
}
