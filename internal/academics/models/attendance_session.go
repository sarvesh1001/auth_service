// models/attendance_session.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceSessionStatus string

const (
	AttendanceSessionCompleted AttendanceSessionStatus = "completed"
)

// AttendanceSession prevents duplicate marking of the same session.
type AttendanceSession struct {
	SessionMarkID uuid.UUID               `json:"session_mark_id"`
	SessionID     uuid.UUID               `json:"session_id"`
	MarkedBy      *uuid.UUID              `json:"marked_by,omitempty"`
	SourceType    *AttendanceSourceType   `json:"source_type,omitempty"`
	Status        AttendanceSessionStatus `json:"status"`
	CreatedAt     time.Time               `json:"created_at"`
}
