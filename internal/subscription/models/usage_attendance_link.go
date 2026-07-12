package models

import (
	"time"
	"github.com/google/uuid"
)

type UsageAttendanceLink struct {
	LinkID             uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"linkId"`
	UsageID            uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex" json:"usageId"`
	AttendanceEventID  uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex" json:"attendanceEventId"` // attendance.attendance_events
	CreatedAt          time.Time  `gorm:"not null;default:now()" json:"createdAt"`
}
