package service

import (
	"time"

	"github.com/google/uuid"
)

// ShiftContext is a RUNTIME structure (NOT a DB model)
type ShiftContext struct {
	// Business date in schedule timezone
	ScheduleDate time.Time

	// Scheduling state
	ScheduleStatus string // active | weekly_off | holiday | on_leave | not_schedulable
	Timezone       string

	// Shift expectations
	ExpectedStart *time.Time
	ExpectedEnd   *time.Time

	// Shift identity
	ShiftID   *uuid.UUID
	ShiftName *string

	// Org context
	WorkCenterCode *string
	PositionID     *uuid.UUID
	DepartmentID   *uuid.UUID

	// Flags
	IsOnLeave    bool
	IsOverride   bool
	OverrideType *string
}
