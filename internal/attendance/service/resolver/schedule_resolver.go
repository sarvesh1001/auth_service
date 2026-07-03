package resolver

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ScheduleSubjectInfo provides all schedule-related data for a subject.
type ScheduleSubjectInfo struct {
	SubjectID          uuid.UUID
	SubjectType        string // "employee", "student", etc.
	IsActive           bool
	PositionID         *uuid.UUID
	PositionTitle      string
	IsSchedulable      bool
	AttendanceRequired bool
	OvertimeAllowed    bool
	DepartmentID       *uuid.UUID
	DepartmentName     string
	WorkCenterCode     *string
	WorkCenterName     string
	WorkCenterTimezone string
	CompanyID          uuid.UUID
}

// ScheduleOverrideInfo provides override/leave info.
type ScheduleOverrideInfo struct {
	IsOverride     bool
	OverrideType   string // "off", "force_work", "holiday_override"
	Reason         *string
	IsOnLeave      bool
	LeaveTypeID    *uuid.UUID
	IsLeavePaid    bool
	LeaveRequestID *uuid.UUID
}

// ScheduleSubjectResolver resolves schedule-related info for a subject.
type ScheduleSubjectResolver interface {
	// ResolveSubject returns schedule-relevant data for a subject on a given date.
	ResolveSubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*ScheduleSubjectInfo, error)

	// ResolveOverride returns override/leave info for a subject on a given date.
	ResolveOverride(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*ScheduleOverrideInfo, error)

	// GetUsersByPosition returns subject IDs assigned to a given position.
	GetUsersByPosition(ctx context.Context, positionID uuid.UUID) ([]uuid.UUID, error)

	// GetActiveSubjectsByCompany returns active subject IDs for a company (optionally filtered by position/work center).
	GetActiveSubjectsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}) ([]uuid.UUID, error)
}
