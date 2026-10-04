package resolver

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type ScheduleSubjectInfo struct {
	SubjectID          uuid.UUID
	SubjectType        string
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

	// ── NEW: timezone inputs for the resolution chain ──────────────────
	//
	// WorkCenterTimezone is the tz declared on the work center record.
	// CompanyTimezone is the ultimate fallback.
	//
	// The resolver populates these so callers (scheduling, ingest) can
	// compute the effective tz without an extra DB round-trip.
	//
	// If either is empty, the caller MUST still call TimezoneProvider.
	// These are hints, not guarantees.
	WorkCenterTimezone string
	CompanyTimezone    string

	CompanyID uuid.UUID
}

type ScheduleOverrideInfo struct {
	IsOverride     bool
	OverrideType   string
	Reason         *string
	IsOnLeave      bool
	LeaveTypeID    *uuid.UUID
	IsLeavePaid    bool
	LeaveRequestID *uuid.UUID
}

type ScheduleSubjectResolver interface {
	ResolveSubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*ScheduleSubjectInfo, error)
	ResolveOverride(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*ScheduleOverrideInfo, error)
	GetUsersByPosition(ctx context.Context, positionID uuid.UUID) ([]uuid.UUID, error)
	GetActiveSubjectsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}) ([]uuid.UUID, error)
}
