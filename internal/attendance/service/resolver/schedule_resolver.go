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
	PositionLocationID *uuid.UUID // ← NEW
	IsSchedulable      bool
	AttendanceRequired bool
	OvertimeAllowed    bool
	DepartmentID       *uuid.UUID
	DepartmentName     string
	WorkCenterCode     *string
	WorkCenterName     string
	WorkCenterTimezone string
	CompanyTimezone    string
	PrimaryLocationID  *uuid.UUID
	CompanyID          uuid.UUID
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

	// GetUsersByPosition — company-scoped. Position IDs are only unique
	// within a company, so the caller must supply the tenant.
	GetUsersByPosition(ctx context.Context, companyID, positionID uuid.UUID) ([]uuid.UUID, error)

	GetActiveSubjectsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}) ([]uuid.UUID, error)
}
