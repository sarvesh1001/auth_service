package resolver

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	SubjectTypeEmployee = "employee"
	SubjectTypeStudent  = "student"
	SubjectTypeCustomer = "customer"
)

type ResolvedSubject struct {
	IsActive       bool
	Timezone       string
	ScheduleStatus string
	ExpectedStart  *time.Time
	ExpectedEnd    *time.Time

	// ShiftID is the schedule template chosen for the day by the WC →
	// shift mapping chain. Populated by EmployeeResolver when the fallback
	// path runs. Nil for non-employees and for subjects whose day resolves
	// without a shift mapping.
	ShiftID *uuid.UUID

	WorkCenterCode        *string
	PositionID            *uuid.UUID
	DepartmentID          *uuid.UUID
	IsOnLeave             bool
	IsLeavePaid           bool
	LeaveTypeID           *uuid.UUID
	LeaveRequestID        *uuid.UUID
	IsOverride            bool
	OverrideType          *string
	PolicyID              *uuid.UUID
	PolicyCode            *string
	PolicyType            *string
	PolicyRules           interface{}
	SubscriptionStatus    string     `json:"subscription_status,omitempty"`
	SubscriptionID        *uuid.UUID `json:"subscription_id,omitempty"`
	TrialID               *uuid.UUID `json:"trial_id,omitempty"`
	HasActiveSubscription bool       `json:"has_active_subscription"`
	HasActiveTrial        bool       `json:"has_active_trial"`
}

type SubjectResolver interface {
	Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error)
}
