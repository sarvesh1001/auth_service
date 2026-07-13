package resolver

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SubjectType constants (should match models)
const (
	SubjectTypeEmployee = "employee"
	SubjectTypeStudent  = "student"
	SubjectTypeCustomer = "customer"
)

// ResolvedSubject holds all context needed for attendance resolution
type ResolvedSubject struct {
	// Basic
	IsActive bool
	Timezone string

	// Schedule
	ScheduleStatus     string     // "working", "weekly_off", "holiday", "on_leave", "not_schedulable"
	ExpectedStart      *time.Time // local time in the subject's timezone
	ExpectedEnd        *time.Time
	ScheduleInstanceID *uuid.UUID

	// Work Center & Position (for employees)
	WorkCenterCode *string
	PositionID     *uuid.UUID
	DepartmentID   *uuid.UUID

	// Leave context
	IsOnLeave      bool
	IsLeavePaid    bool
	LeaveTypeID    *uuid.UUID
	LeaveRequestID *uuid.UUID

	// Override info
	IsOverride   bool
	OverrideType *string

	// Policies (attendance rules)
	PolicyID    *uuid.UUID
	PolicyCode  *string
	PolicyType  *string
	PolicyRules interface{} // can be *models.PolicyRules or JSON

	// Subscription related (for customers)
	SubscriptionStatus    string     `json:"subscription_status,omitempty"` // "active", "trial", "no_subscription"
	SubscriptionID        *uuid.UUID `json:"subscription_id,omitempty"`
	TrialID               *uuid.UUID `json:"trial_id,omitempty"`
	HasActiveSubscription bool       `json:"has_active_subscription"`
	HasActiveTrial        bool       `json:"has_active_trial"`
}

// SubjectResolver is the main interface for resolving any subject.
type SubjectResolver interface {
	Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error)
}
