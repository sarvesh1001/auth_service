package models

import (
	"time"

	"github.com/google/uuid"
)

// UserScheduleWarning is a non-fatal per-user issue: the user was not
// scheduled for one or more days, but the overall job did not fail.
//
// Reason is a stable code clients can switch on. See the switch in
// scheduling_service.generateInstancesForUser for the canonical set.
type UserScheduleWarning struct {
	UserID uuid.UUID  `json:"user_id"`
	Date   *time.Time `json:"date,omitempty"` // nil = range-wide
	Reason string     `json:"reason"`
	Detail string     `json:"detail,omitempty"`
}

// UserScheduleFailure is a hard per-user failure. Reserved for future use
// — currently the generator treats chunk-level insert failures as
// job-level failures, not per-user failures.
type UserScheduleFailure struct {
	UserID uuid.UUID `json:"user_id"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail,omitempty"`
}

// ScheduleGenerationOutcome is the structured result of a generation run.
//
// Lives in the models package (not the scheduling service) so the job
// repository can accept it without importing the service and creating a
// cycle.
type ScheduleGenerationOutcome struct {
	InstancesCreated int                   `json:"instances_created"`
	UsersProcessed   int                   `json:"users_processed"`
	Warnings         []UserScheduleWarning `json:"warnings,omitempty"`
	Failures         []UserScheduleFailure `json:"failures,omitempty"`
}

// HasIssues returns true when the run produced warnings or failures.
// Used by the worker to decide between 'completed' and
// 'completed_with_warnings'.
func (o *ScheduleGenerationOutcome) HasIssues() bool {
	if o == nil {
		return false
	}
	return len(o.Warnings) > 0 || len(o.Failures) > 0
}
