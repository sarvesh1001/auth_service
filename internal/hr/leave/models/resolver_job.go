package models

import (
	"time"

	"github.com/google/uuid"
)

const (
	ResolverJobTypeResolveUser     = "resolve_user"
	ResolverJobTypeResolveCompany  = "resolve_company"
	ResolverJobTypeResolvePosition = "resolve_position"
	ResolverJobTypeEndEntitlements = "end_entitlements"

	ResolverJobStatusQueued     = "queued"
	ResolverJobStatusProcessing = "processing"
	ResolverJobStatusCompleted  = "completed"
	ResolverJobStatusFailed     = "failed"
	ResolverJobStatusCancelled  = "cancelled"
)

// ResolverJob mirrors a row in leave.resolver_job.
type ResolverJob struct {
	JobID        uuid.UUID  `db:"job_id"`
	CompanyID    uuid.UUID  `db:"company_id"`
	UserID       *uuid.UUID `db:"user_id"`
	PositionID   *uuid.UUID `db:"position_id"`
	JobType      string     `db:"job_type"`
	Status       string     `db:"status"`
	Attempts     int        `db:"attempts"`
	MaxAttempts  int        `db:"max_attempts"`
	Priority     int        `db:"priority"`
	Reason       *string    `db:"reason"`
	ErrorMessage *string    `db:"error_message"`
	Payload      []byte     `db:"payload"`
	CreatedAt    time.Time  `db:"created_at"`
	NextRunAt    *time.Time `db:"next_run_at"`
	StartedAt    *time.Time `db:"started_at"`
	CompletedAt  *time.Time `db:"completed_at"`
	LockedBy     *string    `db:"locked_by"`
	LockedAt     *time.Time `db:"locked_at"`
}
