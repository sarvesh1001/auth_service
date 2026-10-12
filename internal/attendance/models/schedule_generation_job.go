package models

import (
	"time"

	"github.com/google/uuid"
)

const (
	ScheduleGenJobTypeGenerateUser     = "generate_user"
	ScheduleGenJobTypeGenerateCompany  = "generate_company"
	ScheduleGenJobTypeGeneratePosition = "generate_position"

	ScheduleGenJobStatusQueued     = "queued"
	ScheduleGenJobStatusProcessing = "processing"
	ScheduleGenJobStatusCompleted  = "completed"
	ScheduleGenJobStatusFailed     = "failed"
)

type ScheduleGenerationJob struct {
	JobID        uuid.UUID
	CompanyID    uuid.UUID
	UserID       *uuid.UUID
	PositionID   *uuid.UUID
	LocationID   *uuid.UUID
	JobType      string
	Status       string
	Attempts     int
	MaxAttempts  int
	Priority     int
	Reason       *string
	Payload      []byte
	ErrorMessage *string

	// Per-user outcomes, populated by MarkCompletedWithResult.
	// Raw JSON so the handler can pass them through to the API without
	// re-marshalling.
	Warnings      []byte `json:"warnings,omitempty"`
	Failures      []byte `json:"failures,omitempty"`
	ResultSummary []byte `json:"result_summary,omitempty"`

	CreatedAt   time.Time
	NextRunAt   *time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	LockedBy    *string
	LockedAt    *time.Time
}
