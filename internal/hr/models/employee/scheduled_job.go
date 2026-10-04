package employee

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// HR job types — kept as constants so the SQL CHECK constraint and Go agree.
const (
	JobProbationReminder   = "probation_reminder"
	JobProbationEndReached = "probation_end_reached"
	JobLeaveAccrualMonthly = "leave.accrual.monthly"

	JobNoticeReminder = "notice_reminder" // 👈 NEW — T-3, T-1 before notice end
	JobNoticeExpiry   = "notice_expiry"   // reserved; daily enforcer handles the actual flip

	JobOnHoldReminder = "on_hold_reminder" // 👈 NEW — T-3, T-1 before on-hold end
	JobOnHoldExpiry   = "on_hold_expiry"
)
const (
	JobStatusQueued     = "queued"
	JobStatusProcessing = "processing"
	JobStatusCompleted  = "completed"
	JobStatusFailed     = "failed"
	JobStatusCancelled  = "cancelled"
)

type ScheduledJob struct {
	JobID        uuid.UUID       `json:"job_id"        db:"job_id"`
	CompanyID    uuid.UUID       `json:"company_id"    db:"company_id"`
	UserID       *uuid.UUID      `json:"user_id,omitempty" db:"user_id"`
	JobType      string          `json:"job_type"      db:"job_type"`
	Status       string          `json:"status"        db:"status"`
	RunAt        time.Time       `json:"run_at"        db:"run_at"`
	Attempts     int             `json:"attempts"      db:"attempts"`
	MaxAttempts  int             `json:"max_attempts"  db:"max_attempts"`
	Priority     int             `json:"priority"      db:"priority"`
	Payload      json.RawMessage `json:"payload,omitempty" db:"payload"`
	ErrorMessage *string         `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time       `json:"created_at"    db:"created_at"`
	StartedAt    *time.Time      `json:"started_at,omitempty"    db:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"  db:"completed_at"`
	LockedBy     *string         `json:"locked_by,omitempty"     db:"locked_by"`
	LockedAt     *time.Time      `json:"locked_at,omitempty"     db:"locked_at"`
}

type Reminder struct {
	ReminderID    uuid.UUID  `json:"reminder_id"     db:"reminder_id"`
	CompanyID     uuid.UUID  `json:"company_id"      db:"company_id"`
	RecipientID   uuid.UUID  `json:"recipient_id"    db:"recipient_id"`
	RecipientType string     `json:"recipient_type"  db:"recipient_type"`
	SubjectUserID *uuid.UUID `json:"subject_user_id,omitempty" db:"subject_user_id"`
	LocationID    *uuid.UUID `json:"location_id,omitempty" db:"location_id"`

	ReminderType string  `json:"reminder_type" db:"reminder_type"`
	Severity     string  `json:"severity"      db:"severity"`
	Title        string  `json:"title"         db:"title"`
	Body         *string `json:"body,omitempty" db:"body"`

	ActionType    *string         `json:"action_type,omitempty"    db:"action_type"`
	ActionPayload json.RawMessage `json:"action_payload,omitempty" db:"action_payload"`

	Metadata json.RawMessage `json:"metadata,omitempty" db:"metadata"`

	Status      string     `json:"status"      db:"status"`
	ReadAt      *time.Time `json:"read_at,omitempty"      db:"read_at"`
	ActionedAt  *time.Time `json:"actioned_at,omitempty"  db:"actioned_at"`
	DismissedAt *time.Time `json:"dismissed_at,omitempty" db:"dismissed_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"   db:"expires_at"`

	DedupeKey string    `json:"-" db:"dedupe_key"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Reminder types — kept as constants so SQL strings and Go don't drift.
const (
	ReminderProbationT14       = "probation_reminder_t14"
	ReminderProbationT7        = "probation_reminder_t7"
	ReminderProbationT3        = "probation_reminder_t3"
	ReminderProbationOverdue   = "probation_overdue"
	ReminderOnHoldExpiring     = "on_hold_expiring"
	ReminderNoticeExpiring     = "notice_expiring"
	ReminderProbationConfirmed = "probation_confirmed"
	ReminderProbationFailed    = "probation_failed"
)
