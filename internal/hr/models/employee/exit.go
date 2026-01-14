package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeExit struct {
	ExitID            uuid.UUID  `json:"exit_id" db:"exit_id"`
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	CompanyID         uuid.UUID  `json:"company_id" db:"company_id"`
	ExitDate          *time.Time `json:"exit_date" db:"exit_date"`
	ExitReason        *string    `json:"exit_reason" db:"exit_reason"`
	EligibleForRehire *bool      `json:"eligible_for_rehire" db:"eligible_for_rehire"`

	ExitState string `json:"exit_state" db:"exit_state"` // scheduled | effective | rehired

	EnforcedAt *time.Time `json:"enforced_at,omitempty" db:"enforced_at"`
	EnforcedBy *uuid.UUID `json:"enforced_by,omitempty" db:"enforced_by"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
