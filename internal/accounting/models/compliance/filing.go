package compliance

import (
	"time"

	"github.com/google/uuid"
)

type ComplianceFiling struct {
	FilingID          uuid.UUID  `db:"filing_id" json:"filing_id"`
	ReturnID          uuid.UUID  `db:"return_id" json:"return_id"`
	SubmissionDate    time.Time  `db:"submission_date" json:"submission_date"`
	AcknowledgementNo *string    `db:"acknowledgement_no" json:"acknowledgement_no,omitempty"`
	FilingStatus      string     `db:"filing_status" json:"filing_status"` // submitted, accepted, rejected, pending
	ErrorMessage      *string    `db:"error_message" json:"error_message,omitempty"`
	Metadata          []byte     `db:"metadata" json:"metadata,omitempty"` // JSONB
	CreatedBy         *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
}
