package compliance

import (
	"time"

	"github.com/google/uuid"
)

type ComplianceAuditLog struct {
	AuditID   uuid.UUID  `db:"audit_id" json:"audit_id"`
	CompanyID uuid.UUID  `db:"company_id" json:"company_id"`
	ReturnID  *uuid.UUID `db:"return_id" json:"return_id,omitempty"`
	Action    string     `db:"action" json:"action"`
	OldState  []byte     `db:"old_state" json:"old_state,omitempty"` // JSONB
	NewState  []byte     `db:"new_state" json:"new_state,omitempty"` // JSONB
	ActedBy   *uuid.UUID `db:"acted_by" json:"acted_by,omitempty"`
	ActedAt   time.Time  `db:"acted_at" json:"acted_at"`
	IPAddress *string    `db:"ip_address" json:"ip_address,omitempty"`
}
