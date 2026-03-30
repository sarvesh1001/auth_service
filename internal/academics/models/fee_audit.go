package models

import (
	"time"

	"github.com/google/uuid"
)

type FeeTransactionAudit struct {
	AuditID   uuid.UUID              `json:"audit_id"`
	PaymentID uuid.UUID              `json:"payment_id"`
	Action    string                 `json:"action"` // created, updated, deleted, refunded
	OldData   map[string]interface{} `json:"old_data"`
	NewData   map[string]interface{} `json:"new_data"`
	ChangedBy *uuid.UUID             `json:"changed_by,omitempty"`
	ChangedAt time.Time              `json:"changed_at"`
}
