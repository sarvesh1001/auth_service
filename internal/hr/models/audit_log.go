// models/audit_log.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	AuditID     uuid.UUID  `db:"audit_id"`
	CompanyID   *uuid.UUID `db:"company_id"`
	Module      string     `db:"module"`
	Action      string     `db:"action"`
	EntityType  string     `db:"entity_type"`
	EntityID    *uuid.UUID `db:"entity_id"`
	ActorType   string     `db:"actor_type"`
	ActorID     *uuid.UUID `db:"actor_id"`
	BeforeState []byte     `db:"before_state"` // JSONB
	AfterState  []byte     `db:"after_state"`  // JSONB
	Metadata    []byte     `db:"metadata"`     // JSONB
	CreatedAt   time.Time  `db:"created_at"`
}
