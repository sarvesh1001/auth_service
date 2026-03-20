package audit

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
type AuditLogEvent struct {
	EventID     string      `json:"event_id"`
	AuditID     string      `json:"audit_id"`
	Timestamp   time.Time   `json:"timestamp"`
	EventType   string      `json:"event_type"` // Always "audit"
	CompanyID   *string     `json:"company_id,omitempty"`
	Module      string      `json:"module"`      // hr, attendance, leave, payroll, admin, system
	Action      string      `json:"action"`      // leave.approve, attendance.manual_add, etc.
	EntityType  string      `json:"entity_type"` // leave_request, attendance_event, etc.
	EntityID    *string     `json:"entity_id,omitempty"`
	ActorType   string      `json:"actor_type"` // user, admin, system
	ActorID     *string     `json:"actor_id,omitempty"`
	BeforeState interface{} `json:"before_state,omitempty"`
	AfterState  interface{} `json:"after_state,omitempty"`
	Metadata    interface{} `json:"metadata,omitempty"`
	Environment string      `json:"environment"`
	Version     string      `json:"version"`
	Message     string      `json:"message"`
	ServiceName string      `json:"service_name"`
}
