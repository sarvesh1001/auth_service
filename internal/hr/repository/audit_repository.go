package repository

import (
	"auth-service/internal/hr/models"
	"context"
	"time"

	"github.com/google/uuid"
)

// AuditRepository defines the interface for audit logging storage operations
// This is a BORING, STORAGE-ONLY interface. No business logic here.
type AuditRepository interface {
	// ==============================================
	// APPEND-ONLY WRITE OPERATIONS
	// ==============================================

	// CreateAuditLog creates a single audit log entry
	// This is append-only - no updates or deletes allowed
	CreateAuditLog(ctx context.Context, log *models.AuditLog) error

	// CreateAuditLogBatch creates multiple audit log entries in a single transaction
	// Used for bulk operations or event sourcing
	CreateAuditLogBatch(ctx context.Context, logs []*models.AuditLog) error

	// ==============================================
	// READ OPERATIONS (STORAGE-ONLY, NO BUSINESS LOGIC)
	// ==============================================

	// GetAuditLogByID retrieves a single audit log by its unique ID
	GetAuditLogByID(ctx context.Context, auditID uuid.UUID) (*models.AuditLog, error)

	// ListAuditLogs retrieves audit logs with filtering and pagination
	// Returns: logs, total count, error
	// Total count is for ALL matching records (not just current page)
	ListAuditLogs(
		ctx context.Context,
		filter AuditLogFilter,
	) ([]*models.AuditLog, int, error)

	// ==============================================
	// INFRASTRUCTURE METHODS
	// ==============================================

	// HealthCheck verifies repository connectivity
	HealthCheck(ctx context.Context) error
}

// AuditLogFilter represents filtering criteria for audit logs
// All optional fields are pointers - nil means "don't filter by this"
type AuditLogFilter struct {
	// Optional: Filter by company
	CompanyID *uuid.UUID `json:"company_id,omitempty"`

	// Optional: Module-level filtering
	Module *string `json:"module,omitempty"` // e.g., "hr", "attendance"
	Action *string `json:"action,omitempty"` // e.g., "create", "update"

	// Optional: Entity filtering
	EntityType *string    `json:"entity_type,omitempty"` // e.g., "employee", "leave_request"
	EntityID   *uuid.UUID `json:"entity_id,omitempty"`

	// Optional: Actor filtering
	ActorType *string    `json:"actor_type,omitempty"` // "user", "admin", "system"
	ActorID   *uuid.UUID `json:"actor_id,omitempty"`

	// Optional: Time range filtering
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`

	// Pagination (required for ListAuditLogs)
	Limit  int `json:"limit"`  // Required, max 1000
	Offset int `json:"offset"` // Required, min 0
}

// ============================================================================
// BUILDER PATTERN METHODS
// ============================================================================

// WithCompanyID creates a copy of filter with company ID set
func (f AuditLogFilter) WithCompanyID(companyID uuid.UUID) AuditLogFilter {
	f.CompanyID = &companyID
	return f
}

// WithModule creates a copy of filter with module set
func (f AuditLogFilter) WithModule(module string) AuditLogFilter {
	f.Module = &module
	return f
}

// WithAction creates a copy of filter with action set
func (f AuditLogFilter) WithAction(action string) AuditLogFilter {
	f.Action = &action
	return f
}

// WithEntity creates a copy of filter with entity filters set
func (f AuditLogFilter) WithEntity(entityType string, entityID uuid.UUID) AuditLogFilter {
	f.EntityType = &entityType
	f.EntityID = &entityID
	return f
}

// WithActor creates a copy of filter with actor filters set
func (f AuditLogFilter) WithActor(actorType string, actorID uuid.UUID) AuditLogFilter {
	f.ActorType = &actorType
	f.ActorID = &actorID
	return f
}

// WithTimeRange creates a copy of filter with time range set
// Automatically converts to UTC to prevent timezone bugs
func (f AuditLogFilter) WithTimeRange(start, end time.Time) AuditLogFilter {
	startUTC := start.UTC()
	endUTC := end.UTC()
	f.StartDate = &startUTC
	f.EndDate = &endUTC
	return f
}

// WithLastNDays creates a copy of filter for last N days
func (f AuditLogFilter) WithLastNDays(days int) AuditLogFilter {
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)
	f.StartDate = &start
	f.EndDate = &end
	return f
}
