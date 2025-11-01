// internal/repository/scylla/audit_repository.go
package scylla

import (
	"context"
	"time"

	"auth-service/internal/models"
	"github.com/google/uuid"
)

// AuditRepository defines the interface for audit log repository operations
type AuditRepository interface {
	// ===== CORE OPERATIONS =====

	// LogAdminAction logs an admin action to audit trail (immutable)
	LogAdminAction(ctx context.Context, auditLog *models.AdminAuditLog) error

	// ===== QUERY OPERATIONS =====

	// GetAuditLogByAdminID retrieves all actions by specific admin
	GetAuditLogByAdminID(ctx context.Context, adminID uuid.UUID, limit int, pageState []byte) ([]*models.AdminAuditLog, []byte, error)

	// GetAuditLogByResourceID retrieves all actions affecting specific resource
	GetAuditLogByResourceID(ctx context.Context, resourceID uuid.UUID, limit int) ([]*models.AdminAuditLog, error)

	// GetAuditLogByActionType retrieves all actions of specific type
	GetAuditLogByActionType(ctx context.Context, actionType string, limit int) ([]*models.AdminAuditLog, error)

	// GetAuditLogBetweenDates retrieves audit log entries within date range
	GetAuditLogBetweenDates(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.AdminAuditLog, error)

	// GetAuditLogByOperationStatus retrieves audit log by success/failure status
	GetAuditLogByOperationStatus(ctx context.Context, status string, limit int) ([]*models.AdminAuditLog, error)

	// ===== FILTERS & SEARCH =====

	// QueryAuditLog retrieves audit logs with multiple filters
	QueryAuditLog(ctx context.Context, filter *models.AuditLogFilter) ([]*models.AdminAuditLog, error)

	// ===== STATISTICS =====

	// GetAuditStats returns audit statistics
	GetAuditStats(ctx context.Context) (map[string]interface{}, error)

	// GetAdminActionStats returns action statistics for admin
	GetAdminActionStats(ctx context.Context, adminID uuid.UUID) (map[string]interface{}, error)

	// ===== EXPORT & REPORTING =====

	// ExportAuditLog exports audit logs in specified format
	// format: "json" | "csv"
	ExportAuditLog(ctx context.Context, startDate, endDate time.Time, format string) ([]byte, error)

	// ===== HEALTH & MAINTENANCE =====

	// HealthCheck verifies repository connectivity
	HealthCheck(ctx context.Context) error

	// CleanupExpiredLogs removes logs older than retention period (manual cleanup)
	// Retention is handled by TTL, this is backup cleanup
	CleanupExpiredLogs(ctx context.Context, retentionDays int) (int, error)
}