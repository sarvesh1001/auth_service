// internal/service/audit_service.go
package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuditService handles all audit log business logic
type AuditService struct {
	auditRepo scylla.AuditRepository
	logger    *zap.Logger
}

// NewAuditService creates a new audit service

// TO:
func NewAuditService(auditRepo scylla.AuditRepository, logger *zap.Logger) *AuditService {
    return &AuditService{
        auditRepo: auditRepo,
        logger:    logger,
    }
}
// ===== CORE LOGGING =====

// LogAction logs an admin action
func (s AuditService) LogAction(ctx context.Context, adminID uuid.UUID, actionType, resourceType string, resourceID uuid.UUID, status, reason string) error {
	auditLog := models.NewAuditLog(adminID, actionType, resourceType, resourceID, status)
	auditLog.Reason = reason

	if err := s.auditRepo.LogAdminAction(ctx, auditLog); err != nil {
		return fmt.Errorf("failed to log action: %w", err)
	}

	s.logger.Debug("Action logged",
		util.String("action", actionType),
		util.String("resource", resourceType),
		util.String("status", status),
	)

	return nil
}

// LogActionWithChanges logs an admin action with before/after values
func (s AuditService) LogActionWithChanges(ctx context.Context, adminID uuid.UUID, actionType, resourceType string,
	resourceID uuid.UUID, oldValues, newValues interface{}, status, reason string) error {

	auditLog := models.NewAuditLog(adminID, actionType, resourceType, resourceID, status)
	auditLog.Reason = reason

	// Set old and new values
	if oldValues != nil {
		if err := auditLog.SetOldValues(oldValues); err != nil {
			s.logger.Warn("Failed to set old values", util.ErrorField(err))
		}
	}

	if newValues != nil {
		if err := auditLog.SetNewValues(newValues); err != nil {
			s.logger.Warn("Failed to set new values", util.ErrorField(err))
		}
	}

	if err := s.auditRepo.LogAdminAction(ctx, auditLog); err != nil {
		return fmt.Errorf("failed to log action with changes: %w", err)
	}

	return nil
}

// LogFailedAction logs a failed admin action with error message
func (s AuditService) LogFailedAction(ctx context.Context, adminID uuid.UUID, actionType, resourceType string,
	resourceID uuid.UUID, reason, errorMsg string) error {

	auditLog := models.NewAuditLog(adminID, actionType, resourceType, resourceID, models.StatusFailure)
	auditLog.Reason = reason
	auditLog.ErrorMessage = errorMsg

	if err := s.auditRepo.LogAdminAction(ctx, auditLog); err != nil {
		return fmt.Errorf("failed to log failed action: %w", err)
	}

	s.logger.Warn("Failed action logged",
		util.String("action", actionType),
		util.String("error", errorMsg),
	)

	return nil
}

// ===== QUERY OPERATIONS =====

// GetAuditLogByAdmin retrieves all actions by specific admin
func (s AuditService) GetAuditLogByAdmin(ctx context.Context, adminID uuid.UUID, limit int) ([]*models.AdminAuditLog, error) {
	logs, _, err := s.auditRepo.GetAuditLogByAdminID(ctx, adminID, limit, nil)
	return logs, err
}

// GetAuditLogByAdminPaginated retrieves audit logs with pagination
func (s AuditService) GetAuditLogByAdminPaginated(ctx context.Context, adminID uuid.UUID, limit int, pageState []byte) ([]*models.AdminAuditLog, []byte, error) {
	return s.auditRepo.GetAuditLogByAdminID(ctx, adminID, limit, pageState)
}

// GetAuditLogByResource retrieves all actions affecting specific resource
func (s AuditService) GetAuditLogByResource(ctx context.Context, resourceID uuid.UUID, limit int) ([]*models.AdminAuditLog, error) {
	return s.auditRepo.GetAuditLogByResourceID(ctx, resourceID, limit)
}

// GetAuditLogByActionType retrieves all actions of specific type
func (s AuditService) GetAuditLogByActionType(ctx context.Context, actionType string, limit int) ([]*models.AdminAuditLog, error) {
	return s.auditRepo.GetAuditLogByActionType(ctx, actionType, limit)
}

// GetAuditLogBetweenDates retrieves audit logs within date range
func (s AuditService) GetAuditLogBetweenDates(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.AdminAuditLog, error) {
	return s.auditRepo.GetAuditLogBetweenDates(ctx, startDate, endDate, limit)
}

// GetAuditLogByStatus retrieves audit logs by success/failure status
func (s AuditService) GetAuditLogByStatus(ctx context.Context, status string, limit int) ([]*models.AdminAuditLog, error) {
	return s.auditRepo.GetAuditLogByOperationStatus(ctx, status, limit)
}

// QueryAuditLog retrieves audit logs with multiple filters
func (s AuditService) QueryAuditLog(ctx context.Context, filter *models.AuditLogFilter) ([]*models.AdminAuditLog, error) {
	if filter == nil {
		filter = &models.AuditLogFilter{Limit: 100}
	}

	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 10000 {
		filter.Limit = 10000
	}

	return s.auditRepo.QueryAuditLog(ctx, filter)
}

// ===== STATISTICS =====

// GetAuditStats returns overall audit statistics
func (s AuditService) GetAuditStats(ctx context.Context) (map[string]interface{}, error) {
	return s.auditRepo.GetAuditStats(ctx)
}

// GetAdminActionStats returns action statistics for specific admin
func (s AuditService) GetAdminActionStats(ctx context.Context, adminID uuid.UUID) (map[string]interface{}, error) {
	return s.auditRepo.GetAdminActionStats(ctx, adminID)
}

// ===== REPORTING =====

// ExportAuditLog exports audit logs in specified format
func (s AuditService) ExportAuditLog(ctx context.Context, startDate, endDate time.Time, format string) ([]byte, error) {
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Limit export range to 90 days (retention period)
	maxRange := 90 * 24 * time.Hour
	if endDate.Sub(startDate) > maxRange {
		return nil, fmt.Errorf("export range cannot exceed %d days", 90)
	}

	data, err := s.auditRepo.ExportAuditLog(ctx, startDate, endDate, format)
	if err != nil {
		return nil, fmt.Errorf("failed to export audit log: %w", err)
	}

	s.logger.Info("Audit log exported",
		util.String("format", format),
		util.String("start_date", startDate.Format("2006-01-02")),
		util.String("end_date", endDate.Format("2006-01-02")),
		util.Int("size_bytes", len(data)),
	)

	return data, nil
}

// ===== COMPLIANCE & ANALYSIS =====

// GetSuspiciousActivity returns potentially suspicious activities
func (s AuditService) GetSuspiciousActivity(ctx context.Context, limit int) ([]*models.AdminAuditLog, error) {
	// Get failed operations
	failedLogs, err := s.auditRepo.GetAuditLogByOperationStatus(ctx, models.StatusFailure, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get suspicious activity: %w", err)
	}

	s.logger.Info("Suspicious activity queried",
		util.Int("failed_operation_count", len(failedLogs)),
	)

	return failedLogs, nil
}

// GetAdminActionsToday returns actions performed today
func (s AuditService) GetAdminActionsToday(ctx context.Context, adminID uuid.UUID) ([]*models.AdminAuditLog, error) {
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	return s.auditRepo.GetAuditLogBetweenDates(ctx, startOfDay, endOfDay, 1000)
}

// ===== HEALTH & MAINTENANCE =====

// HealthCheck verifies audit service health
func (s AuditService) HealthCheck(ctx context.Context) error {
	return s.auditRepo.HealthCheck(ctx)
}

// CleanupExpiredLogs performs manual cleanup (TTL handles this automatically)
func (s AuditService) CleanupExpiredLogs(ctx context.Context, retentionDays int) (int, error) {
	return s.auditRepo.CleanupExpiredLogs(ctx, retentionDays)
}