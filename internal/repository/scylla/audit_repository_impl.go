// internal/repository/scylla/audit_repository_impl.go
package scylla

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"
	"github.com/gocql/gocql"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuditRepositoryImpl implements AuditRepository interface
type AuditRepositoryImpl struct {
	client *ScyllaClient
	logger *zap.Logger

	// Prepared statements
	stmtLogAction                    *gocql.Query
	stmtGetAuditByAdminID           *gocql.Query
	stmtGetAuditByResourceID        *gocql.Query
	stmtGetAuditByActionType        *gocql.Query
	stmtGetAuditByOperationStatus   *gocql.Query
	stmtMutex                       sync.RWMutex
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(client *ScyllaClient, logger *zap.Logger) AuditRepository {
	repo := &AuditRepositoryImpl{
		client: client,
		logger: logger,
	}
	repo.prepareStatements()
	return repo
}

// prepareStatements prepares frequently used queries for better performance
func (r *AuditRepositoryImpl) prepareStatements() {
	r.stmtMutex.Lock()
	defer r.stmtMutex.Unlock()

	// Prepare LogAction query
	r.stmtLogAction = r.client.Session.Query(
		`INSERT INTO admin_audit_log 
		 (audit_bucket, audit_id, admin_id, action_date, action_time, action_type, 
		  resource_type, resource_id, operation_status, changes, ip_address, user_agent, 
		  old_values, new_values, reason, error_message)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)

	// Prepare GetAuditByAdminID query (using materialized view)
	r.stmtGetAuditByAdminID = r.client.Session.Query(
		`SELECT audit_id, admin_id, action_date, action_time, action_type, resource_type, 
		        resource_id, operation_status, changes, ip_address, user_agent, old_values, 
		        new_values, reason, error_message
		 FROM audit_log_by_admin_id WHERE admin_id = ? LIMIT ?`,
	)

	// Prepare GetAuditByResourceID query (using materialized view)
	r.stmtGetAuditByResourceID = r.client.Session.Query(
		`SELECT audit_id, admin_id, action_date, action_time, action_type, resource_type, 
		        resource_id, operation_status, changes
		 FROM audit_log_by_resource_id WHERE resource_id = ? LIMIT ?`,
	)

	// Prepare GetAuditByActionType query (using materialized view)
	r.stmtGetAuditByActionType = r.client.Session.Query(
		`SELECT audit_id, admin_id, action_date, action_time, action_type, resource_type, 
		        resource_id, operation_status
		 FROM audit_log_by_action_type WHERE action_type = ? LIMIT ?`,
	)

	r.logger.Info("Prepared statements initialized for audit repository")
}

// ===== CORE OPERATIONS =====

// LogAdminAction logs an admin action to audit trail (immutable)
func (r *AuditRepositoryImpl) LogAdminAction(ctx context.Context, auditLog *models.AdminAuditLog) error {
    startTime := time.Now()

    // Validate audit log
    if auditLog.AuditID == uuid.Nil {
        auditLog.AuditID = uuid.New()
    }
    if auditLog.ActionTime.IsZero() {
        auditLog.ActionTime = time.Now().UTC()
    }
    if auditLog.ActionDate == "" {
        auditLog.ActionDate = auditLog.ActionTime.Format("2006-01-02")
    }
    if auditLog.AuditBucket == 0 {
        auditLog.AuditBucket = int(auditLog.ActionTime.Unix() / 86400)
    }

    // ✅ FIXED: Use only columns that actually exist in your schema
    query := r.client.Session.Query(
        `INSERT INTO admin_audit_log 
         (audit_bucket, audit_id, admin_id, action_date, action_time, action_type, 
          resource_type, resource_id, operation_status, changes, ip_address, 
          old_values, new_values, error_message)  -- ✅ REMOVED user_agent and reason
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,  // ✅ 14 parameters now
        auditLog.AuditBucket,
        gocql.UUID(auditLog.AuditID),
        gocql.UUID(auditLog.AdminID),
        auditLog.ActionDate,
        auditLog.ActionTime,
        auditLog.ActionType,
        auditLog.ResourceType,
        gocql.UUID(auditLog.ResourceID),
        auditLog.OperationStatus,
        auditLog.Changes,
        auditLog.IPAddress,
        // ❌ REMOVED: user_agent (column doesn't exist)
        auditLog.OldValues,
        auditLog.NewValues,
        // ❌ REMOVED: reason (column doesn't exist)  
        auditLog.ErrorMessage,
    )

    if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
        return fmt.Errorf("failed to log audit action: %w", err)
    }

    r.logger.Debug("Audit action logged",
        util.String("audit_id", auditLog.AuditID.String()),
        util.String("admin_id", auditLog.AdminID.String()),
        util.String("action_type", auditLog.ActionType),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}
// ===== QUERY OPERATIONS =====

// GetAuditLogByAdminID retrieves all actions by specific admin
func (r *AuditRepositoryImpl) GetAuditLogByAdminID(ctx context.Context, adminID uuid.UUID, limit int, pageState []byte) ([]*models.AdminAuditLog, []byte, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}

	r.stmtMutex.RLock()
	query := r.stmtGetAuditByAdminID.Bind(gocql.UUID(adminID), limit)
	r.stmtMutex.RUnlock()

	if pageState != nil {
		query = query.PageState(pageState)
	}

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var auditLogs []*models.AdminAuditLog

	for {
		var auditLog models.AdminAuditLog
		var scannedID gocql.UUID
		var scannedAdminID gocql.UUID
		var scannedResourceID gocql.UUID

		if !iter.Scan(&scannedID, &scannedAdminID, &auditLog.ActionDate, &auditLog.ActionTime,
			&auditLog.ActionType, &auditLog.ResourceType, &scannedResourceID, &auditLog.OperationStatus,
			&auditLog.Changes, &auditLog.IPAddress, &auditLog.UserAgent, &auditLog.OldValues,
			&auditLog.NewValues, &auditLog.Reason, &auditLog.ErrorMessage) {
			break
		}

		auditLog.AuditID = uuid.UUID(scannedID)
		auditLog.AdminID = uuid.UUID(scannedAdminID)
		auditLog.ResourceID = uuid.UUID(scannedResourceID)
		auditLogs = append(auditLogs, &auditLog)
	}

	if err := iter.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to query audit logs by admin: %w", err)
	}

	return auditLogs, iter.PageState(), nil
}

// GetAuditLogByResourceID retrieves all actions affecting specific resource
func (r *AuditRepositoryImpl) GetAuditLogByResourceID(ctx context.Context, resourceID uuid.UUID, limit int) ([]*models.AdminAuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}

	r.stmtMutex.RLock()
	query := r.stmtGetAuditByResourceID.Bind(gocql.UUID(resourceID), limit)
	r.stmtMutex.RUnlock()

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var auditLogs []*models.AdminAuditLog

	for {
		var auditLog models.AdminAuditLog
		var scannedID gocql.UUID
		var scannedAdminID gocql.UUID
		var scannedResourceID gocql.UUID

		if !iter.Scan(&scannedID, &scannedAdminID, &auditLog.ActionDate, &auditLog.ActionTime,
			&auditLog.ActionType, &auditLog.ResourceType, &scannedResourceID, &auditLog.OperationStatus,
			&auditLog.Changes) {
			break
		}

		auditLog.AuditID = uuid.UUID(scannedID)
		auditLog.AdminID = uuid.UUID(scannedAdminID)
		auditLog.ResourceID = uuid.UUID(scannedResourceID)
		auditLogs = append(auditLogs, &auditLog)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query audit logs by resource: %w", err)
	}

	return auditLogs, nil
}

// GetAuditLogByActionType retrieves all actions of specific type
func (r *AuditRepositoryImpl) GetAuditLogByActionType(ctx context.Context, actionType string, limit int) ([]*models.AdminAuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}

	r.stmtMutex.RLock()
	query := r.stmtGetAuditByActionType.Bind(actionType, limit)
	r.stmtMutex.RUnlock()

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var auditLogs []*models.AdminAuditLog

	for {
		var auditLog models.AdminAuditLog
		var scannedID gocql.UUID
		var scannedAdminID gocql.UUID
		var scannedResourceID gocql.UUID

		if !iter.Scan(&scannedID, &scannedAdminID, &auditLog.ActionDate, &auditLog.ActionTime,
			&auditLog.ActionType, &auditLog.ResourceType, &scannedResourceID, &auditLog.OperationStatus) {
			break
		}

		auditLog.AuditID = uuid.UUID(scannedID)
		auditLog.AdminID = uuid.UUID(scannedAdminID)
		auditLog.ResourceID = uuid.UUID(scannedResourceID)
		auditLogs = append(auditLogs, &auditLog)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query audit logs by action type: %w", err)
	}

	return auditLogs, nil
}

// GetAuditLogBetweenDates retrieves audit log entries within date range
func (r *AuditRepositoryImpl) GetAuditLogBetweenDates(ctx context.Context, startDate, endDate time.Time, limit int) ([]*models.AdminAuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}

	query := r.client.Session.Query(
		`SELECT audit_id, admin_id, action_date, action_time, action_type, resource_type, 
		        resource_id, operation_status, changes, ip_address
		 FROM admin_audit_log WHERE action_date >= ? AND action_date <= ? LIMIT ?`,
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"),
		limit,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var auditLogs []*models.AdminAuditLog

	for {
		var auditLog models.AdminAuditLog
		var scannedID gocql.UUID
		var scannedAdminID gocql.UUID
		var scannedResourceID gocql.UUID

		if !iter.Scan(&scannedID, &scannedAdminID, &auditLog.ActionDate, &auditLog.ActionTime,
			&auditLog.ActionType, &auditLog.ResourceType, &scannedResourceID, &auditLog.OperationStatus,
			&auditLog.Changes, &auditLog.IPAddress) {
			break
		}

		auditLog.AuditID = uuid.UUID(scannedID)
		auditLog.AdminID = uuid.UUID(scannedAdminID)
		auditLog.ResourceID = uuid.UUID(scannedResourceID)
		auditLogs = append(auditLogs, &auditLog)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query audit logs by date range: %w", err)
	}

	return auditLogs, nil
}

// GetAuditLogByOperationStatus retrieves audit log by success/failure status
func (r *AuditRepositoryImpl) GetAuditLogByOperationStatus(ctx context.Context, status string, limit int) ([]*models.AdminAuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 10000 {
		limit = 10000
	}

	query := r.client.Session.Query(
		`SELECT audit_id, admin_id, action_date, action_time, action_type, resource_type, 
		        resource_id, operation_status, error_message
		 FROM admin_audit_log WHERE operation_status = ? LIMIT ?`,
		status,
		limit,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var auditLogs []*models.AdminAuditLog

	for {
		var auditLog models.AdminAuditLog
		var scannedID gocql.UUID
		var scannedAdminID gocql.UUID
		var scannedResourceID gocql.UUID

		if !iter.Scan(&scannedID, &scannedAdminID, &auditLog.ActionDate, &auditLog.ActionTime,
			&auditLog.ActionType, &auditLog.ResourceType, &scannedResourceID, &auditLog.OperationStatus,
			&auditLog.ErrorMessage) {
			break
		}

		auditLog.AuditID = uuid.UUID(scannedID)
		auditLog.AdminID = uuid.UUID(scannedAdminID)
		auditLog.ResourceID = uuid.UUID(scannedResourceID)
		auditLogs = append(auditLogs, &auditLog)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query audit logs by status: %w", err)
	}

	return auditLogs, nil
}

// ===== FILTERS & SEARCH =====

// QueryAuditLog retrieves audit logs with multiple filters
func (r *AuditRepositoryImpl) QueryAuditLog(ctx context.Context, filter *models.AuditLogFilter) ([]*models.AdminAuditLog, error) {
	// Build query based on filters
	if filter.AdminID != nil {
		logs, _, err := r.GetAuditLogByAdminID(ctx, *filter.AdminID, filter.Limit, filter.PageState)
		return logs, err
			}

	if filter.ResourceID != nil {
		return r.GetAuditLogByResourceID(ctx, *filter.ResourceID, filter.Limit)
	}

	if filter.ActionType != nil {
		return r.GetAuditLogByActionType(ctx, *filter.ActionType, filter.Limit)
	}

	if filter.Status != nil {
		return r.GetAuditLogByOperationStatus(ctx, *filter.Status, filter.Limit)
	}

	if filter.StartDate != nil && filter.EndDate != nil {
		return r.GetAuditLogBetweenDates(ctx, *filter.StartDate, *filter.EndDate, filter.Limit)
	}

	// Default: return recent logs
	query := r.client.Session.Query(
		`SELECT audit_id, admin_id, action_date, action_time, action_type, resource_type, 
		        resource_id, operation_status
		 FROM admin_audit_log LIMIT ?`,
		filter.Limit,
	)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var auditLogs []*models.AdminAuditLog

	for {
		var auditLog models.AdminAuditLog
		var scannedID gocql.UUID
		var scannedAdminID gocql.UUID
		var scannedResourceID gocql.UUID

		if !iter.Scan(&scannedID, &scannedAdminID, &auditLog.ActionDate, &auditLog.ActionTime,
			&auditLog.ActionType, &auditLog.ResourceType, &scannedResourceID, &auditLog.OperationStatus) {
			break
		}

		auditLog.AuditID = uuid.UUID(scannedID)
		auditLog.AdminID = uuid.UUID(scannedAdminID)
		auditLog.ResourceID = uuid.UUID(scannedResourceID)
		auditLogs = append(auditLogs, &auditLog)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}

	return auditLogs, nil
}

// ===== STATISTICS =====

// GetAuditStats returns audit statistics
func (r *AuditRepositoryImpl) GetAuditStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count total audit logs
	var totalLogs int
	if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_audit_log`).WithContext(ctx).Scan(&totalLogs); err != nil {
		return nil, fmt.Errorf("failed to count audit logs: %w", err)
	}
	stats["total_audit_logs"] = totalLogs

	// Count by status
	var successCount, failureCount int
	if err := r.client.Session.Query(
		`SELECT COUNT(*) FROM admin_audit_log WHERE operation_status = ?`,
		models.StatusSuccess,
	).WithContext(ctx).Scan(&successCount); err == nil {
		stats["successful_operations"] = successCount
	}

	if err := r.client.Session.Query(
		`SELECT COUNT(*) FROM admin_audit_log WHERE operation_status = ?`,
		models.StatusFailure,
	).WithContext(ctx).Scan(&failureCount); err == nil {
		stats["failed_operations"] = failureCount
	}

	// Count by action type (top actions)
	actionTypes := []string{
		models.ActionPromoteAdmin,
		models.ActionUpdatePermissions,
		models.ActionAdminLogin,
		models.ActionBanUser,
	}

	actionStats := make(map[string]int)
	for _, actionType := range actionTypes {
		var count int
		if err := r.client.Session.Query(
			`SELECT COUNT(*) FROM admin_audit_log WHERE action_type = ?`,
			actionType,
		).WithContext(ctx).Scan(&count); err == nil {
			actionStats[actionType] = count
		}
	}
	stats["actions"] = actionStats

	return stats, nil
}

// GetAdminActionStats returns action statistics for specific admin
func (r *AuditRepositoryImpl) GetAdminActionStats(ctx context.Context, adminID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	logs, _, err := r.GetAuditLogByAdminID(ctx, adminID, 10000, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin actions: %w", err)
	}

	stats["total_actions"] = len(logs)

	// Count by action type
	actionCounts := make(map[string]int)
	successCount := 0
	failureCount := 0

	for _, log := range logs {
		actionCounts[log.ActionType]++
		if log.IsSuccess() {
			successCount++
		} else {
			failureCount++
		}
	}

	stats["action_breakdown"] = actionCounts
	stats["successful_actions"] = successCount
	stats["failed_actions"] = failureCount

	return stats, nil
}

// ===== EXPORT & REPORTING =====

// ExportAuditLog exports audit logs in specified format
func (r *AuditRepositoryImpl) ExportAuditLog(ctx context.Context, startDate, endDate time.Time, format string) ([]byte, error) {
	// Get audit logs within date range
	logs, err := r.GetAuditLogBetweenDates(ctx, startDate, endDate, 100000)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs for export: %w", err)
	}

	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(logs, "", "  ")

	case "csv":
		var csv strings.Builder
		// Write header
		csv.WriteString("audit_id,admin_id,action_time,action_type,resource_type,resource_id,status,reason\n")

		// Write rows
		for _, log := range logs {
			csv.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
				log.AuditID.String(),
				log.AdminID.String(),
				log.ActionTime.Format(time.RFC3339),
				log.ActionType,
				log.ResourceType,
				log.ResourceID.String(),
				log.OperationStatus,
				log.Reason,
			))
		}
		return []byte(csv.String()), nil

	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ===== HEALTH & MAINTENANCE =====

// HealthCheck verifies repository connectivity
func (r *AuditRepositoryImpl) HealthCheck(ctx context.Context) error {
	var count int
	if err := r.client.Session.Query(`SELECT COUNT(*) FROM admin_audit_log`).WithContext(ctx).Scan(&count); err != nil {
		return fmt.Errorf("audit repository health check failed: %w", err)
	}
	return nil
}

// CleanupExpiredLogs removes logs older than retention period
func (r *AuditRepositoryImpl) CleanupExpiredLogs(ctx context.Context, retentionDays int) (int, error) {
	// Note: TTL handles automatic cleanup, this is manual cleanup backup
	// In practice, Cassandra/Scylla handles TTL-based deletion automatically
	// This method exists for manual trigger if needed

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	// Manual cleanup is limited because Cassandra doesn't support efficient bulk deletes
	// Better to rely on TTL: admin_audit_log table has default_time_to_live = 7776000 (90 days)

	r.logger.Info("Manual audit log cleanup triggered",
		util.String("cutoff_date", cutoffDate.Format("2006-01-02")),
		util.Int("retention_days", retentionDays),
	)

	// Return 0 deleted as TTL handles it automatically
	return 0, nil
}