package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuditQueryService handles audit log queries and exports
type AuditQueryService struct {
	repo   AuditRepository
	logger *zap.Logger
}

// NewAuditQueryService creates a new audit query service
func NewAuditQueryService(repo AuditRepository, logger *zap.Logger) *AuditQueryService {
	return &AuditQueryService{
		repo:   repo,
		logger: logger,
	}
}

// ============================================================================
// QUERY OPERATIONS (Service Layer)
// ============================================================================

// GetCompanyAuditLogs retrieves audit logs for a company with full filtering support
func (qs *AuditQueryService) GetCompanyAuditLogs(
	ctx context.Context,
	companyID uuid.UUID,
	module *string,
	action *string,
	entityType *string,
	entityID *uuid.UUID,
	actorType *string,
	actorID *uuid.UUID,
	startDate *time.Time,
	endDate *time.Time,
	page int,
	pageSize int,
) ([]*AuditLog, int, error) {

	// Validation
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// Build filter
	filter := AuditLogFilter{
		Limit:  pageSize,
		Offset: offset,
	}.WithCompanyID(companyID)

	if module != nil {
		filter = filter.WithModule(*module)
	}

	if action != nil {
		filter = filter.WithAction(*action)
	}

	if entityType != nil && entityID != nil {
		filter = filter.WithEntity(*entityType, *entityID)
	}

	if actorType != nil && actorID != nil {
		filter = filter.WithActor(*actorType, *actorID)
	}

	// ✅ Correct time filtering (repository supports ONLY this)
	if startDate != nil && endDate != nil {
		filter = filter.WithTimeRange(*startDate, *endDate)
	}

	// Call repository
	return qs.repo.ListAuditLogs(ctx, filter)
}

// GetEntityAuditHistory retrieves complete audit history for an entity
func (qs *AuditQueryService) GetEntityAuditHistory(
	ctx context.Context,
	entityType string,
	entityID uuid.UUID,
	limit int,
) ([]*AuditLog, error) {
	// Service-level validation
	if limit < 1 || limit > 1000 {
		limit = 100
	}

	filter := AuditLogFilter{
		Limit:  limit,
		Offset: 0,
	}.WithEntity(entityType, entityID)

	logs, _, err := qs.repo.ListAuditLogs(ctx, filter)
	return logs, err
}

// GetActorActivity retrieves all actions performed by an actor
func (qs *AuditQueryService) GetActorActivity(
	ctx context.Context,
	actorType string,
	actorID uuid.UUID,
	days int,
) ([]*AuditLog, error) {
	// Default to last 30 days
	if days < 1 || days > 365 {
		days = 30
	}

	filter := AuditLogFilter{
		Limit:  1000,
		Offset: 0,
	}.WithActor(actorType, actorID).WithLastNDays(days)

	logs, _, err := qs.repo.ListAuditLogs(ctx, filter)
	return logs, err
}

// ============================================================================
// EXPORT OPERATIONS (Service Layer)
// ============================================================================

// ExportAuditLogs exports audit logs in requested format
func (qs *AuditQueryService) ExportAuditLogs(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	format string,
) ([]byte, string, error) {
	// Business logic: limit exports to 90 days max
	if endDate.Sub(startDate) > 90*24*time.Hour {
		return nil, "", fmt.Errorf("export period cannot exceed 90 days")
	}

	// Get logs for period
	filter := AuditLogFilter{
		Limit:  10000, // Export limit
		Offset: 0,
	}.WithCompanyID(companyID).WithTimeRange(startDate, endDate)

	logs, _, err := qs.repo.ListAuditLogs(ctx, filter)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch audit logs: %w", err)
	}

	// Export based on format
	switch strings.ToLower(format) {
	case "json":
		data, err := qs.exportAsJSON(logs)
		return data, "application/json", err
	case "csv":
		data, err := qs.exportAsCSV(logs)
		return data, "text/csv", err
	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// exportAsJSON converts audit logs to JSON format
func (qs *AuditQueryService) exportAsJSON(logs []*AuditLog) ([]byte, error) {
	type exportLog struct {
		ID         string                 `json:"id"`
		Timestamp  time.Time              `json:"timestamp"`
		Module     string                 `json:"module"`
		Action     string                 `json:"action"`
		EntityType string                 `json:"entity_type"`
		EntityID   *string                `json:"entity_id,omitempty"`
		ActorType  string                 `json:"actor_type"`
		ActorID    *string                `json:"actor_id,omitempty"`
		Changes    map[string]interface{} `json:"changes,omitempty"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
	}

	var exportLogs []exportLog
	for _, log := range logs {
		el := exportLog{
			ID:         log.AuditID.String(),
			Timestamp:  log.CreatedAt,
			Module:     log.Module,
			Action:     log.Action,
			EntityType: log.EntityType,
			ActorType:  log.ActorType,
		}

		if log.EntityID != nil {
			entityID := log.EntityID.String()
			el.EntityID = &entityID
		}

		if log.ActorID != nil {
			actorID := log.ActorID.String()
			el.ActorID = &actorID
		}

		// Parse before/after state if available
		if len(log.BeforeState) > 0 && len(log.AfterState) > 0 {
			var before, after map[string]interface{}
			if err := json.Unmarshal(log.BeforeState, &before); err == nil {
				if err := json.Unmarshal(log.AfterState, &after); err == nil {
					// Calculate changes
					changes := make(map[string]interface{})
					for key, newVal := range after {
						oldVal, exists := before[key]
						if !exists || oldVal != newVal {
							changes[key] = map[string]interface{}{
								"old": oldVal,
								"new": newVal,
							}
						}
					}
					if len(changes) > 0 {
						el.Changes = changes
					}
				}
			}
		}

		// Parse metadata if available
		if len(log.Metadata) > 0 {
			var metadata map[string]interface{}
			if err := json.Unmarshal(log.Metadata, &metadata); err == nil {
				el.Metadata = metadata
			}
		}

		exportLogs = append(exportLogs, el)
	}

	return json.MarshalIndent(exportLogs, "", "  ")
}

// exportAsCSV converts audit logs to CSV format
func (qs *AuditQueryService) exportAsCSV(logs []*AuditLog) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"Timestamp (UTC)",
		"Module",
		"Action",
		"Entity Type",
		"Entity ID",
		"Actor Type",
		"Actor ID",
		"Changes Summary",
		"IP Address",
		"User Agent",
	}

	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, log := range logs {
		entityID := ""
		if log.EntityID != nil {
			entityID = log.EntityID.String()
		}

		actorID := ""
		if log.ActorID != nil {
			actorID = log.ActorID.String()
		}

		// Extract metadata for CSV
		var ipAddress, userAgent, changesSummary string
		if len(log.Metadata) > 0 {
			var metadata map[string]interface{}
			if err := json.Unmarshal(log.Metadata, &metadata); err == nil {
				if ip, ok := metadata["ip"].(string); ok {
					ipAddress = ip
				}
				if ua, ok := metadata["user_agent"].(string); ok {
					userAgent = ua
				}
			}
		}

		// Calculate changes summary
		if len(log.BeforeState) > 0 && len(log.AfterState) > 0 {
			var before, after map[string]interface{}
			if err := json.Unmarshal(log.BeforeState, &before); err == nil {
				if err := json.Unmarshal(log.AfterState, &after); err == nil {
					changedFields := 0
					for key := range after {
						if before[key] != after[key] {
							changedFields++
						}
					}
					if changedFields > 0 {
						changesSummary = fmt.Sprintf("%d fields changed", changedFields)
					}
				}
			}
		}

		row := []string{
			log.CreatedAt.Format(time.RFC3339),
			log.Module,
			log.Action,
			log.EntityType,
			entityID,
			log.ActorType,
			actorID,
			changesSummary,
			ipAddress,
			userAgent,
		}

		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV flush error: %w", err)
	}

	return []byte(buf.String()), nil
}

// ============================================================================
// ANALYTICS OPERATIONS (Service Layer)
// ============================================================================

// AuditStats represents audit statistics
type AuditStats struct {
	TotalLogs     int64            `json:"total_logs"`
	ByModule      map[string]int64 `json:"by_module"`
	ByAction      map[string]int64 `json:"by_action"`
	ByEntityType  map[string]int64 `json:"by_entity_type"`
	ByActorType   map[string]int64 `json:"by_actor_type"`
	DailyActivity map[string]int64 `json:"daily_activity"` // date -> count
	TopActors     []ActorActivity  `json:"top_actors"`
}

// ActorActivity represents actor-level activity
type ActorActivity struct {
	ActorID   string `json:"actor_id"`
	ActorType string `json:"actor_type"`
	Count     int64  `json:"count"`
}

// GetAuditStats calculates audit statistics for a period
func (qs *AuditQueryService) GetAuditStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*AuditStats, error) {
	// Get all logs for the period
	filter := AuditLogFilter{
		Limit:  100000, // Large enough for stats
		Offset: 0,
	}.WithCompanyID(companyID).WithTimeRange(startDate, endDate)

	logs, _, err := qs.repo.ListAuditLogs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch logs for stats: %w", err)
	}

	// Calculate statistics
	stats := &AuditStats{
		TotalLogs:     int64(len(logs)),
		ByModule:      make(map[string]int64),
		ByAction:      make(map[string]int64),
		ByEntityType:  make(map[string]int64),
		ByActorType:   make(map[string]int64),
		DailyActivity: make(map[string]int64),
	}

	// Actor activity tracking
	actorCounts := make(map[string]int64)

	for _, log := range logs {
		// Count by module
		stats.ByModule[log.Module]++

		// Count by action
		stats.ByAction[log.Action]++

		// Count by entity type
		stats.ByEntityType[log.EntityType]++

		// Count by actor type
		stats.ByActorType[log.ActorType]++

		// Count daily activity
		dateKey := log.CreatedAt.Format("2006-01-02")
		stats.DailyActivity[dateKey]++

		// Track actor activity
		if log.ActorID != nil {
			actorKey := fmt.Sprintf("%s:%s", log.ActorType, log.ActorID.String())
			actorCounts[actorKey]++
		}
	}

	// Calculate top actors
	stats.TopActors = qs.calculateTopActors(actorCounts, 10)

	return stats, nil
}

// calculateTopActors identifies the most active actors
func (qs *AuditQueryService) calculateTopActors(
	actorCounts map[string]int64,
	topN int,
) []ActorActivity {
	var activities []ActorActivity
	for key, count := range actorCounts {
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			continue
		}
		activities = append(activities, ActorActivity{
			ActorType: parts[0],
			ActorID:   parts[1],
			Count:     count,
		})
	}

	// Sort by count (descending)
	sort.Slice(activities, func(i, j int) bool {
		return activities[i].Count > activities[j].Count
	})

	// Return top N
	if len(activities) > topN {
		return activities[:topN]
	}
	return activities
}

// HealthCheck performs a service-level health check
func (qs *AuditQueryService) HealthCheck(ctx context.Context) error {
	return qs.repo.HealthCheck(ctx)
}
