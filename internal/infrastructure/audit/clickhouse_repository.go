package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
)

// AuditRepositoryClickHouse implements AuditRepository using ClickHouse.
// It uses the ReplacingMergeTree engine to deduplicate on audit_id.
type AuditRepositoryClickHouse struct {
	chClient *client.ClickHouseClient
	logger   *zap.Logger
}

// NewAuditRepositoryClickHouse creates a new ClickHouse-backed audit repository.
func NewAuditRepositoryClickHouse(chClient *client.ClickHouseClient, logger *zap.Logger) AuditRepository {
	return &AuditRepositoryClickHouse{
		chClient: chClient,
		logger:   logger.Named("audit_repo_clickhouse"),
	}
}

// ----------------------------------------------------------------------------
// Helper: convert *uuid.UUID to interface{} that ClickHouse can handle.
// Returns nil for nil pointer, otherwise the dereferenced uuid.UUID.
// This prevents a panic when the driver calls Value() on a nil pointer.
// ----------------------------------------------------------------------------
func nullableUUID(id *uuid.UUID) interface{} {
	if id == nil {
		return nil
	}
	return *id
}

// ----------------------------------------------------------------------------
// Write operations (append-only)
// ----------------------------------------------------------------------------

func (r *AuditRepositoryClickHouse) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	return r.insert(ctx, log)
}

// CreateAuditLogWithTx ignores the tx parameter (ClickHouse has no transactions).
func (r *AuditRepositoryClickHouse) CreateAuditLogWithTx(ctx context.Context, _ *sql.Tx, log *AuditLog) error {
	return r.insert(ctx, log)
}

func (r *AuditRepositoryClickHouse) CreateAuditLogBatch(ctx context.Context, logs []*AuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	batch, err := r.chClient.Conn().PrepareBatch(ctx, `
		INSERT INTO auth_analytics.audit_events (
			audit_id, company_id, module, action, entity_type, entity_id,
			actor_type, actor_id, before_state, after_state, metadata, created_at
		)
	`)
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, log := range logs {
		err := batch.Append(
			log.AuditID,
			nullableUUID(log.CompanyID), // fixed
			log.Module,
			log.Action,
			log.EntityType,
			nullableUUID(log.EntityID), // fixed
			log.ActorType,
			nullableUUID(log.ActorID), // fixed
			string(log.BeforeState),
			string(log.AfterState),
			string(log.Metadata),
			log.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("append to batch: %w", err)
		}
	}
	return batch.Send()
}

// insert performs a single-row insert.
func (r *AuditRepositoryClickHouse) insert(ctx context.Context, log *AuditLog) error {
	query := `
		INSERT INTO auth_analytics.audit_events (
			audit_id, company_id, module, action, entity_type, entity_id,
			actor_type, actor_id, before_state, after_state, metadata, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	return r.chClient.Exec(ctx, query,
		log.AuditID,
		nullableUUID(log.CompanyID),
		log.Module,
		log.Action,
		log.EntityType,
		nullableUUID(log.EntityID),
		log.ActorType,
		nullableUUID(log.ActorID),
		string(log.BeforeState),
		string(log.AfterState),
		string(log.Metadata),
		log.CreatedAt,
	)
}

// ----------------------------------------------------------------------------
// Read operations
// ----------------------------------------------------------------------------

func (r *AuditRepositoryClickHouse) GetAuditLogByID(ctx context.Context, auditID uuid.UUID) (*AuditLog, error) {
	query := `
		SELECT audit_id, company_id, module, action, entity_type, entity_id,
		       actor_type, actor_id, before_state, after_state, metadata, created_at
		FROM auth_analytics.audit_events
		WHERE audit_id = ?
	`
	rows, err := r.chClient.QueryRows(ctx, query, auditID)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanRow(rows)
	}
	return nil, fmt.Errorf("audit log not found: %s", auditID)
}

func (r *AuditRepositoryClickHouse) ListAuditLogs(
	ctx context.Context,
	filter AuditLogFilter,
) ([]*AuditLog, int, error) {
	// Build WHERE clause
	conditions := []string{}
	args := []interface{}{}

	addCondition := func(field string, value interface{}, isPtr bool) {
		if !isPtr || value != nil {
			conditions = append(conditions, fmt.Sprintf("%s = ?", field))
			args = append(args, value)
		}
	}

	addCondition("company_id", filter.CompanyID, true)
	addCondition("module", filter.Module, true)
	addCondition("action", filter.Action, true)
	addCondition("entity_type", filter.EntityType, true)
	addCondition("entity_id", filter.EntityID, true)
	addCondition("actor_type", filter.ActorType, true)
	addCondition("actor_id", filter.ActorID, true)

	if filter.StartDate != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *filter.StartDate)
	}
	if filter.EndDate != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *filter.EndDate)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM auth_analytics.audit_events %s", whereClause)
	var total int
	rows, err := r.chClient.QueryRows(ctx, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("scan count: %w", err)
		}
	}
	rows.Close()
	if total == 0 {
		return []*AuditLog{}, 0, nil
	}

	// Data query with pagination
	dataQuery := fmt.Sprintf(`
		SELECT audit_id, company_id, module, action, entity_type, entity_id,
		       actor_type, actor_id, before_state, after_state, metadata, created_at
		FROM auth_analytics.audit_events
		%s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	params := append(args, filter.Limit, filter.Offset)
	dataRows, err := r.chClient.QueryRows(ctx, dataQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("data query: %w", err)
	}
	defer dataRows.Close()

	logs := make([]*AuditLog, 0, filter.Limit)
	for dataRows.Next() {
		log, err := r.scanRow(dataRows)
		if err != nil {
			r.logger.Warn("failed to scan row", zap.Error(err))
			continue
		}
		logs = append(logs, log)
	}
	return logs, total, nil
}

// ----------------------------------------------------------------------------
// Infrastructure
// ----------------------------------------------------------------------------

func (r *AuditRepositoryClickHouse) HealthCheck(ctx context.Context) error {
	return r.chClient.HealthCheck(ctx)
}

// ----------------------------------------------------------------------------
// Helper: scan a single row into AuditLog
// ----------------------------------------------------------------------------

func (r *AuditRepositoryClickHouse) scanRow(rows driver.Rows) (*AuditLog, error) {
	var log AuditLog
	var companyID, entityID, actorID *uuid.UUID
	var beforeState, afterState, metadata string

	err := rows.Scan(
		&log.AuditID,
		&companyID,
		&log.Module,
		&log.Action,
		&log.EntityType,
		&entityID,
		&log.ActorType,
		&actorID,
		&beforeState,
		&afterState,
		&metadata,
		&log.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	log.CompanyID = companyID
	log.EntityID = entityID
	log.ActorID = actorID
	log.BeforeState = []byte(beforeState)
	log.AfterState = []byte(afterState)
	log.Metadata = []byte(metadata)

	return &log, nil
}
