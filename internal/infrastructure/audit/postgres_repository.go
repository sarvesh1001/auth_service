package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/util"
)

type AuditRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

func NewAuditRepository(postgresClient *client.PostgresClient, logger *zap.Logger) AuditRepository {
	repo := &AuditRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}
	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ============================================================================
// APPEND-ONLY WRITE OPERATIONS (non‑transactional)
// ============================================================================

func (r *AuditRepositoryImpl) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	startTime := time.Now()
	query := `
		INSERT INTO audit.audit_logs (
			audit_id, company_id, module, action, entity_type, entity_id,
			actor_type, actor_id, before_state, after_state, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.client.Exec(ctx, query,
		log.AuditID, log.CompanyID, log.Module, log.Action, log.EntityType, log.EntityID,
		log.ActorType, log.ActorID, log.BeforeState, log.AfterState, log.Metadata, log.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create audit log",
			util.String("module", log.Module),
			util.String("action", log.Action),
			util.ErrorField(err))
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	r.logger.Debug("Audit log created",
		util.String("audit_id", log.AuditID.String()),
		util.Duration("duration", time.Since(startTime)))
	return nil
}

func (r *AuditRepositoryImpl) CreateAuditLogBatch(ctx context.Context, logs []*AuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO audit.audit_logs (
			audit_id, company_id, module, action, entity_type, entity_id,
			actor_type, actor_id, before_state, after_state, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, log := range logs {
		_, err := stmt.ExecContext(ctx,
			log.AuditID, log.CompanyID, log.Module, log.Action, log.EntityType, log.EntityID,
			log.ActorType, log.ActorID, log.BeforeState, log.AfterState, log.Metadata, log.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert audit log %s: %w", log.AuditID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}
	r.logger.Info("Batch audit logs creation completed", util.Int("logs_created", len(logs)))
	return nil
}

// ✅ NEW: Transaction‑aware create
func (r *AuditRepositoryImpl) CreateAuditLogWithTx(ctx context.Context, tx *sql.Tx, log *AuditLog) error {
	query := `
		INSERT INTO audit.audit_logs (
			audit_id, company_id, module, action, entity_type, entity_id,
			actor_type, actor_id, before_state, after_state, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := tx.ExecContext(ctx, query,
		log.AuditID, log.CompanyID, log.Module, log.Action, log.EntityType, log.EntityID,
		log.ActorType, log.ActorID, log.BeforeState, log.AfterState, log.Metadata, log.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create audit log (with tx)",
			util.String("module", log.Module),
			util.String("action", log.Action),
			util.ErrorField(err))
		return fmt.Errorf("failed to create audit log with tx: %w", err)
	}
	return nil
}

// ============================================================================
// READ OPERATIONS (unchanged)
// ============================================================================

func (r *AuditRepositoryImpl) GetAuditLogByID(ctx context.Context, auditID uuid.UUID) (*AuditLog, error) {
	stmt, ok := r.getStmt("get_audit_log_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_audit_log_by_id")
	}
	rows, err := stmt.QueryContext(ctx, auditID)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log by ID: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanAuditLog(rows)
	}
	return nil, fmt.Errorf("audit log not found: %s", auditID)
}

func (r *AuditRepositoryImpl) ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int, error) {
	conditions := []string{}
	params := []interface{}{}
	paramCount := 1

	addCondition := func(field string, value interface{}, isPointer bool) {
		if !isPointer || value != nil {
			conditions = append(conditions, fmt.Sprintf("%s = $%d", field, paramCount))
			params = append(params, value)
			paramCount++
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
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", paramCount))
		params = append(params, *filter.StartDate)
		paramCount++
	}
	if filter.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", paramCount))
		params = append(params, *filter.EndDate)
		paramCount++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit.audit_logs %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	if totalCount == 0 {
		return []*AuditLog{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT audit_id, company_id, module, action, entity_type, entity_id,
		       actor_type, actor_id, before_state, after_state, metadata, created_at
		FROM audit.audit_logs %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCount, paramCount+1)
	params = append(params, filter.Limit, filter.Offset)

	rows, err := r.client.Query(ctx, dataQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*AuditLog, 0, filter.Limit)
	for rows.Next() {
		auditLog, err := r.scanAuditLog(rows)
		if err != nil {
			r.logger.Warn("Failed to scan audit log", util.ErrorField(err))
			continue
		}
		logs = append(logs, auditLog)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating audit logs: %w", err)
	}
	return logs, totalCount, nil
}

// ============================================================================
// INFRASTRUCTURE (unchanged)
// ============================================================================

func (r *AuditRepositoryImpl) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, "SELECT 1 FROM audit.audit_logs LIMIT 1")
	if err != nil {
		return fmt.Errorf("audit repository health check failed: %w", err)
	}
	return nil
}

// ============================================================================
// HELPER METHODS (unchanged)
// ============================================================================

func (r *AuditRepositoryImpl) scanAuditLog(rows *sql.Rows) (*AuditLog, error) {
	var log AuditLog
	var companyID, entityID, actorID sql.NullString
	var beforeState, afterState, metadata []byte

	err := rows.Scan(
		&log.AuditID, &companyID, &log.Module, &log.Action, &log.EntityType, &entityID,
		&log.ActorType, &actorID, &beforeState, &afterState, &metadata, &log.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan audit log: %w", err)
	}
	log.CompanyID = r.parseNullableUUID(companyID)
	log.EntityID = r.parseNullableUUID(entityID)
	log.ActorID = r.parseNullableUUID(actorID)
	if beforeState != nil {
		log.BeforeState = make([]byte, len(beforeState))
		copy(log.BeforeState, beforeState)
	}
	if afterState != nil {
		log.AfterState = make([]byte, len(afterState))
		copy(log.AfterState, afterState)
	}
	if metadata != nil {
		log.Metadata = make([]byte, len(metadata))
		copy(log.Metadata, metadata)
	}
	return &log, nil
}

func (r *AuditRepositoryImpl) parseNullableUUID(ns sql.NullString) *uuid.UUID {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	parsedUUID, err := uuid.Parse(ns.String)
	if err != nil {
		r.logger.Warn("Failed to parse UUID",
			util.String("uuid_string", ns.String),
			util.ErrorField(err))
		return nil
	}
	return &parsedUUID
}

func (r *AuditRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_audit_log_by_id": `
			SELECT audit_id, company_id, module, action, entity_type, entity_id,
			       actor_type, actor_id, before_state, after_state, metadata, created_at
			FROM audit.audit_logs
			WHERE audit_id = $1`,
	}
	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}
		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}
	r.logger.Info("Audit repository prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *AuditRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}
