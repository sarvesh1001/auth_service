package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

// AttendanceRepositoryImpl handles PostgreSQL attendance operations
type AttendanceRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

// NewAttendanceRepository creates a new PostgreSQL attendance repository
func NewAttendanceRepository(postgresClient *client.PostgresClient, logger *zap.Logger) AttendanceRepository {
	repo := &AttendanceRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ============================================================================
// ATTENDANCE EVENT METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateAttendanceEvent(ctx context.Context, event *attendance.AttendanceEvent) error {
	startTime := time.Now()

	query := `
		INSERT INTO attendance_events (
			attendance_event_id, company_id, user_id, event_type, event_time,
			source_type, source_id, device_id, ip_address, metadata,
			created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = r.client.Exec(ctx, query,
		event.AttendanceEventID,
		event.CompanyID,
		event.UserID,
		event.EventType,
		event.EventTime,
		event.SourceType,
		event.SourceID,
		event.DeviceID,
		event.IPAddress,
		metadataJSON,
		event.CreatedAt,
		event.CreatedBy,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance event",
			util.String("user_id", event.UserID.String()),
			util.String("company_id", event.CompanyID.String()),
			util.String("event_type", event.EventType),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance event: %w", err)
	}

	r.logger.Debug("Attendance event created",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("user_id", event.UserID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceEventByID(ctx context.Context, eventID uuid.UUID) (*attendance.AttendanceEvent, error) {
	if stmt, exists := r.getStmt("get_attendance_event_by_id"); exists {
		rows, err := stmt.QueryContext(ctx, eventID)
		if err != nil {
			return nil, fmt.Errorf("failed to get attendance event with prepared statement: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAttendanceEvent(rows)
		}
		return nil, fmt.Errorf("attendance event not found: %s", eventID)
	}

	// Fallback to regular query if prepared statement not available
	query := `
		SELECT attendance_event_id, company_id, user_id, event_type, event_time,
		       source_type, source_id, device_id, ip_address, metadata,
		       created_at, created_by
		FROM attendance_events 
		WHERE attendance_event_id = $1`

	rows, err := r.client.Query(ctx, query, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendanceEvent(rows)
	}

	return nil, fmt.Errorf("attendance event not found: %s", eventID)
}

func (r *AttendanceRepositoryImpl) GetAttendanceEventsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, limit int) ([]*attendance.AttendanceEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := `
		SELECT attendance_event_id, company_id, user_id, event_type, event_time,
		       source_type, source_id, device_id, ip_address, metadata,
		       created_at, created_by
		FROM attendance_events 
		WHERE user_id = $1 
		AND event_time BETWEEN $2 AND $3
		ORDER BY event_time DESC
		LIMIT $4`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance events by user: %w", err)
	}
	defer rows.Close()

	events := make([]*attendance.AttendanceEvent, 0, limit)
	for rows.Next() {
		event, err := r.scanAttendanceEvent(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance event", util.ErrorField(err))
			continue
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance events: %w", err)
	}

	return events, nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceEventsByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, limit, offset int) ([]*attendance.AttendanceEvent, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM attendance_events WHERE company_id = $1 AND event_time BETWEEN $2 AND $3`
	err := r.client.QueryRow(ctx, countQuery, companyID, startDate, endDate).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count attendance events: %w", err)
	}

	// Get events
	query := `
		SELECT attendance_event_id, company_id, user_id, event_type, event_time,
		       source_type, source_id, device_id, ip_address, metadata,
		       created_at, created_by
		FROM attendance_events 
		WHERE company_id = $1 
		AND event_time BETWEEN $2 AND $3
		ORDER BY event_time DESC
		LIMIT $4 OFFSET $5`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get attendance events by company: %w", err)
	}
	defer rows.Close()

	events := make([]*attendance.AttendanceEvent, 0, limit)
	for rows.Next() {
		event, err := r.scanAttendanceEvent(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance event", util.ErrorField(err))
			continue
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating attendance events: %w", err)
	}

	return events, totalCount, nil
}

func (r *AttendanceRepositoryImpl) SearchAttendanceEvents(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*attendance.AttendanceEvent, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramCount := 2

	// Build dynamic WHERE clause
	for field, value := range filters {
		switch field {
		case "user_id":
			if userIDs, ok := value.([]uuid.UUID); ok && len(userIDs) > 0 {
				conditions = append(conditions, fmt.Sprintf("user_id = ANY($%d)", paramCount))
				params = append(params, pq.Array(userIDs))
				paramCount++
			}
		case "event_type":
			if eventTypes, ok := value.([]string); ok && len(eventTypes) > 0 {
				conditions = append(conditions, fmt.Sprintf("event_type = ANY($%d)", paramCount))
				params = append(params, pq.Array(eventTypes))
				paramCount++
			}
		case "source_type":
			if sourceTypes, ok := value.([]string); ok && len(sourceTypes) > 0 {
				conditions = append(conditions, fmt.Sprintf("source_type = ANY($%d)", paramCount))
				params = append(params, pq.Array(sourceTypes))
				paramCount++
			}
		case "start_date":
			conditions = append(conditions, fmt.Sprintf("event_time >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "end_date":
			conditions = append(conditions, fmt.Sprintf("event_time <= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "device_id":
			conditions = append(conditions, fmt.Sprintf("device_id = $%d", paramCount))
			params = append(params, value)
			paramCount++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM attendance_events %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Search query
	searchQuery := fmt.Sprintf(`
		SELECT attendance_event_id, company_id, user_id, event_type, event_time,
		       source_type, source_id, device_id, ip_address, metadata,
		       created_at, created_by
		FROM attendance_events %s
		ORDER BY event_time DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCount, paramCount+1)

	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search attendance events: %w", err)
	}
	defer rows.Close()

	events := make([]*attendance.AttendanceEvent, 0, limit)
	for rows.Next() {
		event, err := r.scanAttendanceEvent(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance event", util.ErrorField(err))
			continue
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return events, totalCount, nil
}

func (r *AttendanceRepositoryImpl) UpdateAttendanceEvent(ctx context.Context, event *attendance.AttendanceEvent) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE attendance_events SET
			event_type = $1, event_time = $2, source_type = $3, source_id = $4,
			device_id = $5, ip_address = $6, metadata = $7
		WHERE attendance_event_id = $8`

	result, err := r.client.Exec(ctx, query,
		event.EventType,
		event.EventTime,
		event.SourceType,
		event.SourceID,
		event.DeviceID,
		event.IPAddress,
		metadataJSON,
		event.AttendanceEventID,
	)

	if err != nil {
		return fmt.Errorf("failed to update attendance event: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance event not found: %s", event.AttendanceEventID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeleteAttendanceEvent(ctx context.Context, eventID uuid.UUID) error {
	query := `DELETE FROM attendance_events WHERE attendance_event_id = $1`
	result, err := r.client.Exec(ctx, query, eventID)
	if err != nil {
		return fmt.Errorf("failed to delete attendance event: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance event not found: %s", eventID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetRecentAttendanceEvents(ctx context.Context, companyID uuid.UUID, limit int) ([]*attendance.AttendanceEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `
		SELECT attendance_event_id, company_id, user_id, event_type, event_time,
		       source_type, source_id, device_id, ip_address, metadata,
		       created_at, created_by
		FROM attendance_events 
		WHERE company_id = $1
		ORDER BY event_time DESC
		LIMIT $2`

	rows, err := r.client.Query(ctx, query, companyID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent attendance events: %w", err)
	}
	defer rows.Close()

	events := make([]*attendance.AttendanceEvent, 0, limit)
	for rows.Next() {
		event, err := r.scanAttendanceEvent(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance event", util.ErrorField(err))
			continue
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance events: %w", err)
	}

	return events, nil
}

// ============================================================================
// ATTENDANCE POLICY METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateAttendancePolicy(ctx context.Context, policy *attendance.AttendancePolicy) error {
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal policy rules: %w", err)
	}

	query := `
		INSERT INTO attendance_policies (
			policy_id, company_id, department_id, policy_code, policy_type,
			rules, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = r.client.Exec(ctx, query,
		policy.PolicyID,
		policy.CompanyID,
		policy.DepartmentID,
		policy.PolicyCode,
		policy.PolicyType,
		rulesJSON,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance policy",
			util.String("policy_code", policy.PolicyCode),
			util.String("company_id", policy.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance policy: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetAttendancePolicyByID(ctx context.Context, policyID uuid.UUID) (*attendance.AttendancePolicy, error) {
	if stmt, exists := r.getStmt("get_attendance_policy_by_id"); exists {
		rows, err := stmt.QueryContext(ctx, policyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get attendance policy with prepared statement: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAttendancePolicy(rows)
		}
		return nil, fmt.Errorf("attendance policy not found: %s", policyID)
	}

	// Fallback to regular query if prepared statement not available
	query := `
		SELECT policy_id, company_id, department_id, policy_code, policy_type,
		       rules, is_active, created_at, updated_at
		FROM attendance_policies 
		WHERE policy_id = $1`

	rows, err := r.client.Query(ctx, query, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policy: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendancePolicy(rows)
	}

	return nil, fmt.Errorf("attendance policy not found: %s", policyID)
}

func (r *AttendanceRepositoryImpl) GetAttendancePolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*attendance.AttendancePolicy, error) {
	if stmt, exists := r.getStmt("get_attendance_policy_by_code"); exists {
		rows, err := stmt.QueryContext(ctx, companyID, policyCode)
		if err != nil {
			return nil, fmt.Errorf("failed to get attendance policy by code with prepared statement: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAttendancePolicy(rows)
		}
		return nil, fmt.Errorf("attendance policy not found: %s", policyCode)
	}

	// Fallback to regular query if prepared statement not available
	query := `
		SELECT policy_id, company_id, department_id, policy_code, policy_type,
		       rules, is_active, created_at, updated_at
		FROM attendance_policies 
		WHERE company_id = $1 AND policy_code = $2`

	rows, err := r.client.Query(ctx, query, companyID, policyCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policy by code: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendancePolicy(rows)
	}

	return nil, fmt.Errorf("attendance policy not found: %s", policyCode)
}

func (r *AttendanceRepositoryImpl) GetAttendancePoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, department_id, policy_code, policy_type,
		       rules, is_active, created_at, updated_at
		FROM attendance_policies 
		WHERE company_id = $1`

	params := []interface{}{companyID}
	if activeOnly {
		query += " AND is_active = true"
	}

	query += " ORDER BY policy_code"

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*attendance.AttendancePolicy, 0)
	for rows.Next() {
		policy, err := r.scanAttendancePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance policies: %w", err)
	}

	return policies, nil
}

func (r *AttendanceRepositoryImpl) UpdateAttendancePolicy(ctx context.Context, policy *attendance.AttendancePolicy) error {
	now := time.Now().UTC()
	policy.UpdatedAt = now

	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal policy rules: %w", err)
	}

	query := `
		UPDATE attendance_policies SET
			policy_code = $1, policy_type = $2, department_id = $3,
			rules = $4, is_active = $5, updated_at = $6
		WHERE policy_id = $7`

	result, err := r.client.Exec(ctx, query,
		policy.PolicyCode,
		policy.PolicyType,
		policy.DepartmentID,
		rulesJSON,
		policy.IsActive,
		policy.UpdatedAt,
		policy.PolicyID,
	)

	if err != nil {
		return fmt.Errorf("failed to update attendance policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance policy not found: %s", policy.PolicyID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeleteAttendancePolicy(ctx context.Context, policyID uuid.UUID) error {
	query := `DELETE FROM attendance_policies WHERE policy_id = $1`
	result, err := r.client.Exec(ctx, query, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete attendance policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance policy not found: %s", policyID)
	}

	return nil
}

// ============================================================================
// USER ATTENDANCE POLICY METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) AssignUserAttendancePolicy(ctx context.Context, userPolicy *attendance.UserAttendancePolicy) error {
	query := `
		INSERT INTO user_attendance_policies (
			user_id, policy_id, effective_from, effective_to,
			assigned_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.client.Exec(ctx, query,
		userPolicy.UserID,
		userPolicy.PolicyID,
		userPolicy.EffectiveFrom,
		userPolicy.EffectiveTo,
		userPolicy.AssignedBy,
		userPolicy.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to assign user attendance policy",
			util.String("user_id", userPolicy.UserID.String()),
			util.String("policy_id", userPolicy.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user attendance policy: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetUserAttendancePolicy(ctx context.Context, userID uuid.UUID, policyID uuid.UUID) (*attendance.UserAttendancePolicy, error) {
	query := `
		SELECT user_id, policy_id, effective_from, effective_to,
		       assigned_by, created_at
		FROM user_attendance_policies 
		WHERE user_id = $1 AND policy_id = $2`

	rows, err := r.client.Query(ctx, query, userID, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance policy: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanUserAttendancePolicy(rows)
	}

	return nil, fmt.Errorf("user attendance policy not found")
}

func (r *AttendanceRepositoryImpl) GetUserCurrentAttendancePolicy(ctx context.Context, userID uuid.UUID, asOfDate time.Time) (*attendance.AttendancePolicy, error) {
	query := `
		SELECT p.policy_id, p.company_id, p.department_id, p.policy_code,
		       p.policy_type, p.rules, p.is_active, p.created_at, p.updated_at
		FROM attendance_policies p
		INNER JOIN user_attendance_policies up ON p.policy_id = up.policy_id
		WHERE up.user_id = $1 
		AND (up.effective_from <= $2 AND (up.effective_to IS NULL OR up.effective_to >= $2))
		AND p.is_active = true
		ORDER BY up.effective_from DESC
		LIMIT 1`

	rows, err := r.client.Query(ctx, query, userID, asOfDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get user current attendance policy: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendancePolicy(rows)
	}

	return nil, fmt.Errorf("no active attendance policy found for user")
}

func (r *AttendanceRepositoryImpl) GetUserAttendancePolicyHistory(ctx context.Context, userID uuid.UUID) ([]*attendance.UserAttendancePolicy, error) {
	query := `
		SELECT user_id, policy_id, effective_from, effective_to,
		       assigned_by, created_at
		FROM user_attendance_policies 
		WHERE user_id = $1
		ORDER BY effective_from DESC`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance policy history: %w", err)
	}
	defer rows.Close()

	policies := make([]*attendance.UserAttendancePolicy, 0)
	for rows.Next() {
		policy, err := r.scanUserAttendancePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan user attendance policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user attendance policies: %w", err)
	}

	return policies, nil
}

func (r *AttendanceRepositoryImpl) UpdateUserAttendancePolicy(ctx context.Context, userPolicy *attendance.UserAttendancePolicy) error {
	query := `
		UPDATE user_attendance_policies SET
			effective_from = $1, effective_to = $2
		WHERE user_id = $3 AND policy_id = $4`

	result, err := r.client.Exec(ctx, query,
		userPolicy.EffectiveFrom,
		userPolicy.EffectiveTo,
		userPolicy.UserID,
		userPolicy.PolicyID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user attendance policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user attendance policy not found")
	}

	return nil
}

func (r *AttendanceRepositoryImpl) RemoveUserAttendancePolicy(ctx context.Context, userID, policyID uuid.UUID) error {
	query := `DELETE FROM user_attendance_policies WHERE user_id = $1 AND policy_id = $2`
	result, err := r.client.Exec(ctx, query, userID, policyID)
	if err != nil {
		return fmt.Errorf("failed to remove user attendance policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user attendance policy not found")
	}

	return nil
}

// ============================================================================
// ATTENDANCE SOURCE METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateAttendanceSource(ctx context.Context, source *attendance.AttendanceSource) error {
	query := `
		INSERT INTO attendance_sources (
			source_id, company_id, source_type, name, reference_type,
			reference_id, is_active, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.client.Exec(ctx, query,
		source.SourceID,
		source.CompanyID,
		source.SourceType,
		source.Name,
		source.ReferenceType,
		source.ReferenceID,
		source.IsActive,
		source.CreatedAt,
		source.CreatedBy,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance source",
			util.String("name", source.Name),
			util.String("company_id", source.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance source: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceSourceByID(ctx context.Context, sourceID uuid.UUID) (*attendance.AttendanceSource, error) {
	if stmt, exists := r.getStmt("get_attendance_source_by_id"); exists {
		rows, err := stmt.QueryContext(ctx, sourceID)
		if err != nil {
			return nil, fmt.Errorf("failed to get attendance source with prepared statement: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAttendanceSource(rows)
		}
		return nil, fmt.Errorf("attendance source not found: %s", sourceID)
	}

	// Fallback to regular query if prepared statement not available
	query := `
		SELECT source_id, company_id, source_type, name, reference_type,
		       reference_id, is_active, created_at, created_by
		FROM attendance_sources 
		WHERE source_id = $1`

	rows, err := r.client.Query(ctx, query, sourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance source: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendanceSource(rows)
	}

	return nil, fmt.Errorf("attendance source not found: %s", sourceID)
}

func (r *AttendanceRepositoryImpl) GetAttendanceSourcesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendanceSource, error) {
	query := `
		SELECT source_id, company_id, source_type, name, reference_type,
		       reference_id, is_active, created_at, created_by
		FROM attendance_sources 
		WHERE company_id = $1`

	params := []interface{}{companyID}
	if activeOnly {
		query += " AND is_active = true"
	}

	query += " ORDER BY name"

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance sources: %w", err)
	}
	defer rows.Close()

	sources := make([]*attendance.AttendanceSource, 0)
	for rows.Next() {
		source, err := r.scanAttendanceSource(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance source", util.ErrorField(err))
			continue
		}
		sources = append(sources, source)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance sources: %w", err)
	}

	return sources, nil
}

func (r *AttendanceRepositoryImpl) UpdateAttendanceSource(ctx context.Context, source *attendance.AttendanceSource) error {
	query := `
		UPDATE attendance_sources SET
			name = $1, source_type = $2, reference_type = $3,
			reference_id = $4, is_active = $5
		WHERE source_id = $6`

	result, err := r.client.Exec(ctx, query,
		source.Name,
		source.SourceType,
		source.ReferenceType,
		source.ReferenceID,
		source.IsActive,
		source.SourceID,
	)

	if err != nil {
		return fmt.Errorf("failed to update attendance source: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance source not found: %s", source.SourceID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeleteAttendanceSource(ctx context.Context, sourceID uuid.UUID) error {
	query := `DELETE FROM attendance_sources WHERE source_id = $1`
	result, err := r.client.Exec(ctx, query, sourceID)
	if err != nil {
		return fmt.Errorf("failed to delete attendance source: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance source not found: %s", sourceID)
	}

	return nil
}

// ============================================================================
// ATTENDANCE DAILY SUMMARY METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateAttendanceDailySummary(ctx context.Context, summary *attendance.AttendanceDailySummary) error {
	metadataJSON, err := json.Marshal(summary.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO attendance_daily_summary (
			attendance_summary_id, company_id, user_id, attendance_date,
			status, worked_minutes, overtime_minutes, late_minutes,
			metadata, generated_at, generated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err = r.client.Exec(ctx, query,
		summary.AttendanceSummaryID,
		summary.CompanyID,
		summary.UserID,
		summary.AttendanceDate,
		summary.Status,
		summary.WorkedMinutes,
		summary.OvertimeMinutes,
		summary.LateMinutes,
		metadataJSON,
		summary.GeneratedAt,
		summary.GeneratedBy,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance daily summary",
			util.String("user_id", summary.UserID.String()),
			util.String("date", summary.AttendanceDate.Format("2006-01-02")),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance daily summary: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceDailySummaryByID(ctx context.Context, summaryID uuid.UUID) (*attendance.AttendanceDailySummary, error) {
	if stmt, exists := r.getStmt("get_attendance_daily_summary_by_id"); exists {
		rows, err := stmt.QueryContext(ctx, summaryID)
		if err != nil {
			return nil, fmt.Errorf("failed to get attendance daily summary with prepared statement: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAttendanceDailySummary(rows)
		}
		return nil, fmt.Errorf("attendance daily summary not found: %s", summaryID)
	}

	// Fallback to regular query if prepared statement not available
	query := `
		SELECT attendance_summary_id, company_id, user_id, attendance_date,
		       status, worked_minutes, overtime_minutes, late_minutes,
		       metadata, generated_at, generated_by
		FROM attendance_daily_summary 
		WHERE attendance_summary_id = $1`

	rows, err := r.client.Query(ctx, query, summaryID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summary: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendanceDailySummary(rows)
	}

	return nil, fmt.Errorf("attendance daily summary not found: %s", summaryID)
}

func (r *AttendanceRepositoryImpl) GetAttendanceDailySummaryByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*attendance.AttendanceDailySummary, error) {
	query := `
		SELECT attendance_summary_id, company_id, user_id, attendance_date,
		       status, worked_minutes, overtime_minutes, late_minutes,
		       metadata, generated_at, generated_by
		FROM attendance_daily_summary 
		WHERE user_id = $1 AND attendance_date = $2`

	rows, err := r.client.Query(ctx, query, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summary by user and date: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendanceDailySummary(rows)
	}

	return nil, fmt.Errorf("attendance daily summary not found for user %s on date %s", userID, date.Format("2006-01-02"))
}

func (r *AttendanceRepositoryImpl) GetAttendanceDailySummariesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*attendance.AttendanceDailySummary, error) {
	query := `
		SELECT attendance_summary_id, company_id, user_id, attendance_date,
		       status, worked_minutes, overtime_minutes, late_minutes,
		       metadata, generated_at, generated_by
		FROM attendance_daily_summary 
		WHERE user_id = $1 
		AND attendance_date BETWEEN $2 AND $3
		ORDER BY attendance_date DESC`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summaries by user: %w", err)
	}
	defer rows.Close()

	summaries := make([]*attendance.AttendanceDailySummary, 0)
	for rows.Next() {
		summary, err := r.scanAttendanceDailySummary(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance daily summary", util.ErrorField(err))
			continue
		}
		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance daily summaries: %w", err)
	}

	return summaries, nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceDailySummariesByCompany(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*attendance.AttendanceDailySummary, error) {
	query := `
		SELECT attendance_summary_id, company_id, user_id, attendance_date,
		       status, worked_minutes, overtime_minutes, late_minutes,
		       metadata, generated_at, generated_by
		FROM attendance_daily_summary 
		WHERE company_id = $1 AND attendance_date = $2
		ORDER BY user_id`

	rows, err := r.client.Query(ctx, query, companyID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summaries by company: %w", err)
	}
	defer rows.Close()

	summaries := make([]*attendance.AttendanceDailySummary, 0)
	for rows.Next() {
		summary, err := r.scanAttendanceDailySummary(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance daily summary", util.ErrorField(err))
			continue
		}
		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance daily summaries: %w", err)
	}

	return summaries, nil
}

func (r *AttendanceRepositoryImpl) UpdateAttendanceDailySummary(ctx context.Context, summary *attendance.AttendanceDailySummary) error {
	metadataJSON, err := json.Marshal(summary.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE attendance_daily_summary SET
			status = $1, worked_minutes = $2, overtime_minutes = $3,
			late_minutes = $4, metadata = $5, generated_at = $6
		WHERE attendance_summary_id = $7`

	result, err := r.client.Exec(ctx, query,
		summary.Status,
		summary.WorkedMinutes,
		summary.OvertimeMinutes,
		summary.LateMinutes,
		metadataJSON,
		summary.GeneratedAt,
		summary.AttendanceSummaryID,
	)

	if err != nil {
		return fmt.Errorf("failed to update attendance daily summary: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance daily summary not found: %s", summary.AttendanceSummaryID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeleteAttendanceDailySummary(ctx context.Context, summaryID uuid.UUID) error {
	query := `DELETE FROM attendance_daily_summary WHERE attendance_summary_id = $1`
	result, err := r.client.Exec(ctx, query, summaryID)
	if err != nil {
		return fmt.Errorf("failed to delete attendance daily summary: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance daily summary not found: %s", summaryID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceSummaryStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total attendance records
	var totalRecords int
	err := r.client.QueryRow(ctx,
		`SELECT COUNT(*) FROM attendance_daily_summary WHERE company_id = $1 AND attendance_date BETWEEN $2 AND $3`,
		companyID, startDate, endDate).Scan(&totalRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to get total attendance records: %w", err)
	}
	stats["total_records"] = totalRecords

	// Average worked minutes
	var avgWorkedMinutes float64
	err = r.client.QueryRow(ctx,
		`SELECT AVG(worked_minutes) FROM attendance_daily_summary WHERE company_id = $1 AND attendance_date BETWEEN $2 AND $3 AND worked_minutes IS NOT NULL`,
		companyID, startDate, endDate).Scan(&avgWorkedMinutes)
	if err != nil {
		stats["avg_worked_minutes"] = 0
	} else {
		stats["avg_worked_minutes"] = avgWorkedMinutes
	}

	// Attendance by status
	query := `
		SELECT status, COUNT(*) as count
		FROM attendance_daily_summary 
		WHERE company_id = $1 AND attendance_date BETWEEN $2 AND $3
		GROUP BY status`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance by status: %w", err)
	}
	defer rows.Close()

	statusStats := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		statusStats[status] = count
	}
	stats["status_distribution"] = statusStats

	// Late arrivals count
	var lateArrivals int
	err = r.client.QueryRow(ctx,
		`SELECT COUNT(*) FROM attendance_daily_summary WHERE company_id = $1 AND attendance_date BETWEEN $2 AND $3 AND late_minutes > 0`,
		companyID, startDate, endDate).Scan(&lateArrivals)
	if err != nil {
		stats["late_arrivals"] = 0
	} else {
		stats["late_arrivals"] = lateArrivals
	}

	// Total overtime minutes
	var totalOvertime int
	err = r.client.QueryRow(ctx,
		`SELECT COALESCE(SUM(overtime_minutes), 0) FROM attendance_daily_summary WHERE company_id = $1 AND attendance_date BETWEEN $2 AND $3`,
		companyID, startDate, endDate).Scan(&totalOvertime)
	if err != nil {
		stats["total_overtime_minutes"] = 0
	} else {
		stats["total_overtime_minutes"] = totalOvertime
	}

	// Attendance trend (last 7 days)
	trendQuery := `
		SELECT attendance_date, COUNT(*) as present_count
		FROM attendance_daily_summary 
		WHERE company_id = $1 
			AND attendance_date BETWEEN $2 AND $3
			AND status IN ('present', 'half_day')
		GROUP BY attendance_date
		ORDER BY attendance_date`

	trendRows, err := r.client.Query(ctx, trendQuery, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance trend: %w", err)
	}
	defer trendRows.Close()

	trendData := make([]map[string]interface{}, 0)
	for trendRows.Next() {
		var date time.Time
		var count int
		if err := trendRows.Scan(&date, &count); err != nil {
			continue
		}
		trendData = append(trendData, map[string]interface{}{
			"date":          date.Format("2006-01-02"),
			"present_count": count,
		})
	}
	stats["attendance_trend"] = trendData

	return stats, nil
}

// ============================================================================
// ATTENDANCE LOCATION METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateAttendanceLocation(ctx context.Context, location *attendance.AttendanceLocation) error {
	query := `
		INSERT INTO attendance_locations (
			location_id, company_id, name, location_type,
			geo_lat, geo_lng, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.client.Exec(ctx, query,
		location.LocationID,
		location.CompanyID,
		location.Name,
		location.LocationType,
		location.GeoLat,
		location.GeoLng,
		location.IsActive,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance location",
			util.String("name", *location.Name),
			util.String("company_id", location.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance location: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetAttendanceLocationByID(ctx context.Context, locationID uuid.UUID) (*attendance.AttendanceLocation, error) {
	if stmt, exists := r.getStmt("get_attendance_location_by_id"); exists {
		rows, err := stmt.QueryContext(ctx, locationID)
		if err != nil {
			return nil, fmt.Errorf("failed to get attendance location with prepared statement: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAttendanceLocation(rows)
		}
		return nil, fmt.Errorf("attendance location not found: %s", locationID)
	}

	// Fallback to regular query if prepared statement not available
	query := `
		SELECT location_id, company_id, name, location_type,
		       geo_lat, geo_lng, is_active
		FROM attendance_locations 
		WHERE location_id = $1`

	rows, err := r.client.Query(ctx, query, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance location: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAttendanceLocation(rows)
	}

	return nil, fmt.Errorf("attendance location not found: %s", locationID)
}

func (r *AttendanceRepositoryImpl) GetAttendanceLocationsByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendanceLocation, error) {
	query := `
		SELECT location_id, company_id, name, location_type,
		       geo_lat, geo_lng, is_active
		FROM attendance_locations 
		WHERE company_id = $1`

	params := []interface{}{companyID}
	if activeOnly {
		query += " AND is_active = true"
	}

	query += " ORDER BY name"

	rows, err := r.client.Query(ctx, query, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance locations: %w", err)
	}
	defer rows.Close()

	locations := make([]*attendance.AttendanceLocation, 0)
	for rows.Next() {
		location, err := r.scanAttendanceLocation(rows)
		if err != nil {
			r.logger.Warn("Failed to scan attendance location", util.ErrorField(err))
			continue
		}
		locations = append(locations, location)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating attendance locations: %w", err)
	}

	return locations, nil
}

func (r *AttendanceRepositoryImpl) UpdateAttendanceLocation(ctx context.Context, location *attendance.AttendanceLocation) error {
	query := `
		UPDATE attendance_locations SET
			name = $1, location_type = $2, geo_lat = $3,
			geo_lng = $4, is_active = $5
		WHERE location_id = $6`

	result, err := r.client.Exec(ctx, query,
		location.Name,
		location.LocationType,
		location.GeoLat,
		location.GeoLng,
		location.IsActive,
		location.LocationID,
	)

	if err != nil {
		return fmt.Errorf("failed to update attendance location: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance location not found: %s", location.LocationID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeleteAttendanceLocation(ctx context.Context, locationID uuid.UUID) error {
	query := `DELETE FROM attendance_locations WHERE location_id = $1`
	result, err := r.client.Exec(ctx, query, locationID)
	if err != nil {
		return fmt.Errorf("failed to delete attendance location: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance location not found: %s", locationID)
	}

	return nil
}

// ============================================================================
// BATCH OPERATIONS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateAttendanceEventsBatch(ctx context.Context, events []*attendance.AttendanceEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO attendance_events (
			attendance_event_id, company_id, user_id, event_type, event_time,
			source_type, source_id, device_id, ip_address, metadata,
			created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		metadataJSON, err := json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata for event %s: %w", event.AttendanceEventID, err)
		}

		_, err = stmt.ExecContext(ctx,
			event.AttendanceEventID,
			event.CompanyID,
			event.UserID,
			event.EventType,
			event.EventTime,
			event.SourceType,
			event.SourceID,
			event.DeviceID,
			event.IPAddress,
			metadataJSON,
			event.CreatedAt,
			event.CreatedBy,
		)
		if err != nil {
			return fmt.Errorf("failed to insert attendance event %s: %w", event.AttendanceEventID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info("Batch attendance events creation completed",
		util.Int("events_created", len(events)))
	return nil
}

func (r *AttendanceRepositoryImpl) CreateAttendanceDailySummariesBatch(ctx context.Context, summaries []*attendance.AttendanceDailySummary) error {
	if len(summaries) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO attendance_daily_summary (
			attendance_summary_id, company_id, user_id, attendance_date,
			status, worked_minutes, overtime_minutes, late_minutes,
			metadata, generated_at, generated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, summary := range summaries {
		metadataJSON, err := json.Marshal(summary.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata for summary %s: %w", summary.AttendanceSummaryID, err)
		}

		_, err = stmt.ExecContext(ctx,
			summary.AttendanceSummaryID,
			summary.CompanyID,
			summary.UserID,
			summary.AttendanceDate,
			summary.Status,
			summary.WorkedMinutes,
			summary.OvertimeMinutes,
			summary.LateMinutes,
			metadataJSON,
			summary.GeneratedAt,
			summary.GeneratedBy,
		)
		if err != nil {
			return fmt.Errorf("failed to insert attendance summary %s: %w", summary.AttendanceSummaryID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info("Batch attendance daily summaries creation completed",
		util.Int("summaries_created", len(summaries)))
	return nil
}

// ============================================================================
// ANALYTICS & REPORTS
// ============================================================================

func (r *AttendanceRepositoryImpl) GetAttendanceReportByDepartment(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	report := make(map[string]interface{})

	query := `
		SELECT 
			d.department_name,
			COUNT(DISTINCT ads.user_id) as total_employees,
			COUNT(CASE WHEN ads.status = 'present' THEN 1 END) as present_count,
			COUNT(CASE WHEN ads.status = 'absent' THEN 1 END) as absent_count,
			COUNT(CASE WHEN ads.status = 'half_day' THEN 1 END) as half_day_count,
			COALESCE(AVG(ads.worked_minutes), 0) as avg_worked_minutes,
			COALESCE(SUM(ads.late_minutes), 0) as total_late_minutes
		FROM attendance_daily_summary ads
		INNER JOIN company_employees ce ON ads.user_id = ce.user_id AND ads.company_id = ce.company_id
		INNER JOIN roles r ON ce.role_id = r.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id
		INNER JOIN departments d ON rd.department_id = d.department_id
		WHERE ads.company_id = $1 
			AND ads.attendance_date BETWEEN $2 AND $3
			AND ce.is_active = true
		GROUP BY d.department_name
		ORDER BY d.department_name`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance report by department: %w", err)
	}
	defer rows.Close()

	departmentReports := make([]map[string]interface{}, 0)
	for rows.Next() {
		var deptName string
		var totalEmployees, presentCount, absentCount, halfDayCount int
		var avgWorkedMinutes float64
		var totalLateMinutes int

		err := rows.Scan(&deptName, &totalEmployees, &presentCount, &absentCount, &halfDayCount, &avgWorkedMinutes, &totalLateMinutes)
		if err != nil {
			continue
		}

		attendanceRate := 0.0
		if totalEmployees > 0 {
			attendanceRate = (float64(presentCount+halfDayCount) / float64(totalEmployees)) * 100
		}

		departmentReports = append(departmentReports, map[string]interface{}{
			"department_name":    deptName,
			"total_employees":    totalEmployees,
			"present_count":      presentCount,
			"absent_count":       absentCount,
			"half_day_count":     halfDayCount,
			"attendance_rate":    attendanceRate,
			"avg_worked_minutes": avgWorkedMinutes,
			"total_late_minutes": totalLateMinutes,
		})
	}

	report["department_reports"] = departmentReports
	report["report_period"] = map[string]interface{}{
		"start_date": startDate.Format("2006-01-02"),
		"end_date":   endDate.Format("2006-01-02"),
	}

	return report, nil
}

func (r *AttendanceRepositoryImpl) GetLateArrivalsReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error) {
	query := `
		SELECT 
			u.user_id,
			u.full_name,
			u.username,
			ce.employee_id,
			d.department_name,
			COUNT(ads.attendance_summary_id) as late_days,
			COALESCE(AVG(ads.late_minutes), 0) as avg_late_minutes,
			MAX(ads.late_minutes) as max_late_minutes
		FROM attendance_daily_summary ads
		INNER JOIN users u ON ads.user_id = u.user_id
		INNER JOIN company_employees ce ON ads.user_id = ce.user_id AND ads.company_id = ce.company_id
		INNER JOIN roles r ON ce.role_id = r.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id
		INNER JOIN departments d ON rd.department_id = d.department_id
		WHERE ads.company_id = $1 
			AND ads.attendance_date BETWEEN $2 AND $3
			AND ads.late_minutes > 0
			AND ce.is_active = true
		GROUP BY u.user_id, u.full_name, u.username, ce.employee_id, d.department_name
		ORDER BY late_days DESC, avg_late_minutes DESC
		LIMIT 50`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get late arrivals report: %w", err)
	}
	defer rows.Close()

	lateArrivals := make([]map[string]interface{}, 0)
	for rows.Next() {
		var userID uuid.UUID
		var fullName, username, employeeID, departmentName sql.NullString
		var lateDays int
		var avgLateMinutes float64
		var maxLateMinutes int

		err := rows.Scan(&userID, &fullName, &username, &employeeID, &departmentName, &lateDays, &avgLateMinutes, &maxLateMinutes)
		if err != nil {
			continue
		}

		lateArrivals = append(lateArrivals, map[string]interface{}{
			"user_id":          userID,
			"full_name":        fullName.String,
			"username":         username.String,
			"employee_id":      employeeID.String,
			"department_name":  departmentName.String,
			"late_days":        lateDays,
			"avg_late_minutes": avgLateMinutes,
			"max_late_minutes": maxLateMinutes,
		})
	}

	return lateArrivals, nil
}

func (r *AttendanceRepositoryImpl) GetAbsenceReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error) {
	query := `
		SELECT 
			u.user_id,
			u.full_name,
			u.username,
			ce.employee_id,
			d.department_name,
			COUNT(ads.attendance_summary_id) as absence_days,
			STRING_AGG(DISTINCT TO_CHAR(ads.attendance_date, 'YYYY-MM-DD'), ', ') as absence_dates
		FROM attendance_daily_summary ads
		INNER JOIN users u ON ads.user_id = u.user_id
		INNER JOIN company_employees ce ON ads.user_id = ce.user_id AND ads.company_id = ce.company_id
		INNER JOIN roles r ON ce.role_id = r.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id
		INNER JOIN departments d ON rd.department_id = d.department_id
		WHERE ads.company_id = $1 
			AND ads.attendance_date BETWEEN $2 AND $3
			AND ads.status = 'absent'
			AND ce.is_active = true
		GROUP BY u.user_id, u.full_name, u.username, ce.employee_id, d.department_name
		ORDER BY absence_days DESC
		LIMIT 50`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get absence report: %w", err)
	}
	defer rows.Close()

	absences := make([]map[string]interface{}, 0)
	for rows.Next() {
		var userID uuid.UUID
		var fullName, username, employeeID, departmentName, absenceDates sql.NullString
		var absenceDays int

		err := rows.Scan(&userID, &fullName, &username, &employeeID, &departmentName, &absenceDays, &absenceDates)
		if err != nil {
			continue
		}

		absences = append(absences, map[string]interface{}{
			"user_id":         userID,
			"full_name":       fullName.String,
			"username":        username.String,
			"employee_id":     employeeID.String,
			"department_name": departmentName.String,
			"absence_days":    absenceDays,
			"absence_dates":   absenceDates.String,
		})
	}

	return absences, nil
}

func (r *AttendanceRepositoryImpl) GetOvertimeReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error) {
	query := `
		SELECT 
			u.user_id,
			u.full_name,
			u.username,
			ce.employee_id,
			d.department_name,
			COUNT(ads.attendance_summary_id) as overtime_days,
			COALESCE(SUM(ads.overtime_minutes), 0) as total_overtime_minutes,
			COALESCE(AVG(ads.overtime_minutes), 0) as avg_overtime_minutes
		FROM attendance_daily_summary ads
		INNER JOIN users u ON ads.user_id = u.user_id
		INNER JOIN company_employees ce ON ads.user_id = ce.user_id AND ads.company_id = ce.company_id
		INNER JOIN roles r ON ce.role_id = r.role_id
		INNER JOIN role_departments rd ON r.role_id = rd.role_id
		INNER JOIN departments d ON rd.department_id = d.department_id
		WHERE ads.company_id = $1 
			AND ads.attendance_date BETWEEN $2 AND $3
			AND ads.overtime_minutes > 0
			AND ce.is_active = true
		GROUP BY u.user_id, u.full_name, u.username, ce.employee_id, d.department_name
		ORDER BY total_overtime_minutes DESC
		LIMIT 50`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get overtime report: %w", err)
	}
	defer rows.Close()

	overtimeReports := make([]map[string]interface{}, 0)
	for rows.Next() {
		var userID uuid.UUID
		var fullName, username, employeeID, departmentName sql.NullString
		var overtimeDays, totalOvertimeMinutes int
		var avgOvertimeMinutes float64

		err := rows.Scan(&userID, &fullName, &username, &employeeID, &departmentName, &overtimeDays, &totalOvertimeMinutes, &avgOvertimeMinutes)
		if err != nil {
			continue
		}

		overtimeHours := float64(totalOvertimeMinutes) / 60.0

		overtimeReports = append(overtimeReports, map[string]interface{}{
			"user_id":                userID,
			"full_name":              fullName.String,
			"username":               username.String,
			"employee_id":            employeeID.String,
			"department_name":        departmentName.String,
			"overtime_days":          overtimeDays,
			"total_overtime_minutes": totalOvertimeMinutes,
			"total_overtime_hours":   overtimeHours,
			"avg_overtime_minutes":   avgOvertimeMinutes,
		})
	}

	return overtimeReports, nil
}

// ============================================================================
// HELPER METHODS FOR SCANNING
// ============================================================================

func (r *AttendanceRepositoryImpl) scanAttendanceEvent(rows *sql.Rows) (*attendance.AttendanceEvent, error) {
	var event attendance.AttendanceEvent
	var sourceID, deviceID, ipAddress, createdBy sql.NullString
	var metadataJSON []byte

	err := rows.Scan(
		&event.AttendanceEventID,
		&event.CompanyID,
		&event.UserID,
		&event.EventType,
		&event.EventTime,
		&event.SourceType,
		&sourceID,
		&deviceID,
		&ipAddress,
		&metadataJSON,
		&event.CreatedAt,
		&createdBy,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if sourceID.Valid && sourceID.String != "" {
		sourceUUID, err := uuid.Parse(sourceID.String)
		if err == nil {
			event.SourceID = &sourceUUID
		}
	}
	if deviceID.Valid {
		event.DeviceID = &deviceID.String
	}
	if ipAddress.Valid {
		event.IPAddress = &ipAddress.String
	}
	if createdBy.Valid && createdBy.String != "" {
		createdByUUID, err := uuid.Parse(createdBy.String)
		if err == nil {
			event.CreatedBy = &createdByUUID
		}
	}

	// Parse metadata
	if len(metadataJSON) > 0 {
		var metadata attendance.EventMetadata
		if err := json.Unmarshal(metadataJSON, &metadata); err == nil {
			event.Metadata = metadata
		}
	}

	return &event, nil
}

func (r *AttendanceRepositoryImpl) scanAttendancePolicy(rows *sql.Rows) (*attendance.AttendancePolicy, error) {
	var policy attendance.AttendancePolicy
	var departmentID sql.NullString
	var rulesJSON []byte

	err := rows.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&departmentID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if departmentID.Valid && departmentID.String != "" {
		departmentUUID, err := uuid.Parse(departmentID.String)
		if err == nil {
			policy.DepartmentID = &departmentUUID
		}
	}

	// Parse rules
	if len(rulesJSON) > 0 {
		var rules attendance.PolicyRules
		if err := json.Unmarshal(rulesJSON, &rules); err == nil {
			policy.Rules = rules
		}
	}

	return &policy, nil
}

func (r *AttendanceRepositoryImpl) scanUserAttendancePolicy(rows *sql.Rows) (*attendance.UserAttendancePolicy, error) {
	var policy attendance.UserAttendancePolicy
	var effectiveTo sql.NullTime
	var assignedBy sql.NullString

	err := rows.Scan(
		&policy.UserID,
		&policy.PolicyID,
		&policy.EffectiveFrom,
		&effectiveTo,
		&assignedBy,
		&policy.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if effectiveTo.Valid {
		policy.EffectiveTo = &effectiveTo.Time
	}
	if assignedBy.Valid && assignedBy.String != "" {
		assignedByUUID, err := uuid.Parse(assignedBy.String)
		if err == nil {
			policy.AssignedBy = &assignedByUUID
		}
	}

	return &policy, nil
}

func (r *AttendanceRepositoryImpl) scanAttendanceSource(rows *sql.Rows) (*attendance.AttendanceSource, error) {
	var source attendance.AttendanceSource
	var name, referenceType sql.NullString
	var referenceID, createdBy sql.NullString

	err := rows.Scan(
		&source.SourceID,
		&source.CompanyID,
		&source.SourceType,
		&name,
		&referenceType,
		&referenceID,
		&source.IsActive,
		&source.CreatedAt,
		&createdBy,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if name.Valid {
		source.Name = name.String
	}
	if referenceType.Valid {
		source.ReferenceType = &referenceType.String
	}
	if referenceID.Valid && referenceID.String != "" {
		refUUID, err := uuid.Parse(referenceID.String)
		if err == nil {
			source.ReferenceID = &refUUID
		}
	}
	if createdBy.Valid && createdBy.String != "" {
		createdByUUID, err := uuid.Parse(createdBy.String)
		if err == nil {
			source.CreatedBy = &createdByUUID
		}
	}

	return &source, nil
}

func (r *AttendanceRepositoryImpl) scanAttendanceDailySummary(rows *sql.Rows) (*attendance.AttendanceDailySummary, error) {
	var summary attendance.AttendanceDailySummary
	var workedMinutes, overtimeMinutes, lateMinutes sql.NullInt32
	var metadataJSON []byte

	err := rows.Scan(
		&summary.AttendanceSummaryID,
		&summary.CompanyID,
		&summary.UserID,
		&summary.AttendanceDate,
		&summary.Status,
		&workedMinutes,
		&overtimeMinutes,
		&lateMinutes,
		&metadataJSON,
		&summary.GeneratedAt,
		&summary.GeneratedBy,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if workedMinutes.Valid {
		worked := int(workedMinutes.Int32)
		summary.WorkedMinutes = &worked
	}
	if overtimeMinutes.Valid {
		overtime := int(overtimeMinutes.Int32)
		summary.OvertimeMinutes = &overtime
	}
	if lateMinutes.Valid {
		late := int(lateMinutes.Int32)
		summary.LateMinutes = &late
	}

	// Parse metadata
	if len(metadataJSON) > 0 {
		var metadata attendance.SummaryMetadata
		if err := json.Unmarshal(metadataJSON, &metadata); err == nil {
			summary.Metadata = metadata
		}
	}

	return &summary, nil
}

func (r *AttendanceRepositoryImpl) scanAttendanceLocation(rows *sql.Rows) (*attendance.AttendanceLocation, error) {
	var location attendance.AttendanceLocation
	var name, locationType sql.NullString
	var geoLat, geoLng sql.NullFloat64

	err := rows.Scan(
		&location.LocationID,
		&location.CompanyID,
		&name,
		&locationType,
		&geoLat,
		&geoLng,
		&location.IsActive,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if name.Valid {
		location.Name = &name.String
	}
	if locationType.Valid {
		location.LocationType = &locationType.String
	}
	if geoLat.Valid {
		location.GeoLat = &geoLat.Float64
	}
	if geoLng.Valid {
		location.GeoLng = &geoLng.Float64
	}

	return &location, nil
}

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

func (r *AttendanceRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_attendance_event_by_id": `
			SELECT attendance_event_id, company_id, user_id, event_type, event_time,
			       source_type, source_id, device_id, ip_address, metadata,
			       created_at, created_by
			FROM attendance_events WHERE attendance_event_id = $1`,

		"get_attendance_policy_by_id": `
			SELECT policy_id, company_id, department_id, policy_code, policy_type,
			       rules, is_active, created_at, updated_at
			FROM attendance_policies WHERE policy_id = $1`,

		"get_attendance_policy_by_code": `
			SELECT policy_id, company_id, department_id, policy_code, policy_type,
			       rules, is_active, created_at, updated_at
			FROM attendance_policies WHERE company_id = $1 AND policy_code = $2`,

		"get_attendance_source_by_id": `
			SELECT source_id, company_id, source_type, name, reference_type,
			       reference_id, is_active, created_at, created_by
			FROM attendance_sources WHERE source_id = $1`,

		"get_attendance_daily_summary_by_id": `
			SELECT attendance_summary_id, company_id, user_id, attendance_date,
			       status, worked_minutes, overtime_minutes, late_minutes,
			       metadata, generated_at, generated_by
			FROM attendance_daily_summary WHERE attendance_summary_id = $1`,

		"get_attendance_location_by_id": `
			SELECT location_id, company_id, name, location_type,
			       geo_lat, geo_lng, is_active
			FROM attendance_locations WHERE location_id = $1`,
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

	r.logger.Info("Attendance prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *AttendanceRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (r *AttendanceRepositoryImpl) HealthCheck(ctx context.Context) error {
	// Simple query to check database connectivity
	query := `SELECT 1 FROM attendance_events LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

// ============================================================================
// RFID MAPPING METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateRFIDMapping(ctx context.Context, mapping *attendance.EmployeeRFIDMapping) error {
	query := `
		INSERT INTO employee_rfid_mappings (
			rfid_id, user_id, company_id, rfid_tag, is_active,
			assigned_at, unassigned_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.client.Exec(ctx, query,
		mapping.RFIDID,
		mapping.UserID,
		mapping.CompanyID,
		mapping.RFIDTag,
		mapping.IsActive,
		mapping.AssignedAt,
		mapping.UnassignedAt,
		mapping.CreatedAt,
		mapping.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create RFID mapping",
			util.String("rfid_tag", mapping.RFIDTag),
			util.String("user_id", mapping.UserID.String()),
			util.String("company_id", mapping.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create RFID mapping: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetRFIDMappingByTag(ctx context.Context, rfidTag string, companyID uuid.UUID) (*attendance.EmployeeRFIDMapping, error) {
	query := `
		SELECT rfid_id, user_id, company_id, rfid_tag, is_active,
		       assigned_at, unassigned_at, created_at, updated_at
		FROM employee_rfid_mappings
		WHERE company_id = $1 AND rfid_tag = $2
		ORDER BY assigned_at DESC
		LIMIT 1`

	rows, err := r.client.Query(ctx, query, companyID, rfidTag)
	if err != nil {
		return nil, fmt.Errorf("failed to get RFID mapping by tag: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanRFIDMapping(rows)
	}

	return nil, fmt.Errorf("RFID mapping not found for tag: %s", rfidTag)
}

func (r *AttendanceRepositoryImpl) GetRFIDMappingByUser(ctx context.Context, userID uuid.UUID, companyID uuid.UUID) (*attendance.EmployeeRFIDMapping, error) {
	query := `
		SELECT rfid_id, user_id, company_id, rfid_tag, is_active,
		       assigned_at, unassigned_at, created_at, updated_at
		FROM employee_rfid_mappings
		WHERE company_id = $1 AND user_id = $2
		AND is_active = true AND unassigned_at IS NULL
		LIMIT 1`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get RFID mapping by user: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanRFIDMapping(rows)
	}

	return nil, fmt.Errorf("active RFID mapping not found for user: %s", userID)
}

func (r *AttendanceRepositoryImpl) UpdateRFIDMapping(ctx context.Context, mapping *attendance.EmployeeRFIDMapping) error {
	query := `
		UPDATE employee_rfid_mappings SET
			rfid_tag = $1, is_active = $2, assigned_at = $3,
			unassigned_at = $4, updated_at = $5
		WHERE rfid_id = $6`

	result, err := r.client.Exec(ctx, query,
		mapping.RFIDTag,
		mapping.IsActive,
		mapping.AssignedAt,
		mapping.UnassignedAt,
		mapping.UpdatedAt,
		mapping.RFIDID,
	)

	if err != nil {
		return fmt.Errorf("failed to update RFID mapping: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("RFID mapping not found: %s", mapping.RFIDID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeactivateRFIDMapping(ctx context.Context, rfidID uuid.UUID) error {
	query := `
		UPDATE employee_rfid_mappings SET
			is_active = false, unassigned_at = NOW(), updated_at = NOW()
		WHERE rfid_id = $1 AND is_active = true`

	result, err := r.client.Exec(ctx, query, rfidID)
	if err != nil {
		return fmt.Errorf("failed to deactivate RFID mapping: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("RFID mapping not found or already inactive: %s", rfidID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetActiveRFIDMappingsByCompany(ctx context.Context, companyID uuid.UUID) ([]*attendance.EmployeeRFIDMapping, error) {
	query := `
		SELECT rfid_id, user_id, company_id, rfid_tag, is_active,
		       assigned_at, unassigned_at, created_at, updated_at
		FROM employee_rfid_mappings
		WHERE company_id = $1
		AND is_active = true
		AND unassigned_at IS NULL
		ORDER BY rfid_tag`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active RFID mappings: %w", err)
	}
	defer rows.Close()

	mappings := make([]*attendance.EmployeeRFIDMapping, 0)
	for rows.Next() {
		mapping, err := r.scanRFIDMapping(rows)
		if err != nil {
			r.logger.Warn("Failed to scan RFID mapping", util.ErrorField(err))
			continue
		}
		mappings = append(mappings, mapping)
	}

	return mappings, nil
}

// ============================================================================
// WORK CENTER SHIFT METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) CreateWorkCenterShift(ctx context.Context, wcShift *attendance.WorkCenterShift) error {
	query := `
		INSERT INTO work_center_shifts (
			mapping_id, company_id, work_center_code, shift_id,
			effective_from, effective_to, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.client.Exec(ctx, query,
		wcShift.MappingID,
		wcShift.CompanyID,
		wcShift.WorkCenterCode,
		wcShift.ShiftID,
		wcShift.EffectiveFrom,
		wcShift.EffectiveTo,
		wcShift.IsActive,
		wcShift.CreatedAt,
		wcShift.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create work center shift",
			util.String("work_center_code", wcShift.WorkCenterCode),
			util.String("company_id", wcShift.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create work center shift: %w", err)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) GetWorkCenterShiftByCode(ctx context.Context, workCenterCode string, companyID uuid.UUID) (*attendance.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM work_center_shifts
		WHERE company_id = $1 AND work_center_code = $2
		AND is_active = true
		AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		ORDER BY effective_from DESC
		LIMIT 1`

	rows, err := r.client.Query(ctx, query, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center shift: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanWorkCenterShift(rows)
	}

	return nil, fmt.Errorf("active work center shift not found for code: %s", workCenterCode)
}

func (r *AttendanceRepositoryImpl) GetWorkCenterShiftsByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM work_center_shifts
		WHERE company_id = $1`

	if activeOnly {
		query += " AND is_active = true AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)"
	}

	query += " ORDER BY work_center_code, effective_from DESC"

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center shifts: %w", err)
	}
	defer rows.Close()

	shifts := make([]*attendance.WorkCenterShift, 0)
	for rows.Next() {
		shift, err := r.scanWorkCenterShift(rows)
		if err != nil {
			r.logger.Warn("Failed to scan work center shift", util.ErrorField(err))
			continue
		}
		shifts = append(shifts, shift)
	}

	return shifts, nil
}

func (r *AttendanceRepositoryImpl) UpdateWorkCenterShift(ctx context.Context, wcShift *attendance.WorkCenterShift) error {
	query := `
		UPDATE work_center_shifts SET
			work_center_code = $1, shift_id = $2, effective_from = $3,
			effective_to = $4, is_active = $5, updated_at = $6
		WHERE mapping_id = $7`

	result, err := r.client.Exec(ctx, query,
		wcShift.WorkCenterCode,
		wcShift.ShiftID,
		wcShift.EffectiveFrom,
		wcShift.EffectiveTo,
		wcShift.IsActive,
		wcShift.UpdatedAt,
		wcShift.MappingID,
	)

	if err != nil {
		return fmt.Errorf("failed to update work center shift: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("work center shift not found: %s", wcShift.MappingID)
	}

	return nil
}

func (r *AttendanceRepositoryImpl) DeactivateWorkCenterShift(ctx context.Context, mappingID uuid.UUID) error {
	query := `
		UPDATE work_center_shifts SET
			is_active = false, effective_to = CURRENT_DATE, updated_at = NOW()
		WHERE mapping_id = $1 AND is_active = true`

	result, err := r.client.Exec(ctx, query, mappingID)
	if err != nil {
		return fmt.Errorf("failed to deactivate work center shift: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("work center shift not found or already inactive: %s", mappingID)
	}

	return nil
}

// ============================================================================
// LOOKUP METHODS IMPLEMENTATION
// ============================================================================

func (r *AttendanceRepositoryImpl) GetUserIDByEmployeeID(ctx context.Context, employeeID string, companyID uuid.UUID) (uuid.UUID, error) {
	query := `
		SELECT user_id 
		FROM company_employees 
		WHERE company_id = $1 
		AND employee_id = $2 
		AND is_active = true
		LIMIT 1`

	var userID uuid.UUID
	err := r.client.QueryRow(ctx, query, companyID, employeeID).Scan(&userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("employee not found with ID: %s", employeeID)
		}
		return uuid.Nil, fmt.Errorf("failed to lookup user by employee ID: %w", err)
	}

	return userID, nil
}

func (r *AttendanceRepositoryImpl) GetUserIDByRFID(ctx context.Context, rfid string, companyID uuid.UUID) (uuid.UUID, error) {
	query := `
		SELECT user_id 
		FROM employee_rfid_mappings 
		WHERE company_id = $1 
		AND rfid_tag = $2 
		AND is_active = true 
		AND unassigned_at IS NULL
		LIMIT 1`

	var userID uuid.UUID
	err := r.client.QueryRow(ctx, query, companyID, rfid).Scan(&userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("user not found for RFID: %s", rfid)
		}
		return uuid.Nil, fmt.Errorf("failed to lookup user by RFID: %w", err)
	}

	return userID, nil
}

func (r *AttendanceRepositoryImpl) GetLocationIDByCode(ctx context.Context, locationCode string, companyID uuid.UUID) (uuid.UUID, error) {
	if locationCode == "" {
		return uuid.Nil, fmt.Errorf("location code cannot be empty")
	}

	query := `
		SELECT location_id 
		FROM attendance_locations 
		WHERE company_id = $1 
		AND location_code = $2 
		AND is_active = true
		LIMIT 1`

	var locationID uuid.UUID
	err := r.client.QueryRow(ctx, query, companyID, locationCode).Scan(&locationID)

	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("location not found with code: %s", locationCode)
		}
		return uuid.Nil, fmt.Errorf("failed to lookup location by code: %w", err)
	}

	return locationID, nil
}

func (r *AttendanceRepositoryImpl) GetLocationIDByFactoryZone(ctx context.Context, zone string, companyID uuid.UUID) (uuid.UUID, error) {
	if zone == "" {
		return uuid.Nil, fmt.Errorf("zone cannot be empty")
	}

	query := `
		SELECT location_id 
		FROM attendance_locations 
		WHERE company_id = $1 
		AND zone = $2 
		AND is_active = true
		LIMIT 1`

	var locationID uuid.UUID
	err := r.client.QueryRow(ctx, query, companyID, zone).Scan(&locationID)

	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("factory zone location not found: %s", zone)
		}
		return uuid.Nil, fmt.Errorf("failed to lookup factory zone location: %w", err)
	}

	return locationID, nil
}

func (r *AttendanceRepositoryImpl) GetShiftIDByWorkCenter(ctx context.Context, workCenter string, companyID uuid.UUID) (uuid.UUID, error) {
	if workCenter == "" {
		return uuid.Nil, fmt.Errorf("work center cannot be empty")
	}

	query := `
		SELECT shift_id 
		FROM work_center_shifts 
		WHERE company_id = $1 
		AND work_center_code = $2 
		AND is_active = true
		AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		ORDER BY effective_from DESC
		LIMIT 1`

	var shiftID uuid.UUID
	err := r.client.QueryRow(ctx, query, companyID, workCenter).Scan(&shiftID)

	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("shift not found for work center: %s", workCenter)
		}
		return uuid.Nil, fmt.Errorf("failed to lookup shift by work center: %w", err)
	}

	return shiftID, nil
}

// ============================================================================
// SAP BUSINESS RULES METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) GetSAPBusinessRules(ctx context.Context, companyID uuid.UUID) (*attendance.SAPBusinessRules, error) {
	query := `
		SELECT rules 
		FROM attendance_policies 
		WHERE company_id = $1 
		AND policy_type = 'sap'
		AND is_active = true
		LIMIT 1`

	var rulesJSON []byte
	err := r.client.QueryRow(ctx, query, companyID).Scan(&rulesJSON)

	if err != nil {
		if err == sql.ErrNoRows {
			// Return default rules if none found
			return &attendance.SAPBusinessRules{
				ValidateWorkCenter: boolPtr(true),
				ValidateEmployeeID: boolPtr(true),
				GracePeriodMinutes: intPtr(5),
				MaxLateAllowed:     intPtr(30),
			}, nil
		}
		return nil, fmt.Errorf("failed to get SAP business rules: %w", err)
	}

	var rules attendance.SAPBusinessRules
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		// Return default rules if parsing fails
		return &attendance.SAPBusinessRules{
			ValidateWorkCenter: boolPtr(true),
			ValidateEmployeeID: boolPtr(true),
			GracePeriodMinutes: intPtr(5),
			MaxLateAllowed:     intPtr(30),
		}, nil
	}

	return &rules, nil
}

func (r *AttendanceRepositoryImpl) SaveSAPBusinessRules(ctx context.Context, companyID uuid.UUID, rules *attendance.SAPBusinessRules) error {
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("failed to marshal SAP business rules: %w", err)
	}

	// Check if SAP policy already exists
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM attendance_policies WHERE company_id = $1 AND policy_type = 'sap')`
	err = r.client.QueryRow(ctx, checkQuery, companyID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check SAP policy existence: %w", err)
	}

	if exists {
		// Update existing policy
		query := `
			UPDATE attendance_policies SET
				rules = $1, updated_at = NOW()
			WHERE company_id = $2 AND policy_type = 'sap'`

		_, err = r.client.Exec(ctx, query, rulesJSON, companyID)
		if err != nil {
			return fmt.Errorf("failed to update SAP business rules: %w", err)
		}
	} else {
		// Create new policy
		query := `
			INSERT INTO attendance_policies (
				policy_id, company_id, policy_code, policy_type,
				rules, is_active, created_at, updated_at
			) VALUES (gen_random_uuid(), $1, 'SAP_BUSINESS_RULES', 'sap', $2, true, NOW(), NOW())`

		_, err = r.client.Exec(ctx, query, companyID, rulesJSON)
		if err != nil {
			return fmt.Errorf("failed to create SAP business rules: %w", err)
		}
	}

	return nil
}

// ============================================================================
// HELPER SCAN METHODS
// ============================================================================

func (r *AttendanceRepositoryImpl) scanRFIDMapping(rows *sql.Rows) (*attendance.EmployeeRFIDMapping, error) {
	var mapping attendance.EmployeeRFIDMapping
	var unassignedAt sql.NullTime

	err := rows.Scan(
		&mapping.RFIDID,
		&mapping.UserID,
		&mapping.CompanyID,
		&mapping.RFIDTag,
		&mapping.IsActive,
		&mapping.AssignedAt,
		&unassignedAt,
		&mapping.CreatedAt,
		&mapping.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if unassignedAt.Valid {
		mapping.UnassignedAt = &unassignedAt.Time
	}

	return &mapping, nil
}

func (r *AttendanceRepositoryImpl) scanWorkCenterShift(rows *sql.Rows) (*attendance.WorkCenterShift, error) {
	var shift attendance.WorkCenterShift
	var effectiveTo sql.NullTime

	err := rows.Scan(
		&shift.MappingID,
		&shift.CompanyID,
		&shift.WorkCenterCode,
		&shift.ShiftID,
		&shift.EffectiveFrom,
		&effectiveTo,
		&shift.IsActive,
		&shift.CreatedAt,
		&shift.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if effectiveTo.Valid {
		shift.EffectiveTo = &effectiveTo.Time
	}

	return &shift, nil
}

// Helper functions
func boolPtr(b bool) *bool {
	return &b
}

func intPtr(i int) *int {
	return &i
}
