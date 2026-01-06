package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/compensation"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// CompensationRepositoryImpl handles PostgreSQL compensation operations
type CompensationRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

// NewCompensationRepository creates a new PostgreSQL compensation repository
func NewCompensationRepository(postgresClient *client.PostgresClient, logger *zap.Logger) CompensationRepository {
	repo := &CompensationRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ============================================================================
// PAY UNIT METHODS
// ============================================================================

func (r *CompensationRepositoryImpl) GetPayUnitByID(ctx context.Context, payUnitID uuid.UUID) (*compensation.PayUnit, error) {
	stmt, ok := r.getStmt("get_pay_unit_by_id")
	if !ok {
		// Fallback to direct query if prepared statement not available
		query := `SELECT pay_unit_id, name, description FROM pay_units WHERE pay_unit_id = $1`
		rows, err := r.client.Query(ctx, query, payUnitID)
		if err != nil {
			return nil, fmt.Errorf("failed to get pay unit: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanPayUnit(rows)
		}
		return nil, fmt.Errorf("pay unit not found: %s", payUnitID)
	}

	rows, err := stmt.QueryContext(ctx, payUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pay unit: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanPayUnit(rows)
	}

	return nil, fmt.Errorf("pay unit not found: %s", payUnitID)
}

func (r *CompensationRepositoryImpl) ListPayUnits(ctx context.Context) ([]*compensation.PayUnit, error) {
	query := `SELECT pay_unit_id, name, description FROM pay_units ORDER BY name`

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list pay units: %w", err)
	}
	defer rows.Close()

	payUnits := make([]*compensation.PayUnit, 0)
	for rows.Next() {
		payUnit, err := r.scanPayUnit(rows)
		if err != nil {
			r.logger.Warn("Failed to scan pay unit", util.ErrorField(err))
			continue
		}
		payUnits = append(payUnits, payUnit)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating pay units: %w", err)
	}

	return payUnits, nil
}

// ============================================================================
// COMPENSATION STRUCTURE METHODS
// ============================================================================

func (r *CompensationRepositoryImpl) CreateCompensationStructure(ctx context.Context, structure *compensation.CompensationStructure) error {
	startTime := time.Now()

	// Convert components to JSONB
	componentsJSON, err := json.Marshal(structure.Components)
	if err != nil {
		return fmt.Errorf("failed to marshal components: %w", err)
	}

	query := `
        INSERT INTO compensation_structures (
            structure_id, company_id, structure_code, name, currency, 
            components, is_active, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.client.Exec(ctx, query,
		structure.StructureID,
		structure.CompanyID,
		structure.StructureCode,
		structure.Name,
		structure.Currency,
		componentsJSON,
		structure.IsActive,
		structure.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create compensation structure",
			util.String("company_id", structure.CompanyID.String()),
			util.String("structure_code", structure.StructureCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create compensation structure: %w", err)
	}

	r.logger.Debug("Compensation structure created",
		util.String("structure_id", structure.StructureID.String()),
		util.String("company_id", structure.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *CompensationRepositoryImpl) GetCompensationStructureByID(ctx context.Context, structureID uuid.UUID) (*compensation.CompensationStructure, error) {
	stmt, ok := r.getStmt("get_compensation_structure_by_id")
	if !ok {
		// Fallback to direct query if prepared statement not available
		query := `
			SELECT structure_id, company_id, structure_code, name, currency, 
				   components, is_active, created_at
			FROM compensation_structures 
			WHERE structure_id = $1`
		rows, err := r.client.Query(ctx, query, structureID)
		if err != nil {
			return nil, fmt.Errorf("failed to get compensation structure: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanCompensationStructure(rows)
		}
		return nil, fmt.Errorf("compensation structure not found: %s", structureID)
	}

	rows, err := stmt.QueryContext(ctx, structureID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation structure: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanCompensationStructure(rows)
	}

	return nil, fmt.Errorf("compensation structure not found: %s", structureID)
}

func (r *CompensationRepositoryImpl) GetCompensationStructureByCode(ctx context.Context, companyID uuid.UUID, structureCode string) (*compensation.CompensationStructure, error) {
	query := `
        SELECT structure_id, company_id, structure_code, name, currency, 
               components, is_active, created_at
        FROM compensation_structures 
        WHERE company_id = $1 AND structure_code = $2`

	rows, err := r.client.Query(ctx, query, companyID, structureCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation structure by code: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanCompensationStructure(rows)
	}

	return nil, fmt.Errorf("compensation structure not found: %s", structureCode)
}

func (r *CompensationRepositoryImpl) GetCompensationStructuresByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*compensation.CompensationStructure, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM compensation_structures WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count compensation structures: %w", err)
	}

	// Get structures
	query := `
        SELECT structure_id, company_id, structure_code, name, currency, 
               components, is_active, created_at
        FROM compensation_structures 
        WHERE company_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list compensation structures: %w", err)
	}
	defer rows.Close()

	structures := make([]*compensation.CompensationStructure, 0, limit)
	for rows.Next() {
		structure, err := r.scanCompensationStructure(rows)
		if err != nil {
			r.logger.Warn("Failed to scan compensation structure", util.ErrorField(err))
			continue
		}
		structures = append(structures, structure)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating compensation structures: %w", err)
	}

	return structures, totalCount, nil
}

func (r *CompensationRepositoryImpl) GetActiveCompensationStructures(ctx context.Context, companyID uuid.UUID) ([]*compensation.CompensationStructure, error) {
	query := `
        SELECT structure_id, company_id, structure_code, name, currency, 
               components, is_active, created_at
        FROM compensation_structures 
        WHERE company_id = $1 AND is_active = true
        ORDER BY name`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active compensation structures: %w", err)
	}
	defer rows.Close()

	structures := make([]*compensation.CompensationStructure, 0)
	for rows.Next() {
		structure, err := r.scanCompensationStructure(rows)
		if err != nil {
			r.logger.Warn("Failed to scan compensation structure", util.ErrorField(err))
			continue
		}
		structures = append(structures, structure)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating compensation structures: %w", err)
	}

	return structures, nil
}

func (r *CompensationRepositoryImpl) UpdateCompensationStructure(ctx context.Context, structure *compensation.CompensationStructure) error {
	// Convert components to JSONB
	componentsJSON, err := json.Marshal(structure.Components)
	if err != nil {
		return fmt.Errorf("failed to marshal components: %w", err)
	}

	query := `
        UPDATE compensation_structures SET
            structure_code = $1, name = $2, currency = $3, 
            components = $4, is_active = $5
        WHERE structure_id = $6`

	result, err := r.client.Exec(ctx, query,
		structure.StructureCode,
		structure.Name,
		structure.Currency,
		componentsJSON,
		structure.IsActive,
		structure.StructureID,
	)

	if err != nil {
		return fmt.Errorf("failed to update compensation structure: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("compensation structure not found: %s", structure.StructureID)
	}

	return nil
}

func (r *CompensationRepositoryImpl) DeleteCompensationStructure(ctx context.Context, structureID uuid.UUID) error {
	query := `DELETE FROM compensation_structures WHERE structure_id = $1`
	result, err := r.client.Exec(ctx, query, structureID)
	if err != nil {
		return fmt.Errorf("failed to delete compensation structure: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("compensation structure not found: %s", structureID)
	}

	return nil
}

// ============================================================================
// USER COMPENSATION METHODS
// ============================================================================

func (r *CompensationRepositoryImpl) CreateUserCompensation(ctx context.Context, userComp *compensation.UserCompensation) error {
	startTime := time.Now()

	// Convert structure snapshot to JSONB
	snapshotJSON, err := json.Marshal(userComp.StructureSnapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal structure snapshot: %w", err)
	}

	query := `
        INSERT INTO user_compensations (
            user_id, structure_id, pay_unit_id, ctc_amount, effective_from,
            effective_to, assigned_by, structure_snapshot, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = r.client.Exec(ctx, query,
		userComp.UserID,
		userComp.StructureID,
		userComp.PayUnitID,
		userComp.CTCAmount,
		userComp.EffectiveFrom,
		userComp.EffectiveTo,
		userComp.AssignedBy,
		snapshotJSON,
		userComp.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create user compensation",
			util.String("user_id", userComp.UserID.String()),
			util.String("structure_id", userComp.StructureID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create user compensation: %w", err)
	}

	r.logger.Debug("User compensation created",
		util.String("user_id", userComp.UserID.String()),
		util.String("structure_id", userComp.StructureID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *CompensationRepositoryImpl) GetUserCompensationByID(ctx context.Context, userID, structureID uuid.UUID, effectiveFrom time.Time) (*compensation.UserCompensation, error) {
	query := `
        SELECT user_id, structure_id, pay_unit_id, ctc_amount, effective_from,
               effective_to, assigned_by, structure_snapshot, created_at
        FROM user_compensations 
        WHERE user_id = $1 AND structure_id = $2 AND effective_from = $3`

	rows, err := r.client.Query(ctx, query, userID, structureID, effectiveFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get user compensation: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanUserCompensation(rows)
	}

	return nil, fmt.Errorf("user compensation not found")
}

func (r *CompensationRepositoryImpl) GetUserCompensationsByUser(ctx context.Context, userID uuid.UUID) ([]*compensation.UserCompensation, error) {
	query := `
        SELECT user_id, structure_id, pay_unit_id, ctc_amount, effective_from,
               effective_to, assigned_by, structure_snapshot, created_at
        FROM user_compensations 
        WHERE user_id = $1
        ORDER BY effective_from DESC`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user compensations: %w", err)
	}
	defer rows.Close()

	compensations := make([]*compensation.UserCompensation, 0)
	for rows.Next() {
		comp, err := r.scanUserCompensation(rows)
		if err != nil {
			r.logger.Warn("Failed to scan user compensation", util.ErrorField(err))
			continue
		}
		compensations = append(compensations, comp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user compensations: %w", err)
	}

	return compensations, nil
}

func (r *CompensationRepositoryImpl) GetCurrentUserCompensation(ctx context.Context, userID uuid.UUID) (*compensation.UserCompensation, error) {
	stmt, ok := r.getStmt("get_current_user_compensation")
	if !ok {
		// Fallback to direct query if prepared statement not available
		query := `
			SELECT user_id, structure_id, pay_unit_id, ctc_amount, effective_from,
				   effective_to, assigned_by, structure_snapshot, created_at
			FROM user_compensations 
			WHERE user_id = $1 
			  AND effective_from <= NOW()
			  AND (effective_to IS NULL OR effective_to >= NOW())
			ORDER BY effective_from DESC
			LIMIT 1`
		rows, err := r.client.Query(ctx, query, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to get current user compensation: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanUserCompensation(rows)
		}
		return nil, fmt.Errorf("no active compensation found for user: %s", userID)
	}

	rows, err := stmt.QueryContext(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current user compensation: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanUserCompensation(rows)
	}

	return nil, fmt.Errorf("no active compensation found for user: %s", userID)
}

func (r *CompensationRepositoryImpl) GetUserCompensationsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*compensation.UserCompensation, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count through join
	countQuery := `
        SELECT COUNT(DISTINCT uc.user_id)
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        WHERE ce.company_id = $1`

	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count user compensations: %w", err)
	}

	// Get current compensations for each user in company
	query := `
        SELECT DISTINCT ON (uc.user_id)
               uc.user_id, uc.structure_id, uc.pay_unit_id, uc.ctc_amount, uc.effective_from,
               uc.effective_to, uc.assigned_by, uc.structure_snapshot, uc.created_at
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        WHERE ce.company_id = $1 
          AND uc.effective_from <= NOW()
          AND (uc.effective_to IS NULL OR uc.effective_to >= NOW())
        ORDER BY uc.user_id, uc.effective_from DESC
        LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get user compensations by company: %w", err)
	}
	defer rows.Close()

	compensations := make([]*compensation.UserCompensation, 0, limit)
	for rows.Next() {
		comp, err := r.scanUserCompensation(rows)
		if err != nil {
			r.logger.Warn("Failed to scan user compensation", util.ErrorField(err))
			continue
		}
		compensations = append(compensations, comp)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user compensations: %w", err)
	}

	return compensations, totalCount, nil
}

func (r *CompensationRepositoryImpl) UpdateUserCompensation(ctx context.Context, userComp *compensation.UserCompensation) error {
	// Convert structure snapshot to JSONB
	snapshotJSON, err := json.Marshal(userComp.StructureSnapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal structure snapshot: %w", err)
	}

	query := `
        UPDATE user_compensations SET
            pay_unit_id = $1, ctc_amount = $2, effective_to = $3,
            assigned_by = $4, structure_snapshot = $5
        WHERE user_id = $6 AND structure_id = $7 AND effective_from = $8`

	result, err := r.client.Exec(ctx, query,
		userComp.PayUnitID,
		userComp.CTCAmount,
		userComp.EffectiveTo,
		userComp.AssignedBy,
		snapshotJSON,
		userComp.UserID,
		userComp.StructureID,
		userComp.EffectiveFrom,
	)

	if err != nil {
		return fmt.Errorf("failed to update user compensation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user compensation not found")
	}

	return nil
}

func (r *CompensationRepositoryImpl) DeleteUserCompensation(ctx context.Context, userID, structureID uuid.UUID, effectiveFrom time.Time) error {
	query := `DELETE FROM user_compensations WHERE user_id = $1 AND structure_id = $2 AND effective_from = $3`
	result, err := r.client.Exec(ctx, query, userID, structureID, effectiveFrom)
	if err != nil {
		return fmt.Errorf("failed to delete user compensation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user compensation not found")
	}

	return nil
}

func (r *CompensationRepositoryImpl) EndUserCompensation(ctx context.Context, userID uuid.UUID, endDate time.Time) error {
	query := `
        UPDATE user_compensations 
        SET effective_to = $1
        WHERE user_id = $2 AND effective_to IS NULL`

	result, err := r.client.Exec(ctx, query, endDate, userID)
	if err != nil {
		return fmt.Errorf("failed to end user compensation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("no active compensation found for user: %s", userID)
	}

	return nil
}

// ============================================================================
// BATCH OPERATIONS
// ============================================================================

func (r *CompensationRepositoryImpl) CreateUserCompensationsBatch(ctx context.Context, compensations []*compensation.UserCompensation) error {
	if len(compensations) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
        INSERT INTO user_compensations (
            user_id, structure_id, pay_unit_id, ctc_amount, effective_from,
            effective_to, assigned_by, structure_snapshot, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, comp := range compensations {
		// Convert structure snapshot to JSONB
		snapshotJSON, err := json.Marshal(comp.StructureSnapshot)
		if err != nil {
			return fmt.Errorf("failed to marshal structure snapshot: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			comp.UserID,
			comp.StructureID,
			comp.PayUnitID,
			comp.CTCAmount,
			comp.EffectiveFrom,
			comp.EffectiveTo,
			comp.AssignedBy,
			snapshotJSON,
			comp.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert user compensation: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info("Batch user compensations creation completed",
		util.Int("compensations_created", len(compensations)))
	return nil
}

// ============================================================================
// ANALYTICS METHODS
// ============================================================================

func (r *CompensationRepositoryImpl) GetCompensationStatsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total employees with compensation
	var totalEmployees int
	err := r.client.QueryRow(ctx, `
        SELECT COUNT(DISTINCT uc.user_id)
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        WHERE ce.company_id = $1 
          AND uc.effective_from <= NOW()
          AND (uc.effective_to IS NULL OR uc.effective_to >= NOW())`,
		companyID).Scan(&totalEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get total employees with compensation: %w", err)
	}
	stats["total_employees_with_compensation"] = totalEmployees

	// Average CTC
	var avgCTC sql.NullFloat64
	err = r.client.QueryRow(ctx, `
        SELECT AVG(uc.ctc_amount)
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        WHERE ce.company_id = $1 
          AND uc.effective_from <= NOW()
          AND (uc.effective_to IS NULL OR uc.effective_to >= NOW())`,
		companyID).Scan(&avgCTC)
	if err != nil {
		return nil, fmt.Errorf("failed to get average CTC: %w", err)
	}
	if avgCTC.Valid {
		stats["average_ctc"] = decimal.NewFromFloat(avgCTC.Float64)
	}

	// Total monthly payroll estimate (assuming monthly pay unit)
	var totalMonthlyPayroll sql.NullFloat64
	err = r.client.QueryRow(ctx, `
        SELECT SUM(uc.ctc_amount / 12)
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        INNER JOIN pay_units pu ON uc.pay_unit_id = pu.pay_unit_id
        WHERE ce.company_id = $1 
          AND uc.effective_from <= NOW()
          AND (uc.effective_to IS NULL OR uc.effective_to >= NOW())
          AND pu.name = 'monthly'`,
		companyID).Scan(&totalMonthlyPayroll)
	if err != nil {
		return nil, fmt.Errorf("failed to get total monthly payroll: %w", err)
	}
	if totalMonthlyPayroll.Valid {
		stats["total_monthly_payroll"] = decimal.NewFromFloat(totalMonthlyPayroll.Float64)
	}

	// Compensation by pay unit
	query := `
        SELECT pu.name, COUNT(DISTINCT uc.user_id) as employee_count, 
               AVG(uc.ctc_amount) as avg_ctc
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        INNER JOIN pay_units pu ON uc.pay_unit_id = pu.pay_unit_id
        WHERE ce.company_id = $1 
          AND uc.effective_from <= NOW()
          AND (uc.effective_to IS NULL OR uc.effective_to >= NOW())
        GROUP BY pu.name`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation by pay unit: %w", err)
	}
	defer rows.Close()

	payUnitStats := make(map[string]map[string]interface{})
	for rows.Next() {
		var payUnitName string
		var employeeCount int
		var avgCTC float64
		if err := rows.Scan(&payUnitName, &employeeCount, &avgCTC); err != nil {
			continue
		}
		payUnitStats[payUnitName] = map[string]interface{}{
			"employee_count": employeeCount,
			"average_ctc":    decimal.NewFromFloat(avgCTC),
		}
	}
	stats["pay_unit_stats"] = payUnitStats

	return stats, nil
}

func (r *CompensationRepositoryImpl) GetAverageCTCByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]decimal.Decimal, error) {
	query := `
        SELECT d.department_id, AVG(uc.ctc_amount) as avg_ctc
        FROM departments d
        LEFT JOIN employee_department_history edh ON d.department_id = edh.department_id 
            AND edh.end_date IS NULL
        LEFT JOIN user_compensations uc ON edh.user_id = uc.user_id
            AND uc.effective_from <= NOW()
            AND (uc.effective_to IS NULL OR uc.effective_to >= NOW())
        WHERE d.company_id = $1
        GROUP BY d.department_id`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get average CTC by department: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]decimal.Decimal)
	for rows.Next() {
		var departmentID uuid.UUID
		var avgCTC sql.NullFloat64
		if err := rows.Scan(&departmentID, &avgCTC); err != nil {
			continue
		}
		if avgCTC.Valid {
			result[departmentID] = decimal.NewFromFloat(avgCTC.Float64)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department averages: %w", err)
	}

	return result, nil
}

func (r *CompensationRepositoryImpl) GetCompensationTrends(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error) {
	query := `
        SELECT 
            DATE_TRUNC('month', uc.effective_from) as month,
            COUNT(DISTINCT uc.user_id) as employee_count,
            AVG(uc.ctc_amount) as avg_ctc,
            SUM(uc.ctc_amount) as total_ctc
        FROM user_compensations uc
        INNER JOIN company_employees ce ON uc.user_id = ce.user_id
        WHERE ce.company_id = $1 
          AND uc.effective_from >= $2
          AND uc.effective_from <= $3
        GROUP BY DATE_TRUNC('month', uc.effective_from)
        ORDER BY month`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation trends: %w", err)
	}
	defer rows.Close()

	trends := make([]map[string]interface{}, 0)
	for rows.Next() {
		var month time.Time
		var employeeCount int
		var avgCTC, totalCTC sql.NullFloat64

		if err := rows.Scan(&month, &employeeCount, &avgCTC, &totalCTC); err != nil {
			continue
		}

		trend := map[string]interface{}{
			"month":          month,
			"employee_count": employeeCount,
		}

		if avgCTC.Valid {
			trend["average_ctc"] = decimal.NewFromFloat(avgCTC.Float64)
		}
		if totalCTC.Valid {
			trend["total_ctc"] = decimal.NewFromFloat(totalCTC.Float64)
		}

		trends = append(trends, trend)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating compensation trends: %w", err)
	}

	return trends, nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (r *CompensationRepositoryImpl) scanPayUnit(rows *sql.Rows) (*compensation.PayUnit, error) {
	var payUnit compensation.PayUnit
	var description sql.NullString

	err := rows.Scan(
		&payUnit.PayUnitID,
		&payUnit.Name,
		&description,
	)

	if err != nil {
		return nil, err
	}

	if description.Valid {
		payUnit.Description = &description.String
	}

	return &payUnit, nil
}

func (r *CompensationRepositoryImpl) scanCompensationStructure(rows *sql.Rows) (*compensation.CompensationStructure, error) {
	var structure compensation.CompensationStructure
	var componentsJSON []byte
	var currency sql.NullString

	err := rows.Scan(
		&structure.StructureID,
		&structure.CompanyID,
		&structure.StructureCode,
		&structure.Name,
		&currency,
		&componentsJSON,
		&structure.IsActive,
		&structure.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Parse components JSON
	var components []compensation.Component
	if err := json.Unmarshal(componentsJSON, &components); err != nil {
		return nil, fmt.Errorf("failed to unmarshal components: %w", err)
	}
	structure.Components = components

	if currency.Valid {
		structure.Currency = currency.String
	} else {
		structure.Currency = "INR"
	}

	return &structure, nil
}

func (r *CompensationRepositoryImpl) scanUserCompensation(rows *sql.Rows) (*compensation.UserCompensation, error) {
	var comp compensation.UserCompensation
	var payUnitID sql.NullString
	var effectiveTo sql.NullTime
	var assignedBy sql.NullString
	var snapshotJSON []byte

	err := rows.Scan(
		&comp.UserID,
		&comp.StructureID,
		&payUnitID,
		&comp.CTCAmount,
		&comp.EffectiveFrom,
		&effectiveTo,
		&assignedBy,
		&snapshotJSON,
		&comp.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Parse nullable fields
	if payUnitID.Valid && payUnitID.String != "" {
		parsedUUID, err := uuid.Parse(payUnitID.String)
		if err == nil {
			comp.PayUnitID = &parsedUUID
		}
	}

	if effectiveTo.Valid {
		comp.EffectiveTo = &effectiveTo.Time
	}

	if assignedBy.Valid && assignedBy.String != "" {
		parsedUUID, err := uuid.Parse(assignedBy.String)
		if err == nil {
			comp.AssignedBy = &parsedUUID
		}
	}

	// Parse structure snapshot
	comp.StructureSnapshot = snapshotJSON

	return &comp, nil
}

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

func (r *CompensationRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_pay_unit_by_id": `
            SELECT pay_unit_id, name, description
            FROM pay_units WHERE pay_unit_id = $1`,

		"get_compensation_structure_by_id": `
            SELECT structure_id, company_id, structure_code, name, currency, 
                   components, is_active, created_at
            FROM compensation_structures WHERE structure_id = $1`,

		"get_current_user_compensation": `
            SELECT user_id, structure_id, pay_unit_id, ctc_amount, effective_from,
                   effective_to, assigned_by, structure_snapshot, created_at
            FROM user_compensations 
            WHERE user_id = $1 
              AND effective_from <= NOW()
              AND (effective_to IS NULL OR effective_to >= NOW())
            ORDER BY effective_from DESC
            LIMIT 1`,
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

	r.logger.Info("Compensation prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *CompensationRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (r *CompensationRepositoryImpl) HealthCheck(ctx context.Context) error {
	// Simple query to check database connectivity
	query := `SELECT 1 FROM pay_units LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("compensation repository health check failed: %w", err)
	}
	return nil
}

func (r *CompensationRepositoryImpl) CreatePayUnit(
	ctx context.Context,
	payUnit *compensation.PayUnit,
) error {
	startTime := time.Now()

	query := `
        INSERT INTO pay_units (pay_unit_id, name, description)
        VALUES ($1, $2, $3)
    `

	_, err := r.client.Exec(
		ctx,
		query,
		payUnit.PayUnitID,
		payUnit.Name,
		payUnit.Description,
	)

	if err != nil {
		if strings.Contains(err.Error(), "uq_pay_units_name") {
			return fmt.Errorf("pay unit '%s' already exists", payUnit.Name)
		}
		return fmt.Errorf("failed to create pay unit: %w", err)
	}

	r.logger.Info("Pay unit created",
		util.String("pay_unit_id", payUnit.PayUnitID.String()),
		util.String("name", payUnit.Name),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}
func (r *CompensationRepositoryImpl) GetPayUnitByName(
	ctx context.Context,
	name string,
) (*compensation.PayUnit, error) {

	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("pay unit name is required")
	}

	query := `
        SELECT pay_unit_id, name, description
        FROM pay_units
        WHERE name = $1
        LIMIT 1
    `

	rows, err := r.client.Query(ctx, query, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get pay unit by name: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanPayUnit(rows)
	}

	return nil, fmt.Errorf("pay unit not found: %s", name)
}
