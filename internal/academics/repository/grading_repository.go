package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// GradingRepository defines all database operations for grading policies and boundaries.
type GradingRepository interface {
	// GradingPolicy methods
	CreateGradingPolicy(ctx context.Context, db DBTX, p *models.GradingPolicy) error
	GetGradingPolicyByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.GradingPolicy, error)
	GetGradingPolicyByCompanyAndName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.GradingPolicy, error)
	GetDefaultGradingPolicy(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.GradingPolicy, error)
	ListGradingPolicies(ctx context.Context, db DBTX, filter GradingPolicyFilter, p Pagination, s Sort) ([]*models.GradingPolicy, error)
	CountGradingPolicies(ctx context.Context, db DBTX, filter GradingPolicyFilter) (int64, error)
	UpdateGradingPolicy(ctx context.Context, db DBTX, p *models.GradingPolicy) error
	DeleteGradingPolicy(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// GradeBoundary methods
	CreateGradeBoundary(ctx context.Context, db DBTX, b *models.GradeBoundary) error
	BulkCreateGradeBoundaries(ctx context.Context, db DBTX, boundaries []*models.GradeBoundary) error
	GetGradeBoundaryByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.GradeBoundary, error)
	ListGradeBoundaries(ctx context.Context, db DBTX, filter GradeBoundaryFilter, p Pagination, s Sort) ([]*models.GradeBoundary, error)
	UpdateGradeBoundary(ctx context.Context, db DBTX, b *models.GradeBoundary) error
	DeleteGradeBoundary(ctx context.Context, db DBTX, id uuid.UUID) error
	DeleteGradeBoundariesByPolicy(ctx context.Context, db DBTX, policyID uuid.UUID) error
}

type gradingRepository struct {
	logger *zap.Logger
}

func NewGradingRepository(logger *zap.Logger) GradingRepository {
	return &gradingRepository{logger: logger.Named("grading_repo")}
}

// ==================== GradingPolicy Helpers ====================

var allowedGradingPolicySortFields = map[string]bool{
	"created_at":    true,
	"updated_at":    true,
	"policy_name":   true,
	"grading_scale": true,
	"is_default":    true,
}

func (r *gradingRepository) validateGradingPolicySort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedGradingPolicySortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY gp.%s %s", field, dir), nil
}

func (r *gradingRepository) buildGradingPolicyFilter(filter GradingPolicyFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("gp.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.PolicyName != "" {
		conditions = append(conditions, fmt.Sprintf("gp.policy_name = $%d", idx))
		args = append(args, filter.PolicyName)
		idx++
	}
	if filter.GradingScale != nil {
		conditions = append(conditions, fmt.Sprintf("gp.grading_scale = $%d", idx))
		args = append(args, *filter.GradingScale)
		idx++
	}
	if filter.IsDefault != nil {
		conditions = append(conditions, fmt.Sprintf("gp.is_default = $%d", idx))
		args = append(args, *filter.IsDefault)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("gp.policy_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "gp.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *gradingRepository) scanGradingPolicy(row scanner) (*models.GradingPolicy, error) {
	var p models.GradingPolicy
	var createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&p.PolicyID,
		&p.CompanyID,
		&p.PolicyName,
		&p.GradingScale,
		&p.IsDefault,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
		&updatedBy,
		&p.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan grading policy: %w", err)
	}

	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	return &p, nil
}

// ==================== GradeBoundary Helpers ====================

var allowedGradeBoundarySortFields = map[string]bool{
	"created_at":     true,
	"grade":          true,
	"min_percentage": true,
	"max_percentage": true,
	"grade_point":    true,
}

func (r *gradingRepository) validateGradeBoundarySort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "min_percentage"
	}
	if !allowedGradeBoundarySortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY gb.%s %s", field, dir), nil
}

func (r *gradingRepository) buildGradeBoundaryFilter(filter GradeBoundaryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.PolicyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("gb.policy_id = $%d", idx))
		args = append(args, filter.PolicyID)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *gradingRepository) scanGradeBoundary(row scanner) (*models.GradeBoundary, error) {
	var b models.GradeBoundary
	var gradePoint sql.NullFloat64

	err := row.Scan(
		&b.BoundaryID,
		&b.PolicyID,
		&b.Grade,
		&b.MinPercentage,
		&b.MaxPercentage,
		&gradePoint,
		&b.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan grade boundary: %w", err)
	}

	if gradePoint.Valid {
		b.GradePoint = &gradePoint.Float64
	}
	return &b, nil
}

// ==================== GradingPolicy Implementation ====================

func (r *gradingRepository) CreateGradingPolicy(ctx context.Context, db DBTX, p *models.GradingPolicy) error {
	query := `
        INSERT INTO academics.grading_policies (
            company_id, policy_name, grading_scale, is_default,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        RETURNING policy_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		p.CompanyID, p.PolicyName, p.GradingScale, p.IsDefault,
		p.CreatedBy, p.UpdatedBy,
	).Scan(&p.PolicyID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create grading policy",
			util.String("company_id", p.CompanyID.String()),
			util.String("policy_name", p.PolicyName),
			util.ErrorField(err))
		return fmt.Errorf("create grading policy: %w", err)
	}
	return nil
}

func (r *gradingRepository) GetGradingPolicyByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.GradingPolicy, error) {
	query := `
        SELECT
            policy_id, company_id, policy_name, grading_scale, is_default,
            created_at, updated_at, created_by, updated_by, deleted_at
        FROM academics.grading_policies
        WHERE policy_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanGradingPolicy(row)
}

func (r *gradingRepository) GetGradingPolicyByCompanyAndName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.GradingPolicy, error) {
	query := `
        SELECT
            policy_id, company_id, policy_name, grading_scale, is_default,
            created_at, updated_at, created_by, updated_by, deleted_at
        FROM academics.grading_policies
        WHERE company_id = $1 AND policy_name = $2 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanGradingPolicy(row)
}

func (r *gradingRepository) GetDefaultGradingPolicy(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.GradingPolicy, error) {
	query := `
        SELECT
            policy_id, company_id, policy_name, grading_scale, is_default,
            created_at, updated_at, created_by, updated_by, deleted_at
        FROM academics.grading_policies
        WHERE company_id = $1 AND is_default = true AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID)
	return r.scanGradingPolicy(row)
}

func (r *gradingRepository) ListGradingPolicies(ctx context.Context, db DBTX, filter GradingPolicyFilter, p Pagination, s Sort) ([]*models.GradingPolicy, error) {
	where, args := r.buildGradingPolicyFilter(filter)
	orderBy, err := r.validateGradingPolicySort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            policy_id, company_id, policy_name, grading_scale, is_default,
            created_at, updated_at, created_by, updated_by, deleted_at
        FROM academics.grading_policies gp
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list grading policies",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list grading policies: %w", err)
	}
	defer rows.Close()

	var result []*models.GradingPolicy
	for rows.Next() {
		p, err := r.scanGradingPolicy(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *gradingRepository) CountGradingPolicies(ctx context.Context, db DBTX, filter GradingPolicyFilter) (int64, error) {
	where, args := r.buildGradingPolicyFilter(filter)

	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.grading_policies gp %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count grading policies",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count grading policies: %w", err)
	}
	return count, nil
}

func (r *gradingRepository) UpdateGradingPolicy(ctx context.Context, db DBTX, p *models.GradingPolicy) error {
	// If this policy is being set as default, ensure no other default exists for the same company.
	// We'll handle that in service layer or via a trigger. Here just update.
	query := `
        UPDATE academics.grading_policies
        SET
            policy_name = $2,
            grading_scale = $3,
            is_default = $4,
            updated_by = $5,
            updated_at = NOW()
        WHERE policy_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		p.PolicyID, p.PolicyName, p.GradingScale, p.IsDefault, p.UpdatedBy,
	).Scan(&p.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: grading policy %s", ErrNotFound, p.PolicyID)
		}
		r.logger.Error("failed to update grading policy",
			util.String("id", p.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update grading policy: %w", err)
	}
	return nil
}

func (r *gradingRepository) DeleteGradingPolicy(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	// Soft delete. Also cascade delete grade boundaries? Schema has ON DELETE CASCADE on grade_boundaries.policy_id.
	query := `UPDATE academics.grading_policies SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE policy_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete grading policy",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete grading policy: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("grading policy %s not found or already deleted", id)
	}
	return nil
}

// ==================== GradeBoundary Implementation ====================

func (r *gradingRepository) CreateGradeBoundary(ctx context.Context, db DBTX, b *models.GradeBoundary) error {
	query := `
        INSERT INTO academics.grade_boundaries (
            policy_id, grade, min_percentage, max_percentage, grade_point, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        RETURNING boundary_id, created_at
    `
	err := db.QueryRowContext(ctx, query,
		b.PolicyID, b.Grade, b.MinPercentage, b.MaxPercentage, b.GradePoint,
	).Scan(&b.BoundaryID, &b.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create grade boundary",
			util.String("policy_id", b.PolicyID.String()),
			util.String("grade", b.Grade),
			util.ErrorField(err))
		return fmt.Errorf("create grade boundary: %w", err)
	}
	return nil
}

func (r *gradingRepository) BulkCreateGradeBoundaries(ctx context.Context, db DBTX, boundaries []*models.GradeBoundary) error {
	if len(boundaries) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO academics.grade_boundaries (
            policy_id, grade, min_percentage, max_percentage, grade_point, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        RETURNING boundary_id, created_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, b := range boundaries {
		err := stmt.QueryRowContext(ctx,
			b.PolicyID, b.Grade, b.MinPercentage, b.MaxPercentage, b.GradePoint,
		).Scan(&b.BoundaryID, &b.CreatedAt)
		if err != nil {
			r.logger.Error("bulk create grade boundary failed",
				util.String("policy_id", b.PolicyID.String()),
				util.String("grade", b.Grade),
				util.ErrorField(err))
			return fmt.Errorf("bulk create grade boundary row: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

func (r *gradingRepository) GetGradeBoundaryByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.GradeBoundary, error) {
	query := `
        SELECT
            boundary_id, policy_id, grade, min_percentage, max_percentage, grade_point, created_at
        FROM academics.grade_boundaries
        WHERE boundary_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanGradeBoundary(row)
}

func (r *gradingRepository) ListGradeBoundaries(ctx context.Context, db DBTX, filter GradeBoundaryFilter, p Pagination, s Sort) ([]*models.GradeBoundary, error) {
	where, args := r.buildGradeBoundaryFilter(filter)
	orderBy, err := r.validateGradeBoundarySort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            boundary_id, policy_id, grade, min_percentage, max_percentage, grade_point, created_at
        FROM academics.grade_boundaries gb
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list grade boundaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list grade boundaries: %w", err)
	}
	defer rows.Close()

	var result []*models.GradeBoundary
	for rows.Next() {
		b, err := r.scanGradeBoundary(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *gradingRepository) UpdateGradeBoundary(ctx context.Context, db DBTX, b *models.GradeBoundary) error {
	query := `
        UPDATE academics.grade_boundaries
        SET
            grade = $2,
            min_percentage = $3,
            max_percentage = $4,
            grade_point = $5
        WHERE boundary_id = $1
        RETURNING created_at
    `
	err := db.QueryRowContext(ctx, query,
		b.BoundaryID, b.Grade, b.MinPercentage, b.MaxPercentage, b.GradePoint,
	).Scan(&b.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: grade boundary %s", ErrNotFound, b.BoundaryID)
		}
		r.logger.Error("failed to update grade boundary",
			util.String("id", b.BoundaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update grade boundary: %w", err)
	}
	return nil
}

func (r *gradingRepository) DeleteGradeBoundary(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.grade_boundaries WHERE boundary_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete grade boundary",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete grade boundary: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("grade boundary %s not found", id)
	}
	return nil
}

func (r *gradingRepository) DeleteGradeBoundariesByPolicy(ctx context.Context, db DBTX, policyID uuid.UUID) error {
	// Delete all boundaries for a policy (cascade will also happen if we delete policy, but we might need this separately)
	query := `DELETE FROM academics.grade_boundaries WHERE policy_id = $1`
	_, err := db.ExecContext(ctx, query, policyID)
	if err != nil {
		r.logger.Error("failed to delete grade boundaries by policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete grade boundaries by policy: %w", err)
	}
	// Not checking rows affected – may be zero.
	return nil
}

// ==================== Common Helpers ====================

func (r *gradingRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
