// repository/benefit.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// BenefitRepository Interface
// ---------------------------------------------------------------------

type BenefitRepository interface {
	Create(ctx context.Context, db DBTX, benefit *models.Benefit) error
	Update(ctx context.Context, db DBTX, benefit *models.Benefit) error
	Delete(ctx context.Context, db DBTX, benefitID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error)

	List(ctx context.Context, db DBTX, filter BenefitFilter, p Pagination, s Sort) ([]*models.Benefit, int64, error)
	ListByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Benefit, error)

	Exists(ctx context.Context, db DBTX, benefitID uuid.UUID) (bool, error)

	Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Benefit, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type BenefitFilter struct {
	BenefitIDs  []uuid.UUID
	PlanItemID  *uuid.UUID
	BenefitType *string
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type benefitRepository struct {
	logger *zap.Logger
}

func NewBenefitRepository(logger *zap.Logger) BenefitRepository {
	return &benefitRepository{
		logger: logger.Named("subscription_benefit_repo"),
	}
}

const benefitTable = "subscription.benefits"

func (r *benefitRepository) scanBenefit(s scanner) (*models.Benefit, error) {
	var b models.Benefit
	var desc, val sql.NullString
	err := s.Scan(
		&b.BenefitID,
		&b.PlanItemID,
		&b.BenefitType,
		&desc,
		&val,
		&b.CreatedAt,
		&b.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan benefit: %w", err)
	}
	if desc.Valid {
		b.BenefitDescription = &desc.String
	}
	if val.Valid {
		b.Value = datatypes.JSON(val.String) // ✅ fixed: convert string to JSON
	}
	return &b, nil
}

func (r *benefitRepository) buildBenefitFilter(filter BenefitFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if len(filter.BenefitIDs) > 0 {
		placeholders := make([]string, len(filter.BenefitIDs))
		for i, id := range filter.BenefitIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("benefit_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.PlanItemID != nil {
		conds = append(conds, fmt.Sprintf("plan_item_id = $%d", idx))
		args = append(args, *filter.PlanItemID)
		idx++
	}
	if filter.BenefitType != nil {
		conds = append(conds, fmt.Sprintf("benefit_type = $%d", idx))
		args = append(args, *filter.BenefitType)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var benefitAllowedSort = map[string]bool{
	"benefit_id":   true,
	"benefit_type": true,
	"created_at":   true,
	"updated_at":   true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *benefitRepository) Create(ctx context.Context, db DBTX, benefit *models.Benefit) error {
	query := `
		INSERT INTO subscription.benefits (
			benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		benefit.BenefitID,
		benefit.PlanItemID,
		benefit.BenefitType,
		benefit.BenefitDescription,
		benefit.Value,
	).Scan(&benefit.CreatedAt, &benefit.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create benefit: %w", err)
	}
	return nil
}

func (r *benefitRepository) Update(ctx context.Context, db DBTX, benefit *models.Benefit) error {
	query := `
		UPDATE subscription.benefits SET
			benefit_type = $2,
			benefit_description = $3,
			value = $4,
			updated_at = NOW()
		WHERE benefit_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		benefit.BenefitID,
		benefit.BenefitType,
		benefit.BenefitDescription,
		benefit.Value,
	).Scan(&benefit.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update benefit: %w", err)
	}
	return nil
}

func (r *benefitRepository) Delete(ctx context.Context, db DBTX, benefitID uuid.UUID) error {
	query := `DELETE FROM subscription.benefits WHERE benefit_id = $1`
	result, err := db.ExecContext(ctx, query, benefitID)
	if err != nil {
		return fmt.Errorf("delete benefit: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *benefitRepository) GetByID(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error) {
	query := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		FROM subscription.benefits
		WHERE benefit_id = $1
	`
	row := db.QueryRowContext(ctx, query, benefitID)
	return r.scanBenefit(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *benefitRepository) List(ctx context.Context, db DBTX, filter BenefitFilter, p Pagination, s Sort) ([]*models.Benefit, int64, error) {
	where, args := r.buildBenefitFilter(filter)
	orderBy, err := validateSort(s, benefitAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY benefit_type"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", benefitTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count benefits: %w", err)
	}
	if total == 0 {
		return []*models.Benefit{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, benefitTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list benefits: %w", err)
	}
	defer rows.Close()

	var result []*models.Benefit
	for rows.Next() {
		b, err := r.scanBenefit(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, b)
	}
	return result, total, rows.Err()
}

func (r *benefitRepository) ListByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Benefit, error) {
	filter := BenefitFilter{PlanItemID: &planItemID}
	benefits, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return benefits, err
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *benefitRepository) Exists(ctx context.Context, db DBTX, benefitID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.benefits WHERE benefit_id = $1)`
	err := db.QueryRowContext(ctx, query, benefitID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *benefitRepository) Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Benefit, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE plan_item_id = $1 AND (benefit_type ILIKE $2 OR benefit_description ILIKE $2)"
	args := []interface{}{planItemID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", benefitTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search benefits count: %w", err)
	}
	if total == 0 {
		return []*models.Benefit{}, 0, nil
	}

	baseQuery := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		FROM subscription.benefits
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY benefit_type LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search benefits: %w", err)
	}
	defer rows.Close()

	var result []*models.Benefit
	for rows.Next() {
		b, err := r.scanBenefit(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, b)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *benefitRepository) GetByIDForUpdate(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error) {
	query := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		FROM subscription.benefits
		WHERE benefit_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, benefitID)
	return r.scanBenefit(row)
}
