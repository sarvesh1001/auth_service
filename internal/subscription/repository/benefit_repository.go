// FILE: repository/benefit_repository.go

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// BenefitRepository Interface
// -------------------------------------------------------------------------

type BenefitRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, benefit *models.Benefit) error
	BulkCreate(ctx context.Context, db DBTX, benefits []*models.Benefit) error
	GetByID(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error)
	Update(ctx context.Context, db DBTX, benefit *models.Benefit) error
	Delete(ctx context.Context, db DBTX, benefitID uuid.UUID) error

	// Bulk operations
	ReplaceByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID, benefits []*models.Benefit) error
	DeleteByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) error

	// Validation
	Exists(ctx context.Context, db DBTX, benefitID uuid.UUID) (bool, error)
	ExistsByType(ctx context.Context, db DBTX, planItemID uuid.UUID, benefitType enums.BenefitType) (bool, error)
	// NEW: check duplicate based on plan_item_id, benefit_type, and value (JSONB)
	ExistsByPlanItemTypeAndValue(ctx context.Context, db DBTX, planItemID uuid.UUID, benefitType enums.BenefitType, value json.RawMessage) (bool, error)

	// Querying
	List(ctx context.Context, db DBTX, filter BenefitFilter, p Pagination, s Sort) ([]*models.Benefit, int64, error)
	GetByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) ([]*models.Benefit, error)
	GetByType(ctx context.Context, db DBTX, benefitType enums.BenefitType) ([]*models.Benefit, error)
	Search(ctx context.Context, db DBTX, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Benefit, int64, error)

	// Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type BenefitFilter struct {
	BenefitIDs  []uuid.UUID
	PlanItemID  *uuid.UUID
	BenefitType *enums.BenefitType
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

// Implementation
// -------------------------------------------------------------------------

type benefitRepository struct {
	logger *zap.Logger
}

func NewBenefitRepository(logger *zap.Logger) BenefitRepository {
	return &benefitRepository{
		logger: logger.Named("subscription_benefit_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *benefitRepository) Create(ctx context.Context, db DBTX, benefit *models.Benefit) error {
	query := `
		INSERT INTO subscription.benefits (
			benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := db.ExecContext(ctx, query,
		benefit.BenefitID,
		benefit.PlanItemID,
		string(benefit.BenefitType),
		benefit.BenefitDescription,
		benefit.Value,
		benefit.CreatedAt,
		benefit.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create benefit", zap.Error(err))
		return fmt.Errorf("create benefit: %w", err)
	}
	return nil
}

func (r *benefitRepository) BulkCreate(ctx context.Context, db DBTX, benefits []*models.Benefit) error {
	if len(benefits) == 0 {
		return nil
	}

	query := `
		INSERT INTO subscription.benefits (
			benefit_id, plan_item_id, benefit_type, benefit_description, value,
			created_at, updated_at
		) VALUES 
	`
	placeholders := make([]string, 0, len(benefits))
	args := make([]interface{}, 0, len(benefits)*7)
	argPos := 1

	for _, b := range benefits {
		placeholders = append(placeholders, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			argPos, argPos+1, argPos+2, argPos+3, argPos+4, argPos+5, argPos+6,
		))
		args = append(args,
			b.BenefitID,
			b.PlanItemID,
			string(b.BenefitType),
			b.BenefitDescription,
			b.Value,
			b.CreatedAt,
			b.UpdatedAt,
		)
		argPos += 7
	}

	query += strings.Join(placeholders, ", ")
	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create benefits", zap.Error(err))
		return fmt.Errorf("bulk create benefits: %w", err)
	}
	return nil
}

func (r *benefitRepository) GetByID(ctx context.Context, db DBTX, benefitID uuid.UUID) (*models.Benefit, error) {
	query := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
		       created_at, updated_at
		FROM subscription.benefits
		WHERE benefit_id = $1
	`
	var benefit models.Benefit
	var benefitType string
	err := db.QueryRowContext(ctx, query, benefitID).Scan(
		&benefit.BenefitID,
		&benefit.PlanItemID,
		&benefitType,
		&benefit.BenefitDescription,
		&benefit.Value,
		&benefit.CreatedAt,
		&benefit.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get benefit by ID", zap.Error(err))
		return nil, fmt.Errorf("get benefit by ID: %w", err)
	}
	benefit.BenefitType = enums.BenefitType(benefitType)
	return &benefit, nil
}

func (r *benefitRepository) Update(ctx context.Context, db DBTX, benefit *models.Benefit) error {
	query := `
		UPDATE subscription.benefits
		SET benefit_type = $1,
		    benefit_description = $2,
		    value = $3,
		    updated_at = $4
		WHERE benefit_id = $5
	`
	_, err := db.ExecContext(ctx, query,
		string(benefit.BenefitType),
		benefit.BenefitDescription,
		benefit.Value,
		benefit.UpdatedAt,
		benefit.BenefitID,
	)
	if err != nil {
		r.logger.Error("failed to update benefit", zap.Error(err))
		return fmt.Errorf("update benefit: %w", err)
	}
	return nil
}

func (r *benefitRepository) Delete(ctx context.Context, db DBTX, benefitID uuid.UUID) error {
	query := `DELETE FROM subscription.benefits WHERE benefit_id = $1`
	result, err := db.ExecContext(ctx, query, benefitID)
	if err != nil {
		r.logger.Error("failed to delete benefit", zap.Error(err))
		return fmt.Errorf("delete benefit: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Bulk Operations
// -------------------------------------------------------------------------

func (r *benefitRepository) ReplaceByPlanItem(
	ctx context.Context,
	db DBTX,
	planItemID uuid.UUID,
	benefits []*models.Benefit,
) error {
	// Delete existing benefits for this plan item
	if err := r.DeleteByPlanItem(ctx, db, planItemID); err != nil {
		return fmt.Errorf("delete by plan item (replace): %w", err)
	}
	if len(benefits) == 0 {
		return nil
	}
	return r.BulkCreate(ctx, db, benefits)
}

func (r *benefitRepository) DeleteByPlanItem(ctx context.Context, db DBTX, planItemID uuid.UUID) error {
	query := `DELETE FROM subscription.benefits WHERE plan_item_id = $1`
	_, err := db.ExecContext(ctx, query, planItemID)
	if err != nil {
		r.logger.Error("failed to delete benefits by plan item", zap.Error(err))
		return fmt.Errorf("delete by plan item: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *benefitRepository) Exists(ctx context.Context, db DBTX, benefitID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.benefits WHERE benefit_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, benefitID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *benefitRepository) ExistsByType(
	ctx context.Context,
	db DBTX,
	planItemID uuid.UUID,
	benefitType enums.BenefitType,
) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.benefits WHERE plan_item_id = $1 AND benefit_type = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, planItemID, string(benefitType)).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by type: %w", err)
	}
	return exists, nil
}

// NEW: ExistsByPlanItemTypeAndValue checks for duplicate benefit (same plan_item, type, and JSON value)
func (r *benefitRepository) ExistsByPlanItemTypeAndValue(
	ctx context.Context,
	db DBTX,
	planItemID uuid.UUID,
	benefitType enums.BenefitType,
	value json.RawMessage,
) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.benefits WHERE plan_item_id = $1 AND benefit_type = $2 AND value = $3::jsonb)`
	var exists bool
	err := db.QueryRowContext(ctx, query, planItemID, string(benefitType), value).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check duplicate benefit: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *benefitRepository) List(
	ctx context.Context,
	db DBTX,
	filter BenefitFilter,
	p Pagination,
	s Sort,
) ([]*models.Benefit, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.benefits %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count benefits: %w", err)
	}
	if total == 0 {
		return []*models.Benefit{}, 0, nil
	}

	// Build sort
	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY created_at DESC"
	}

	query := fmt.Sprintf(`
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
		       created_at, updated_at
		FROM subscription.benefits
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list benefits: %w", err)
	}
	defer rows.Close()

	var benefits []*models.Benefit
	for rows.Next() {
		var b models.Benefit
		var benefitType string
		err := rows.Scan(
			&b.BenefitID,
			&b.PlanItemID,
			&benefitType,
			&b.BenefitDescription,
			&b.Value,
			&b.CreatedAt,
			&b.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan benefit: %w", err)
		}
		b.BenefitType = enums.BenefitType(benefitType)
		benefits = append(benefits, &b)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return benefits, total, nil
}

func (r *benefitRepository) GetByPlanItem(
	ctx context.Context,
	db DBTX,
	planItemID uuid.UUID,
) ([]*models.Benefit, error) {
	query := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
		       created_at, updated_at
		FROM subscription.benefits
		WHERE plan_item_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, planItemID)
	if err != nil {
		return nil, fmt.Errorf("get by plan item: %w", err)
	}
	defer rows.Close()

	var benefits []*models.Benefit
	for rows.Next() {
		var b models.Benefit
		var benefitType string
		err := rows.Scan(
			&b.BenefitID,
			&b.PlanItemID,
			&benefitType,
			&b.BenefitDescription,
			&b.Value,
			&b.CreatedAt,
			&b.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan benefit: %w", err)
		}
		b.BenefitType = enums.BenefitType(benefitType)
		benefits = append(benefits, &b)
	}
	return benefits, rows.Err()
}

func (r *benefitRepository) GetByType(
	ctx context.Context,
	db DBTX,
	benefitType enums.BenefitType,
) ([]*models.Benefit, error) {
	query := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
		       created_at, updated_at
		FROM subscription.benefits
		WHERE benefit_type = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, string(benefitType))
	if err != nil {
		return nil, fmt.Errorf("get by type: %w", err)
	}
	defer rows.Close()

	var benefits []*models.Benefit
	for rows.Next() {
		var b models.Benefit
		var bt string
		err := rows.Scan(
			&b.BenefitID,
			&b.PlanItemID,
			&bt,
			&b.BenefitDescription,
			&b.Value,
			&b.CreatedAt,
			&b.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan benefit: %w", err)
		}
		b.BenefitType = enums.BenefitType(bt)
		benefits = append(benefits, &b)
	}
	return benefits, rows.Err()
}

func (r *benefitRepository) Search(
	ctx context.Context,
	db DBTX,
	planItemID uuid.UUID,
	query string,
	limit,
	offset int,
) ([]*models.Benefit, int64, error) {
	searchPattern := "%" + query + "%"
	where := "plan_item_id = $1 AND benefit_description ILIKE $2"

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.benefits WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, planItemID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search benefits: %w", err)
	}
	if total == 0 {
		return []*models.Benefit{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
		       created_at, updated_at
		FROM subscription.benefits
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, planItemID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search benefits: %w", err)
	}
	defer rows.Close()

	var benefits []*models.Benefit
	for rows.Next() {
		var b models.Benefit
		var benefitType string
		err := rows.Scan(
			&b.BenefitID,
			&b.PlanItemID,
			&benefitType,
			&b.BenefitDescription,
			&b.Value,
			&b.CreatedAt,
			&b.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan benefit: %w", err)
		}
		b.BenefitType = enums.BenefitType(benefitType)
		benefits = append(benefits, &b)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return benefits, total, nil
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *benefitRepository) GetByIDForUpdate(
	ctx context.Context,
	db DBTX,
	benefitID uuid.UUID,
) (*models.Benefit, error) {
	query := `
		SELECT benefit_id, plan_item_id, benefit_type, benefit_description, value,
		       created_at, updated_at
		FROM subscription.benefits
		WHERE benefit_id = $1
		FOR UPDATE
	`
	var b models.Benefit
	var benefitType string
	err := db.QueryRowContext(ctx, query, benefitID).Scan(
		&b.BenefitID,
		&b.PlanItemID,
		&benefitType,
		&b.BenefitDescription,
		&b.Value,
		&b.CreatedAt,
		&b.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get benefit for update", zap.Error(err))
		return nil, fmt.Errorf("get benefit for update: %w", err)
	}
	b.BenefitType = enums.BenefitType(benefitType)
	return &b, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *benefitRepository) buildFilterConditions(filter BenefitFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.BenefitIDs) > 0 {
		placeholders := make([]string, len(filter.BenefitIDs))
		for i, id := range filter.BenefitIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("benefit_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.BenefitIDs)
	}

	if filter.PlanItemID != nil {
		conditions = append(conditions, fmt.Sprintf("plan_item_id = $%d", argPos))
		args = append(args, *filter.PlanItemID)
		argPos++
	}

	if filter.BenefitType != nil {
		conditions = append(conditions, fmt.Sprintf("benefit_type = $%d", argPos))
		args = append(args, string(*filter.BenefitType))
		argPos++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argPos))
		args = append(args, *filter.CreatedFrom)
		argPos++
	}
	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argPos))
		args = append(args, *filter.CreatedTo)
		argPos++
	}

	if filter.UpdatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argPos))
		args = append(args, *filter.UpdatedFrom)
		argPos++
	}
	if filter.UpdatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argPos))
		args = append(args, *filter.UpdatedTo)
		argPos++
	}

	return conditions, args
}
