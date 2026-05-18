package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

type ProductionOrderScrapRepository interface {
	Create(ctx context.Context, db DBTX, scrap *models.ProductionOrderScrap) error
	GetByID(ctx context.Context, db DBTX, companyID, scrapID uuid.UUID) (*models.ProductionOrderScrap, error)
	GetByProductionOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.ProductionOrderScrap, error)
	GetByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) ([]*models.ProductionOrderScrap, error)
	GetByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (*models.ProductionOrderScrap, error)
	GetTotalScrappedByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) (decimal.Decimal, error)
	List(ctx context.Context, db DBTX, filter ScrapFilter, p Pagination, s Sort) ([]*models.ProductionOrderScrap, int64, error)
	UpdateReason(ctx context.Context, db DBTX, companyID, scrapID uuid.UUID, reason string) error
	Delete(ctx context.Context, db DBTX, companyID, scrapID uuid.UUID) error
	ExistsByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (bool, error)
}

type ScrapFilter struct {
	CompanyID         uuid.UUID
	ProductionOrderID *uuid.UUID
	ComponentID       *uuid.UUID
	ItemID            *uuid.UUID
	FromRecordedAt    *time.Time
	ToRecordedAt      *time.Time
}

type productionOrderScrapRepository struct {
	logger *zap.Logger
}

func NewProductionOrderScrapRepository(logger *zap.Logger) ProductionOrderScrapRepository {
	return &productionOrderScrapRepository{
		logger: logger.Named("prod_order_scrap_repo"),
	}
}

// Helper functions same as above (reuse nullUUIDParam, validateSort, etc.)
// (Assume they are present; you can copy from consumption repo or make a shared util)

func (r *productionOrderScrapRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

func (r *productionOrderScrapRepository) validatePagination(p Pagination) (int, int) {
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

func (r *productionOrderScrapRepository) buildScrapFilter(filter ScrapFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ProductionOrderID != nil {
		conds = append(conds, fmt.Sprintf("production_order_id = $%d", idx))
		args = append(args, *filter.ProductionOrderID)
		idx++
	}
	if filter.ComponentID != nil {
		conds = append(conds, fmt.Sprintf("component_id = $%d", idx))
		args = append(args, *filter.ComponentID)
		idx++
	}
	if filter.ItemID != nil {
		conds = append(conds, fmt.Sprintf("item_id = $%d", idx))
		args = append(args, *filter.ItemID)
		idx++
	}
	if filter.FromRecordedAt != nil {
		conds = append(conds, fmt.Sprintf("recorded_at >= $%d", idx))
		args = append(args, *filter.FromRecordedAt)
		idx++
	}
	if filter.ToRecordedAt != nil {
		conds = append(conds, fmt.Sprintf("recorded_at <= $%d", idx))
		args = append(args, *filter.ToRecordedAt)
		idx++
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *productionOrderScrapRepository) scanScrap(s scanner) (*models.ProductionOrderScrap, error) {
	var sc models.ProductionOrderScrap
	var componentID, batchID, createdBy uuid.NullUUID
	var reason sql.NullString
	err := s.Scan(
		&sc.ScrapID,
		&sc.CompanyID,
		&sc.ProductionOrderID,
		&componentID,
		&sc.ItemID,
		&batchID,
		&sc.ScrapQuantity,
		&sc.MovementID,
		&reason,
		&sc.RecordedAt,
		&createdBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan scrap: %w", err)
	}
	if componentID.Valid {
		sc.ComponentID = &componentID.UUID
	}
	if batchID.Valid {
		sc.BatchID = &batchID.UUID
	}
	if createdBy.Valid {
		sc.CreatedBy = &createdBy.UUID
	}
	if reason.Valid {
		sc.Reason = &reason.String
	}
	return &sc, nil
}

func (r *productionOrderScrapRepository) Create(ctx context.Context, db DBTX, scrap *models.ProductionOrderScrap) error {
	query := `
		INSERT INTO production_order_scrap (
			scrap_id, company_id, production_order_id, component_id, item_id, batch_id,
			scrap_quantity, movement_id, reason, recorded_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING recorded_at
	`
	err := db.QueryRowContext(ctx, query,
		scrap.ScrapID,
		scrap.CompanyID,
		scrap.ProductionOrderID,
		nullUUIDParam(scrap.ComponentID),
		scrap.ItemID,
		nullUUIDParam(scrap.BatchID),
		scrap.ScrapQuantity,
		scrap.MovementID,
		scrap.Reason,
		scrap.RecordedAt,
		nullUUIDParam(scrap.CreatedBy),
	).Scan(&scrap.RecordedAt)
	if err != nil {
		r.logger.Error("failed to create scrap record", util.ErrorField(err))
		return fmt.Errorf("create scrap: %w", err)
	}
	return nil
}

func (r *productionOrderScrapRepository) GetByID(ctx context.Context, db DBTX, companyID, scrapID uuid.UUID) (*models.ProductionOrderScrap, error) {
	query := `
		SELECT scrap_id, company_id, production_order_id, component_id, item_id, batch_id,
		       scrap_quantity, movement_id, reason, recorded_at, created_by
		FROM production_order_scrap
		WHERE scrap_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, scrapID, companyID)
	return r.scanScrap(row)
}

func (r *productionOrderScrapRepository) GetByProductionOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.ProductionOrderScrap, error) {
	query := `
		SELECT scrap_id, company_id, production_order_id, component_id, item_id, batch_id,
		       scrap_quantity, movement_id, reason, recorded_at, created_by
		FROM production_order_scrap
		WHERE company_id = $1 AND production_order_id = $2
		ORDER BY recorded_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, orderID)
	if err != nil {
		return nil, fmt.Errorf("get scrap by order: %w", err)
	}
	defer rows.Close()
	var result []*models.ProductionOrderScrap
	for rows.Next() {
		s, err := r.scanScrap(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *productionOrderScrapRepository) GetByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) ([]*models.ProductionOrderScrap, error) {
	query := `
		SELECT scrap_id, company_id, production_order_id, component_id, item_id, batch_id,
		       scrap_quantity, movement_id, reason, recorded_at, created_by
		FROM production_order_scrap
		WHERE company_id = $1 AND component_id = $2
		ORDER BY recorded_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, componentID)
	if err != nil {
		return nil, fmt.Errorf("get scrap by component: %w", err)
	}
	defer rows.Close()
	var result []*models.ProductionOrderScrap
	for rows.Next() {
		s, err := r.scanScrap(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *productionOrderScrapRepository) GetByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (*models.ProductionOrderScrap, error) {
	query := `
		SELECT scrap_id, company_id, production_order_id, component_id, item_id, batch_id,
		       scrap_quantity, movement_id, reason, recorded_at, created_by
		FROM production_order_scrap
		WHERE company_id = $1 AND movement_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, movementID)
	return r.scanScrap(row)
}

func (r *productionOrderScrapRepository) GetTotalScrappedByComponent(ctx context.Context, db DBTX, companyID, componentID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(scrap_quantity), 0)
		FROM production_order_scrap
		WHERE company_id = $1 AND component_id = $2
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, componentID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total scrapped by component: %w", err)
	}
	return total, nil
}

func (r *productionOrderScrapRepository) List(ctx context.Context, db DBTX, filter ScrapFilter, p Pagination, s Sort) ([]*models.ProductionOrderScrap, int64, error) {
	where, args := r.buildScrapFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"recorded_at":    true,
		"scrap_quantity": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY recorded_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM production_order_scrap %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count scrap records: %w", err)
	}
	if total == 0 {
		return []*models.ProductionOrderScrap{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT scrap_id, company_id, production_order_id, component_id, item_id, batch_id,
		       scrap_quantity, movement_id, reason, recorded_at, created_by
		FROM production_order_scrap
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scrap records: %w", err)
	}
	defer rows.Close()
	var result []*models.ProductionOrderScrap
	for rows.Next() {
		s, err := r.scanScrap(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, s)
	}
	return result, total, rows.Err()
}

func (r *productionOrderScrapRepository) UpdateReason(ctx context.Context, db DBTX, companyID, scrapID uuid.UUID, reason string) error {
	query := `
		UPDATE production_order_scrap
		SET reason = $3
		WHERE scrap_id = $1 AND company_id = $2
	`
	result, err := db.ExecContext(ctx, query, scrapID, companyID, reason)
	if err != nil {
		return fmt.Errorf("update reason: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: scrap %s", inventory_errors.ErrNotFound, scrapID)
	}
	return nil
}

func (r *productionOrderScrapRepository) Delete(ctx context.Context, db DBTX, companyID, scrapID uuid.UUID) error {
	query := `DELETE FROM production_order_scrap WHERE scrap_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, scrapID, companyID)
	if err != nil {
		return fmt.Errorf("delete scrap: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%w: scrap %s", inventory_errors.ErrNotFound, scrapID)
	}
	return nil
}

func (r *productionOrderScrapRepository) ExistsByMovementID(ctx context.Context, db DBTX, companyID, movementID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM production_order_scrap WHERE company_id = $1 AND movement_id = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, movementID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by movement id: %w", err)
	}
	return exists, nil
}
