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

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
)

// -----------------------------------------------------------------------------
// Interface (same as before)
// -----------------------------------------------------------------------------

type TaxSnapshotRepository interface {
	Create(ctx context.Context, db DBTX, snapshot *models.TaxSnapshot) error
	BulkCreate(ctx context.Context, db DBTX, snapshots []*models.TaxSnapshot) error
	GetByID(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) (*models.TaxSnapshot, error)
	Delete(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) error
	DeleteByEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) (bool, error)
	ExistsForEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (bool, error)
	ExistsForLine(ctx context.Context, db DBTX, companyID uuid.UUID, lineID uuid.UUID) (bool, error)

	GetByEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*models.TaxSnapshot, error)
	GetByLine(ctx context.Context, db DBTX, companyID uuid.UUID, lineID uuid.UUID) ([]*models.TaxSnapshot, error)
	GetByTaxRate(ctx context.Context, db DBTX, companyID uuid.UUID, taxRateID uuid.UUID) ([]*models.TaxSnapshot, error)
	GetByTaxName(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string) ([]*models.TaxSnapshot, error)

	GetTotalTaxAmountForEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (decimal.Decimal, error)
	GetTotalTaxableAmountForEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (decimal.Decimal, error)
	GetTotalTaxAmountByTaxRate(ctx context.Context, db DBTX, companyID uuid.UUID, taxRateID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalTaxAmountByTaxName(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, from, to *time.Time) (decimal.Decimal, error)
	GetTotalTaxCollected(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)

	GetTaxBreakdownByRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*TaxRateBreakdown, error)
	GetTaxBreakdownByName(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*TaxNameBreakdown, error)
	GetTopTaxedEntities(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, limit int, from, to *time.Time) ([]*TaxedEntityAggregate, error)

	List(ctx context.Context, db DBTX, filter TaxSnapshotFilter, p Pagination, s Sort) ([]*models.TaxSnapshot, int64, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) (*models.TaxSnapshot, error)
}

// -----------------------------------------------------------------------------
// Filter, Aggregation Types
// -----------------------------------------------------------------------------

type TaxSnapshotFilter struct {
	CompanyID        uuid.UUID
	EntityType       *string
	EntityID         *uuid.UUID
	LineID           *uuid.UUID
	TaxRateID        *uuid.UUID
	TaxName          *string
	MinTaxPercentage *decimal.Decimal
	MaxTaxPercentage *decimal.Decimal
	MinTaxableAmount *decimal.Decimal
	MaxTaxableAmount *decimal.Decimal
	MinTaxAmount     *decimal.Decimal
	MaxTaxAmount     *decimal.Decimal
	CreatedFrom      *time.Time
	CreatedTo        *time.Time
}

type TaxRateBreakdown struct {
	TaxRateID      *uuid.UUID
	TaxName        *string
	TaxPercentage  *decimal.Decimal
	TaxableAmount  decimal.Decimal
	TotalTaxAmount decimal.Decimal
}

type TaxNameBreakdown struct {
	TaxName        *string
	TaxableAmount  decimal.Decimal
	TotalTaxAmount decimal.Decimal
}

type TaxedEntityAggregate struct {
	EntityType     string
	EntityID       uuid.UUID
	TaxableAmount  decimal.Decimal
	TotalTaxAmount decimal.Decimal
}

// -----------------------------------------------------------------------------
// Repository Implementation
// -----------------------------------------------------------------------------

type taxSnapshotRepository struct {
	logger *zap.Logger
}

func NewTaxSnapshotRepository(logger *zap.Logger) TaxSnapshotRepository {
	return &taxSnapshotRepository{
		logger: logger.Named("sales_tax_snapshot_repo"),
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) buildFilter(filter TaxSnapshotFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.EntityType != nil {
		conds = append(conds, fmt.Sprintf("entity_type = $%d", idx))
		args = append(args, *filter.EntityType)
		idx++
	}
	if filter.EntityID != nil {
		conds = append(conds, fmt.Sprintf("entity_id = $%d", idx))
		args = append(args, *filter.EntityID)
		idx++
	}
	if filter.LineID != nil {
		conds = append(conds, fmt.Sprintf("line_id = $%d", idx))
		args = append(args, nullUUIDParam(filter.LineID))
		idx++
	}
	if filter.TaxRateID != nil {
		conds = append(conds, fmt.Sprintf("tax_rate_id = $%d", idx))
		args = append(args, nullUUIDParam(filter.TaxRateID))
		idx++
	}
	if filter.TaxName != nil {
		conds = append(conds, fmt.Sprintf("tax_name = $%d", idx))
		args = append(args, *filter.TaxName)
		idx++
	}
	if filter.MinTaxPercentage != nil {
		conds = append(conds, fmt.Sprintf("tax_percentage >= $%d", idx))
		args = append(args, *filter.MinTaxPercentage)
		idx++
	}
	if filter.MaxTaxPercentage != nil {
		conds = append(conds, fmt.Sprintf("tax_percentage <= $%d", idx))
		args = append(args, *filter.MaxTaxPercentage)
		idx++
	}
	if filter.MinTaxableAmount != nil {
		conds = append(conds, fmt.Sprintf("taxable_amount >= $%d", idx))
		args = append(args, *filter.MinTaxableAmount)
		idx++
	}
	if filter.MaxTaxableAmount != nil {
		conds = append(conds, fmt.Sprintf("taxable_amount <= $%d", idx))
		args = append(args, *filter.MaxTaxableAmount)
		idx++
	}
	if filter.MinTaxAmount != nil {
		conds = append(conds, fmt.Sprintf("tax_amount >= $%d", idx))
		args = append(args, *filter.MinTaxAmount)
		idx++
	}
	if filter.MaxTaxAmount != nil {
		conds = append(conds, fmt.Sprintf("tax_amount <= $%d", idx))
		args = append(args, *filter.MaxTaxAmount)
		idx++
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanSnapshot maps a database row to models.TaxSnapshot.
// Uses uuid.NullUUID for nullable UUID columns.
func (r *taxSnapshotRepository) scanSnapshot(s scanner) (*models.TaxSnapshot, error) {
	var ts models.TaxSnapshot
	var lineID, taxRateID uuid.NullUUID
	var taxName, taxPercentage sql.NullString

	err := s.Scan(
		&ts.TaxSnapshotID,
		&ts.CompanyID,
		&ts.EntityType,
		&ts.EntityID,
		&lineID,
		&taxRateID,
		&taxName,
		&taxPercentage,
		&ts.TaxableAmount,
		&ts.TaxAmount,
		&ts.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan tax snapshot: %w", err)
	}

	if lineID.Valid {
		ts.LineID = &lineID.UUID
	}
	if taxRateID.Valid {
		ts.TaxRateID = &taxRateID.UUID
	}
	if taxName.Valid {
		ts.TaxName = &taxName.String
	}
	if taxPercentage.Valid {
		p, err := decimal.NewFromString(taxPercentage.String)
		if err == nil {
			ts.TaxPercentage = &p
		}
	}
	return &ts, nil
}

// -----------------------------------------------------------------------------
// CRUD Operations
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) Create(ctx context.Context, db DBTX, snapshot *models.TaxSnapshot) error {
	query := `
		INSERT INTO sales.tax_snapshots (
			tax_snapshot_id, company_id, entity_type, entity_id, line_id,
			tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		snapshot.TaxSnapshotID,
		snapshot.CompanyID,
		snapshot.EntityType,
		snapshot.EntityID,
		nullUUIDParam(snapshot.LineID),
		nullUUIDParam(snapshot.TaxRateID),
		snapshot.TaxName,
		snapshot.TaxPercentage,
		snapshot.TaxableAmount,
		snapshot.TaxAmount,
	).Scan(&snapshot.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create tax snapshot", zap.Error(err))
		return fmt.Errorf("create tax snapshot: %w", err)
	}
	return nil
}

func (r *taxSnapshotRepository) BulkCreate(ctx context.Context, db DBTX, snapshots []*models.TaxSnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	query := `
		INSERT INTO sales.tax_snapshots (
			tax_snapshot_id, company_id, entity_type, entity_id, line_id,
			tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		) VALUES `
	values := make([]string, 0, len(snapshots))
	args := make([]interface{}, 0, len(snapshots)*11)
	idx := 1
	for _, s := range snapshots {
		values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, NOW())",
			idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7, idx+8, idx+9))
		args = append(args,
			s.TaxSnapshotID,
			s.CompanyID,
			s.EntityType,
			s.EntityID,
			nullUUIDParam(s.LineID),
			nullUUIDParam(s.TaxRateID),
			s.TaxName,
			s.TaxPercentage,
			s.TaxableAmount,
			s.TaxAmount,
		)
		idx += 10
	}
	query += strings.Join(values, ",")
	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create tax snapshots", zap.Error(err))
		return fmt.Errorf("bulk create tax snapshots: %w", err)
	}
	return nil
}

func (r *taxSnapshotRepository) GetByID(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) (*models.TaxSnapshot, error) {
	query := `
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND tax_snapshot_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, taxSnapshotID)
	return r.scanSnapshot(row)
}

func (r *taxSnapshotRepository) Delete(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) error {
	query := `DELETE FROM sales.tax_snapshots WHERE company_id = $1 AND tax_snapshot_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, taxSnapshotID)
	if err != nil {
		return fmt.Errorf("delete tax snapshot: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *taxSnapshotRepository) DeleteByEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) error {
	query := `DELETE FROM sales.tax_snapshots WHERE company_id = $1 AND entity_type = $2 AND entity_id = $3`
	_, err := db.ExecContext(ctx, query, companyID, entityType, entityID)
	if err != nil {
		return fmt.Errorf("delete by entity: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Existence Checks
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) Exists(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.tax_snapshots WHERE company_id = $1 AND tax_snapshot_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, taxSnapshotID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *taxSnapshotRepository) ExistsForEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.tax_snapshots WHERE company_id = $1 AND entity_type = $2 AND entity_id = $3)`
	err := db.QueryRowContext(ctx, query, companyID, entityType, entityID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists for entity: %w", err)
	}
	return exists, nil
}

func (r *taxSnapshotRepository) ExistsForLine(ctx context.Context, db DBTX, companyID uuid.UUID, lineID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.tax_snapshots WHERE company_id = $1 AND line_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, lineID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists for line: %w", err)
	}
	return exists, nil
}

// -----------------------------------------------------------------------------
// Lookups
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) GetByEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*models.TaxSnapshot, error) {
	query := `
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND entity_type = $2 AND entity_id = $3
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, entityType, entityID)
	if err != nil {
		return nil, fmt.Errorf("get by entity: %w", err)
	}
	defer rows.Close()
	var result []*models.TaxSnapshot
	for rows.Next() {
		s, err := r.scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *taxSnapshotRepository) GetByLine(ctx context.Context, db DBTX, companyID uuid.UUID, lineID uuid.UUID) ([]*models.TaxSnapshot, error) {
	query := `
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND line_id = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, lineID)
	if err != nil {
		return nil, fmt.Errorf("get by line: %w", err)
	}
	defer rows.Close()
	var result []*models.TaxSnapshot
	for rows.Next() {
		s, err := r.scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *taxSnapshotRepository) GetByTaxRate(ctx context.Context, db DBTX, companyID uuid.UUID, taxRateID uuid.UUID) ([]*models.TaxSnapshot, error) {
	query := `
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND tax_rate_id = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, taxRateID)
	if err != nil {
		return nil, fmt.Errorf("get by tax rate: %w", err)
	}
	defer rows.Close()
	var result []*models.TaxSnapshot
	for rows.Next() {
		s, err := r.scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r *taxSnapshotRepository) GetByTaxName(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string) ([]*models.TaxSnapshot, error) {
	query := `
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND tax_name = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, taxName)
	if err != nil {
		return nil, fmt.Errorf("get by tax name: %w", err)
	}
	defer rows.Close()
	var result []*models.TaxSnapshot
	for rows.Next() {
		s, err := r.scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

// -----------------------------------------------------------------------------
// Financial Totals
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) GetTotalTaxAmountForEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `
		SELECT COALESCE(SUM(tax_amount), 0)
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND entity_type = $2 AND entity_id = $3
	`
	err := db.QueryRowContext(ctx, query, companyID, entityType, entityID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total tax amount for entity: %w", err)
	}
	return total, nil
}

func (r *taxSnapshotRepository) GetTotalTaxableAmountForEntity(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, entityID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `
		SELECT COALESCE(SUM(taxable_amount), 0)
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND entity_type = $2 AND entity_id = $3
	`
	err := db.QueryRowContext(ctx, query, companyID, entityType, entityID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total taxable amount for entity: %w", err)
	}
	return total, nil
}

func (r *taxSnapshotRepository) GetTotalTaxAmountByTaxRate(ctx context.Context, db DBTX, companyID uuid.UUID, taxRateID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	args := []interface{}{companyID, taxRateID}
	idx := 3
	dateFilter := ""
	if from != nil {
		dateFilter += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		dateFilter += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(tax_amount), 0)
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND tax_rate_id = $2%s
	`, dateFilter)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total tax by rate: %w", err)
	}
	return total, nil
}

func (r *taxSnapshotRepository) GetTotalTaxAmountByTaxName(ctx context.Context, db DBTX, companyID uuid.UUID, taxName string, from, to *time.Time) (decimal.Decimal, error) {
	args := []interface{}{companyID, taxName}
	idx := 3
	dateFilter := ""
	if from != nil {
		dateFilter += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		dateFilter += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(tax_amount), 0)
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND tax_name = $2%s
	`, dateFilter)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total tax by name: %w", err)
	}
	return total, nil
}

func (r *taxSnapshotRepository) GetTotalTaxCollected(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	args := []interface{}{companyID}
	idx := 2
	dateFilter := ""
	if from != nil {
		dateFilter += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		dateFilter += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(tax_amount), 0)
		FROM sales.tax_snapshots
		WHERE company_id = $1%s
	`, dateFilter)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total tax collected: %w", err)
	}
	return total, nil
}

// -----------------------------------------------------------------------------
// Analytics / Reporting
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) GetTaxBreakdownByRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*TaxRateBreakdown, error) {
	args := []interface{}{companyID}
	idx := 2
	dateFilter := ""
	if from != nil {
		dateFilter += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		dateFilter += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf(`
		SELECT tax_rate_id, tax_name, tax_percentage,
		       SUM(taxable_amount) AS total_taxable,
		       SUM(tax_amount) AS total_tax
		FROM sales.tax_snapshots
		WHERE company_id = $1%s
		GROUP BY tax_rate_id, tax_name, tax_percentage
		ORDER BY tax_name
	`, dateFilter)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tax breakdown by rate: %w", err)
	}
	defer rows.Close()

	var result []*TaxRateBreakdown
	for rows.Next() {
		var taxRateID, taxName, taxPercentage sql.NullString
		var taxableAmount, taxAmount decimal.Decimal
		err := rows.Scan(&taxRateID, &taxName, &taxPercentage, &taxableAmount, &taxAmount)
		if err != nil {
			return nil, fmt.Errorf("scan breakdown row: %w", err)
		}
		item := &TaxRateBreakdown{
			TaxableAmount:  taxableAmount,
			TotalTaxAmount: taxAmount,
		}
		if taxRateID.Valid {
			id, _ := uuid.Parse(taxRateID.String)
			item.TaxRateID = &id
		}
		if taxName.Valid {
			item.TaxName = &taxName.String
		}
		if taxPercentage.Valid {
			p, _ := decimal.NewFromString(taxPercentage.String)
			item.TaxPercentage = &p
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *taxSnapshotRepository) GetTaxBreakdownByName(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) ([]*TaxNameBreakdown, error) {
	args := []interface{}{companyID}
	idx := 2
	dateFilter := ""
	if from != nil {
		dateFilter += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		dateFilter += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf(`
		SELECT tax_name, SUM(taxable_amount) AS total_taxable, SUM(tax_amount) AS total_tax
		FROM sales.tax_snapshots
		WHERE company_id = $1%s AND tax_name IS NOT NULL
		GROUP BY tax_name
		ORDER BY tax_name
	`, dateFilter)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tax breakdown by name: %w", err)
	}
	defer rows.Close()

	var result []*TaxNameBreakdown
	for rows.Next() {
		var taxName sql.NullString
		var taxableAmount, taxAmount decimal.Decimal
		err := rows.Scan(&taxName, &taxableAmount, &taxAmount)
		if err != nil {
			return nil, fmt.Errorf("scan breakdown row: %w", err)
		}
		item := &TaxNameBreakdown{
			TaxableAmount:  taxableAmount,
			TotalTaxAmount: taxAmount,
		}
		if taxName.Valid {
			item.TaxName = &taxName.String
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *taxSnapshotRepository) GetTopTaxedEntities(ctx context.Context, db DBTX, companyID uuid.UUID, entityType string, limit int, from, to *time.Time) ([]*TaxedEntityAggregate, error) {
	args := []interface{}{companyID, entityType}
	idx := 3
	dateFilter := ""
	if from != nil {
		dateFilter += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		dateFilter += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT entity_id,
		       SUM(taxable_amount) AS total_taxable,
		       SUM(tax_amount) AS total_tax
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND entity_type = $2%s
		GROUP BY entity_id
		ORDER BY total_tax DESC
		LIMIT $%d
	`, dateFilter, idx)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("top taxed entities: %w", err)
	}
	defer rows.Close()

	var result []*TaxedEntityAggregate
	for rows.Next() {
		var entityID uuid.UUID
		var taxableAmount, taxAmount decimal.Decimal
		err := rows.Scan(&entityID, &taxableAmount, &taxAmount)
		if err != nil {
			return nil, fmt.Errorf("scan top entity row: %w", err)
		}
		result = append(result, &TaxedEntityAggregate{
			EntityType:     entityType,
			EntityID:       entityID,
			TaxableAmount:  taxableAmount,
			TotalTaxAmount: taxAmount,
		})
	}
	return result, rows.Err()
}

// -----------------------------------------------------------------------------
// List with Pagination & Sorting
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) List(ctx context.Context, db DBTX, filter TaxSnapshotFilter, p Pagination, s Sort) ([]*models.TaxSnapshot, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"created_at": true,
		"tax_amount": true,
	}
	orderBy, err := validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.tax_snapshots %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count tax snapshots: %w", err)
	}
	if total == 0 {
		return []*models.TaxSnapshot{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list tax snapshots: %w", err)
	}
	defer rows.Close()

	var result []*models.TaxSnapshot
	for rows.Next() {
		s, err := r.scanSnapshot(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, s)
	}
	return result, total, rows.Err()
}

// -----------------------------------------------------------------------------
// Concurrency Locking
// -----------------------------------------------------------------------------

func (r *taxSnapshotRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, taxSnapshotID uuid.UUID) (*models.TaxSnapshot, error) {
	query := `
		SELECT tax_snapshot_id, company_id, entity_type, entity_id, line_id,
		       tax_rate_id, tax_name, tax_percentage, taxable_amount, tax_amount, created_at
		FROM sales.tax_snapshots
		WHERE company_id = $1 AND tax_snapshot_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, taxSnapshotID)
	return r.scanSnapshot(row)
}
