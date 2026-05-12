package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// SerialNumberTransactionFilter defines filters for listing transactions.
type SerialNumberTransactionFilter struct {
	CompanyID       uuid.UUID
	SerialID        *uuid.UUID
	MovementID      *uuid.UUID
	TransactionType *string
	FromDate        *time.Time
	ToDate          *time.Time
}

// SerialNumberTransactionRepository defines operations for serial number audit trail.
type SerialNumberTransactionRepository interface {
	Create(ctx context.Context, db DBTX, tx *models.SerialNumberTransaction) error
	GetByID(ctx context.Context, db DBTX, transactionID uuid.UUID) (*models.SerialNumberTransaction, error)
	GetBySerialID(ctx context.Context, db DBTX, serialID uuid.UUID, limit, offset int) ([]*models.SerialNumberTransaction, error)
	GetByMovementID(ctx context.Context, db DBTX, movementID uuid.UUID) ([]*models.SerialNumberTransaction, error)
	ListByCompany(ctx context.Context, db DBTX, filter SerialNumberTransactionFilter, p Pagination, s Sort) ([]*models.SerialNumberTransaction, int64, error)
}

type serialNumberTransactionRepository struct {
	logger *zap.Logger
}

// NewSerialNumberTransactionRepository creates a new repository instance.
func NewSerialNumberTransactionRepository(logger *zap.Logger) SerialNumberTransactionRepository {
	return &serialNumberTransactionRepository{
		logger: logger.Named("serial_number_txn_repo"),
	}
}

// validateSort validates sort field and direction.
func (r *serialNumberTransactionRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", fmt.Errorf("sort field required")
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

// validatePagination returns limit and offset with defaults.
func (r *serialNumberTransactionRepository) validatePagination(p Pagination) (int, int) {
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

// buildFilter builds WHERE clause and args for ListByCompany.
func (r *serialNumberTransactionRepository) buildFilter(filter SerialNumberTransactionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.SerialID != nil {
		conds = append(conds, fmt.Sprintf("serial_id = $%d", idx))
		args = append(args, *filter.SerialID)
		idx++
	}
	if filter.MovementID != nil {
		conds = append(conds, fmt.Sprintf("movement_id = $%d", idx))
		args = append(args, *filter.MovementID)
		idx++
	}
	if filter.TransactionType != nil && *filter.TransactionType != "" {
		conds = append(conds, fmt.Sprintf("transaction_type = $%d", idx))
		args = append(args, *filter.TransactionType)
		idx++
	}
	if filter.FromDate != nil {
		conds = append(conds, fmt.Sprintf("transaction_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conds = append(conds, fmt.Sprintf("transaction_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanTransaction scans a row into a SerialNumberTransaction model.
func (r *serialNumberTransactionRepository) scanTransaction(s scanner) (*models.SerialNumberTransaction, error) {
	var txn models.SerialNumberTransaction
	var movementID, fromWarehouseID, toWarehouseID, fromBatchID, toBatchID, createdBy uuid.NullUUID
	var oldStatus, newStatus, notes sql.NullString

	err := s.Scan(
		&txn.TransactionID,
		&txn.SerialID,
		&txn.CompanyID,
		&movementID,
		&fromWarehouseID,
		&toWarehouseID,
		&fromBatchID,
		&toBatchID,
		&oldStatus,
		&newStatus,
		&txn.TransactionType,
		&txn.TransactionDate,
		&createdBy,
		&notes,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan serial number transaction: %w", err)
	}

	if movementID.Valid {
		txn.MovementID = &movementID.UUID
	}
	if fromWarehouseID.Valid {
		txn.FromWarehouseID = &fromWarehouseID.UUID
	}
	if toWarehouseID.Valid {
		txn.ToWarehouseID = &toWarehouseID.UUID
	}
	if fromBatchID.Valid {
		txn.FromBatchID = &fromBatchID.UUID
	}
	if toBatchID.Valid {
		txn.ToBatchID = &toBatchID.UUID
	}
	if oldStatus.Valid {
		txn.OldStatus = &oldStatus.String
	}
	if newStatus.Valid {
		txn.NewStatus = &newStatus.String
	}
	if createdBy.Valid {
		txn.CreatedBy = &createdBy.UUID
	}
	if notes.Valid {
		txn.Notes = &notes.String
	}
	return &txn, nil
}

// Create inserts a new serial number transaction.
func (r *serialNumberTransactionRepository) Create(ctx context.Context, db DBTX, txn *models.SerialNumberTransaction) error {
	query := `
		INSERT INTO serial_number_transactions (
			transaction_id, serial_id, company_id, movement_id,
			from_warehouse_id, to_warehouse_id, from_batch_id, to_batch_id,
			old_status, new_status, transaction_type, transaction_date, created_by, notes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := db.ExecContext(ctx, query,
		txn.TransactionID,
		txn.SerialID,
		txn.CompanyID,
		txn.MovementID,
		txn.FromWarehouseID,
		txn.ToWarehouseID,
		txn.FromBatchID,
		txn.ToBatchID,
		txn.OldStatus,
		txn.NewStatus,
		txn.TransactionType,
		txn.TransactionDate,
		txn.CreatedBy,
		txn.Notes,
	)
	if err != nil {
		r.logger.Error("failed to create serial number transaction", util.ErrorField(err))
		return fmt.Errorf("create serial number transaction: %w", err)
	}
	return nil
}

// GetByID retrieves a transaction by its ID.
func (r *serialNumberTransactionRepository) GetByID(ctx context.Context, db DBTX, transactionID uuid.UUID) (*models.SerialNumberTransaction, error) {
	query := `
		SELECT transaction_id, serial_id, company_id, movement_id,
		       from_warehouse_id, to_warehouse_id, from_batch_id, to_batch_id,
		       old_status, new_status, transaction_type, transaction_date, created_by, notes
		FROM serial_number_transactions
		WHERE transaction_id = $1
	`
	row := db.QueryRowContext(ctx, query, transactionID)
	return r.scanTransaction(row)
}

// GetBySerialID retrieves all transactions for a given serial number, ordered by date descending.
func (r *serialNumberTransactionRepository) GetBySerialID(ctx context.Context, db DBTX, serialID uuid.UUID, limit, offset int) ([]*models.SerialNumberTransaction, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `
		SELECT transaction_id, serial_id, company_id, movement_id,
		       from_warehouse_id, to_warehouse_id, from_batch_id, to_batch_id,
		       old_status, new_status, transaction_type, transaction_date, created_by, notes
		FROM serial_number_transactions
		WHERE serial_id = $1
		ORDER BY transaction_date DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := db.QueryContext(ctx, query, serialID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("get by serial id: %w", err)
	}
	defer rows.Close()

	var result []*models.SerialNumberTransaction
	for rows.Next() {
		txn, err := r.scanTransaction(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, txn)
	}
	return result, rows.Err()
}

// GetByMovementID retrieves all transactions linked to a stock movement.
func (r *serialNumberTransactionRepository) GetByMovementID(ctx context.Context, db DBTX, movementID uuid.UUID) ([]*models.SerialNumberTransaction, error) {
	query := `
		SELECT transaction_id, serial_id, company_id, movement_id,
		       from_warehouse_id, to_warehouse_id, from_batch_id, to_batch_id,
		       old_status, new_status, transaction_type, transaction_date, created_by, notes
		FROM serial_number_transactions
		WHERE movement_id = $1
		ORDER BY transaction_date ASC
	`
	rows, err := db.QueryContext(ctx, query, movementID)
	if err != nil {
		return nil, fmt.Errorf("get by movement id: %w", err)
	}
	defer rows.Close()

	var result []*models.SerialNumberTransaction
	for rows.Next() {
		txn, err := r.scanTransaction(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, txn)
	}
	return result, rows.Err()
}

// ListByCompany lists transactions for a company with filters, pagination, and sorting.
func (r *serialNumberTransactionRepository) ListByCompany(ctx context.Context, db DBTX, filter SerialNumberTransactionFilter, p Pagination, s Sort) ([]*models.SerialNumberTransaction, int64, error) {
	where, args := r.buildFilter(filter)

	allowedSort := map[string]bool{
		"transaction_date": true,
		"transaction_type": true,
		"created_at":       true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		orderBy = "ORDER BY transaction_date DESC"
	}

	limit, offset := r.validatePagination(p)

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM serial_number_transactions %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count serial number transactions: %w", err)
	}
	if total == 0 {
		return []*models.SerialNumberTransaction{}, 0, nil
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT transaction_id, serial_id, company_id, movement_id,
		       from_warehouse_id, to_warehouse_id, from_batch_id, to_batch_id,
		       old_status, new_status, transaction_type, transaction_date, created_by, notes
		FROM serial_number_transactions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list serial number transactions: %w", err)
	}
	defer rows.Close()

	var result []*models.SerialNumberTransaction
	for rows.Next() {
		txn, err := r.scanTransaction(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, txn)
	}
	return result, total, rows.Err()
}
