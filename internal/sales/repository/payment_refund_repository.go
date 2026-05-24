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

// PaymentRefundRepository defines the interface for payment refund data access.
type PaymentRefundRepository interface {
	Create(ctx context.Context, db DBTX, refund *models.PaymentRefund) error
	GetByID(ctx context.Context, db DBTX, companyID, refundID uuid.UUID) (*models.PaymentRefund, error)
	GetByPayment(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) ([]*models.PaymentRefund, error)
	GetByReturnID(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) ([]*models.PaymentRefund, error) // new method
	UpdateStatus(ctx context.Context, db DBTX, companyID, refundID uuid.UUID, status string, completedAt *time.Time, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, refundID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter PaymentRefundFilter, p Pagination, s Sort) ([]*models.PaymentRefund, int64, error)
}

// PaymentRefundFilter defines filtering options for listing refunds.
type PaymentRefundFilter struct {
	CompanyID uuid.UUID
	PaymentID *uuid.UUID
	ReturnID  *uuid.UUID // new filter
	Status    *string
	FromDate  *time.Time
	ToDate    *time.Time
	MinAmount *decimal.Decimal
	MaxAmount *decimal.Decimal
}

type paymentRefundRepository struct {
	logger *zap.Logger
}

// NewPaymentRefundRepository creates a new instance of PaymentRefundRepository.
func NewPaymentRefundRepository(logger *zap.Logger) PaymentRefundRepository {
	return &paymentRefundRepository{
		logger: logger.Named("sales_payment_refund_repo"),
	}
}

// ----------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------

func (r *paymentRefundRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *paymentRefundRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *paymentRefundRepository) validatePagination(p Pagination) (int, int) {
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

func (r *paymentRefundRepository) buildFilter(filter PaymentRefundFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.PaymentID != nil {
		conds = append(conds, fmt.Sprintf("payment_id = $%d", idx))
		args = append(args, *filter.PaymentID)
		idx++
	}
	if filter.ReturnID != nil {
		conds = append(conds, fmt.Sprintf("return_id = $%d", idx))
		args = append(args, r.nullUUIDParam(filter.ReturnID))
		idx++
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.FromDate != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.MinAmount != nil {
		conds = append(conds, fmt.Sprintf("amount >= $%d", idx))
		args = append(args, filter.MinAmount.String())
		idx++
	}
	if filter.MaxAmount != nil {
		conds = append(conds, fmt.Sprintf("amount <= $%d", idx))
		args = append(args, filter.MaxAmount.String())
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *paymentRefundRepository) scanRefund(s scanner) (*models.PaymentRefund, error) {
	var refund models.PaymentRefund
	var gatewayRef, refundedBy sql.NullString
	var completedAt sql.NullTime
	var returnID sql.NullString // added for the new column

	err := s.Scan(
		&refund.RefundID,
		&refund.CompanyID,
		&refund.PaymentID,
		&returnID, // scan into NullString
		&refund.Amount,
		&refund.Reason,
		&gatewayRef,
		&refund.Status,
		&refundedBy,
		&completedAt,
		&refund.CreatedAt,
		&refund.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan payment refund: %w", err)
	}

	if returnID.Valid {
		id, err := uuid.Parse(returnID.String)
		if err == nil {
			refund.ReturnID = &id
		}
	}
	if gatewayRef.Valid {
		refund.GatewayRef = &gatewayRef.String
	}
	if refundedBy.Valid {
		id, err := uuid.Parse(refundedBy.String)
		if err == nil {
			refund.RefundedBy = &id
		}
	}
	if completedAt.Valid {
		refund.CompletedAt = &completedAt.Time
	}
	return &refund, nil
}

// ----------------------------------------------------------------------
// Interface implementation
// ----------------------------------------------------------------------

// Create inserts a new payment refund record.
func (r *paymentRefundRepository) Create(ctx context.Context, db DBTX, refund *models.PaymentRefund) error {
	query := `
		INSERT INTO sales.payment_refunds (
			refund_id, company_id, payment_id, return_id, amount, reason,
			gateway_ref, status, refunded_by, completed_at,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		refund.RefundID,
		refund.CompanyID,
		refund.PaymentID,
		r.nullUUIDParam(refund.ReturnID),
		refund.Amount.String(),
		refund.Reason,
		refund.GatewayRef,
		refund.Status,
		r.nullUUIDParam(refund.RefundedBy),
		refund.CompletedAt,
	).Scan(&refund.CreatedAt, &refund.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create payment refund", zap.Error(err))
		return fmt.Errorf("create payment refund: %w", err)
	}
	return nil
}

// GetByID retrieves a refund by its ID.
func (r *paymentRefundRepository) GetByID(ctx context.Context, db DBTX, companyID, refundID uuid.UUID) (*models.PaymentRefund, error) {
	query := `
		SELECT refund_id, company_id, payment_id, return_id, amount, reason,
		       gateway_ref, status, refunded_by, completed_at,
		       created_at, updated_at
		FROM sales.payment_refunds
		WHERE company_id = $1 AND refund_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, refundID)
	return r.scanRefund(row)
}

// GetByPayment retrieves all refunds for a given payment.
func (r *paymentRefundRepository) GetByPayment(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) ([]*models.PaymentRefund, error) {
	filter := PaymentRefundFilter{
		CompanyID: companyID,
		PaymentID: &paymentID,
	}
	refunds, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return refunds, err
}

// GetByReturnID retrieves all refunds linked to a specific return.
func (r *paymentRefundRepository) GetByReturnID(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) ([]*models.PaymentRefund, error) {
	filter := PaymentRefundFilter{
		CompanyID: companyID,
		ReturnID:  &returnID,
	}
	refunds, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return refunds, err
}

// UpdateStatus updates the status and optional completion timestamp of a refund.
func (r *paymentRefundRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, refundID uuid.UUID, status string, completedAt *time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payment_refunds
		SET status = $1, completed_at = $2, updated_by = $3, updated_at = NOW()
		WHERE company_id = $4 AND refund_id = $5
	`
	var completed interface{}
	if completedAt != nil {
		completed = *completedAt
	} else {
		completed = nil
	}
	result, err := db.ExecContext(ctx, query, status, completed, r.nullUUIDParam(updatedBy), companyID, refundID)
	if err != nil {
		return fmt.Errorf("update refund status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// Exists checks whether a refund exists.
func (r *paymentRefundRepository) Exists(ctx context.Context, db DBTX, companyID, refundID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payment_refunds WHERE company_id = $1 AND refund_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, refundID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

// List returns a paginated list of refunds matching the filter.
func (r *paymentRefundRepository) List(ctx context.Context, db DBTX, filter PaymentRefundFilter, p Pagination, s Sort) ([]*models.PaymentRefund, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"created_at": true,
		"amount":     true,
		"status":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.payment_refunds %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count payment refunds: %w", err)
	}
	if total == 0 {
		return []*models.PaymentRefund{}, 0, nil
	}

	// Fetch data
	query := fmt.Sprintf(`
		SELECT refund_id, company_id, payment_id, return_id, amount, reason,
		       gateway_ref, status, refunded_by, completed_at,
		       created_at, updated_at
		FROM sales.payment_refunds
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list payment refunds: %w", err)
	}
	defer rows.Close()

	var result []*models.PaymentRefund
	for rows.Next() {
		refund, err := r.scanRefund(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, refund)
	}
	return result, total, rows.Err()
}
