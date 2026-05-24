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

	"auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// PaymentRepository Interface & PaymentFilter
// -------------------------------------------------------------------------

type PaymentRepository interface {
	// Payment CRUD
	Create(ctx context.Context, db DBTX, payment *models.Payment, allocations []*models.PaymentAllocation) error
	GetByID(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (*models.Payment, error)
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, paymentNumber string) (*models.Payment, error)
	GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, reference string) (*models.Payment, error)
	Update(ctx context.Context, db DBTX, payment *models.Payment) error
	Delete(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) error

	// Payment Allocations
	AddAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, allocations []*models.PaymentAllocation) error
	ReplaceAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, allocations []*models.PaymentAllocation) error
	DeleteAllocation(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) error
	GetAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) ([]*models.PaymentAllocation, error)
	GetAllocationByID(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) (*models.PaymentAllocation, error)
	GetAllocationsByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.PaymentAllocation, error)
	ExistsAllocation(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) (bool, error)

	// Financials / Reconciliation
	GetTotalAllocated(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (decimal.Decimal, error)
	GetUnallocatedAmount(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (decimal.Decimal, error)
	UpdateRefundedAmount(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, refundedAmount decimal.Decimal, updatedBy *uuid.UUID) error
	GetRefundedAmount(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (decimal.Decimal, error)

	// Status / Lifecycle
	UpdateStatus(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, status enums.PaymentStatus, updatedBy *uuid.UUID) error
	MarkProcessing(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, updatedBy *uuid.UUID) error
	MarkCompleted(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, completedAt time.Time, updatedBy *uuid.UUID) error
	MarkFailed(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, failureReason string, updatedBy *uuid.UUID) error
	MarkRefunded(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, refundedAmount decimal.Decimal, updatedBy *uuid.UUID) error
	MarkPartiallyRefunded(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, refundedAmount decimal.Decimal, updatedBy *uuid.UUID) error

	// Existence / Validation
	Exists(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (bool, error)
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, paymentNumber string) (bool, error)
	ExistsByExternalRef(ctx context.Context, db DBTX, companyID uuid.UUID, externalRef string) (bool, error)
	HasAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (bool, error)
	IsFullyAllocated(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (bool, error)

	// Querying / Listing
	List(ctx context.Context, db DBTX, filter PaymentFilter, p Pagination, s Sort) ([]*models.Payment, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.Payment, int64, error)
	GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.Payment, error)
	GetUnallocatedPayments(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Payment, error)
	GetFailedPayments(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Payment, error)

	// Analytics / Reporting
	GetCollectedAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetRefundedAmountTotal(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetPaymentMethodBreakdown(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (map[enums.PaymentMethod]decimal.Decimal, error)
	GetTopPayments(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Payment, error)

	// Concurrency / Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (*models.Payment, error)
	GetAllocationByIDForUpdate(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) (*models.PaymentAllocation, error)
}

type PaymentFilter struct {
	CompanyID uuid.UUID

	PaymentIDs []uuid.UUID

	Statuses []enums.PaymentStatus

	Methods []enums.PaymentMethod

	PaymentNumber *string
	ExternalRef   *string
	Reference     *string

	MinAmount *decimal.Decimal
	MaxAmount *decimal.Decimal

	MinRefundedAmount *decimal.Decimal
	MaxRefundedAmount *decimal.Decimal

	PaymentDateFrom *time.Time
	PaymentDateTo   *time.Time

	CompletedFrom *time.Time
	CompletedTo   *time.Time

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

// -------------------------------------------------------------------------
// Repository implementation
// -------------------------------------------------------------------------

type paymentRepository struct {
	logger *zap.Logger
}

func NewPaymentRepository(logger *zap.Logger) PaymentRepository {
	return &paymentRepository{
		logger: logger.Named("sales_payment_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers (only those not already in tx_helper.go)
// -------------------------------------------------------------------------

func (r *paymentRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

// validateSort and validatePagination are already in tx_helper.go – reuse them.
// We do NOT redefine them here.

func (r *paymentRepository) buildFilter(filter PaymentFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.PaymentIDs) > 0 {
		placeholders := make([]string, len(filter.PaymentIDs))
		for i, id := range filter.PaymentIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("payment_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, string(st))
			idx++
		}
		conds = append(conds, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filter.Methods) > 0 {
		placeholders := make([]string, len(filter.Methods))
		for i, m := range filter.Methods {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, string(m))
			idx++
		}
		conds = append(conds, fmt.Sprintf("payment_method IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.PaymentNumber != nil {
		conds = append(conds, fmt.Sprintf("payment_number = $%d", idx))
		args = append(args, *filter.PaymentNumber)
		idx++
	}
	if filter.ExternalRef != nil {
		conds = append(conds, fmt.Sprintf("external_ref = $%d", idx))
		args = append(args, *filter.ExternalRef)
		idx++
	}
	if filter.Reference != nil {
		conds = append(conds, fmt.Sprintf("reference = $%d", idx))
		args = append(args, *filter.Reference)
		idx++
	}
	if filter.MinAmount != nil {
		conds = append(conds, fmt.Sprintf("amount >= $%d", idx))
		args = append(args, *filter.MinAmount)
		idx++
	}
	if filter.MaxAmount != nil {
		conds = append(conds, fmt.Sprintf("amount <= $%d", idx))
		args = append(args, *filter.MaxAmount)
		idx++
	}
	if filter.MinRefundedAmount != nil {
		conds = append(conds, fmt.Sprintf("refunded_amount >= $%d", idx))
		args = append(args, *filter.MinRefundedAmount)
		idx++
	}
	if filter.MaxRefundedAmount != nil {
		conds = append(conds, fmt.Sprintf("refunded_amount <= $%d", idx))
		args = append(args, *filter.MaxRefundedAmount)
		idx++
	}
	if filter.PaymentDateFrom != nil {
		conds = append(conds, fmt.Sprintf("payment_date >= $%d", idx))
		args = append(args, *filter.PaymentDateFrom)
		idx++
	}
	if filter.PaymentDateTo != nil {
		conds = append(conds, fmt.Sprintf("payment_date <= $%d", idx))
		args = append(args, *filter.PaymentDateTo)
		idx++
	}
	if filter.CompletedFrom != nil {
		conds = append(conds, fmt.Sprintf("completed_at >= $%d", idx))
		args = append(args, *filter.CompletedFrom)
		idx++
	}
	if filter.CompletedTo != nil {
		conds = append(conds, fmt.Sprintf("completed_at <= $%d", idx))
		args = append(args, *filter.CompletedTo)
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
	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// -------------------------------------------------------------------------
// Scanners (using the package-level scanner interface from tx_helper)
// -------------------------------------------------------------------------

func (r *paymentRepository) scanPayment(s scanner) (*models.Payment, error) {
	var p models.Payment
	var createdBy, updatedBy uuid.NullUUID
	var exchangeRate, refundedAmount sql.NullString
	var completedAt sql.NullTime

	err := s.Scan(
		&p.PaymentID,
		&p.CompanyID,
		&p.PaymentNumber,
		&p.ExternalRef,
		&p.PaymentDate,
		&p.Amount,
		&p.PaymentMethod,
		&p.Status,
		&exchangeRate,
		&p.Reference,
		&p.GatewayResponse,
		&p.FailureReason,
		&completedAt,
		&refundedAmount,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan payment: %w", err)
	}

	if exchangeRate.Valid {
		val, err := decimal.NewFromString(exchangeRate.String)
		if err == nil {
			p.ExchangeRate = &val
		}
	}
	if refundedAmount.Valid {
		val, err := decimal.NewFromString(refundedAmount.String)
		if err == nil {
			p.RefundedAmount = val
		}
	}
	if completedAt.Valid {
		p.CompletedAt = &completedAt.Time
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	return &p, nil
}

func (r *paymentRepository) scanAllocation(s scanner) (*models.PaymentAllocation, error) {
	var a models.PaymentAllocation
	err := s.Scan(
		&a.AllocationID,
		&a.PaymentID,
		&a.InvoiceID,
		&a.Amount,
		&a.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan allocation: %w", err)
	}
	return &a, nil
}

// -------------------------------------------------------------------------
// Payment CRUD
// -------------------------------------------------------------------------

func (r *paymentRepository) Create(ctx context.Context, db DBTX, payment *models.Payment, allocations []*models.PaymentAllocation) error {
	query := `
		INSERT INTO sales.payments (
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14, NOW(), NOW(),
			$15, $16
		)
		RETURNING created_at, updated_at
	`
	var exchangeRate interface{}
	if payment.ExchangeRate != nil {
		exchangeRate = payment.ExchangeRate.String()
	} else {
		exchangeRate = nil
	}
	err := db.QueryRowContext(ctx, query,
		payment.PaymentID,
		payment.CompanyID,
		payment.PaymentNumber,
		payment.ExternalRef,
		payment.PaymentDate,
		payment.Amount,
		payment.PaymentMethod,
		payment.Status,
		exchangeRate,
		payment.Reference,
		payment.GatewayResponse,
		payment.FailureReason,
		payment.CompletedAt,
		payment.RefundedAmount,
		r.nullUUIDParam(payment.CreatedBy),
		r.nullUUIDParam(payment.UpdatedBy),
	).Scan(&payment.CreatedAt, &payment.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create payment", zap.Error(err))
		return fmt.Errorf("create payment: %w", err)
	}

	if len(allocations) > 0 {
		if err := r.AddAllocations(ctx, db, payment.CompanyID, payment.PaymentID, allocations); err != nil {
			return fmt.Errorf("create allocations: %w", err)
		}
	}
	return nil
}

func (r *paymentRepository) GetByID(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (*models.Payment, error) {
	query := `
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		WHERE company_id = $1 AND payment_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, paymentID)
	return r.scanPayment(row)
}

func (r *paymentRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, paymentNumber string) (*models.Payment, error) {
	query := `
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		WHERE company_id = $1 AND payment_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, paymentNumber)
	return r.scanPayment(row)
}

func (r *paymentRepository) GetByReference(ctx context.Context, db DBTX, companyID uuid.UUID, reference string) (*models.Payment, error) {
	query := `
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		WHERE company_id = $1 AND reference = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, reference)
	return r.scanPayment(row)
}

func (r *paymentRepository) Update(ctx context.Context, db DBTX, payment *models.Payment) error {
	query := `
		UPDATE sales.payments SET
			payment_number = $3,
			external_ref = $4,
			payment_date = $5,
			amount = $6,
			payment_method = $7,
			status = $8,
			exchange_rate = $9,
			reference = $10,
			gateway_response = $11,
			failure_reason = $12,
			completed_at = $13,
			refunded_amount = $14,
			updated_at = NOW(),
			updated_by = $15
		WHERE payment_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	var exchangeRate interface{}
	if payment.ExchangeRate != nil {
		exchangeRate = payment.ExchangeRate.String()
	} else {
		exchangeRate = nil
	}
	err := db.QueryRowContext(ctx, query,
		payment.PaymentID,
		payment.CompanyID,
		payment.PaymentNumber,
		payment.ExternalRef,
		payment.PaymentDate,
		payment.Amount,
		payment.PaymentMethod,
		payment.Status,
		exchangeRate,
		payment.Reference,
		payment.GatewayResponse,
		payment.FailureReason,
		payment.CompletedAt,
		payment.RefundedAmount,
		r.nullUUIDParam(payment.UpdatedBy),
	).Scan(&payment.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update payment: %w", err)
	}
	return nil
}

func (r *paymentRepository) Delete(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sales.payment_allocations WHERE payment_id = $1`, paymentID); err != nil {
		return fmt.Errorf("delete allocations: %w", err)
	}
	query := `DELETE FROM sales.payments WHERE company_id = $1 AND payment_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, paymentID)
	if err != nil {
		return fmt.Errorf("delete payment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Payment Allocations
// -------------------------------------------------------------------------

func (r *paymentRepository) AddAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, allocations []*models.PaymentAllocation) error {
	if len(allocations) == 0 {
		return nil
	}
	query := `
		INSERT INTO sales.payment_allocations (
			allocation_id, payment_id, invoice_id, amount, created_at
		) VALUES ($1, $2, $3, $4, NOW())
	`
	for _, alloc := range allocations {
		_, err := db.ExecContext(ctx, query,
			alloc.AllocationID,
			paymentID,
			alloc.InvoiceID,
			alloc.Amount,
		)
		if err != nil {
			return fmt.Errorf("insert allocation: %w", err)
		}
	}
	return nil
}

func (r *paymentRepository) ReplaceAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, allocations []*models.PaymentAllocation) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sales.payment_allocations WHERE payment_id = $1`, paymentID); err != nil {
		return fmt.Errorf("delete old allocations: %w", err)
	}
	return r.AddAllocations(ctx, db, companyID, paymentID, allocations)
}

func (r *paymentRepository) DeleteAllocation(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) error {
	query := `DELETE FROM sales.payment_allocations WHERE allocation_id = $1 AND payment_id = $2`
	result, err := db.ExecContext(ctx, query, allocationID, paymentID)
	if err != nil {
		return fmt.Errorf("delete allocation: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *paymentRepository) GetAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) ([]*models.PaymentAllocation, error) {
	query := `
		SELECT allocation_id, payment_id, invoice_id, amount, created_at
		FROM sales.payment_allocations
		WHERE payment_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, paymentID)
	if err != nil {
		return nil, fmt.Errorf("get allocations: %w", err)
	}
	defer rows.Close()
	var result []*models.PaymentAllocation
	for rows.Next() {
		a, err := r.scanAllocation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (r *paymentRepository) GetAllocationByID(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) (*models.PaymentAllocation, error) {
	query := `
		SELECT allocation_id, payment_id, invoice_id, amount, created_at
		FROM sales.payment_allocations
		WHERE allocation_id = $1 AND payment_id = $2
	`
	row := db.QueryRowContext(ctx, query, allocationID, paymentID)
	return r.scanAllocation(row)
}

func (r *paymentRepository) GetAllocationsByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.PaymentAllocation, error) {
	query := `
		SELECT a.allocation_id, a.payment_id, a.invoice_id, a.amount, a.created_at
		FROM sales.payment_allocations a
		JOIN sales.payments p ON a.payment_id = p.payment_id
		WHERE p.company_id = $1 AND a.invoice_id = $2
		ORDER BY a.created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get allocations by invoice: %w", err)
	}
	defer rows.Close()
	var result []*models.PaymentAllocation
	for rows.Next() {
		a, err := r.scanAllocation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (r *paymentRepository) ExistsAllocation(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.payment_allocations a
			JOIN sales.payments p ON a.payment_id = p.payment_id
			WHERE p.company_id = $1 AND p.payment_id = $2 AND a.allocation_id = $3
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, paymentID, allocationID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists allocation: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Financials / Reconciliation
// -------------------------------------------------------------------------

func (r *paymentRepository) GetTotalAllocated(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `SELECT COALESCE(SUM(amount), 0) FROM sales.payment_allocations WHERE payment_id = $1`
	err := db.QueryRowContext(ctx, query, paymentID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total allocated: %w", err)
	}
	return total, nil
}

func (r *paymentRepository) GetUnallocatedAmount(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (decimal.Decimal, error) {
	payment, err := r.GetByID(ctx, db, companyID, paymentID)
	if err != nil {
		return decimal.Zero, err
	}
	allocated, err := r.GetTotalAllocated(ctx, db, companyID, paymentID)
	if err != nil {
		return decimal.Zero, err
	}
	return payment.Amount.Sub(allocated), nil
}

func (r *paymentRepository) UpdateRefundedAmount(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, refundedAmount decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payments
		SET refunded_amount = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND payment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, paymentID, refundedAmount, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update refunded amount: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *paymentRepository) GetRefundedAmount(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (decimal.Decimal, error) {
	var refunded decimal.Decimal
	query := `SELECT refunded_amount FROM sales.payments WHERE company_id = $1 AND payment_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, paymentID).Scan(&refunded)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, errors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get refunded amount: %w", err)
	}
	return refunded, nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *paymentRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, status enums.PaymentStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payments
		SET status = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND payment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, paymentID, status, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *paymentRepository) MarkProcessing(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, paymentID, enums.PaymentStatusProcessing, updatedBy)
}

func (r *paymentRepository) MarkCompleted(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, completedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payments
		SET status = 'completed', completed_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND payment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, paymentID, completedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark completed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *paymentRepository) MarkFailed(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, failureReason string, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payments
		SET status = 'failed', failure_reason = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND payment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, paymentID, failureReason, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *paymentRepository) MarkRefunded(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, refundedAmount decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payments
		SET status = 'refunded', refunded_amount = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND payment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, paymentID, refundedAmount, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark refunded: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *paymentRepository) MarkPartiallyRefunded(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID, refundedAmount decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payments
		SET status = 'partially_refunded', refunded_amount = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND payment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, paymentID, refundedAmount, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark partially refunded: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Existence / Validation
// -------------------------------------------------------------------------

func (r *paymentRepository) Exists(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payments WHERE company_id = $1 AND payment_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, paymentID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *paymentRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, paymentNumber string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payments WHERE company_id = $1 AND payment_number = $2)`
	err := db.QueryRowContext(ctx, query, companyID, paymentNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by number: %w", err)
	}
	return exists, nil
}

func (r *paymentRepository) ExistsByExternalRef(ctx context.Context, db DBTX, companyID uuid.UUID, externalRef string) (bool, error) {
	if externalRef == "" {
		return false, nil
	}
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payments WHERE company_id = $1 AND external_ref = $2 AND external_ref IS NOT NULL)`
	err := db.QueryRowContext(ctx, query, companyID, externalRef).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by external ref: %w", err)
	}
	return exists, nil
}

func (r *paymentRepository) HasAllocations(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payment_allocations WHERE payment_id = $1)`
	err := db.QueryRowContext(ctx, query, paymentID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has allocations: %w", err)
	}
	return exists, nil
}

func (r *paymentRepository) IsFullyAllocated(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (bool, error) {
	unallocated, err := r.GetUnallocatedAmount(ctx, db, companyID, paymentID)
	if err != nil {
		return false, err
	}
	return unallocated.LessThanOrEqual(decimal.Zero), nil
}

// -------------------------------------------------------------------------
// Querying / Listing
// -------------------------------------------------------------------------

func (r *paymentRepository) List(ctx context.Context, db DBTX, filter PaymentFilter, p Pagination, s Sort) ([]*models.Payment, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"payment_number": true,
		"payment_date":   true,
		"amount":         true,
		"status":         true,
		"payment_method": true,
		"created_at":     true,
		"updated_at":     true,
	}
	orderBy, err := validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY payment_date DESC"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.payments %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count payments: %w", err)
	}
	if total == 0 {
		return []*models.Payment{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list payments: %w", err)
	}
	defer rows.Close()

	var result []*models.Payment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *paymentRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Payment, int64, error) {
	pattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, pattern, pattern, pattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.payments
		WHERE company_id = $1
		AND (payment_number ILIKE $2 OR reference ILIKE $3 OR external_ref ILIKE $4)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.Payment{}, 0, nil
	}

	dataQuery := `
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		WHERE company_id = $1
		AND (payment_number ILIKE $2 OR reference ILIKE $3 OR external_ref ILIKE $4)
		ORDER BY payment_date DESC
		LIMIT $5 OFFSET $6
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()
	var result []*models.Payment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *paymentRepository) GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.Payment, error) {
	query := `
		SELECT DISTINCT p.payment_id, p.company_id, p.payment_number, p.external_ref,
			p.payment_date, p.amount, p.payment_method, p.status,
			p.exchange_rate, p.reference, p.gateway_response, p.failure_reason,
			p.completed_at, p.refunded_amount, p.created_at, p.updated_at,
			p.created_by, p.updated_by
		FROM sales.payments p
		JOIN sales.payment_allocations a ON p.payment_id = a.payment_id
		WHERE p.company_id = $1 AND a.invoice_id = $2
		ORDER BY p.payment_date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get by invoice: %w", err)
	}
	defer rows.Close()
	var result []*models.Payment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (r *paymentRepository) GetUnallocatedPayments(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Payment, error) {
	query := `
		SELECT p.payment_id, p.company_id, p.payment_number, p.external_ref,
			p.payment_date, p.amount, p.payment_method, p.status,
			p.exchange_rate, p.reference, p.gateway_response, p.failure_reason,
			p.completed_at, p.refunded_amount, p.created_at, p.updated_at,
			p.created_by, p.updated_by
		FROM sales.payments p
		WHERE p.company_id = $1
		AND p.status = 'completed'
		AND p.amount > COALESCE((SELECT SUM(amount) FROM sales.payment_allocations WHERE payment_id = p.payment_id), 0)
		ORDER BY p.payment_date
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get unallocated payments: %w", err)
	}
	defer rows.Close()
	var result []*models.Payment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (r *paymentRepository) GetFailedPayments(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Payment, error) {
	query := `
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		WHERE company_id = $1 AND status = 'failed'
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get failed payments: %w", err)
	}
	defer rows.Close()
	var result []*models.Payment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Analytics / Reporting
// -------------------------------------------------------------------------

func (r *paymentRepository) GetCollectedAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status = 'completed'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("payment_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("payment_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(amount), 0) FROM sales.payments %s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get collected amount: %w", err)
	}
	return total, nil
}

func (r *paymentRepository) GetRefundedAmountTotal(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status IN ('refunded', 'partially_refunded')")
	if from != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(refunded_amount), 0) FROM sales.payments %s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get refunded total: %w", err)
	}
	return total, nil
}

func (r *paymentRepository) GetPaymentMethodBreakdown(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (map[enums.PaymentMethod]decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status = 'completed'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("payment_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("payment_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT payment_method, COALESCE(SUM(amount), 0)
		FROM sales.payments
		%s
		GROUP BY payment_method
	`, where)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("payment method breakdown: %w", err)
	}
	defer rows.Close()
	result := make(map[enums.PaymentMethod]decimal.Decimal)
	for rows.Next() {
		var methodStr string
		var total decimal.Decimal
		if err := rows.Scan(&methodStr, &total); err != nil {
			return nil, err
		}
		result[enums.PaymentMethod(methodStr)] = total
	}
	return result, rows.Err()
}

func (r *paymentRepository) GetTopPayments(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Payment, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	if from != nil {
		conds = append(conds, fmt.Sprintf("payment_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("payment_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		%s
		ORDER BY amount DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top payments: %w", err)
	}
	defer rows.Close()
	var result []*models.Payment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / Locking
// -------------------------------------------------------------------------

func (r *paymentRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, paymentID uuid.UUID) (*models.Payment, error) {
	query := `
		SELECT
			payment_id, company_id, payment_number, external_ref,
			payment_date, amount, payment_method, status,
			exchange_rate, reference, gateway_response, failure_reason,
			completed_at, refunded_amount, created_at, updated_at,
			created_by, updated_by
		FROM sales.payments
		WHERE company_id = $1 AND payment_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, paymentID)
	return r.scanPayment(row)
}

func (r *paymentRepository) GetAllocationByIDForUpdate(ctx context.Context, db DBTX, companyID, paymentID, allocationID uuid.UUID) (*models.PaymentAllocation, error) {
	query := `
		SELECT a.allocation_id, a.payment_id, a.invoice_id, a.amount, a.created_at
		FROM sales.payment_allocations a
		JOIN sales.payments p ON a.payment_id = p.payment_id
		WHERE p.company_id = $1 AND p.payment_id = $2 AND a.allocation_id = $3
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, paymentID, allocationID)
	return r.scanAllocation(row)
}
