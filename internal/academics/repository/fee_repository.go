// File: repository/fee_repository.go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// FeeRepository defines all operations for fee management.
type FeeRepository interface {
	// Fee Structures
	CreateFeeStructure(ctx context.Context, db DBTX, fs *models.FeeStructure) error
	GetFeeStructureByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.FeeStructure, error)
	ListFeeStructures(ctx context.Context, db DBTX, filter FeeStructureFilter, p Pagination, s Sort) ([]*models.FeeStructure, error)
	CountFeeStructures(ctx context.Context, db DBTX, filter FeeStructureFilter) (int64, error)
	UpdateFeeStructure(ctx context.Context, db DBTX, fs *models.FeeStructure) error
	DeleteFeeStructure(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Fee Structure Items
	AddFeeStructureItem(ctx context.Context, db DBTX, item *models.FeeStructureItem) error
	GetFeeStructureItems(ctx context.Context, db DBTX, feeStructureID uuid.UUID) ([]*models.FeeStructureItem, error)
	UpdateFeeStructureItem(ctx context.Context, db DBTX, item *models.FeeStructureItem) error
	DeleteFeeStructureItem(ctx context.Context, db DBTX, itemID uuid.UUID) error

	// Invoices
	CreateInvoice(ctx context.Context, db DBTX, inv *models.StudentFeeInvoice, items []*models.StudentFeeInvoiceItem) error
	GetInvoiceByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentFeeInvoice, error)
	GetInvoiceByNumber(ctx context.Context, db DBTX, invoiceNo string) (*models.StudentFeeInvoice, error)
	ListInvoices(ctx context.Context, db DBTX, filter InvoiceFilter, p Pagination, s Sort) ([]*models.StudentFeeInvoice, error)
	CountInvoices(ctx context.Context, db DBTX, filter InvoiceFilter) (int64, error)
	UpdateInvoiceStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	UpdateInvoicePaidAmount(ctx context.Context, db DBTX, id uuid.UUID, newPaidAmount float64) error

	// Payments
	CreatePayment(ctx context.Context, db DBTX, payment *models.StudentFeePayment) error
	GetPaymentByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentFeePayment, error)
	GetPaymentsByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*models.StudentFeePayment, error)
	ListPayments(ctx context.Context, db DBTX, filter PaymentFilter, p Pagination, s Sort) ([]*models.StudentFeePayment, error)
	CountPayments(ctx context.Context, db DBTX, filter PaymentFilter) (int64, error)
	UpdatePayment(ctx context.Context, db DBTX, payment *models.StudentFeePayment) error
	GetFeeStructureItemByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.FeeStructureItem, error)
	GetPenaltyByID(ctx context.Context, db DBTX, penaltyID uuid.UUID) (*models.FeePenalty, error)

	// Discounts
	CreateDiscount(ctx context.Context, db DBTX, discount *models.FeeDiscount) error
	GetDiscountByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.FeeDiscount, error)
	GetActiveDiscountsForStudent(ctx context.Context, db DBTX, studentID uuid.UUID, asOfDate time.Time) ([]*models.FeeDiscount, error)
	UpdateDiscount(ctx context.Context, db DBTX, discount *models.FeeDiscount) error
	DeleteDiscount(ctx context.Context, db DBTX, id uuid.UUID) error

	// Penalties
	CreatePenalty(ctx context.Context, db DBTX, penalty *models.FeePenalty) error
	GetPenaltiesByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*models.FeePenalty, error)
	UpdatePenalty(ctx context.Context, db DBTX, penalty *models.FeePenalty) error

	// Receipts
	CreateReceipt(ctx context.Context, db DBTX, receipt *models.FeeReceipt) error
	GetReceiptByPaymentID(ctx context.Context, db DBTX, paymentID uuid.UUID) (*models.FeeReceipt, error)
	GetReceiptByNumber(ctx context.Context, db DBTX, receiptNo string) (*models.FeeReceipt, error)

	// Audit (optional)
	LogAudit(ctx context.Context, db DBTX, audit *models.FeeTransactionAudit) error
}

type feeRepository struct {
	logger *zap.Logger
}

func NewFeeRepository(logger *zap.Logger) FeeRepository {
	return &feeRepository{
		logger: logger.Named("fee_repo"),
	}
}

// Helper for pagination
func (r *feeRepository) validatePagination(p Pagination) (int, int) {
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

// --- Fee Structures -----------------------------------------------------

func (r *feeRepository) CreateFeeStructure(ctx context.Context, db DBTX, fs *models.FeeStructure) error {
	query := `
        INSERT INTO academics.fee_structures (
            academic_year_id, course_id, section_id, fee_structure_name, total_amount, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING fee_structure_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		fs.AcademicYearID, fs.CourseID, fs.SectionID, fs.FeeStructureName, fs.TotalAmount, fs.IsActive,
		fs.CreatedBy, fs.UpdatedBy,
	).Scan(&fs.FeeStructureID, &fs.CreatedAt, &fs.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create fee structure", util.ErrorField(err))
		return fmt.Errorf("create fee structure: %w", err)
	}
	return nil
}

func (r *feeRepository) GetFeeStructureByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.FeeStructure, error) {
	query := `
        SELECT fee_structure_id, academic_year_id, course_id, section_id, fee_structure_name, total_amount, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.fee_structures
        WHERE fee_structure_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanFeeStructure(row)
}

func (r *feeRepository) ListFeeStructures(ctx context.Context, db DBTX, filter FeeStructureFilter, p Pagination, s Sort) ([]*models.FeeStructure, error) {
	where, args := r.buildFeeStructureFilter(filter)
	orderBy := r.validateFeeStructureSort(s)
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT fee_structure_id, academic_year_id, course_id, section_id, fee_structure_name, total_amount, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.fee_structures
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list fee structures", util.ErrorField(err))
		return nil, fmt.Errorf("list fee structures: %w", err)
	}
	defer rows.Close()

	var result []*models.FeeStructure
	for rows.Next() {
		fs, err := r.scanFeeStructure(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, fs)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *feeRepository) CountFeeStructures(ctx context.Context, db DBTX, filter FeeStructureFilter) (int64, error) {
	where, args := r.buildFeeStructureFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.fee_structures %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count fee structures", util.ErrorField(err))
		return 0, fmt.Errorf("count fee structures: %w", err)
	}
	return count, nil
}

func (r *feeRepository) UpdateFeeStructure(ctx context.Context, db DBTX, fs *models.FeeStructure) error {
	query := `
        UPDATE academics.fee_structures
        SET academic_year_id = $2, course_id = $3, section_id = $4, fee_structure_name = $5,
            total_amount = $6, is_active = $7, updated_by = $8, updated_at = NOW()
        WHERE fee_structure_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		fs.FeeStructureID, fs.AcademicYearID, fs.CourseID, fs.SectionID, fs.FeeStructureName,
		fs.TotalAmount, fs.IsActive, fs.UpdatedBy,
	).Scan(&fs.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: fee structure %s", ErrNotFound, fs.FeeStructureID)
		}
		r.logger.Error("failed to update fee structure", util.ErrorField(err))
		return fmt.Errorf("update fee structure: %w", err)
	}
	return nil
}

func (r *feeRepository) DeleteFeeStructure(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.fee_structures SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE fee_structure_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete fee structure", util.ErrorField(err))
		return fmt.Errorf("delete fee structure: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("fee structure %s not found or already deleted", id)
	}
	return nil
}

// --- Fee Structure Items ------------------------------------------------

func (r *feeRepository) AddFeeStructureItem(ctx context.Context, db DBTX, item *models.FeeStructureItem) error {
	query := `
        INSERT INTO academics.fee_structure_items (
            fee_structure_id, fee_head, amount, is_mandatory, description, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        RETURNING item_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		item.FeeStructureID, item.FeeHead, item.Amount, item.IsMandatory, item.Description, item.CreatedBy,
	).Scan(&item.ItemID, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add fee structure item", util.ErrorField(err))
		return fmt.Errorf("add fee structure item: %w", err)
	}
	return nil
}

func (r *feeRepository) GetFeeStructureItems(ctx context.Context, db DBTX, feeStructureID uuid.UUID) ([]*models.FeeStructureItem, error) {
	query := `
        SELECT item_id, fee_structure_id, fee_head, amount, is_mandatory, description,
               created_at, updated_at, created_by
        FROM academics.fee_structure_items
        WHERE fee_structure_id = $1
    `
	rows, err := db.QueryContext(ctx, query, feeStructureID)
	if err != nil {
		return nil, fmt.Errorf("get fee structure items: %w", err)
	}
	defer rows.Close()

	var items []*models.FeeStructureItem
	for rows.Next() {
		item := &models.FeeStructureItem{}
		var createdBy uuid.NullUUID
		if err := rows.Scan(
			&item.ItemID, &item.FeeStructureID, &item.FeeHead, &item.Amount,
			&item.IsMandatory, &item.Description, &item.CreatedAt, &item.UpdatedAt, &createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		if createdBy.Valid {
			item.CreatedBy = &createdBy.UUID
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return items, nil
}

func (r *feeRepository) UpdateFeeStructureItem(ctx context.Context, db DBTX, item *models.FeeStructureItem) error {
	query := `
        UPDATE academics.fee_structure_items
        SET fee_head = $2, amount = $3, is_mandatory = $4, description = $5, updated_at = NOW()
        WHERE item_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		item.ItemID, item.FeeHead, item.Amount, item.IsMandatory, item.Description,
	).Scan(&item.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: fee structure item %s", ErrNotFound, item.ItemID)
		}
		return fmt.Errorf("update fee structure item: %w", err)
	}
	return nil
}

func (r *feeRepository) DeleteFeeStructureItem(ctx context.Context, db DBTX, itemID uuid.UUID) error {
	query := `DELETE FROM academics.fee_structure_items WHERE item_id = $1`
	result, err := db.ExecContext(ctx, query, itemID)
	if err != nil {
		return fmt.Errorf("delete fee structure item: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("fee structure item %s not found", itemID)
	}
	return nil
}

// --- Invoices -----------------------------------------------------------

func (r *feeRepository) CreateInvoice(ctx context.Context, db DBTX, inv *models.StudentFeeInvoice, items []*models.StudentFeeInvoiceItem) error {
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

	// Insert invoice
	invQuery := `
        INSERT INTO academics.student_fee_invoices (
            student_id, fee_structure_id, invoice_no, due_date, total_amount, paid_amount, status,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING invoice_id, created_at, updated_at
    `
	err = tx.QueryRowContext(ctx, invQuery,
		inv.StudentID, inv.FeeStructureID, inv.InvoiceNo, inv.DueDate, inv.TotalAmount, inv.PaidAmount, inv.Status,
		inv.CreatedBy,
	).Scan(&inv.InvoiceID, &inv.CreatedAt, &inv.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create invoice: %w", err)
	}

	// Insert invoice items
	if len(items) > 0 {
		itemQuery := `
            INSERT INTO academics.student_fee_invoice_items (
                invoice_id, fee_head, amount, is_mandatory, created_by, created_at
            ) VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING invoice_item_id, created_at
        `
		for _, item := range items {
			item.InvoiceID = inv.InvoiceID
			err = tx.QueryRowContext(ctx, itemQuery,
				item.InvoiceID, item.FeeHead, item.Amount, item.IsMandatory, item.CreatedBy,
			).Scan(&item.InvoiceItemID, &item.CreatedAt)
			if err != nil {
				return fmt.Errorf("create invoice item: %w", err)
			}
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

func (r *feeRepository) GetInvoiceByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentFeeInvoice, error) {
	query := `
        SELECT invoice_id, student_id, fee_structure_id, invoice_no, due_date, total_amount, paid_amount, balance, status,
               created_at, updated_at, created_by
        FROM academics.student_fee_invoices
        WHERE invoice_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanInvoice(row)
}

func (r *feeRepository) GetInvoiceByNumber(ctx context.Context, db DBTX, invoiceNo string) (*models.StudentFeeInvoice, error) {
	query := `
        SELECT invoice_id, student_id, fee_structure_id, invoice_no, due_date, total_amount, paid_amount, balance, status,
               created_at, updated_at, created_by
        FROM academics.student_fee_invoices
        WHERE invoice_no = $1
    `
	row := db.QueryRowContext(ctx, query, invoiceNo)
	return r.scanInvoice(row)
}

func (r *feeRepository) ListInvoices(ctx context.Context, db DBTX, filter InvoiceFilter, p Pagination, s Sort) ([]*models.StudentFeeInvoice, error) {
	where, args := r.buildInvoiceFilter(filter)
	orderBy := r.validateInvoiceSort(s)
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT invoice_id, student_id, fee_structure_id, invoice_no, due_date, total_amount, paid_amount, balance, status,
               created_at, updated_at, created_by
        FROM academics.student_fee_invoices
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list invoices: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentFeeInvoice
	for rows.Next() {
		inv, err := r.scanInvoice(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, inv)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *feeRepository) CountInvoices(ctx context.Context, db DBTX, filter InvoiceFilter) (int64, error) {
	where, args := r.buildInvoiceFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_fee_invoices %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count invoices: %w", err)
	}
	return count, nil
}

func (r *feeRepository) UpdateInvoiceStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	// updated_by column does not exist in student_fee_invoices table – removed from query
	query := `UPDATE academics.student_fee_invoices SET status = $2, updated_at = NOW() WHERE invoice_id = $1`
	result, err := db.ExecContext(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("update invoice status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {

		return fmt.Errorf("invoice %s not found", id)
	}
	return nil
}

func (r *feeRepository) UpdateInvoicePaidAmount(ctx context.Context, db DBTX, id uuid.UUID, newPaidAmount float64) error {
	query := `UPDATE academics.student_fee_invoices SET paid_amount = $2, updated_at = NOW() WHERE invoice_id = $1`
	result, err := db.ExecContext(ctx, query, id, newPaidAmount)
	if err != nil {
		return fmt.Errorf("update invoice paid amount: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("invoice %s not found", id)
	}
	return nil
}

// --- Payments -----------------------------------------------------------

func (r *feeRepository) CreatePayment(ctx context.Context, db DBTX, payment *models.StudentFeePayment) error {
	query := `
        INSERT INTO academics.student_fee_payments (
            invoice_id, payment_date, amount, payment_mode, transaction_id, receipt_no, remarks,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING payment_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		payment.InvoiceID, payment.PaymentDate, payment.Amount, payment.PaymentMode,
		payment.TransactionID, payment.ReceiptNo, payment.Remarks, payment.CreatedBy,
	).Scan(&payment.PaymentID, &payment.CreatedAt, &payment.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create payment: %w", err)
	}
	return nil
}

func (r *feeRepository) GetPaymentByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentFeePayment, error) {
	query := `
        SELECT payment_id, invoice_id, payment_date, amount, payment_mode, transaction_id, receipt_no, remarks,
               created_at, updated_at, created_by
        FROM academics.student_fee_payments
        WHERE payment_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanPayment(row)
}

func (r *feeRepository) GetPaymentsByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*models.StudentFeePayment, error) {
	query := `
        SELECT payment_id, invoice_id, payment_date, amount, payment_mode, transaction_id, receipt_no, remarks,
               created_at, updated_at, created_by
        FROM academics.student_fee_payments
        WHERE invoice_id = $1
        ORDER BY payment_date DESC
    `
	rows, err := db.QueryContext(ctx, query, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get payments by invoice: %w", err)
	}
	defer rows.Close()

	var payments []*models.StudentFeePayment
	for rows.Next() {
		p, err := r.scanPayment(rows)
		if err != nil {
			return nil, err
		}
		payments = append(payments, p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return payments, nil
}

func (r *feeRepository) ListPayments(ctx context.Context, db DBTX, filter PaymentFilter, p Pagination, s Sort) ([]*models.StudentFeePayment, error) {
	where, args := r.buildPaymentFilter(filter)
	orderBy := r.validatePaymentSort(s)
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT payment_id, invoice_id, payment_date, amount, payment_mode, transaction_id, receipt_no, remarks,
               created_at, updated_at, created_by
        FROM academics.student_fee_payments
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list payments: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentFeePayment
	for rows.Next() {
		p, err := r.scanPayment(rows)
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

func (r *feeRepository) CountPayments(ctx context.Context, db DBTX, filter PaymentFilter) (int64, error) {
	where, args := r.buildPaymentFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_fee_payments %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count payments: %w", err)
	}
	return count, nil
}

func (r *feeRepository) UpdatePayment(ctx context.Context, db DBTX, payment *models.StudentFeePayment) error {
	query := `
        UPDATE academics.student_fee_payments
        SET payment_date = $2, amount = $3, payment_mode = $4, transaction_id = $5, receipt_no = $6, remarks = $7,
            updated_by = $8, updated_at = NOW()
        WHERE payment_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		payment.PaymentID, payment.PaymentDate, payment.Amount, payment.PaymentMode,
		payment.TransactionID, payment.ReceiptNo, payment.Remarks, payment.CreatedBy,
	).Scan(&payment.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: payment %s", ErrNotFound, payment.PaymentID)
		}
		return fmt.Errorf("update payment: %w", err)
	}
	return nil
}

// --- Discounts ----------------------------------------------------------

func (r *feeRepository) CreateDiscount(ctx context.Context, db DBTX, discount *models.FeeDiscount) error {
	query := `
        INSERT INTO academics.fee_discounts (
            student_id, discount_type, discount_value, reason, approved_by, valid_from, valid_until,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING discount_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		discount.StudentID, discount.DiscountType, discount.DiscountValue, discount.Reason,
		discount.ApprovedBy, discount.ValidFrom, discount.ValidUntil, discount.CreatedBy,
	).Scan(&discount.DiscountID, &discount.CreatedAt, &discount.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create discount: %w", err)
	}
	return nil
}

func (r *feeRepository) GetDiscountByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.FeeDiscount, error) {
	query := `
        SELECT discount_id, student_id, discount_type, discount_value, reason, approved_by, valid_from, valid_until,
               created_at, updated_at, created_by
        FROM academics.fee_discounts
        WHERE discount_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanDiscount(row)
}

func (r *feeRepository) GetActiveDiscountsForStudent(ctx context.Context, db DBTX, studentID uuid.UUID, asOfDate time.Time) ([]*models.FeeDiscount, error) {
	query := `
        SELECT discount_id, student_id, discount_type, discount_value, reason, approved_by, valid_from, valid_until,
               created_at, updated_at, created_by
        FROM academics.fee_discounts
        WHERE student_id = $1
          AND (valid_from IS NULL OR valid_from <= $2)
          AND (valid_until IS NULL OR valid_until >= $2)
    `
	rows, err := db.QueryContext(ctx, query, studentID, asOfDate)
	if err != nil {
		return nil, fmt.Errorf("get active discounts: %w", err)
	}
	defer rows.Close()

	var discounts []*models.FeeDiscount
	for rows.Next() {
		d, err := r.scanDiscount(rows)
		if err != nil {
			return nil, err
		}
		discounts = append(discounts, d)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return discounts, nil
}

func (r *feeRepository) UpdateDiscount(ctx context.Context, db DBTX, discount *models.FeeDiscount) error {
	query := `
        UPDATE academics.fee_discounts
        SET discount_type = $2, discount_value = $3, reason = $4, approved_by = $5,
            valid_from = $6, valid_until = $7, updated_at = NOW()
        WHERE discount_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		discount.DiscountID, discount.DiscountType, discount.DiscountValue, discount.Reason,
		discount.ApprovedBy, discount.ValidFrom, discount.ValidUntil,
	).Scan(&discount.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: discount %s", ErrNotFound, discount.DiscountID)
		}
		return fmt.Errorf("update discount: %w", err)
	}
	return nil
}

func (r *feeRepository) DeleteDiscount(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.fee_discounts WHERE discount_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete discount: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("discount %s not found", id)
	}
	return nil
}

// --- Penalties ----------------------------------------------------------

func (r *feeRepository) CreatePenalty(ctx context.Context, db DBTX, penalty *models.FeePenalty) error {
	query := `
        INSERT INTO academics.fee_penalties (
            invoice_id, penalty_date, amount, reason, waived, waived_by, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING penalty_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		penalty.InvoiceID, penalty.PenaltyDate, penalty.Amount, penalty.Reason,
		penalty.Waived, penalty.WaivedBy, penalty.CreatedBy,
	).Scan(&penalty.PenaltyID, &penalty.CreatedAt, &penalty.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create penalty: %w", err)
	}
	return nil
}

func (r *feeRepository) GetPenaltiesByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*models.FeePenalty, error) {
	query := `
        SELECT penalty_id, invoice_id, penalty_date, amount, reason, waived, waived_by,
               created_at, updated_at, created_by
        FROM academics.fee_penalties
        WHERE invoice_id = $1
    `
	rows, err := db.QueryContext(ctx, query, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get penalties by invoice: %w", err)
	}
	defer rows.Close()

	var penalties []*models.FeePenalty
	for rows.Next() {
		p, err := r.scanPenalty(rows)
		if err != nil {
			return nil, err
		}
		penalties = append(penalties, p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return penalties, nil
}

func (r *feeRepository) UpdatePenalty(ctx context.Context, db DBTX, penalty *models.FeePenalty) error {
	query := `
        UPDATE academics.fee_penalties
        SET penalty_date = $2, amount = $3, reason = $4, waived = $5, waived_by = $6,
            updated_at = NOW()
        WHERE penalty_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		penalty.PenaltyID, penalty.PenaltyDate, penalty.Amount, penalty.Reason,
		penalty.Waived, penalty.WaivedBy,
	).Scan(&penalty.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: penalty %s", ErrNotFound, penalty.PenaltyID)
		}
		return fmt.Errorf("update penalty: %w", err)
	}
	return nil
}

// --- Receipts -----------------------------------------------------------

func (r *feeRepository) CreateReceipt(ctx context.Context, db DBTX, receipt *models.FeeReceipt) error {
	// Marshal receipt data to JSON
	receiptDataJSON, err := json.Marshal(receipt.ReceiptData)
	if err != nil {
		return fmt.Errorf("marshal receipt data: %w", err)
	}

	query := `
        INSERT INTO academics.fee_receipts (
            payment_id, receipt_no, receipt_data, generated_at, created_by, created_at
        ) VALUES ($1, $2, $3, NOW(), $4, NOW())
        RETURNING receipt_id, generated_at, created_at
    `
	err = db.QueryRowContext(ctx, query,
		receipt.PaymentID, receipt.ReceiptNo, receiptDataJSON, receipt.CreatedBy,
	).Scan(&receipt.ReceiptID, &receipt.GeneratedAt, &receipt.CreatedAt)
	if err != nil {
		return fmt.Errorf("create receipt: %w", err)
	}
	return nil
}
func (r *feeRepository) GetReceiptByPaymentID(ctx context.Context, db DBTX, paymentID uuid.UUID) (*models.FeeReceipt, error) {
	query := `
        SELECT receipt_id, payment_id, receipt_no, receipt_data, generated_at, created_at, created_by
        FROM academics.fee_receipts
        WHERE payment_id = $1
    `
	row := db.QueryRowContext(ctx, query, paymentID)
	return r.scanReceipt(row)
}

func (r *feeRepository) GetReceiptByNumber(ctx context.Context, db DBTX, receiptNo string) (*models.FeeReceipt, error) {
	query := `
        SELECT receipt_id, payment_id, receipt_no, receipt_data, generated_at, created_at, created_by
        FROM academics.fee_receipts
        WHERE receipt_no = $1
    `
	row := db.QueryRowContext(ctx, query, receiptNo)
	return r.scanReceipt(row)
}

// --- Audit --------------------------------------------------------------

func (r *feeRepository) LogAudit(ctx context.Context, db DBTX, audit *models.FeeTransactionAudit) error {
	query := `
        INSERT INTO academics.fee_transaction_audit (
            payment_id, action, old_data, new_data, changed_by, changed_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        RETURNING audit_id, changed_at
    `
	err := db.QueryRowContext(ctx, query,
		audit.PaymentID, audit.Action, audit.OldData, audit.NewData, audit.ChangedBy,
	).Scan(&audit.AuditID, &audit.ChangedAt)
	if err != nil {
		return fmt.Errorf("log audit: %w", err)
	}
	return nil
}

// --- Internal Filter Builders -------------------------------------------

func (r *feeRepository) buildFeeStructureFilter(filter FeeStructureFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.AcademicYearID != nil {
		conditions = append(conditions, fmt.Sprintf("academic_year_id = $%d", idx))
		args = append(args, *filter.AcademicYearID)
		idx++
	}
	if filter.CourseID != nil {
		conditions = append(conditions, fmt.Sprintf("course_id = $%d", idx))
		args = append(args, *filter.CourseID)
		idx++
	}
	if filter.SectionID != nil {
		conditions = append(conditions, fmt.Sprintf("section_id = $%d", idx))
		args = append(args, *filter.SectionID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("fee_structure_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *feeRepository) buildInvoiceFilter(filter InvoiceFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}
	if filter.FeeStructureID != nil {
		conditions = append(conditions, fmt.Sprintf("fee_structure_id = $%d", idx))
		args = append(args, *filter.FeeStructureID)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.DueDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("due_date >= $%d", idx))
		args = append(args, *filter.DueDateFrom)
		idx++
	}
	if filter.DueDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("due_date <= $%d", idx))
		args = append(args, *filter.DueDateTo)
		idx++
	}
	if filter.InvoiceNo != "" {
		conditions = append(conditions, fmt.Sprintf("invoice_no = $%d", idx))
		args = append(args, filter.InvoiceNo)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *feeRepository) buildPaymentFilter(filter PaymentFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.InvoiceID != nil {
		conditions = append(conditions, fmt.Sprintf("invoice_id = $%d", idx))
		args = append(args, *filter.InvoiceID)
		idx++
	}
	if filter.StudentID != nil {
		// Need to join with invoices to filter by student
		conditions = append(conditions, fmt.Sprintf("invoice_id IN (SELECT invoice_id FROM academics.student_fee_invoices WHERE student_id = $%d)", idx))
		args = append(args, *filter.StudentID)
		idx++
	}
	if filter.PaymentDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("payment_date >= $%d", idx))
		args = append(args, *filter.PaymentDateFrom)
		idx++
	}
	if filter.PaymentDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("payment_date <= $%d", idx))
		args = append(args, *filter.PaymentDateTo)
		idx++
	}
	if filter.PaymentMode != nil {
		conditions = append(conditions, fmt.Sprintf("payment_mode = $%d", idx))
		args = append(args, *filter.PaymentMode)
		idx++
	}
	if filter.ReceiptNo != "" {
		conditions = append(conditions, fmt.Sprintf("receipt_no = $%d", idx))
		args = append(args, filter.ReceiptNo)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// --- Validation Helpers for Sort ----------------------------------------

func (r *feeRepository) validateFeeStructureSort(s Sort) string {
	allowed := map[string]bool{
		"fee_structure_id": true, "academic_year_id": true, "course_id": true,
		"section_id": true, "fee_structure_name": true, "total_amount": true,
		"is_active": true, "created_at": true,
	}
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowed[field] {
		field = "created_at"
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir)
}

func (r *feeRepository) validateInvoiceSort(s Sort) string {
	allowed := map[string]bool{
		"invoice_id": true, "student_id": true, "invoice_no": true,
		"due_date": true, "total_amount": true, "paid_amount": true,
		"balance": true, "status": true, "created_at": true,
	}
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowed[field] {
		field = "created_at"
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir)
}

func (r *feeRepository) validatePaymentSort(s Sort) string {
	allowed := map[string]bool{
		"payment_id": true, "invoice_id": true, "payment_date": true,
		"amount": true, "payment_mode": true, "receipt_no": true,
		"created_at": true,
	}
	field := s.Field
	if field == "" {
		field = "payment_date"
	}
	if !allowed[field] {
		field = "payment_date"
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir)
}

// --- Scanner Helpers ----------------------------------------------------

func (r *feeRepository) scanFeeStructure(row scanner) (*models.FeeStructure, error) {
	var fs models.FeeStructure
	var sectionID, createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&fs.FeeStructureID,
		&fs.AcademicYearID,
		&fs.CourseID,
		&sectionID,
		&fs.FeeStructureName,
		&fs.TotalAmount,
		&fs.IsActive,
		&fs.CreatedAt,
		&fs.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan fee structure: %w", err)
	}
	if sectionID.Valid {
		fs.SectionID = &sectionID.UUID
	}
	if createdBy.Valid {
		fs.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		fs.UpdatedBy = &updatedBy.UUID
	}
	return &fs, nil
}

func (r *feeRepository) scanInvoice(row scanner) (*models.StudentFeeInvoice, error) {
	var inv models.StudentFeeInvoice
	var createdBy uuid.NullUUID

	err := row.Scan(
		&inv.InvoiceID,
		&inv.StudentID,
		&inv.FeeStructureID,
		&inv.InvoiceNo,
		&inv.DueDate,
		&inv.TotalAmount,
		&inv.PaidAmount,
		&inv.Balance,
		&inv.Status,
		&inv.CreatedAt,
		&inv.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan invoice: %w", err)
	}
	if createdBy.Valid {
		inv.CreatedBy = &createdBy.UUID
	}
	return &inv, nil
}

func (r *feeRepository) scanPayment(row scanner) (*models.StudentFeePayment, error) {
	var p models.StudentFeePayment
	var createdBy uuid.NullUUID

	err := row.Scan(
		&p.PaymentID,
		&p.InvoiceID,
		&p.PaymentDate,
		&p.Amount,
		&p.PaymentMode,
		&p.TransactionID,
		&p.ReceiptNo,
		&p.Remarks,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan payment: %w", err)
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	return &p, nil
}

func (r *feeRepository) scanDiscount(row scanner) (*models.FeeDiscount, error) {
	var d models.FeeDiscount
	var approvedBy, createdBy uuid.NullUUID
	var validFrom, validUntil sql.NullTime

	err := row.Scan(
		&d.DiscountID,
		&d.StudentID,
		&d.DiscountType,
		&d.DiscountValue,
		&d.Reason,
		&approvedBy,
		&validFrom,
		&validUntil,
		&d.CreatedAt,
		&d.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan discount: %w", err)
	}
	if approvedBy.Valid {
		d.ApprovedBy = &approvedBy.UUID
	}
	if validFrom.Valid {
		d.ValidFrom = &validFrom.Time
	}
	if validUntil.Valid {
		d.ValidUntil = &validUntil.Time
	}
	if createdBy.Valid {
		d.CreatedBy = &createdBy.UUID
	}
	return &d, nil
}

func (r *feeRepository) scanPenalty(row scanner) (*models.FeePenalty, error) {
	var p models.FeePenalty
	var waivedBy, createdBy uuid.NullUUID

	err := row.Scan(
		&p.PenaltyID,
		&p.InvoiceID,
		&p.PenaltyDate,
		&p.Amount,
		&p.Reason,
		&p.Waived,
		&waivedBy,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan penalty: %w", err)
	}
	if waivedBy.Valid {
		p.WaivedBy = &waivedBy.UUID
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	return &p, nil
}

func (r *feeRepository) scanReceipt(row scanner) (*models.FeeReceipt, error) {
	var rec models.FeeReceipt
	var createdBy uuid.NullUUID
	var receiptDataJSON []byte

	err := row.Scan(
		&rec.ReceiptID,
		&rec.PaymentID,
		&rec.ReceiptNo,
		&receiptDataJSON,
		&rec.GeneratedAt,
		&rec.CreatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan receipt: %w", err)
	}

	if createdBy.Valid {
		rec.CreatedBy = &createdBy.UUID
	}

	// Unmarshal JSONB data into the map
	if len(receiptDataJSON) > 0 {
		if err := json.Unmarshal(receiptDataJSON, &rec.ReceiptData); err != nil {
			return nil, fmt.Errorf("unmarshal receipt_data: %w", err)
		}
	} else {
		rec.ReceiptData = make(map[string]interface{})
	}

	return &rec, nil
}

func (r *feeRepository) GetFeeStructureItemByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.FeeStructureItem, error) {
	query := `
		SELECT item_id, fee_structure_id, fee_head, amount, is_mandatory, description,
		       created_at, updated_at, created_by
		FROM academics.fee_structure_items
		WHERE item_id = $1
	`
	row := db.QueryRowContext(ctx, query, itemID)
	return r.scanFeeStructureItem(row)
}

// Helper: scan a single FeeStructureItem from a *sql.Row.
func (r *feeRepository) scanFeeStructureItem(row scanner) (*models.FeeStructureItem, error) {
	var item models.FeeStructureItem
	var createdBy uuid.NullUUID
	err := row.Scan(
		&item.ItemID,
		&item.FeeStructureID,
		&item.FeeHead,
		&item.Amount,
		&item.IsMandatory,
		&item.Description,
		&item.CreatedAt,
		&item.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan fee structure item: %w", err)
	}
	if createdBy.Valid {
		item.CreatedBy = &createdBy.UUID
	}
	return &item, nil
}
func (r *feeRepository) GetPenaltyByID(ctx context.Context, db DBTX, penaltyID uuid.UUID) (*models.FeePenalty, error) {
	query := `
		SELECT penalty_id, invoice_id, penalty_date, amount, reason, waived, waived_by,
		       created_at, updated_at, created_by
		FROM academics.fee_penalties
		WHERE penalty_id = $1
	`
	row := db.QueryRowContext(ctx, query, penaltyID)
	return r.scanPenalty(row)
}
