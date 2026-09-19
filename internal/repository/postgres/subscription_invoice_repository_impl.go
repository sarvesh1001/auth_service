package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

// Ensure SubscriptionInvoiceRepositoryImpl implements the interface.
var _ SubscriptionInvoiceRepository = (*SubscriptionInvoiceRepositoryImpl)(nil)

type SubscriptionInvoiceRepositoryImpl struct {
	client *client.PostgresClient
}

func NewSubscriptionInvoiceRepository(pgClient *client.PostgresClient) *SubscriptionInvoiceRepositoryImpl {
	return &SubscriptionInvoiceRepositoryImpl{client: pgClient}
}

// ---------- Create ----------
func (r *SubscriptionInvoiceRepositoryImpl) Create(ctx context.Context, invoice *models.SubscriptionInvoice) error {
	query := `
		INSERT INTO subscription_invoices (
			invoice_id, company_id, invoice_number, invoice_date, due_date,
			currency, subtotal, tax_total, discount_total, grand_total,
			status, notes, issued_at, paid_at, cancelled_at,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := r.client.Exec(ctx, query,
		invoice.InvoiceID,
		invoice.CompanyID,
		invoice.InvoiceNumber,
		invoice.InvoiceDate,
		invoice.DueDate,
		invoice.Currency,
		invoice.Subtotal,
		invoice.TaxTotal,
		invoice.DiscountTotal,
		invoice.GrandTotal,
		invoice.Status,
		invoice.Notes,
		invoice.IssuedAt,
		invoice.PaidAt,
		invoice.CancelledAt,
		invoice.CreatedAt,
		invoice.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			// Unique violation (company_id, invoice_number)
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to create subscription invoice: %w", err)
	}
	return nil
}

// ---------- GetByID ----------
func (r *SubscriptionInvoiceRepositoryImpl) GetByID(ctx context.Context, invoiceID uuid.UUID) (*models.SubscriptionInvoice, error) {
	query := `
		SELECT invoice_id, company_id, invoice_number, invoice_date, due_date,
			currency, subtotal, tax_total, discount_total, grand_total,
			status, notes, issued_at, paid_at, cancelled_at,
			created_at, updated_at, deleted_at
		FROM subscription_invoices
		WHERE invoice_id = $1 AND deleted_at IS NULL
	`
	var inv models.SubscriptionInvoice
	var deletedAt sql.NullTime

	err := r.client.QueryRow(ctx, query, invoiceID).Scan(
		&inv.InvoiceID,
		&inv.CompanyID,
		&inv.InvoiceNumber,
		&inv.InvoiceDate,
		&inv.DueDate,
		&inv.Currency,
		&inv.Subtotal,
		&inv.TaxTotal,
		&inv.DiscountTotal,
		&inv.GrandTotal,
		&inv.Status,
		&inv.Notes,
		&inv.IssuedAt,
		&inv.PaidAt,
		&inv.CancelledAt,
		&inv.CreatedAt,
		&inv.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get invoice by ID: %w", err)
	}
	if deletedAt.Valid {
		inv.DeletedAt = &deletedAt.Time
	}
	return &inv, nil
}

// ---------- GetByNumber ----------
func (r *SubscriptionInvoiceRepositoryImpl) GetByNumber(ctx context.Context, invoiceNumber string) (*models.SubscriptionInvoice, error) {
	query := `
		SELECT invoice_id, company_id, invoice_number, invoice_date, due_date,
			currency, subtotal, tax_total, discount_total, grand_total,
			status, notes, issued_at, paid_at, cancelled_at,
			created_at, updated_at, deleted_at
		FROM subscription_invoices
		WHERE invoice_number = $1 AND deleted_at IS NULL
	`
	var inv models.SubscriptionInvoice
	var deletedAt sql.NullTime

	err := r.client.QueryRow(ctx, query, invoiceNumber).Scan(
		&inv.InvoiceID,
		&inv.CompanyID,
		&inv.InvoiceNumber,
		&inv.InvoiceDate,
		&inv.DueDate,
		&inv.Currency,
		&inv.Subtotal,
		&inv.TaxTotal,
		&inv.DiscountTotal,
		&inv.GrandTotal,
		&inv.Status,
		&inv.Notes,
		&inv.IssuedAt,
		&inv.PaidAt,
		&inv.CancelledAt,
		&inv.CreatedAt,
		&inv.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get invoice by number: %w", err)
	}
	if deletedAt.Valid {
		inv.DeletedAt = &deletedAt.Time
	}
	return &inv, nil
}

// ---------- Update ----------
func (r *SubscriptionInvoiceRepositoryImpl) Update(ctx context.Context, invoice *models.SubscriptionInvoice) error {
	query := `
		UPDATE subscription_invoices SET
			company_id = $1,
			invoice_number = $2,
			invoice_date = $3,
			due_date = $4,
			currency = $5,
			subtotal = $6,
			tax_total = $7,
			discount_total = $8,
			grand_total = $9,
			status = $10,
			notes = $11,
			issued_at = $12,
			paid_at = $13,
			cancelled_at = $14,
			updated_at = $15
		WHERE invoice_id = $16 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query,
		invoice.CompanyID,
		invoice.InvoiceNumber,
		invoice.InvoiceDate,
		invoice.DueDate,
		invoice.Currency,
		invoice.Subtotal,
		invoice.TaxTotal,
		invoice.DiscountTotal,
		invoice.GrandTotal,
		invoice.Status,
		invoice.Notes,
		invoice.IssuedAt,
		invoice.PaidAt,
		invoice.CancelledAt,
		invoice.UpdatedAt,
		invoice.InvoiceID,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to update invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- SoftDelete ----------
func (r *SubscriptionInvoiceRepositoryImpl) SoftDelete(ctx context.Context, invoiceID uuid.UUID) error {
	query := `UPDATE subscription_invoices SET deleted_at = NOW() WHERE invoice_id = $1 AND deleted_at IS NULL`
	result, err := r.client.Exec(ctx, query, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to soft-delete invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- ListByCompany ----------
func (r *SubscriptionInvoiceRepositoryImpl) ListByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.SubscriptionInvoice, int, error) {
	// Count total (excluding soft‑deleted)
	var total int
	countQuery := `SELECT COUNT(*) FROM subscription_invoices WHERE company_id = $1 AND deleted_at IS NULL`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count invoices: %w", err)
	}

	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT invoice_id, company_id, invoice_number, invoice_date, due_date,
			currency, subtotal, tax_total, discount_total, grand_total,
			status, notes, issued_at, paid_at, cancelled_at,
			created_at, updated_at, deleted_at
		FROM subscription_invoices
		WHERE company_id = $1 AND deleted_at IS NULL
		ORDER BY invoice_date DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list invoices: %w", err)
	}
	defer rows.Close()

	var invoices []*models.SubscriptionInvoice
	for rows.Next() {
		var inv models.SubscriptionInvoice
		var deletedAt sql.NullTime

		err := rows.Scan(
			&inv.InvoiceID,
			&inv.CompanyID,
			&inv.InvoiceNumber,
			&inv.InvoiceDate,
			&inv.DueDate,
			&inv.Currency,
			&inv.Subtotal,
			&inv.TaxTotal,
			&inv.DiscountTotal,
			&inv.GrandTotal,
			&inv.Status,
			&inv.Notes,
			&inv.IssuedAt,
			&inv.PaidAt,
			&inv.CancelledAt,
			&inv.CreatedAt,
			&inv.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan invoice: %w", err)
		}
		if deletedAt.Valid {
			inv.DeletedAt = &deletedAt.Time
		}
		invoices = append(invoices, &inv)
	}
	return invoices, total, nil
}

// ---------- UpdateStatus ----------
func (r *SubscriptionInvoiceRepositoryImpl) UpdateStatus(ctx context.Context, invoiceID uuid.UUID, status string) error {
	// Validate status if needed
	validStatuses := map[string]bool{
		"draft": true, "issued": true, "paid": true, "overdue": true, "cancelled": true,
	}
	if !validStatuses[status] {
		return fmt.Errorf("invalid status: %s", status)
	}
	query := `UPDATE subscription_invoices SET status = $1, updated_at = NOW() WHERE invoice_id = $2 AND deleted_at IS NULL`
	result, err := r.client.Exec(ctx, query, status, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to update invoice status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- MarkAsIssued ----------
func (r *SubscriptionInvoiceRepositoryImpl) MarkAsIssued(ctx context.Context, invoiceID uuid.UUID) error {
	query := `
		UPDATE subscription_invoices
		SET status = 'issued', issued_at = NOW(), updated_at = NOW()
		WHERE invoice_id = $1 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to mark invoice as issued: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- MarkAsPaid ----------
func (r *SubscriptionInvoiceRepositoryImpl) MarkAsPaid(ctx context.Context, invoiceID uuid.UUID) error {
	query := `
		UPDATE subscription_invoices
		SET status = 'paid', paid_at = NOW(), updated_at = NOW()
		WHERE invoice_id = $1 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to mark invoice as paid: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- MarkAsOverdue ----------
func (r *SubscriptionInvoiceRepositoryImpl) MarkAsOverdue(ctx context.Context, invoiceID uuid.UUID) error {
	query := `
		UPDATE subscription_invoices
		SET status = 'overdue', updated_at = NOW()
		WHERE invoice_id = $1 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to mark invoice as overdue: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- Cancel ----------
func (r *SubscriptionInvoiceRepositoryImpl) Cancel(ctx context.Context, invoiceID uuid.UUID) error {
	query := `
		UPDATE subscription_invoices
		SET status = 'cancelled', cancelled_at = NOW(), updated_at = NOW()
		WHERE invoice_id = $1 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to cancel invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}
