package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

// Ensure CompanyPaymentRepositoryImpl implements the interface.
var _ CompanyPaymentRepository = (*CompanyPaymentRepositoryImpl)(nil)

type CompanyPaymentRepositoryImpl struct {
	client *client.PostgresClient
}

func NewCompanyPaymentRepository(pgClient *client.PostgresClient) *CompanyPaymentRepositoryImpl {
	return &CompanyPaymentRepositoryImpl{client: pgClient}
}

// ---------- Create ----------
func (r *CompanyPaymentRepositoryImpl) Create(ctx context.Context, payment *models.CompanyPayment) error {
	query := `
		INSERT INTO company_payments (
			payment_id, company_id, plan_id, invoice_id,
			amount, currency, payment_date, payment_method,
			gateway_txn_id, gateway_response, status, notes,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	// Convert json.RawMessage to []byte for the driver.
	var gatewayResponse []byte
	if payment.GatewayResponse != nil {
		gatewayResponse = []byte(payment.GatewayResponse)
	}

	_, err := r.client.Exec(ctx, query,
		payment.PaymentID,
		payment.CompanyID,
		payment.PlanID,
		payment.InvoiceID,
		payment.Amount,
		payment.Currency,
		payment.PaymentDate,
		payment.PaymentMethod,
		payment.GatewayTxnID,
		gatewayResponse,
		payment.Status,
		payment.Notes,
		payment.CreatedAt,
		payment.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to create company payment: %w", err)
	}
	return nil
}

// ---------- GetByID ----------
func (r *CompanyPaymentRepositoryImpl) GetByID(ctx context.Context, paymentID uuid.UUID) (*models.CompanyPayment, error) {
	query := `
		SELECT payment_id, company_id, plan_id, invoice_id,
			amount, currency, payment_date, payment_method,
			gateway_txn_id, gateway_response, status, notes,
			created_at, updated_at, deleted_at
		FROM company_payments
		WHERE payment_id = $1 AND deleted_at IS NULL
	`
	var payment models.CompanyPayment
	var gatewayResponse []byte
	var deletedAt sql.NullTime

	err := r.client.QueryRow(ctx, query, paymentID).Scan(
		&payment.PaymentID,
		&payment.CompanyID,
		&payment.PlanID,
		&payment.InvoiceID,
		&payment.Amount,
		&payment.Currency,
		&payment.PaymentDate,
		&payment.PaymentMethod,
		&payment.GatewayTxnID,
		&gatewayResponse,
		&payment.Status,
		&payment.Notes,
		&payment.CreatedAt,
		&payment.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get company payment by ID: %w", err)
	}
	if deletedAt.Valid {
		payment.DeletedAt = &deletedAt.Time
	}
	if len(gatewayResponse) > 0 {
		payment.GatewayResponse = json.RawMessage(gatewayResponse)
	}
	return &payment, nil
}

// ---------- GetByGatewayTxnID ----------
func (r *CompanyPaymentRepositoryImpl) GetByGatewayTxnID(ctx context.Context, gatewayTxnID string) (*models.CompanyPayment, error) {
	query := `
		SELECT payment_id, company_id, plan_id, invoice_id,
			amount, currency, payment_date, payment_method,
			gateway_txn_id, gateway_response, status, notes,
			created_at, updated_at, deleted_at
		FROM company_payments
		WHERE gateway_txn_id = $1 AND deleted_at IS NULL
	`
	var payment models.CompanyPayment
	var gatewayResponse []byte
	var deletedAt sql.NullTime

	err := r.client.QueryRow(ctx, query, gatewayTxnID).Scan(
		&payment.PaymentID,
		&payment.CompanyID,
		&payment.PlanID,
		&payment.InvoiceID,
		&payment.Amount,
		&payment.Currency,
		&payment.PaymentDate,
		&payment.PaymentMethod,
		&payment.GatewayTxnID,
		&gatewayResponse,
		&payment.Status,
		&payment.Notes,
		&payment.CreatedAt,
		&payment.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get company payment by gateway txn ID: %w", err)
	}
	if deletedAt.Valid {
		payment.DeletedAt = &deletedAt.Time
	}
	if len(gatewayResponse) > 0 {
		payment.GatewayResponse = json.RawMessage(gatewayResponse)
	}
	return &payment, nil
}

// ---------- Update ----------
func (r *CompanyPaymentRepositoryImpl) Update(ctx context.Context, payment *models.CompanyPayment) error {
	query := `
		UPDATE company_payments SET
			company_id = $1,
			plan_id = $2,
			invoice_id = $3,
			amount = $4,
			currency = $5,
			payment_date = $6,
			payment_method = $7,
			gateway_txn_id = $8,
			gateway_response = $9,
			status = $10,
			notes = $11,
			updated_at = $12
		WHERE payment_id = $13 AND deleted_at IS NULL
	`
	var gatewayResponse []byte
	if payment.GatewayResponse != nil {
		gatewayResponse = []byte(payment.GatewayResponse)
	}

	result, err := r.client.Exec(ctx, query,
		payment.CompanyID,
		payment.PlanID,
		payment.InvoiceID,
		payment.Amount,
		payment.Currency,
		payment.PaymentDate,
		payment.PaymentMethod,
		payment.GatewayTxnID,
		gatewayResponse,
		payment.Status,
		payment.Notes,
		payment.UpdatedAt,
		payment.PaymentID,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to update company payment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- SoftDelete ----------
func (r *CompanyPaymentRepositoryImpl) SoftDelete(ctx context.Context, paymentID uuid.UUID) error {
	query := `UPDATE company_payments SET deleted_at = NOW() WHERE payment_id = $1 AND deleted_at IS NULL`
	result, err := r.client.Exec(ctx, query, paymentID)
	if err != nil {
		return fmt.Errorf("failed to soft-delete company payment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- ListByCompany ----------
func (r *CompanyPaymentRepositoryImpl) ListByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyPayment, int, error) {
	// Count total (excluding soft‑deleted)
	var total int
	countQuery := `SELECT COUNT(*) FROM company_payments WHERE company_id = $1 AND deleted_at IS NULL`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count company payments: %w", err)
	}

	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT payment_id, company_id, plan_id, invoice_id,
			amount, currency, payment_date, payment_method,
			gateway_txn_id, gateway_response, status, notes,
			created_at, updated_at, deleted_at
		FROM company_payments
		WHERE company_id = $1 AND deleted_at IS NULL
		ORDER BY payment_date DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list company payments: %w", err)
	}
	defer rows.Close()

	var payments []*models.CompanyPayment
	for rows.Next() {
		var payment models.CompanyPayment
		var gatewayResponse []byte
		var deletedAt sql.NullTime

		err := rows.Scan(
			&payment.PaymentID,
			&payment.CompanyID,
			&payment.PlanID,
			&payment.InvoiceID,
			&payment.Amount,
			&payment.Currency,
			&payment.PaymentDate,
			&payment.PaymentMethod,
			&payment.GatewayTxnID,
			&gatewayResponse,
			&payment.Status,
			&payment.Notes,
			&payment.CreatedAt,
			&payment.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan company payment: %w", err)
		}
		if deletedAt.Valid {
			payment.DeletedAt = &deletedAt.Time
		}
		if len(gatewayResponse) > 0 {
			payment.GatewayResponse = json.RawMessage(gatewayResponse)
		}
		payments = append(payments, &payment)
	}
	return payments, total, nil
}

// ---------- UpdateInvoiceID ----------
func (r *CompanyPaymentRepositoryImpl) UpdateInvoiceID(ctx context.Context, paymentID, invoiceID uuid.UUID) error {
	query := `
		UPDATE company_payments
		SET invoice_id = $1, updated_at = NOW()
		WHERE payment_id = $2 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query, invoiceID, paymentID)
	if err != nil {
		return fmt.Errorf("failed to update invoice ID for payment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- UpdateStatus ----------
func (r *CompanyPaymentRepositoryImpl) UpdateStatus(ctx context.Context, paymentID uuid.UUID, status string) error {
	query := `
		UPDATE company_payments
		SET status = $1, updated_at = NOW()
		WHERE payment_id = $2 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query, status, paymentID)
	if err != nil {
		return fmt.Errorf("failed to update payment status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}
