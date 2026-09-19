package postgres

import (
	"auth-service/internal/models"
	"context"

	"github.com/google/uuid"
)

// CompanyPaymentRepository defines operations for company payments.
type CompanyPaymentRepository interface {
	// Create inserts a new payment record.
	Create(ctx context.Context, payment *models.CompanyPayment) error

	// GetByID retrieves a payment by its primary key (ignores soft-deleted).
	GetByID(ctx context.Context, paymentID uuid.UUID) (*models.CompanyPayment, error)

	// GetByGatewayTxnID retrieves a payment by the gateway transaction ID (ignores soft-deleted).
	// Used for idempotency.
	GetByGatewayTxnID(ctx context.Context, gatewayTxnID string) (*models.CompanyPayment, error)

	// Update updates an existing payment (ignores soft-deleted).
	Update(ctx context.Context, payment *models.CompanyPayment) error

	// SoftDelete marks a payment as deleted (sets deleted_at).
	SoftDelete(ctx context.Context, paymentID uuid.UUID) error

	// ListByCompany returns payments for a company with pagination (ignores soft-deleted).
	ListByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyPayment, int, error)

	// UpdateInvoiceID links a payment to an invoice.
	UpdateInvoiceID(ctx context.Context, paymentID, invoiceID uuid.UUID) error

	// UpdateStatus updates the payment status (pending, success, failed, refunded).
	UpdateStatus(ctx context.Context, paymentID uuid.UUID, status string) error
}
