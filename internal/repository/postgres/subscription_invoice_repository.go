package postgres

import (
	"auth-service/internal/models"
	"context"

	"github.com/google/uuid"
)

// SubscriptionInvoiceRepository defines operations for subscription invoices.
type SubscriptionInvoiceRepository interface {
	// Create inserts a new invoice.
	Create(ctx context.Context, invoice *models.SubscriptionInvoice) error

	// GetByID retrieves an invoice by its primary key (ignores soft‑deleted).
	GetByID(ctx context.Context, invoiceID uuid.UUID) (*models.SubscriptionInvoice, error)

	// GetByNumber retrieves an invoice by its unique invoice number (ignores soft‑deleted).
	GetByNumber(ctx context.Context, invoiceNumber string) (*models.SubscriptionInvoice, error)

	// Update updates an existing invoice (ignores soft‑deleted).
	Update(ctx context.Context, invoice *models.SubscriptionInvoice) error

	// SoftDelete marks an invoice as deleted (sets deleted_at).
	SoftDelete(ctx context.Context, invoiceID uuid.UUID) error

	// ListByCompany returns invoices for a company with pagination (ignores soft‑deleted).
	ListByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.SubscriptionInvoice, int, error)

	// UpdateStatus updates the invoice status (draft, issued, paid, overdue, cancelled).
	UpdateStatus(ctx context.Context, invoiceID uuid.UUID, status string) error

	// MarkAsIssued sets status to 'issued' and sets issued_at timestamp.
	MarkAsIssued(ctx context.Context, invoiceID uuid.UUID) error

	// MarkAsPaid sets status to 'paid' and sets paid_at timestamp.
	MarkAsPaid(ctx context.Context, invoiceID uuid.UUID) error

	// MarkAsOverdue sets status to 'overdue' (e.g., when due date passes).
	MarkAsOverdue(ctx context.Context, invoiceID uuid.UUID) error

	// Cancel sets status to 'cancelled' and sets cancelled_at timestamp.
	Cancel(ctx context.Context, invoiceID uuid.UUID) error
}
