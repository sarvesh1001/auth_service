package postgres

import (
	"auth-service/internal/models"
	"context"

	"github.com/google/uuid"
)

// SubscriptionInvoiceItemRepository defines operations for invoice line items.
type SubscriptionInvoiceItemRepository interface {
	// Create inserts a single invoice item.
	Create(ctx context.Context, item *models.SubscriptionInvoiceItem) error

	// CreateMany inserts multiple invoice items in a single transaction.
	CreateMany(ctx context.Context, items []*models.SubscriptionInvoiceItem) error

	// GetByID retrieves an item by its primary key.
	GetByID(ctx context.Context, itemID uuid.UUID) (*models.SubscriptionInvoiceItem, error)

	// GetByInvoice retrieves all items for a given invoice, ordered by creation time.
	GetByInvoice(ctx context.Context, invoiceID uuid.UUID) ([]*models.SubscriptionInvoiceItem, error)

	// Update updates an existing item.
	Update(ctx context.Context, item *models.SubscriptionInvoiceItem) error

	// Delete removes an item permanently (hard delete – no soft delete on items).
	Delete(ctx context.Context, itemID uuid.UUID) error

	// DeleteByInvoice removes all items for an invoice.
	DeleteByInvoice(ctx context.Context, invoiceID uuid.UUID) error
}
