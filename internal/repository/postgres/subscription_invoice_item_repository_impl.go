package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

var _ SubscriptionInvoiceItemRepository = (*SubscriptionInvoiceItemRepositoryImpl)(nil)

type SubscriptionInvoiceItemRepositoryImpl struct {
	client *client.PostgresClient
}

func NewSubscriptionInvoiceItemRepository(pgClient *client.PostgresClient) *SubscriptionInvoiceItemRepositoryImpl {
	return &SubscriptionInvoiceItemRepositoryImpl{client: pgClient}
}

// ---------- Create ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) Create(ctx context.Context, item *models.SubscriptionInvoiceItem) error {
	query := `
		INSERT INTO subscription_invoice_items (
			item_id, invoice_id, description, quantity, unit_price, tax_rate, tax_amount, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.client.Exec(ctx, query,
		item.ItemID,
		item.InvoiceID,
		item.Description,
		item.Quantity,
		item.UnitPrice,
		item.TaxRate,
		item.TaxAmount,
		item.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create invoice item: %w", err)
	}
	return nil
}

// ---------- CreateMany (batch insert using a transaction) ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) CreateMany(ctx context.Context, items []*models.SubscriptionInvoiceItem) error {
	if len(items) == 0 {
		return nil
	}

	// Start a transaction using BeginTx with default options
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // ✅ Fixed: Rollback does not take a context

	query := `
		INSERT INTO subscription_invoice_items (
			item_id, invoice_id, description, quantity, unit_price, tax_rate, tax_amount, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	for _, item := range items {
		_, err := tx.ExecContext(ctx, query,
			item.ItemID,
			item.InvoiceID,
			item.Description,
			item.Quantity,
			item.UnitPrice,
			item.TaxRate,
			item.TaxAmount,
			item.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert invoice item: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ---------- GetByID ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) GetByID(ctx context.Context, itemID uuid.UUID) (*models.SubscriptionInvoiceItem, error) {
	query := `
		SELECT item_id, invoice_id, description, quantity, unit_price,
			total_price, tax_rate, tax_amount, created_at
		FROM subscription_invoice_items
		WHERE item_id = $1
	`
	var item models.SubscriptionInvoiceItem
	err := r.client.QueryRow(ctx, query, itemID).Scan(
		&item.ItemID,
		&item.InvoiceID,
		&item.Description,
		&item.Quantity,
		&item.UnitPrice,
		&item.TotalPrice, // generated column, we can scan it
		&item.TaxRate,
		&item.TaxAmount,
		&item.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get invoice item: %w", err)
	}
	return &item, nil
}

// ---------- GetByInvoice ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) GetByInvoice(ctx context.Context, invoiceID uuid.UUID) ([]*models.SubscriptionInvoiceItem, error) {
	query := `
		SELECT item_id, invoice_id, description, quantity, unit_price,
			total_price, tax_rate, tax_amount, created_at
		FROM subscription_invoice_items
		WHERE invoice_id = $1
		ORDER BY created_at ASC
	`
	rows, err := r.client.Query(ctx, query, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query invoice items: %w", err)
	}
	defer rows.Close()

	var items []*models.SubscriptionInvoiceItem
	for rows.Next() {
		var item models.SubscriptionInvoiceItem
		err := rows.Scan(
			&item.ItemID,
			&item.InvoiceID,
			&item.Description,
			&item.Quantity,
			&item.UnitPrice,
			&item.TotalPrice,
			&item.TaxRate,
			&item.TaxAmount,
			&item.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan invoice item: %w", err)
		}
		items = append(items, &item)
	}
	return items, nil
}

// ---------- Update ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) Update(ctx context.Context, item *models.SubscriptionInvoiceItem) error {
	query := `
		UPDATE subscription_invoice_items SET
			description = $1,
			quantity = $2,
			unit_price = $3,
			tax_rate = $4,
			tax_amount = $5
		WHERE item_id = $6
	`
	result, err := r.client.Exec(ctx, query,
		item.Description,
		item.Quantity,
		item.UnitPrice,
		item.TaxRate,
		item.TaxAmount,
		item.ItemID,
	)
	if err != nil {
		return fmt.Errorf("failed to update invoice item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- Delete ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) Delete(ctx context.Context, itemID uuid.UUID) error {
	query := `DELETE FROM subscription_invoice_items WHERE item_id = $1`
	result, err := r.client.Exec(ctx, query, itemID)
	if err != nil {
		return fmt.Errorf("failed to delete invoice item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- DeleteByInvoice ----------
func (r *SubscriptionInvoiceItemRepositoryImpl) DeleteByInvoice(ctx context.Context, invoiceID uuid.UUID) error {
	query := `DELETE FROM subscription_invoice_items WHERE invoice_id = $1`
	_, err := r.client.Exec(ctx, query, invoiceID)
	if err != nil {
		return fmt.Errorf("failed to delete invoice items: %w", err)
	}
	return nil
}
