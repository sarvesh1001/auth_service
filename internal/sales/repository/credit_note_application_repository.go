package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
)

type CreditNoteApplicationRepository interface {
	Create(ctx context.Context, db DBTX, app *models.CreditNoteApplication) error
	GetByID(ctx context.Context, db DBTX, applicationID uuid.UUID) (*models.CreditNoteApplication, error)
	Delete(ctx context.Context, db DBTX, applicationID uuid.UUID) error
	DeleteByCreditNote(ctx context.Context, db DBTX, creditNoteID uuid.UUID) error
	GetByCreditNote(ctx context.Context, db DBTX, creditNoteID uuid.UUID) ([]*models.CreditNoteApplication, error)
	GetByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*models.CreditNoteApplication, error)
	Exists(ctx context.Context, db DBTX, applicationID uuid.UUID) (bool, error)
	GetTotalAppliedForCreditNote(ctx context.Context, db DBTX, creditNoteID uuid.UUID) (decimal.Decimal, error)
	GetTotalAppliedForInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) (decimal.Decimal, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, applicationID uuid.UUID) (*models.CreditNoteApplication, error)
}

type creditNoteApplicationRepository struct {
	logger *zap.Logger
}

func NewCreditNoteApplicationRepository(logger *zap.Logger) CreditNoteApplicationRepository {
	return &creditNoteApplicationRepository{
		logger: logger.Named("sales_credit_note_app_repo"),
	}
}

func (r *creditNoteApplicationRepository) Create(ctx context.Context, db DBTX, app *models.CreditNoteApplication) error {
	query := `
		INSERT INTO sales.credit_note_applications (
			application_id, credit_note_id, invoice_id, amount, applied_at, applied_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		app.ApplicationID,
		app.CreditNoteID,
		app.InvoiceID,
		app.Amount,
		app.AppliedAt,
		nullUUID(app.AppliedBy),
	)
	if err != nil {
		return fmt.Errorf("create credit note application: %w", err)
	}
	return nil
}

func (r *creditNoteApplicationRepository) GetByID(ctx context.Context, db DBTX, applicationID uuid.UUID) (*models.CreditNoteApplication, error) {
	query := `
		SELECT application_id, credit_note_id, invoice_id, amount, applied_at, applied_by, created_at
		FROM sales.credit_note_applications
		WHERE application_id = $1
	`
	row := db.QueryRowContext(ctx, query, applicationID)
	return r.scan(row)
}

func (r *creditNoteApplicationRepository) GetByIDForUpdate(ctx context.Context, db DBTX, applicationID uuid.UUID) (*models.CreditNoteApplication, error) {
	query := `
		SELECT application_id, credit_note_id, invoice_id, amount, applied_at, applied_by, created_at
		FROM sales.credit_note_applications
		WHERE application_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, applicationID)
	return r.scan(row)
}

func (r *creditNoteApplicationRepository) Delete(ctx context.Context, db DBTX, applicationID uuid.UUID) error {
	query := `DELETE FROM sales.credit_note_applications WHERE application_id = $1`
	_, err := db.ExecContext(ctx, query, applicationID)
	if err != nil {
		return fmt.Errorf("delete credit note application: %w", err)
	}
	return nil
}

func (r *creditNoteApplicationRepository) DeleteByCreditNote(ctx context.Context, db DBTX, creditNoteID uuid.UUID) error {
	query := `DELETE FROM sales.credit_note_applications WHERE credit_note_id = $1`
	_, err := db.ExecContext(ctx, query, creditNoteID)
	if err != nil {
		return fmt.Errorf("delete applications for credit note: %w", err)
	}
	return nil
}

func (r *creditNoteApplicationRepository) GetByCreditNote(ctx context.Context, db DBTX, creditNoteID uuid.UUID) ([]*models.CreditNoteApplication, error) {
	query := `
		SELECT application_id, credit_note_id, invoice_id, amount, applied_at, applied_by, created_at
		FROM sales.credit_note_applications
		WHERE credit_note_id = $1
		ORDER BY applied_at
	`
	rows, err := db.QueryContext(ctx, query, creditNoteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*models.CreditNoteApplication
	for rows.Next() {
		app, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, app)
	}
	return result, rows.Err()
}

func (r *creditNoteApplicationRepository) GetByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) ([]*models.CreditNoteApplication, error) {
	query := `
		SELECT application_id, credit_note_id, invoice_id, amount, applied_at, applied_by, created_at
		FROM sales.credit_note_applications
		WHERE invoice_id = $1
	`
	rows, err := db.QueryContext(ctx, query, invoiceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*models.CreditNoteApplication
	for rows.Next() {
		app, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, app)
	}
	return result, rows.Err()
}

func (r *creditNoteApplicationRepository) Exists(ctx context.Context, db DBTX, applicationID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.credit_note_applications WHERE application_id = $1)`
	err := db.QueryRowContext(ctx, query, applicationID).Scan(&exists)
	return exists, err
}

func (r *creditNoteApplicationRepository) GetTotalAppliedForCreditNote(ctx context.Context, db DBTX, creditNoteID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `SELECT COALESCE(SUM(amount), 0) FROM sales.credit_note_applications WHERE credit_note_id = $1`
	err := db.QueryRowContext(ctx, query, creditNoteID).Scan(&total)
	return total, err
}

func (r *creditNoteApplicationRepository) GetTotalAppliedForInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `SELECT COALESCE(SUM(amount), 0) FROM sales.credit_note_applications WHERE invoice_id = $1`
	err := db.QueryRowContext(ctx, query, invoiceID).Scan(&total)
	return total, err
}

func (r *creditNoteApplicationRepository) scan(row scanner) (*models.CreditNoteApplication, error) {
	var app models.CreditNoteApplication
	var appliedBy uuid.NullUUID
	err := row.Scan(
		&app.ApplicationID,
		&app.CreditNoteID,
		&app.InvoiceID,
		&app.Amount,
		&app.AppliedAt,
		&appliedBy,
		&app.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, err
	}
	if appliedBy.Valid {
		app.AppliedBy = &appliedBy.UUID
	}
	return &app, nil
}

func nullUUID(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}
