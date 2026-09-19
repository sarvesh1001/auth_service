// internal/repository/postgres/subscription_reminder.go
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

var _ SubscriptionReminderRepository = (*SubscriptionReminderRepositoryImpl)(nil)

type SubscriptionReminderRepositoryImpl struct {
	client *client.PostgresClient
}

func NewSubscriptionReminderRepository(pgClient *client.PostgresClient) *SubscriptionReminderRepositoryImpl {
	return &SubscriptionReminderRepositoryImpl{client: pgClient}
}

// ---------- Create ----------
func (r *SubscriptionReminderRepositoryImpl) Create(ctx context.Context, reminder *models.SubscriptionReminder) error {
	query := `
		INSERT INTO subscription_reminders (
			reminder_id, company_id, reminder_type, scheduled_date,
			sent_at, sent_via, message, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.client.Exec(ctx, query,
		reminder.ReminderID,
		reminder.CompanyID,
		reminder.ReminderType,
		reminder.ScheduledDate,
		reminder.SentAt,
		reminder.SentVia,
		reminder.Message,
		reminder.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create reminder: %w", err)
	}
	return nil
}

// ---------- GetByID ----------
func (r *SubscriptionReminderRepositoryImpl) GetByID(ctx context.Context, reminderID uuid.UUID) (*models.SubscriptionReminder, error) {
	query := `
		SELECT reminder_id, company_id, reminder_type, scheduled_date,
			sent_at, sent_via, message, created_at
		FROM subscription_reminders
		WHERE reminder_id = $1
	`
	var rem models.SubscriptionReminder
	err := r.client.QueryRow(ctx, query, reminderID).Scan(
		&rem.ReminderID,
		&rem.CompanyID,
		&rem.ReminderType,
		&rem.ScheduledDate,
		&rem.SentAt,
		&rem.SentVia,
		&rem.Message,
		&rem.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get reminder by ID: %w", err)
	}
	return &rem, nil
}

// ---------- GetByCompanyAndType ----------
func (r *SubscriptionReminderRepositoryImpl) GetByCompanyAndType(ctx context.Context, companyID uuid.UUID, reminderType string, scheduledDate time.Time) (*models.SubscriptionReminder, error) {
	query := `
		SELECT reminder_id, company_id, reminder_type, scheduled_date,
			sent_at, sent_via, message, created_at
		FROM subscription_reminders
		WHERE company_id = $1 AND reminder_type = $2 AND scheduled_date = $3
	`
	var rem models.SubscriptionReminder
	err := r.client.QueryRow(ctx, query, companyID, reminderType, scheduledDate).Scan(
		&rem.ReminderID,
		&rem.CompanyID,
		&rem.ReminderType,
		&rem.ScheduledDate,
		&rem.SentAt,
		&rem.SentVia,
		&rem.Message,
		&rem.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get reminder: %w", err)
	}
	return &rem, nil
}

// ---------- MarkSent ----------
func (r *SubscriptionReminderRepositoryImpl) MarkSent(ctx context.Context, reminderID uuid.UUID, sentAt time.Time, sentVia string, message string) error {
	query := `
		UPDATE subscription_reminders
		SET sent_at = $1, sent_via = $2, message = $3
		WHERE reminder_id = $4
	`
	result, err := r.client.Exec(ctx, query, sentAt, sentVia, message, reminderID)
	if err != nil {
		return fmt.Errorf("failed to mark reminder as sent: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- ListPending ----------
func (r *SubscriptionReminderRepositoryImpl) ListPending(ctx context.Context, limit, offset int) ([]*models.SubscriptionReminder, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	query := `
		SELECT reminder_id, company_id, reminder_type, scheduled_date,
			sent_at, sent_via, message, created_at
		FROM subscription_reminders
		WHERE sent_at IS NULL
		ORDER BY scheduled_date ASC
		LIMIT $1 OFFSET $2
	`
	rows, err := r.client.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending reminders: %w", err)
	}
	defer rows.Close()

	var reminders []*models.SubscriptionReminder
	for rows.Next() {
		var rem models.SubscriptionReminder
		err := rows.Scan(
			&rem.ReminderID,
			&rem.CompanyID,
			&rem.ReminderType,
			&rem.ScheduledDate,
			&rem.SentAt,
			&rem.SentVia,
			&rem.Message,
			&rem.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan reminder: %w", err)
		}
		reminders = append(reminders, &rem)
	}
	return reminders, nil
}

// ---------- ListByCompany ----------
func (r *SubscriptionReminderRepositoryImpl) ListByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.SubscriptionReminder, int, error) {
	var total int
	countQuery := `SELECT COUNT(*) FROM subscription_reminders WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count reminders: %w", err)
	}

	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT reminder_id, company_id, reminder_type, scheduled_date,
			sent_at, sent_via, message, created_at
		FROM subscription_reminders
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list reminders: %w", err)
	}
	defer rows.Close()

	var reminders []*models.SubscriptionReminder
	for rows.Next() {
		var rem models.SubscriptionReminder
		err := rows.Scan(
			&rem.ReminderID,
			&rem.CompanyID,
			&rem.ReminderType,
			&rem.ScheduledDate,
			&rem.SentAt,
			&rem.SentVia,
			&rem.Message,
			&rem.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan reminder: %w", err)
		}
		reminders = append(reminders, &rem)
	}
	return reminders, total, nil
}

// ---------- CountPending ----------
func (r *SubscriptionReminderRepositoryImpl) CountPending(ctx context.Context) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM subscription_reminders WHERE sent_at IS NULL`
	err := r.client.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending reminders: %w", err)
	}
	return count, nil
}
