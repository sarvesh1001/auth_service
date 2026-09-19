package postgres

import (
	"auth-service/internal/models"
	"context"
	"time"

	"github.com/google/uuid"
)

// SubscriptionReminderRepository defines operations for subscription reminders.
// internal/repository/postgres/subscription_reminder.go (interface)
type SubscriptionReminderRepository interface {
	Create(ctx context.Context, reminder *models.SubscriptionReminder) error
	GetByID(ctx context.Context, reminderID uuid.UUID) (*models.SubscriptionReminder, error)
	GetByCompanyAndType(ctx context.Context, companyID uuid.UUID, reminderType string, scheduledDate time.Time) (*models.SubscriptionReminder, error)
	MarkSent(ctx context.Context, reminderID uuid.UUID, sentAt time.Time, sentVia string, message string) error
	ListPending(ctx context.Context, limit, offset int) ([]*models.SubscriptionReminder, error) // updated to include offset
	CountPending(ctx context.Context) (int, error)
	ListByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.SubscriptionReminder, int, error)
}
