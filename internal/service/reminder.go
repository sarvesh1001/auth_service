// internal/service/reminder.go
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// NotificationSender defines the interface for sending notifications (email/SMS).
type NotificationSender interface {
	SendEmail(ctx context.Context, to string, subject, body string) error
	SendSMS(ctx context.Context, phoneNumber, message string) error
}

// ReminderConfig holds configuration for the reminder service.
type ReminderConfig struct {
	DaysBeforeTrialEnds        int
	DaysBeforeSubscriptionEnds int
	DaysBeforeGraceEnds        int
	BatchSize                  int
}

// DefaultReminderConfig returns sensible defaults.
func DefaultReminderConfig() ReminderConfig {
	return ReminderConfig{
		DaysBeforeTrialEnds:        3,
		DaysBeforeSubscriptionEnds: 7,
		DaysBeforeGraceEnds:        1,
		BatchSize:                  100,
	}
}

// reminderInfo holds data for a pending reminder.
type reminderInfo struct {
	CompanyID    uuid.UUID
	CompanyName  string
	OwnerUserID  uuid.UUID
	ReminderType string
	DueDate      time.Time
}

// ReminderService handles subscription-related reminders.
type ReminderService struct {
	reminderRepo     postgres.SubscriptionReminderRepository
	companyRepo      postgres.CompanyRepository
	userService      *UserService
	notificationSvc  NotificationSender
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	db               *client.PostgresClient
	cfg              ReminderConfig
}

// NewReminderService creates a new ReminderService.
func NewReminderService(
	reminderRepo postgres.SubscriptionReminderRepository,
	companyRepo postgres.CompanyRepository,
	userService *UserService,
	notificationSvc NotificationSender,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	db *client.PostgresClient,
	cfg *ReminderConfig,
) *ReminderService {
	if cfg == nil {
		defaultCfg := DefaultReminderConfig()
		cfg = &defaultCfg
	}
	return &ReminderService{
		reminderRepo:     reminderRepo,
		companyRepo:      companyRepo,
		userService:      userService,
		notificationSvc:  notificationSvc,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		db:               db,
		cfg:              *cfg,
	}
}

// ProcessPendingReminders fetches companies needing reminders using the DB function
// and sends notifications, then marks them as sent.
// This should be called by a daily cron job.
func (s *ReminderService) ProcessPendingReminders(ctx context.Context) error {
	query := `
		SELECT company_id, company_name, owner_user_id, reminder_type, due_date
		FROM get_companies_needing_reminders($1, $2, $3)
		LIMIT $4
	`
	rows, err := s.db.Query(ctx, query,
		s.cfg.DaysBeforeTrialEnds,
		s.cfg.DaysBeforeSubscriptionEnds,
		s.cfg.DaysBeforeGraceEnds,
		s.cfg.BatchSize,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch reminders: %w", err)
	}
	defer rows.Close()

	var reminders []reminderInfo

	for rows.Next() {
		var r reminderInfo
		if err := rows.Scan(&r.CompanyID, &r.CompanyName, &r.OwnerUserID, &r.ReminderType, &r.DueDate); err != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "reminder", "scan_error", "reminder",
				nil, "system", nil, nil, nil, map[string]interface{}{
					"error": err.Error(),
				})
			continue
		}
		reminders = append(reminders, r)
	}

	if len(reminders) == 0 {
		return nil
	}

	for _, r := range reminders {
		if err := s.processSingleReminder(ctx, r); err != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "reminder", "process_failed", "company",
				&r.CompanyID, "system", nil, nil, nil, map[string]interface{}{
					"reminder_type": r.ReminderType,
					"error":         err.Error(),
				})
			continue
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "reminder", "cron_run", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"processed_count": len(reminders),
				"batch_size":      s.cfg.BatchSize,
			})
	}
	return nil
}

// processSingleReminder handles one reminder: send notification and mark sent.
func (s *ReminderService) processSingleReminder(ctx context.Context, r reminderInfo) error {
	// Get the company owner's contact details
	owner, err := s.userService.GetUserByID(ctx, r.OwnerUserID)
	if err != nil {
		return fmt.Errorf("failed to get owner: %w", err)
	}
	if owner == nil || !owner.IsActive {
		return fmt.Errorf("owner user not active or not found")
	}

	// Build the message
	message := s.buildReminderMessage(r.ReminderType, r.CompanyName, r.DueDate)

	// In a real implementation, you'd fetch email/phone from employee_profiles or user_meta.
	// For now, we'll attempt to send via email if available.
	// We'll use a placeholder: we'll try to get email from employee_profiles (if we have a service).
	email := "" // In production: fetch from employee_profiles using user_id + company_id
	phone := "" // In production: fetch from employee_profiles

	// Attempt to send via email (preferred), fallback to SMS
	sentVia := ""
	sentErr := error(nil)

	if email != "" {
		sentErr = s.notificationSvc.SendEmail(ctx, email, "Subscription Reminder", message)
		if sentErr == nil {
			sentVia = "email"
		}
	}
	if sentVia == "" && phone != "" {
		sentErr = s.notificationSvc.SendSMS(ctx, phone, message)
		if sentErr == nil {
			sentVia = "sms"
		}
	}
	if sentVia == "" {
		return fmt.Errorf("no contact method available or send failed: %w", sentErr)
	}

	// Mark reminder as sent using the SQL function.
	markQuery := `SELECT mark_reminder_sent($1, $2, $3, $4, $5)`
	_, err = s.db.Exec(ctx, markQuery,
		r.CompanyID,
		r.ReminderType,
		r.DueDate,
		sentVia,
		message,
	)
	if err != nil {
		return fmt.Errorf("failed to mark reminder sent: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "reminder", "sent", "company",
			&r.CompanyID, "system", nil, nil, nil, map[string]interface{}{
				"type":     r.ReminderType,
				"sent_via": sentVia,
				"due_date": r.DueDate,
				"message":  message,
			})
	}
	return nil
}

// buildReminderMessage constructs a human-readable reminder message.
func (s *ReminderService) buildReminderMessage(reminderType, companyName string, dueDate time.Time) string {
	dateStr := dueDate.Format("2006-01-02")
	switch reminderType {
	case models.ReminderTrialEnding:
		return fmt.Sprintf("Your trial for '%s' ends on %s. Please upgrade to continue using the service.", companyName, dateStr)
	case models.ReminderTrialEnded:
		return fmt.Sprintf("Your trial for '%s' has ended. Please subscribe to continue using the service.", companyName)
	case models.ReminderSubscriptionEnding:
		return fmt.Sprintf("Your subscription for '%s' ends on %s. Renew now to avoid interruption.", companyName, dateStr)
	case models.ReminderSubscriptionEnded:
		return fmt.Sprintf("Your subscription for '%s' has ended. Please renew to restore access.", companyName)
	case models.ReminderGracePeriodEnding:
		return fmt.Sprintf("Your grace period for '%s' ends on %s. Renew immediately to avoid account deactivation.", companyName, dateStr)
	default:
		return "Subscription reminder: Please check your subscription status."
	}
}

// ListPendingReminders returns reminders that have not been sent yet (sent_at IS NULL)
// with pagination. It uses the repository to fetch and count.
func (s *ReminderService) ListPendingReminders(ctx context.Context, limit, offset int) ([]*models.SubscriptionReminder, int, error) {
	// Fetch reminders
	reminders, err := s.reminderRepo.ListPending(ctx, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list pending reminders: %w", err)
	}
	// Count total pending
	total, err := s.reminderRepo.CountPending(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count pending reminders: %w", err)
	}
	return reminders, total, nil
}
