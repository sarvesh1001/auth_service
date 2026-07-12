// FILE: repository/subscription_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
)

// -------------------------------------------------------------------------
// Interface (unchanged)
// -------------------------------------------------------------------------

type SubscriptionRepository interface {
	Create(ctx context.Context, db DBTX, subscription *models.Subscription) error
	GetByID(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)
	GetByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (*models.Subscription, error)
	Update(ctx context.Context, db DBTX, subscription *models.Subscription) error
	Delete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error

	Activate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error
	Pause(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason *string) error
	Resume(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error
	Cancel(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason *string, cancelledAt time.Time) error
	Expire(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, endDate time.Time) error
	Renew(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, newEndDate time.Time) error
	UpdateStatus(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, status enums.SubscriptionStatus) error
	SoftDelete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error

	UpdateCurrentInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID) error
	UpdateLastInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID) error
	UpdateNextInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID) error

	UpdateSalesOrder(ctx context.Context, db DBTX, companyID, subscriptionID, salesOrderID uuid.UUID) error
	UpdateSchedule(ctx context.Context, db DBTX, companyID, subscriptionID, scheduleID uuid.UUID) error
	UpdateWorkflow(ctx context.Context, db DBTX, companyID, subscriptionID, workflowID uuid.UUID) error
	UpdateNotificationPreference(ctx context.Context, db DBTX, companyID, subscriptionID, notificationPreferenceID uuid.UUID) error

	AddSession(ctx context.Context, db DBTX, session *models.SubscriptionSessionMap) error
	DeleteSession(ctx context.Context, db DBTX, subscriptionID, sessionID uuid.UUID) error
	GetSessions(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionSessionMap, error)
	GetSession(ctx context.Context, db DBTX, sessionType string, sessionID uuid.UUID) (*models.SubscriptionSessionMap, error)

	Exists(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error)
	ExistsByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error)
	IsTrial(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error)

	List(ctx context.Context, db DBTX, filter SubscriptionFilter, p Pagination, s Sort) ([]*models.Subscription, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Subscription, int64, error)
	GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*models.Subscription, error)
	GetByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.Subscription, error)
	GetByStatus(ctx context.Context, db DBTX, companyID uuid.UUID, status enums.SubscriptionStatus) ([]*models.Subscription, error)
	GetExpiringBetween(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*models.Subscription, error)
	GetRenewalDue(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Subscription, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type SubscriptionFilter struct {
	CompanyID       uuid.UUID
	SubscriptionIDs []uuid.UUID
	CustomerID      *uuid.UUID
	PlanID          *uuid.UUID
	Status          *enums.SubscriptionStatus // used in filter (converted to status_id)
	ContractNumber  *string
	AutoRenew       *bool
	CouponID        *uuid.UUID
	SalesOrderID    *uuid.UUID

	StartDateFrom    *time.Time
	StartDateTo      *time.Time
	EndDateFrom      *time.Time
	EndDateTo        *time.Time
	BillingStartFrom *time.Time
	BillingStartTo   *time.Time
	TrialEndFrom     *time.Time
	TrialEndTo       *time.Time
	CancelledFrom    *time.Time
	CancelledTo      *time.Time
	CreatedFrom      *time.Time
	CreatedTo        *time.Time
	UpdatedFrom      *time.Time
	UpdatedTo        *time.Time

	Deleted bool // true = include soft-deleted
}

type Pagination struct {
	Limit  int
	Offset int
}

type Sort struct {
	Field     string
	Direction string
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type subscriptionRepository struct {
	logger *zap.Logger
}

func NewSubscriptionRepository(logger *zap.Logger) SubscriptionRepository {
	return &subscriptionRepository{
		logger: logger.Named("subscription_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers: status <-> id
// -------------------------------------------------------------------------

// statusToID maps a SubscriptionStatus string to its integer ID.
func (r *subscriptionRepository) statusToID(status enums.SubscriptionStatus) int {
	switch status {
	case enums.SubStatusActive:
		return 1
	case enums.SubStatusPaused:
		return 2
	case enums.SubStatusExpired:
		return 3
	case enums.SubStatusCancelled:
		return 4
	case enums.SubStatusTrial:
		return 5
	case enums.SubStatusPending:
		return 6
	default:
		return 1 // fallback to active
	}
}

// idToStatus converts an integer status_id to the string enum.
func (r *subscriptionRepository) idToStatus(id int) enums.SubscriptionStatus {
	switch id {
	case 1:
		return enums.SubStatusActive
	case 2:
		return enums.SubStatusPaused
	case 3:
		return enums.SubStatusExpired
	case 4:
		return enums.SubStatusCancelled
	case 5:
		return enums.SubStatusTrial
	case 6:
		return enums.SubStatusPending
	default:
		return enums.SubStatusActive
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *subscriptionRepository) Create(ctx context.Context, db DBTX, subscription *models.Subscription) error {
	query := `
		INSERT INTO subscription.subscriptions (
			subscription_id, company_id, customer_id, plan_id, status_id,
			start_date, end_date, trial_end, billing_start, auto_renew,
			pause_reason, cancellation_reason, cancelled_at, contract_number,
			signed_at, terms_version, signed_document_key,
			current_invoice_id, last_invoice_id, next_invoice_id, coupon_id,
			version, created_at, updated_at, deleted_at,
			sales_order_id, schedule_id, workflow_id, notification_pref_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22, $23, $24, $25,
			$26, $27, $28, $29
		)
	`
	statusID := r.statusToID(subscription.Status)
	_, err := db.ExecContext(ctx, query,
		subscription.SubscriptionID,
		subscription.CompanyID,
		subscription.CustomerID,
		subscription.PlanID,
		statusID,
		subscription.StartDate,
		subscription.EndDate,
		subscription.TrialEnd,
		subscription.BillingStart,
		subscription.AutoRenew,
		subscription.PauseReason,
		subscription.CancellationReason,
		subscription.CancelledAt,
		subscription.ContractNumber,
		subscription.SignedAt,
		subscription.TermsVersion,
		subscription.SignedDocumentKey,
		subscription.CurrentInvoiceID,
		subscription.LastInvoiceID,
		subscription.NextInvoiceID,
		subscription.CouponID,
		subscription.Version,
		subscription.CreatedAt,
		subscription.UpdatedAt,
		subscription.DeletedAt,
		subscription.SalesOrderID,
		subscription.ScheduleID,
		subscription.WorkflowID,
		subscription.NotificationPrefID,
	)
	if err != nil {
		r.logger.Error("failed to create subscription", zap.Error(err))
		return fmt.Errorf("create subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) GetByID(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND subscription_id = $2 AND deleted_at IS NULL`
	var sub models.Subscription
	var statusID int
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID).Scan(
		&sub.SubscriptionID,
		&sub.CompanyID,
		&sub.CustomerID,
		&sub.PlanID,
		&statusID,
		&sub.StartDate,
		&sub.EndDate,
		&sub.TrialEnd,
		&sub.BillingStart,
		&sub.AutoRenew,
		&sub.PauseReason,
		&sub.CancellationReason,
		&sub.CancelledAt,
		&sub.ContractNumber,
		&sub.SignedAt,
		&sub.TermsVersion,
		&sub.SignedDocumentKey,
		&sub.CurrentInvoiceID,
		&sub.LastInvoiceID,
		&sub.NextInvoiceID,
		&sub.CouponID,
		&sub.Version,
		&sub.CreatedAt,
		&sub.UpdatedAt,
		&sub.DeletedAt,
		&sub.SalesOrderID,
		&sub.ScheduleID,
		&sub.WorkflowID,
		&sub.NotificationPrefID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	sub.Status = r.idToStatus(statusID)
	return &sub, nil
}

func (r *subscriptionRepository) GetByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (*models.Subscription, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND contract_number = $2 AND deleted_at IS NULL`
	var sub models.Subscription
	var statusID int
	err := db.QueryRowContext(ctx, query, companyID, contractNumber).Scan(
		&sub.SubscriptionID,
		&sub.CompanyID,
		&sub.CustomerID,
		&sub.PlanID,
		&statusID,
		&sub.StartDate,
		&sub.EndDate,
		&sub.TrialEnd,
		&sub.BillingStart,
		&sub.AutoRenew,
		&sub.PauseReason,
		&sub.CancellationReason,
		&sub.CancelledAt,
		&sub.ContractNumber,
		&sub.SignedAt,
		&sub.TermsVersion,
		&sub.SignedDocumentKey,
		&sub.CurrentInvoiceID,
		&sub.LastInvoiceID,
		&sub.NextInvoiceID,
		&sub.CouponID,
		&sub.Version,
		&sub.CreatedAt,
		&sub.UpdatedAt,
		&sub.DeletedAt,
		&sub.SalesOrderID,
		&sub.ScheduleID,
		&sub.WorkflowID,
		&sub.NotificationPrefID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	sub.Status = r.idToStatus(statusID)
	return &sub, nil
}

func (r *subscriptionRepository) Update(ctx context.Context, db DBTX, subscription *models.Subscription) error {
	query := `
		UPDATE subscription.subscriptions
		SET customer_id = $1,
		    plan_id = $2,
		    status_id = $3,
		    start_date = $4,
		    end_date = $5,
		    trial_end = $6,
		    billing_start = $7,
		    auto_renew = $8,
		    pause_reason = $9,
		    cancellation_reason = $10,
		    cancelled_at = $11,
		    contract_number = $12,
		    signed_at = $13,
		    terms_version = $14,
		    signed_document_key = $15,
		    current_invoice_id = $16,
		    last_invoice_id = $17,
		    next_invoice_id = $18,
		    coupon_id = $19,
		    version = $20,
		    updated_at = NOW(),
		    deleted_at = $21,
		    sales_order_id = $22,
		    schedule_id = $23,
		    workflow_id = $24,
		    notification_pref_id = $25
		WHERE company_id = $26 AND subscription_id = $27
	`
	statusID := r.statusToID(subscription.Status)
	_, err := db.ExecContext(ctx, query,
		subscription.CustomerID,
		subscription.PlanID,
		statusID,
		subscription.StartDate,
		subscription.EndDate,
		subscription.TrialEnd,
		subscription.BillingStart,
		subscription.AutoRenew,
		subscription.PauseReason,
		subscription.CancellationReason,
		subscription.CancelledAt,
		subscription.ContractNumber,
		subscription.SignedAt,
		subscription.TermsVersion,
		subscription.SignedDocumentKey,
		subscription.CurrentInvoiceID,
		subscription.LastInvoiceID,
		subscription.NextInvoiceID,
		subscription.CouponID,
		subscription.Version,
		subscription.DeletedAt,
		subscription.SalesOrderID,
		subscription.ScheduleID,
		subscription.WorkflowID,
		subscription.NotificationPrefID,
		subscription.CompanyID,
		subscription.SubscriptionID,
	)
	if err != nil {
		r.logger.Error("failed to update subscription", zap.Error(err))
		return fmt.Errorf("update subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Delete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error {
	query := `DELETE FROM subscription.subscriptions WHERE company_id = $1 AND subscription_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to delete subscription", zap.Error(err))
		return fmt.Errorf("delete subscription: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (r *subscriptionRepository) Activate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error {
	return r.updateStatus(ctx, db, companyID, subscriptionID, enums.SubStatusActive)
}

func (r *subscriptionRepository) Pause(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason *string) error {
	query := `UPDATE subscription.subscriptions SET status_id = $1, pause_reason = $2, updated_at = NOW() WHERE company_id = $3 AND subscription_id = $4`
	_, err := db.ExecContext(ctx, query, r.statusToID(enums.SubStatusPaused), reason, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to pause subscription", zap.Error(err))
		return fmt.Errorf("pause subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Resume(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error {
	query := `UPDATE subscription.subscriptions SET status_id = $1, pause_reason = NULL, updated_at = NOW() WHERE company_id = $2 AND subscription_id = $3`
	_, err := db.ExecContext(ctx, query, r.statusToID(enums.SubStatusActive), companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to resume subscription", zap.Error(err))
		return fmt.Errorf("resume subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Cancel(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason *string, cancelledAt time.Time) error {
	query := `
		UPDATE subscription.subscriptions
		SET status_id = $1, cancellation_reason = $2, cancelled_at = $3, updated_at = NOW()
		WHERE company_id = $4 AND subscription_id = $5
	`
	_, err := db.ExecContext(ctx, query, r.statusToID(enums.SubStatusCancelled), reason, cancelledAt, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to cancel subscription", zap.Error(err))
		return fmt.Errorf("cancel subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Expire(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE subscription.subscriptions
		SET status_id = $1, end_date = $2, updated_at = NOW()
		WHERE company_id = $3 AND subscription_id = $4
	`
	_, err := db.ExecContext(ctx, query, r.statusToID(enums.SubStatusExpired), endDate, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to expire subscription", zap.Error(err))
		return fmt.Errorf("expire subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Renew(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, newEndDate time.Time) error {
	query := `
		UPDATE subscription.subscriptions
		SET status_id = $1, end_date = $2, version = version + 1, updated_at = NOW()
		WHERE company_id = $3 AND subscription_id = $4
	`
	_, err := db.ExecContext(ctx, query, r.statusToID(enums.SubStatusActive), newEndDate, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to renew subscription", zap.Error(err))
		return fmt.Errorf("renew subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, status enums.SubscriptionStatus) error {
	return r.updateStatus(ctx, db, companyID, subscriptionID, status)
}

// internal helper to set status by enum
func (r *subscriptionRepository) updateStatus(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, status enums.SubscriptionStatus) error {
	query := `UPDATE subscription.subscriptions SET status_id = $1, updated_at = NOW() WHERE company_id = $2 AND subscription_id = $3`
	_, err := db.ExecContext(ctx, query, r.statusToID(status), companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to update subscription status", zap.Error(err))
		return fmt.Errorf("update subscription status: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) SoftDelete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error {
	query := `UPDATE subscription.subscriptions SET deleted_at = NOW() WHERE company_id = $1 AND subscription_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to soft delete subscription", zap.Error(err))
		return fmt.Errorf("soft delete subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Restore(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error {
	query := `UPDATE subscription.subscriptions SET deleted_at = NULL WHERE company_id = $1 AND subscription_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to restore subscription", zap.Error(err))
		return fmt.Errorf("restore subscription: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Invoice References (same as before)
// -------------------------------------------------------------------------

func (r *subscriptionRepository) UpdateCurrentInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID) error {
	return r.updateInvoiceRef(ctx, db, "current_invoice_id", companyID, subscriptionID, invoiceID)
}

func (r *subscriptionRepository) UpdateLastInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID) error {
	return r.updateInvoiceRef(ctx, db, "last_invoice_id", companyID, subscriptionID, invoiceID)
}

func (r *subscriptionRepository) UpdateNextInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID) error {
	return r.updateInvoiceRef(ctx, db, "next_invoice_id", companyID, subscriptionID, invoiceID)
}

func (r *subscriptionRepository) updateInvoiceRef(ctx context.Context, db DBTX, column string, companyID, subscriptionID, invoiceID uuid.UUID) error {
	query := fmt.Sprintf(`UPDATE subscription.subscriptions SET %s = $1, updated_at = NOW() WHERE company_id = $2 AND subscription_id = $3`, column)
	_, err := db.ExecContext(ctx, query, invoiceID, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to update invoice ref", zap.String("column", column), zap.Error(err))
		return fmt.Errorf("update %s: %w", column, err)
	}
	return nil
}

// -------------------------------------------------------------------------
// External References
// -------------------------------------------------------------------------

func (r *subscriptionRepository) UpdateSalesOrder(ctx context.Context, db DBTX, companyID, subscriptionID, salesOrderID uuid.UUID) error {
	return r.updateExternalRef(ctx, db, "sales_order_id", companyID, subscriptionID, salesOrderID)
}

func (r *subscriptionRepository) UpdateSchedule(ctx context.Context, db DBTX, companyID, subscriptionID, scheduleID uuid.UUID) error {
	return r.updateExternalRef(ctx, db, "schedule_id", companyID, subscriptionID, scheduleID)
}

func (r *subscriptionRepository) UpdateWorkflow(ctx context.Context, db DBTX, companyID, subscriptionID, workflowID uuid.UUID) error {
	return r.updateExternalRef(ctx, db, "workflow_id", companyID, subscriptionID, workflowID)
}

func (r *subscriptionRepository) UpdateNotificationPreference(ctx context.Context, db DBTX, companyID, subscriptionID, notificationPreferenceID uuid.UUID) error {
	return r.updateExternalRef(ctx, db, "notification_pref_id", companyID, subscriptionID, notificationPreferenceID)
}

func (r *subscriptionRepository) updateExternalRef(ctx context.Context, db DBTX, column string, companyID, subscriptionID, refID uuid.UUID) error {
	query := fmt.Sprintf(`UPDATE subscription.subscriptions SET %s = $1, updated_at = NOW() WHERE company_id = $2 AND subscription_id = $3`, column)
	_, err := db.ExecContext(ctx, query, refID, companyID, subscriptionID)
	if err != nil {
		r.logger.Error("failed to update external ref", zap.String("column", column), zap.Error(err))
		return fmt.Errorf("update %s: %w", column, err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Session Mapping
// -------------------------------------------------------------------------

func (r *subscriptionRepository) AddSession(ctx context.Context, db DBTX, session *models.SubscriptionSessionMap) error {
	query := `
		INSERT INTO subscription.subscription_session_map (
			map_id, subscription_id, session_type, session_id, created_at
		) VALUES ($1, $2, $3, $4, $5)
	`
	_, err := db.ExecContext(ctx, query,
		session.MapID,
		session.SubscriptionID,
		session.SessionType,
		session.SessionID,
		session.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to add session mapping", zap.Error(err))
		return fmt.Errorf("add session mapping: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) DeleteSession(ctx context.Context, db DBTX, subscriptionID, sessionID uuid.UUID) error {
	query := `DELETE FROM subscription.subscription_session_map WHERE subscription_id = $1 AND session_id = $2`
	_, err := db.ExecContext(ctx, query, subscriptionID, sessionID)
	if err != nil {
		r.logger.Error("failed to delete session mapping", zap.Error(err))
		return fmt.Errorf("delete session mapping: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) GetSessions(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionSessionMap, error) {
	query := `
		SELECT map_id, subscription_id, session_type, session_id, created_at
		FROM subscription.subscription_session_map
		WHERE subscription_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*models.SubscriptionSessionMap
	for rows.Next() {
		var s models.SubscriptionSessionMap
		if err := rows.Scan(&s.MapID, &s.SubscriptionID, &s.SessionType, &s.SessionID, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, &s)
	}
	return sessions, rows.Err()
}

func (r *subscriptionRepository) GetSession(ctx context.Context, db DBTX, sessionType string, sessionID uuid.UUID) (*models.SubscriptionSessionMap, error) {
	query := `
		SELECT map_id, subscription_id, session_type, session_id, created_at
		FROM subscription.subscription_session_map
		WHERE session_type = $1 AND session_id = $2
	`
	var s models.SubscriptionSessionMap
	err := db.QueryRowContext(ctx, query, sessionType, sessionID).Scan(
		&s.MapID, &s.SubscriptionID, &s.SessionType, &s.SessionID, &s.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	return &s, nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *subscriptionRepository) Exists(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscriptions WHERE company_id = $1 AND subscription_id = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}
	return exists, nil
}

func (r *subscriptionRepository) ExistsByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscriptions WHERE company_id = $1 AND contract_number = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, contractNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check contract exists: %w", err)
	}
	return exists, nil
}

func (r *subscriptionRepository) IsActive(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error) {
	// status_id 1 = active
	query := `SELECT status_id = 1 FROM subscription.subscriptions WHERE company_id = $1 AND subscription_id = $2 AND deleted_at IS NULL`
	var active bool
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check active: %w", err)
	}
	return active, nil
}

func (r *subscriptionRepository) IsTrial(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error) {
	// status_id 5 = trial
	query := `SELECT status_id = 5 FROM subscription.subscriptions WHERE company_id = $1 AND subscription_id = $2 AND deleted_at IS NULL`
	var trial bool
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID).Scan(&trial)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check trial: %w", err)
	}
	return trial, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *subscriptionRepository) List(ctx context.Context, db DBTX, filter SubscriptionFilter, p Pagination, s Sort) ([]*models.Subscription, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.subscriptions %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count subscriptions: %w", err)
	}
	if total == 0 {
		return []*models.Subscription{}, 0, nil
	}

	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY created_at DESC"
	}

	query := fmt.Sprintf(`
		%s %s %s
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list subscriptions: %w", err)
	}
	defer rows.Close()

	var subscriptions []*models.Subscription
	for rows.Next() {
		var sub models.Subscription
		var statusID int
		if err := rows.Scan(
			&sub.SubscriptionID,
			&sub.CompanyID,
			&sub.CustomerID,
			&sub.PlanID,
			&statusID,
			&sub.StartDate,
			&sub.EndDate,
			&sub.TrialEnd,
			&sub.BillingStart,
			&sub.AutoRenew,
			&sub.PauseReason,
			&sub.CancellationReason,
			&sub.CancelledAt,
			&sub.ContractNumber,
			&sub.SignedAt,
			&sub.TermsVersion,
			&sub.SignedDocumentKey,
			&sub.CurrentInvoiceID,
			&sub.LastInvoiceID,
			&sub.NextInvoiceID,
			&sub.CouponID,
			&sub.Version,
			&sub.CreatedAt,
			&sub.UpdatedAt,
			&sub.DeletedAt,
			&sub.SalesOrderID,
			&sub.ScheduleID,
			&sub.WorkflowID,
			&sub.NotificationPrefID,
		); err != nil {
			return nil, 0, fmt.Errorf("scan subscription: %w", err)
		}
		sub.Status = r.idToStatus(statusID)
		subscriptions = append(subscriptions, &sub)
	}
	return subscriptions, total, rows.Err()
}

func (r *subscriptionRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Subscription, int64, error) {
	searchPattern := "%" + query + "%"
	where := "company_id = $1 AND deleted_at IS NULL AND contract_number ILIKE $2"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.subscriptions WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}
	if total == 0 {
		return []*models.Subscription{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		%s WHERE %s
		ORDER BY contract_number
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search subscriptions: %w", err)
	}
	defer rows.Close()

	var subscriptions []*models.Subscription
	for rows.Next() {
		var sub models.Subscription
		var statusID int
		if err := rows.Scan(
			&sub.SubscriptionID,
			&sub.CompanyID,
			&sub.CustomerID,
			&sub.PlanID,
			&statusID,
			&sub.StartDate,
			&sub.EndDate,
			&sub.TrialEnd,
			&sub.BillingStart,
			&sub.AutoRenew,
			&sub.PauseReason,
			&sub.CancellationReason,
			&sub.CancelledAt,
			&sub.ContractNumber,
			&sub.SignedAt,
			&sub.TermsVersion,
			&sub.SignedDocumentKey,
			&sub.CurrentInvoiceID,
			&sub.LastInvoiceID,
			&sub.NextInvoiceID,
			&sub.CouponID,
			&sub.Version,
			&sub.CreatedAt,
			&sub.UpdatedAt,
			&sub.DeletedAt,
			&sub.SalesOrderID,
			&sub.ScheduleID,
			&sub.WorkflowID,
			&sub.NotificationPrefID,
		); err != nil {
			return nil, 0, fmt.Errorf("scan subscription: %w", err)
		}
		sub.Status = r.idToStatus(statusID)
		subscriptions = append(subscriptions, &sub)
	}
	return subscriptions, total, rows.Err()
}

func (r *subscriptionRepository) GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*models.Subscription, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND customer_id = $2 AND deleted_at IS NULL ORDER BY created_at DESC`
	rows, err := db.QueryContext(ctx, query, companyID, customerID)
	if err != nil {
		return nil, fmt.Errorf("get by customer: %w", err)
	}
	defer rows.Close()
	return r.collectSubscriptions(rows)
}

func (r *subscriptionRepository) GetByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.Subscription, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND plan_id = $2 AND deleted_at IS NULL ORDER BY created_at DESC`
	rows, err := db.QueryContext(ctx, query, companyID, planID)
	if err != nil {
		return nil, fmt.Errorf("get by plan: %w", err)
	}
	defer rows.Close()
	return r.collectSubscriptions(rows)
}

func (r *subscriptionRepository) GetByStatus(ctx context.Context, db DBTX, companyID uuid.UUID, status enums.SubscriptionStatus) ([]*models.Subscription, error) {
	statusID := r.statusToID(status)
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND status_id = $2 AND deleted_at IS NULL ORDER BY created_at DESC`
	rows, err := db.QueryContext(ctx, query, companyID, statusID)
	if err != nil {
		return nil, fmt.Errorf("get by status: %w", err)
	}
	defer rows.Close()
	return r.collectSubscriptions(rows)
}

func (r *subscriptionRepository) GetExpiringBetween(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*models.Subscription, error) {
	query := r.buildSelectQuery() + `
		WHERE company_id = $1 AND end_date BETWEEN $2 AND $3 AND status_id = $4 AND deleted_at IS NULL
		ORDER BY end_date
	`
	activeID := r.statusToID(enums.SubStatusActive)
	rows, err := db.QueryContext(ctx, query, companyID, from, to, activeID)
	if err != nil {
		return nil, fmt.Errorf("get expiring between: %w", err)
	}
	defer rows.Close()
	return r.collectSubscriptions(rows)
}

func (r *subscriptionRepository) GetRenewalDue(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Subscription, error) {
	query := r.buildSelectQuery() + `
		WHERE company_id = $1 AND end_date <= $2 AND status_id = $3 AND auto_renew = true AND deleted_at IS NULL
		ORDER BY end_date
	`
	activeID := r.statusToID(enums.SubStatusActive)
	rows, err := db.QueryContext(ctx, query, companyID, before, activeID)
	if err != nil {
		return nil, fmt.Errorf("get renewal due: %w", err)
	}
	defer rows.Close()
	return r.collectSubscriptions(rows)
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *subscriptionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND subscription_id = $2 FOR UPDATE`
	var sub models.Subscription
	var statusID int
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID).Scan(
		&sub.SubscriptionID,
		&sub.CompanyID,
		&sub.CustomerID,
		&sub.PlanID,
		&statusID,
		&sub.StartDate,
		&sub.EndDate,
		&sub.TrialEnd,
		&sub.BillingStart,
		&sub.AutoRenew,
		&sub.PauseReason,
		&sub.CancellationReason,
		&sub.CancelledAt,
		&sub.ContractNumber,
		&sub.SignedAt,
		&sub.TermsVersion,
		&sub.SignedDocumentKey,
		&sub.CurrentInvoiceID,
		&sub.LastInvoiceID,
		&sub.NextInvoiceID,
		&sub.CouponID,
		&sub.Version,
		&sub.CreatedAt,
		&sub.UpdatedAt,
		&sub.DeletedAt,
		&sub.SalesOrderID,
		&sub.ScheduleID,
		&sub.WorkflowID,
		&sub.NotificationPrefID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	sub.Status = r.idToStatus(statusID)
	return &sub, nil
}

// -------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------

func (r *subscriptionRepository) buildSelectQuery() string {
	return `
		SELECT subscription_id, company_id, customer_id, plan_id, status_id,
		       start_date, end_date, trial_end, billing_start, auto_renew,
		       pause_reason, cancellation_reason, cancelled_at, contract_number,
		       signed_at, terms_version, signed_document_key,
		       current_invoice_id, last_invoice_id, next_invoice_id, coupon_id,
		       version, created_at, updated_at, deleted_at,
		       sales_order_id, schedule_id, workflow_id, notification_pref_id
		FROM subscription.subscriptions
	`
}

// collectSubscriptions reads rows, converts status_id, and returns slice.
func (r *subscriptionRepository) collectSubscriptions(rows *sql.Rows) ([]*models.Subscription, error) {
	var subs []*models.Subscription
	for rows.Next() {
		var sub models.Subscription
		var statusID int
		if err := rows.Scan(
			&sub.SubscriptionID,
			&sub.CompanyID,
			&sub.CustomerID,
			&sub.PlanID,
			&statusID,
			&sub.StartDate,
			&sub.EndDate,
			&sub.TrialEnd,
			&sub.BillingStart,
			&sub.AutoRenew,
			&sub.PauseReason,
			&sub.CancellationReason,
			&sub.CancelledAt,
			&sub.ContractNumber,
			&sub.SignedAt,
			&sub.TermsVersion,
			&sub.SignedDocumentKey,
			&sub.CurrentInvoiceID,
			&sub.LastInvoiceID,
			&sub.NextInvoiceID,
			&sub.CouponID,
			&sub.Version,
			&sub.CreatedAt,
			&sub.UpdatedAt,
			&sub.DeletedAt,
			&sub.SalesOrderID,
			&sub.ScheduleID,
			&sub.WorkflowID,
			&sub.NotificationPrefID,
		); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		sub.Status = r.idToStatus(statusID)
		subs = append(subs, &sub)
	}
	return subs, rows.Err()
}

// buildFilterConditions builds WHERE clause and args.
// It converts filter.Status (string enum) to status_id.
func (r *subscriptionRepository) buildFilterConditions(filter SubscriptionFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argPos))
		args = append(args, filter.CompanyID)
		argPos++
	}

	if len(filter.SubscriptionIDs) > 0 {
		placeholders := make([]string, len(filter.SubscriptionIDs))
		for i, id := range filter.SubscriptionIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("subscription_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.SubscriptionIDs)
	}

	if filter.CustomerID != nil {
		conditions = append(conditions, fmt.Sprintf("customer_id = $%d", argPos))
		args = append(args, *filter.CustomerID)
		argPos++
	}

	if filter.PlanID != nil {
		conditions = append(conditions, fmt.Sprintf("plan_id = $%d", argPos))
		args = append(args, *filter.PlanID)
		argPos++
	}

	if filter.Status != nil {
		statusID := r.statusToID(*filter.Status)
		conditions = append(conditions, fmt.Sprintf("status_id = $%d", argPos))
		args = append(args, statusID)
		argPos++
	}

	if filter.ContractNumber != nil {
		conditions = append(conditions, fmt.Sprintf("contract_number ILIKE $%d", argPos))
		args = append(args, "%"+*filter.ContractNumber+"%")
		argPos++
	}

	if filter.AutoRenew != nil {
		conditions = append(conditions, fmt.Sprintf("auto_renew = $%d", argPos))
		args = append(args, *filter.AutoRenew)
		argPos++
	}

	if filter.CouponID != nil {
		conditions = append(conditions, fmt.Sprintf("coupon_id = $%d", argPos))
		args = append(args, *filter.CouponID)
		argPos++
	}

	if filter.SalesOrderID != nil {
		conditions = append(conditions, fmt.Sprintf("sales_order_id = $%d", argPos))
		args = append(args, *filter.SalesOrderID)
		argPos++
	}

	addDateRange(&conditions, &args, &argPos, "start_date", filter.StartDateFrom, filter.StartDateTo)
	addDateRange(&conditions, &args, &argPos, "end_date", filter.EndDateFrom, filter.EndDateTo)
	addDateRange(&conditions, &args, &argPos, "billing_start", filter.BillingStartFrom, filter.BillingStartTo)
	addDateRange(&conditions, &args, &argPos, "trial_end", filter.TrialEndFrom, filter.TrialEndTo)
	addDateRange(&conditions, &args, &argPos, "cancelled_at", filter.CancelledFrom, filter.CancelledTo)
	addDateRange(&conditions, &args, &argPos, "created_at", filter.CreatedFrom, filter.CreatedTo)
	addDateRange(&conditions, &args, &argPos, "updated_at", filter.UpdatedFrom, filter.UpdatedTo)

	if !filter.Deleted {
		conditions = append(conditions, "deleted_at IS NULL")
	}
	// If Deleted is true, we include soft-deleted (no condition)

	return conditions, args
}

func addDateRange(conditions *[]string, args *[]interface{}, argPos *int, column string, from, to *time.Time) {
	if from != nil {
		*conditions = append(*conditions, fmt.Sprintf("%s >= $%d", column, *argPos))
		*args = append(*args, *from)
		*argPos++
	}
	if to != nil {
		*conditions = append(*conditions, fmt.Sprintf("%s <= $%d", column, *argPos))
		*args = append(*args, *to)
		*argPos++
	}
}
