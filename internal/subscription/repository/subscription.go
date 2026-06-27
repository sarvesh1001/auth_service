// repository/subscription.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// SubscriptionRepository Interface
// ---------------------------------------------------------------------

type SubscriptionRepository interface {
	// ---------------------------------------------------------------------
	// CRUD
	// ---------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, subscription *models.Subscription) error
	Update(ctx context.Context, db DBTX, subscription *models.Subscription) error
	Delete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error

	// ---------------------------------------------------------------------
	// Single Fetch
	// ---------------------------------------------------------------------

	GetByID(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)
	GetByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (*models.Subscription, error)

	// ---------------------------------------------------------------------
	// Aggregate Loading
	// ---------------------------------------------------------------------

	GetWithItems(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)
	GetComplete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)

	// ---------------------------------------------------------------------
	// Listing
	// ---------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter SubscriptionFilter, p Pagination, s Sort) ([]*models.Subscription, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Subscription, error)
	ListExpired(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Subscription, error)
	ListDueForRenewal(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Subscription, error)
	ListBySubscriber(ctx context.Context, db DBTX, companyID, subscriberID uuid.UUID, subscriberTypeID int16) ([]*models.Subscription, error)

	// ---------------------------------------------------------------------
	// Status Transitions
	// ---------------------------------------------------------------------

	UpdateStatus(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, statusID int16, updatedBy *uuid.UUID) error
	Activate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) error
	Suspend(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason string, updatedBy *uuid.UUID) error
	Pause(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason string, updatedBy *uuid.UUID) error
	Resume(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) error
	Cancel(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason string, updatedBy *uuid.UUID) error
	Expire(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) error

	// ---------------------------------------------------------------------
	// Date Updates
	// ---------------------------------------------------------------------

	UpdateNextBillingDate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, nextBillingDate time.Time, updatedBy *uuid.UUID) error
	UpdateEndDate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, endDate time.Time, updatedBy *uuid.UUID) error
	UpdateTrialEnd(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, trialEnd time.Time, updatedBy *uuid.UUID) error

	// ---------------------------------------------------------------------
	// Invoice References
	// ---------------------------------------------------------------------

	UpdateCurrentInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error
	UpdateLastInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error
	UpdateNextInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error

	// ---------------------------------------------------------------------
	// Contract Management
	// ---------------------------------------------------------------------

	UpdateContract(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, contractNumber string, signedAt *time.Time, termsVersion string, documentKey string, updatedBy *uuid.UUID) error

	// ---------------------------------------------------------------------
	// Version Management
	// ---------------------------------------------------------------------

	IncrementVersion(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) (int, error)

	// ---------------------------------------------------------------------
	// Validation
	// ---------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error)
	ExistsByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (bool, error)

	// ---------------------------------------------------------------------
	// Search
	// ---------------------------------------------------------------------

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Subscription, int64, error)

	// ---------------------------------------------------------------------
	// Locking
	// ---------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type SubscriptionFilter struct {
	CompanyID        uuid.UUID
	SubscriptionIDs  []uuid.UUID
	SubscriberID     *uuid.UUID
	SubscriberTypeID *int16
	PlanID           *uuid.UUID
	StatusID         *int16
	AutoRenew        *bool
	ContractNumber   *string
	CouponID         *uuid.UUID

	StartDateFrom *time.Time
	StartDateTo   *time.Time
	EndDateFrom   *time.Time
	EndDateTo     *time.Time

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type subscriptionRepository struct {
	logger *zap.Logger
}

func NewSubscriptionRepository(logger *zap.Logger) SubscriptionRepository {
	return &subscriptionRepository{
		logger: logger.Named("subscription_repo"),
	}
}

const subscriptionTable = "subscription.subscriptions"

func (r *subscriptionRepository) nullUUID(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *subscriptionRepository) nullString(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func (r *subscriptionRepository) nullTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

func (r *subscriptionRepository) scanSubscription(s scanner) (*models.Subscription, error) {
	var sub models.Subscription
	var endDate, trialEnd, cancelledAt, signedAt, deletedAt sql.NullTime
	var pauseReason, cancellationReason, contractNumber, termsVersion, signedDocumentKey sql.NullString
	var currentInvoiceID, lastInvoiceID, nextInvoiceID, couponID sql.NullString

	err := s.Scan(
		&sub.SubscriptionID,
		&sub.CompanyID,
		&sub.SubscriberTypeID,
		&sub.SubscriberID,
		&sub.PlanID,
		&sub.StatusID,
		&sub.StartDate,
		&endDate,
		&trialEnd,
		&sub.BillingStart,
		&sub.AutoRenew,
		&pauseReason,
		&cancellationReason,
		&cancelledAt,
		&contractNumber,
		&signedAt,
		&termsVersion,
		&signedDocumentKey,
		&currentInvoiceID,
		&lastInvoiceID,
		&nextInvoiceID,
		&couponID,
		&sub.Version,
		&sub.CreatedAt,
		&sub.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan subscription: %w", err)
	}

	if endDate.Valid {
		sub.EndDate = &endDate.Time
	}
	if trialEnd.Valid {
		sub.TrialEnd = &trialEnd.Time
	}
	if cancelledAt.Valid {
		sub.CancelledAt = &cancelledAt.Time
	}
	if signedAt.Valid {
		sub.SignedAt = &signedAt.Time
	}
	if pauseReason.Valid {
		sub.PauseReason = &pauseReason.String
	}
	if cancellationReason.Valid {
		sub.CancellationReason = &cancellationReason.String
	}
	if contractNumber.Valid {
		sub.ContractNumber = &contractNumber.String
	}
	if termsVersion.Valid {
		sub.TermsVersion = &termsVersion.String
	}
	if signedDocumentKey.Valid {
		sub.SignedDocumentKey = &signedDocumentKey.String
	}
	if currentInvoiceID.Valid {
		if uid, err := uuid.Parse(currentInvoiceID.String); err == nil {
			sub.CurrentInvoiceID = &uid
		}
	}
	if lastInvoiceID.Valid {
		if uid, err := uuid.Parse(lastInvoiceID.String); err == nil {
			sub.LastInvoiceID = &uid
		}
	}
	if nextInvoiceID.Valid {
		if uid, err := uuid.Parse(nextInvoiceID.String); err == nil {
			sub.NextInvoiceID = &uid
		}
	}
	if couponID.Valid {
		if uid, err := uuid.Parse(couponID.String); err == nil {
			sub.CouponID = &uid
		}
	}
	if deletedAt.Valid {
		sub.DeletedAt.Time = deletedAt.Time
		sub.DeletedAt.Valid = true
	}

	return &sub, nil
}

func (r *subscriptionRepository) buildSubscriptionFilter(filter SubscriptionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if len(filter.SubscriptionIDs) > 0 {
		placeholders := make([]string, len(filter.SubscriptionIDs))
		for i, id := range filter.SubscriptionIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("subscription_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.SubscriberID != nil {
		conds = append(conds, fmt.Sprintf("subscriber_id = $%d", idx))
		args = append(args, *filter.SubscriberID)
		idx++
	}

	if filter.SubscriberTypeID != nil {
		conds = append(conds, fmt.Sprintf("subscriber_type_id = $%d", idx))
		args = append(args, *filter.SubscriberTypeID)
		idx++
	}

	if filter.PlanID != nil {
		conds = append(conds, fmt.Sprintf("plan_id = $%d", idx))
		args = append(args, *filter.PlanID)
		idx++
	}

	if filter.StatusID != nil {
		conds = append(conds, fmt.Sprintf("status_id = $%d", idx))
		args = append(args, *filter.StatusID)
		idx++
	}

	if filter.AutoRenew != nil {
		conds = append(conds, fmt.Sprintf("auto_renew = $%d", idx))
		args = append(args, *filter.AutoRenew)
		idx++
	}

	if filter.ContractNumber != nil {
		conds = append(conds, fmt.Sprintf("contract_number = $%d", idx))
		args = append(args, *filter.ContractNumber)
		idx++
	}

	if filter.CouponID != nil {
		conds = append(conds, fmt.Sprintf("coupon_id = $%d", idx))
		args = append(args, *filter.CouponID)
		idx++
	}

	if filter.StartDateFrom != nil {
		conds = append(conds, fmt.Sprintf("start_date >= $%d", idx))
		args = append(args, *filter.StartDateFrom)
		idx++
	}
	if filter.StartDateTo != nil {
		conds = append(conds, fmt.Sprintf("start_date <= $%d", idx))
		args = append(args, *filter.StartDateTo)
		idx++
	}

	if filter.EndDateFrom != nil {
		conds = append(conds, fmt.Sprintf("end_date >= $%d", idx))
		args = append(args, *filter.EndDateFrom)
		idx++
	}
	if filter.EndDateTo != nil {
		conds = append(conds, fmt.Sprintf("end_date <= $%d", idx))
		args = append(args, *filter.EndDateTo)
		idx++
	}

	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}

	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}

	conds = append(conds, "deleted_at IS NULL")

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var subscriptionAllowedSort = map[string]bool{
	"subscription_id":    true,
	"subscriber_type_id": true,
	"plan_id":            true,
	"status_id":          true,
	"start_date":         true,
	"end_date":           true,
	"billing_start":      true,
	"auto_renew":         true,
	"version":            true,
	"created_at":         true,
	"updated_at":         true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *subscriptionRepository) Create(ctx context.Context, db DBTX, subscription *models.Subscription) error {
	query := `
		INSERT INTO subscription.subscriptions (
			subscription_id, company_id, subscriber_type_id, subscriber_id,
			plan_id, status_id, start_date, end_date, trial_end,
			billing_start, auto_renew, pause_reason, cancellation_reason,
			cancelled_at, contract_number, signed_at, terms_version,
			signed_document_key, current_invoice_id, last_invoice_id,
			next_invoice_id, coupon_id, version, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22, $23, NOW(), NOW()
		)
		RETURNING created_at, updated_at
	`

	row := db.QueryRowContext(ctx, query,
		subscription.SubscriptionID,
		subscription.CompanyID,
		subscription.SubscriberTypeID,
		subscription.SubscriberID,
		subscription.PlanID,
		subscription.StatusID,
		subscription.StartDate,
		subscription.EndDate,
		subscription.TrialEnd,
		subscription.BillingStart,
		subscription.AutoRenew,
		r.nullString(subscription.PauseReason),
		r.nullString(subscription.CancellationReason),
		subscription.CancelledAt,
		r.nullString(subscription.ContractNumber),
		subscription.SignedAt,
		r.nullString(subscription.TermsVersion),
		r.nullString(subscription.SignedDocumentKey),
		r.nullUUID(subscription.CurrentInvoiceID),
		r.nullUUID(subscription.LastInvoiceID),
		r.nullUUID(subscription.NextInvoiceID),
		r.nullUUID(subscription.CouponID),
		subscription.Version,
	)

	if err := row.Scan(&subscription.CreatedAt, &subscription.UpdatedAt); err != nil {
		return fmt.Errorf("create subscription: %w", err)
	}
	return nil
}

func (r *subscriptionRepository) Update(ctx context.Context, db DBTX, subscription *models.Subscription) error {
	query := `
		UPDATE subscription.subscriptions SET
			subscriber_type_id = $3,
			subscriber_id = $4,
			plan_id = $5,
			status_id = $6,
			start_date = $7,
			end_date = $8,
			trial_end = $9,
			billing_start = $10,
			auto_renew = $11,
			pause_reason = $12,
			cancellation_reason = $13,
			cancelled_at = $14,
			contract_number = $15,
			signed_at = $16,
			terms_version = $17,
			signed_document_key = $18,
			current_invoice_id = $19,
			last_invoice_id = $20,
			next_invoice_id = $21,
			coupon_id = $22,
			version = version + 1,
			updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
		RETURNING updated_at
	`

	err := db.QueryRowContext(ctx, query,
		subscription.SubscriptionID,
		subscription.CompanyID,
		subscription.SubscriberTypeID,
		subscription.SubscriberID,
		subscription.PlanID,
		subscription.StatusID,
		subscription.StartDate,
		subscription.EndDate,
		subscription.TrialEnd,
		subscription.BillingStart,
		subscription.AutoRenew,
		r.nullString(subscription.PauseReason),
		r.nullString(subscription.CancellationReason),
		subscription.CancelledAt,
		r.nullString(subscription.ContractNumber),
		subscription.SignedAt,
		r.nullString(subscription.TermsVersion),
		r.nullString(subscription.SignedDocumentKey),
		r.nullUUID(subscription.CurrentInvoiceID),
		r.nullUUID(subscription.LastInvoiceID),
		r.nullUUID(subscription.NextInvoiceID),
		r.nullUUID(subscription.CouponID),
	).Scan(&subscription.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update subscription: %w", err)
	}
	subscription.Version++
	return nil
}

func (r *subscriptionRepository) Delete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) error {
	query := `UPDATE subscription.subscriptions SET deleted_at = NOW() WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID)
	if err != nil {
		return fmt.Errorf("soft delete subscription: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *subscriptionRepository) GetByID(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	query := `
		SELECT subscription_id, company_id, subscriber_type_id, subscriber_id,
			plan_id, status_id, start_date, end_date, trial_end,
			billing_start, auto_renew, pause_reason, cancellation_reason,
			cancelled_at, contract_number, signed_at, terms_version,
			signed_document_key, current_invoice_id, last_invoice_id,
			next_invoice_id, coupon_id, version, created_at, updated_at,
			deleted_at
		FROM subscription.subscriptions
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, subscriptionID, companyID)
	return r.scanSubscription(row)
}

func (r *subscriptionRepository) GetByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (*models.Subscription, error) {
	query := `
		SELECT subscription_id, company_id, subscriber_type_id, subscriber_id,
			plan_id, status_id, start_date, end_date, trial_end,
			billing_start, auto_renew, pause_reason, cancellation_reason,
			cancelled_at, contract_number, signed_at, terms_version,
			signed_document_key, current_invoice_id, last_invoice_id,
			next_invoice_id, coupon_id, version, created_at, updated_at,
			deleted_at
		FROM subscription.subscriptions
		WHERE company_id = $1 AND contract_number = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, contractNumber)
	return r.scanSubscription(row)
}

// ---------------------------------------------------------------------
// Aggregate Loading
// ---------------------------------------------------------------------

func (r *subscriptionRepository) GetWithItems(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	sub, err := r.GetByID(ctx, db, companyID, subscriptionID)
	if err != nil {
		return nil, err
	}

	itemRepo := NewSubscriptionItemRepository(r.logger)
	items, _, err := itemRepo.List(ctx, db, SubscriptionItemFilter{
		SubscriptionID: subscriptionID,
	}, Pagination{Limit: 1000}, Sort{})
	if err != nil {
		return nil, fmt.Errorf("load subscription items: %w", err)
	}

	sub.Items = make([]models.SubscriptionItem, len(items))
	for i, item := range items {
		if item != nil {
			sub.Items[i] = *item
		}
	}
	return sub, nil
}

func (r *subscriptionRepository) GetComplete(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	sub, err := r.GetWithItems(ctx, db, companyID, subscriptionID)
	if err != nil {
		return nil, err
	}

	timelineRepo := NewSubscriptionTimelineRepository(r.logger)
	timeline, _, err := timelineRepo.ListBySubscription(ctx, db, subscriptionID, Pagination{Limit: 100}, Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return nil, fmt.Errorf("load timeline: %w", err)
	}

	sub.Timeline = make([]models.SubscriptionTimeline, len(timeline))
	for i, t := range timeline {
		if t != nil {
			sub.Timeline[i] = *t
		}
	}
	return sub, nil
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *subscriptionRepository) List(ctx context.Context, db DBTX, filter SubscriptionFilter, p Pagination, s Sort) ([]*models.Subscription, int64, error) {
	where, args := r.buildSubscriptionFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("company_id is required in filter")
	}

	orderBy, err := validateSort(s, subscriptionAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", subscriptionTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count subscriptions: %w", err)
	}
	if total == 0 {
		return []*models.Subscription{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT subscription_id, company_id, subscriber_type_id, subscriber_id,
			plan_id, status_id, start_date, end_date, trial_end,
			billing_start, auto_renew, pause_reason, cancellation_reason,
			cancelled_at, contract_number, signed_at, terms_version,
			signed_document_key, current_invoice_id, last_invoice_id,
			next_invoice_id, coupon_id, version, created_at, updated_at,
			deleted_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, subscriptionTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list subscriptions: %w", err)
	}
	defer rows.Close()

	var result []*models.Subscription
	for rows.Next() {
		sub, err := r.scanSubscription(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, sub)
	}
	return result, total, rows.Err()
}

func (r *subscriptionRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Subscription, error) {
	// status_id = 1 (active)
	statusID := int16(1)
	filter := SubscriptionFilter{
		CompanyID: companyID,
		StatusID:  &statusID,
	}
	subs, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return subs, err
}

func (r *subscriptionRepository) ListExpired(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Subscription, error) {
	// status_id = 3 (expired)
	statusID := int16(3)
	filter := SubscriptionFilter{
		CompanyID: companyID,
		StatusID:  &statusID,
	}
	subs, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "end_date", Direction: "ASC"})
	return subs, err
}

func (r *subscriptionRepository) ListDueForRenewal(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Subscription, error) {
	// Find active subscriptions that auto-renew and have end_date before the given time
	activeStatus := int16(1)
	filter := SubscriptionFilter{
		CompanyID: companyID,
		StatusID:  &activeStatus,
		AutoRenew: ptrBool(true),
		EndDateTo: &before,
	}
	subs, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "end_date", Direction: "ASC"})
	return subs, err
}

func (r *subscriptionRepository) ListBySubscriber(ctx context.Context, db DBTX, companyID, subscriberID uuid.UUID, subscriberTypeID int16) ([]*models.Subscription, error) {
	filter := SubscriptionFilter{
		CompanyID:        companyID,
		SubscriberID:     &subscriberID,
		SubscriberTypeID: &subscriberTypeID,
	}
	subs, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return subs, err
}

// ---------------------------------------------------------------------
// Status Transitions
// ---------------------------------------------------------------------

func (r *subscriptionRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, statusID int16, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET status_id = $3, updated_at = NOW(), version = version + 1
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, statusID)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionRepository) Activate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) error {
	// status_id = 1 (active)
	return r.UpdateStatus(ctx, db, companyID, subscriptionID, 1, updatedBy)
}

func (r *subscriptionRepository) Suspend(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason string, updatedBy *uuid.UUID) error {
	// status_id = 2 (paused)
	if err := r.UpdateStatus(ctx, db, companyID, subscriptionID, 2, updatedBy); err != nil {
		return err
	}
	// Update pause reason
	query := `UPDATE subscription.subscriptions SET pause_reason = $3, updated_at = NOW() WHERE subscription_id = $1 AND company_id = $2`
	_, err := db.ExecContext(ctx, query, subscriptionID, companyID, reason)
	return err
}

func (r *subscriptionRepository) Pause(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason string, updatedBy *uuid.UUID) error {
	return r.Suspend(ctx, db, companyID, subscriptionID, reason, updatedBy)
}

func (r *subscriptionRepository) Resume(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) error {
	// status_id = 1 (active)
	if err := r.UpdateStatus(ctx, db, companyID, subscriptionID, 1, updatedBy); err != nil {
		return err
	}
	// Clear pause reason
	query := `UPDATE subscription.subscriptions SET pause_reason = NULL, updated_at = NOW() WHERE subscription_id = $1 AND company_id = $2`
	_, err := db.ExecContext(ctx, query, subscriptionID, companyID)
	return err
}

func (r *subscriptionRepository) Cancel(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, reason string, updatedBy *uuid.UUID) error {
	// status_id = 4 (cancelled)
	if err := r.UpdateStatus(ctx, db, companyID, subscriptionID, 4, updatedBy); err != nil {
		return err
	}
	// Update cancellation reason and timestamp
	now := time.Now()
	query := `
		UPDATE subscription.subscriptions
		SET cancellation_reason = $3, cancelled_at = $4, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2
	`
	_, err := db.ExecContext(ctx, query, subscriptionID, companyID, reason, now)
	return err
}

func (r *subscriptionRepository) Expire(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) error {
	// status_id = 3 (expired)
	return r.UpdateStatus(ctx, db, companyID, subscriptionID, 3, updatedBy)
}

// ---------------------------------------------------------------------
// Date Updates
// ---------------------------------------------------------------------

func (r *subscriptionRepository) UpdateNextBillingDate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, nextBillingDate time.Time, updatedBy *uuid.UUID) error {
	// We don't have a dedicated next_billing_date column; we use billing_start
	query := `
		UPDATE subscription.subscriptions
		SET billing_start = $3, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, nextBillingDate)
	if err != nil {
		return fmt.Errorf("update billing start: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionRepository) UpdateEndDate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, endDate time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET end_date = $3, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, endDate)
	if err != nil {
		return fmt.Errorf("update end date: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionRepository) UpdateTrialEnd(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, trialEnd time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET trial_end = $3, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, trialEnd)
	if err != nil {
		return fmt.Errorf("update trial end: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Invoice References
// ---------------------------------------------------------------------

func (r *subscriptionRepository) UpdateCurrentInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET current_invoice_id = $3, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("update current invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionRepository) UpdateLastInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET last_invoice_id = $3, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("update last invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionRepository) UpdateNextInvoice(ctx context.Context, db DBTX, companyID, subscriptionID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET next_invoice_id = $3, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, subscriptionID, companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("update next invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Contract Management
// ---------------------------------------------------------------------

func (r *subscriptionRepository) UpdateContract(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, contractNumber string, signedAt *time.Time, termsVersion string, documentKey string, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscriptions
		SET contract_number = $3, signed_at = $4, terms_version = $5,
			signed_document_key = $6, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query,
		subscriptionID, companyID,
		contractNumber, signedAt, termsVersion, documentKey,
	)
	if err != nil {
		return fmt.Errorf("update contract: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Version Management
// ---------------------------------------------------------------------

func (r *subscriptionRepository) IncrementVersion(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, updatedBy *uuid.UUID) (int, error) {
	var version int
	query := `
		UPDATE subscription.subscriptions
		SET version = version + 1, updated_at = NOW()
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
		RETURNING version
	`
	err := db.QueryRowContext(ctx, query, subscriptionID, companyID).Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.ErrNotFound
		}
		return 0, fmt.Errorf("increment version: %w", err)
	}
	return version, nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *subscriptionRepository) Exists(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscriptions WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, subscriptionID, companyID).Scan(&exists)
	return exists, err
}

func (r *subscriptionRepository) ExistsByContractNumber(ctx context.Context, db DBTX, companyID uuid.UUID, contractNumber string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscriptions WHERE company_id = $1 AND contract_number = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, contractNumber).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *subscriptionRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Subscription, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE company_id = $1 AND deleted_at IS NULL AND (contract_number ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", subscriptionTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search subscriptions count: %w", err)
	}
	if total == 0 {
		return []*models.Subscription{}, 0, nil
	}

	baseQuery := `
		SELECT subscription_id, company_id, subscriber_type_id, subscriber_id,
			plan_id, status_id, start_date, end_date, trial_end,
			billing_start, auto_renew, pause_reason, cancellation_reason,
			cancelled_at, contract_number, signed_at, terms_version,
			signed_document_key, current_invoice_id, last_invoice_id,
			next_invoice_id, coupon_id, version, created_at, updated_at,
			deleted_at
		FROM subscription.subscriptions
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search subscriptions: %w", err)
	}
	defer rows.Close()

	var result []*models.Subscription
	for rows.Next() {
		sub, err := r.scanSubscription(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, sub)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *subscriptionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	query := `
		SELECT subscription_id, company_id, subscriber_type_id, subscriber_id,
			plan_id, status_id, start_date, end_date, trial_end,
			billing_start, auto_renew, pause_reason, cancellation_reason,
			cancelled_at, contract_number, signed_at, terms_version,
			signed_document_key, current_invoice_id, last_invoice_id,
			next_invoice_id, coupon_id, version, created_at, updated_at,
			deleted_at
		FROM subscription.subscriptions
		WHERE subscription_id = $1 AND company_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, subscriptionID, companyID)
	return r.scanSubscription(row)
}
