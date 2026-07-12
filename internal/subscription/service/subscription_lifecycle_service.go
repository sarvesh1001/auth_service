// subscription/service/subscription_lifecycle_service.go
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// ----------------------------------------------------------------------------
// Interface
// ----------------------------------------------------------------------------

// SubscriptionLifecycleService handles all lifecycle transitions for subscriptions.
// It contains business workflows only (no CRUD).
type SubscriptionLifecycleService interface {
	// Activation
	Activate(ctx context.Context, req *ActivateSubscriptionRequest) (*models.Subscription, error)
	Reactivate(ctx context.Context, req *ReactivateSubscriptionRequest) (*models.Subscription, error)
	Suspend(ctx context.Context, req *SuspendSubscriptionRequest) (*models.Subscription, error)

	// Pause / Resume
	Pause(ctx context.Context, req *PauseSubscriptionRequest) (*models.Subscription, error)
	Resume(ctx context.Context, req *ResumeSubscriptionRequest) (*models.Subscription, error)

	// Renewal
	Renew(ctx context.Context, req *RenewSubscriptionRequest) (*models.Subscription, error)
	Expire(ctx context.Context, req *ExpireSubscriptionRequest) (*models.Subscription, error)

	// Plan Changes
	Upgrade(ctx context.Context, req *UpgradeSubscriptionRequest) (*models.Subscription, error)
	Downgrade(ctx context.Context, req *DowngradeSubscriptionRequest) (*models.Subscription, error)
	ChangePlan(ctx context.Context, req *ChangeSubscriptionPlanRequest) (*models.Subscription, error)

	// Cancellation
	Cancel(ctx context.Context, req *CancelSubscriptionRequest) (*models.Subscription, error)

	// Background Operations
	ProcessExpiredSubscriptions(ctx context.Context, asOf time.Time) error
	ProcessRenewals(ctx context.Context, asOf time.Time) error
	ProcessTrialExpirations(ctx context.Context, asOf time.Time) error
}

// ----------------------------------------------------------------------------
// Request / Response types
// ----------------------------------------------------------------------------

type ActivateSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	ActivatedBy    uuid.UUID
	Metadata       map[string]interface{}
}

type ReactivateSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	ActivatedBy    uuid.UUID
}

type SuspendSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	Reason         *string
	SuspendedBy    uuid.UUID
}

type PauseSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	Reason         *string
	PausedBy       uuid.UUID
}

type ResumeSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	ResumedBy      uuid.UUID
}

type RenewSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	RenewedBy      uuid.UUID
	NewEndDate     *time.Time
}

type ExpireSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	ExpiredBy      uuid.UUID
	EndDate        time.Time
}

type UpgradeSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	NewPlanID      uuid.UUID
	UpgradedBy     uuid.UUID
	Metadata       map[string]interface{}
}

type DowngradeSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	NewPlanID      uuid.UUID
	DowngradedBy   uuid.UUID
	Metadata       map[string]interface{}
}

type ChangeSubscriptionPlanRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	NewPlanID      uuid.UUID
	ChangedBy      uuid.UUID
	Metadata       map[string]interface{}
}

type CancelSubscriptionRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	Reason         *string
	CancelledBy    uuid.UUID
	Immediate      bool
}

// ----------------------------------------------------------------------------
// Service implementation
// ----------------------------------------------------------------------------

type subscriptionLifecycleService struct {
	subRepo            repository.SubscriptionRepository
	subItemRepo        repository.SubscriptionItemRepository
	timelineRepo       repository.TimelineRepository
	trialRepo          repository.TrialRepository
	usageRepo          repository.UsageRepository
	planRepo           repository.PlanRepository
	planItemRepo       repository.PlanItemRepository
	entitlementService EntitlementService
	validationService  SubscriptionValidationService
	billingEngine      *BillingEngineService
	auditService       *audit.AuditService
	outboxRepo         outbox.Repository
	idempotencyStore   idempotency.Store
	pgClient           *client.PostgresClient
	logger             *zap.Logger
}

func NewSubscriptionLifecycleService(
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	timelineRepo repository.TimelineRepository,
	trialRepo repository.TrialRepository,
	usageRepo repository.UsageRepository,
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository,
	entitlementService EntitlementService,
	validationService SubscriptionValidationService,
	billingEngine *BillingEngineService,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubscriptionLifecycleService {
	return &subscriptionLifecycleService{
		subRepo:            subRepo,
		subItemRepo:        subItemRepo,
		timelineRepo:       timelineRepo,
		trialRepo:          trialRepo,
		usageRepo:          usageRepo,
		planRepo:           planRepo,
		planItemRepo:       planItemRepo,
		entitlementService: entitlementService,
		validationService:  validationService,
		billingEngine:      billingEngine,
		auditService:       auditService,
		outboxRepo:         outboxRepo,
		idempotencyStore:   idempotencyStore,
		pgClient:           pgClient,
		logger:             logger.Named("subscription_lifecycle_service"),
	}
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func (s *subscriptionLifecycleService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *subscriptionLifecycleService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
	sqlTx, err := s.getSQLTx(tx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "subscription",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *subscriptionLifecycleService) updateSubscriptionStatus(
	ctx context.Context,
	tx repository.DBTX,
	companyID, subscriptionID uuid.UUID,
	newStatus enums.SubscriptionStatus,
	updatedBy uuid.UUID,
) error {
	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	oldStatus := sub.Status
	sub.Status = newStatus
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}
	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: subscriptionID,
		EventType:      mapStatusToTimelineEvent(newStatus),
		OldStatus:      &oldStatus,
		NewStatus:      &newStatus,
		PerformedBy:    &updatedBy,
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return err
	}
	return nil
}

func mapStatusToTimelineEvent(status enums.SubscriptionStatus) enums.TimelineEvent {
	switch status {
	case enums.SubStatusActive:
		return enums.EventActivated
	case enums.SubStatusPaused:
		return enums.EventPaused
	case enums.SubStatusExpired:
		return enums.EventExpired
	case enums.SubStatusCancelled:
		return enums.EventCancelled
	case enums.SubStatusTrial:
		return enums.EventTrialStart
	default:
		return enums.EventCreated
	}
}

// ----------------------------------------------------------------------------
// Activation
// ----------------------------------------------------------------------------

func (s *subscriptionLifecycleService) Activate(ctx context.Context, req *ActivateSubscriptionRequest) (*models.Subscription, error) {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("activate-%s", req.SubscriptionID.String()))
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription")
		return cached, nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		return nil, err
	}

	if err := s.validationService.ValidateActivation(ctx, sub); err != nil {
		return nil, err
	}

	oldStatus := sub.Status
	sub.Status = enums.SubStatusActive
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return nil, err
	}

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventActivated,
		OldStatus:      &oldStatus,
		NewStatus:      &sub.Status,
		PerformedBy:    &req.ActivatedBy,
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return nil, err
	}

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, events.EventSubscriptionActivated, payload); err != nil {
		logger.Warn("failed to emit activation event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// --- AFTER COMMIT: generate initial invoice (async) ---
	go func() {
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if sub.EndDate == nil {
			s.logger.Error("cannot generate initial invoice: end_date is nil",
				zap.String("subscription_id", sub.SubscriptionID.String()))
			return
		}
		_, err := s.billingEngine.GenerateInitialInvoice(
			ctxTimeout,
			req.CompanyID,
			sub.SubscriptionID,
			sub.StartDate,
			*sub.EndDate,
		)
		if err != nil {
			s.logger.Error("initial invoice generation failed",
				zap.String("subscription_id", sub.SubscriptionID.String()),
				zap.Error(err),
			)
		}
	}()

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "subscription", "activate", "subscription",
			&sub.SubscriptionID, "user", &req.ActivatedBy, nil, nil, map[string]interface{}{
				"old_status": oldStatus,
				"new_status": sub.Status,
			})
	}
	return sub, nil
}

func (s *subscriptionLifecycleService) Reactivate(ctx context.Context, req *ReactivateSubscriptionRequest) (*models.Subscription, error) {
	return s.Activate(ctx, &ActivateSubscriptionRequest{
		CompanyID:      req.CompanyID,
		SubscriptionID: req.SubscriptionID,
		ActivatedBy:    req.ActivatedBy,
	})
}

func (s *subscriptionLifecycleService) Suspend(ctx context.Context, req *SuspendSubscriptionRequest) (*models.Subscription, error) {
	logger := s.logger.With(zap.String("method", "Suspend"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("suspend-%s", req.SubscriptionID.String()))
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription")
		return cached, nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		return nil, err
	}

	if err := s.validationService.ValidatePause(ctx, sub); err != nil {
		return nil, err
	}

	oldStatus := sub.Status
	sub.Status = enums.SubStatusPaused
	sub.PauseReason = req.Reason
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return nil, err
	}

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventPaused,
		OldStatus:      &oldStatus,
		NewStatus:      &sub.Status,
		PerformedBy:    &req.SuspendedBy,
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return nil, err
	}

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, events.EventSubscriptionPaused, payload); err != nil {
		logger.Warn("failed to emit pause event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "subscription", "suspend", "subscription",
			&sub.SubscriptionID, "user", &req.SuspendedBy, nil, nil, map[string]interface{}{
				"reason": req.Reason,
			})
	}
	return sub, nil
}

// ----------------------------------------------------------------------------
// Pause / Resume
// ----------------------------------------------------------------------------

func (s *subscriptionLifecycleService) Pause(ctx context.Context, req *PauseSubscriptionRequest) (*models.Subscription, error) {
	return s.Suspend(ctx, &SuspendSubscriptionRequest{
		CompanyID:      req.CompanyID,
		SubscriptionID: req.SubscriptionID,
		Reason:         req.Reason,
		SuspendedBy:    req.PausedBy,
	})
}

func (s *subscriptionLifecycleService) Resume(ctx context.Context, req *ResumeSubscriptionRequest) (*models.Subscription, error) {
	logger := s.logger.With(zap.String("method", "Resume"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("resume-%s", req.SubscriptionID.String()))
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription")
		return cached, nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		return nil, err
	}

	if err := s.validationService.ValidateResume(ctx, sub); err != nil {
		return nil, err
	}

	oldStatus := sub.Status
	sub.Status = enums.SubStatusActive
	sub.PauseReason = nil
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return nil, err
	}

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventResumed,
		OldStatus:      &oldStatus,
		NewStatus:      &sub.Status,
		PerformedBy:    &req.ResumedBy,
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return nil, err
	}

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, events.EventSubscriptionResumed, payload); err != nil {
		logger.Warn("failed to emit resume event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "subscription", "resume", "subscription",
			&sub.SubscriptionID, "user", &req.ResumedBy, nil, nil, nil)
	}
	return sub, nil
}

// ----------------------------------------------------------------------------
// Renewal
// ----------------------------------------------------------------------------

func (s *subscriptionLifecycleService) Renew(ctx context.Context, req *RenewSubscriptionRequest) (*models.Subscription, error) {
	logger := s.logger.With(zap.String("method", "Renew"))

	// 1. Generate renewal invoice FIRST (before updating subscription)
	invoice, err := s.billingEngine.GenerateRenewalInvoice(ctx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		logger.Error("renewal invoice generation failed", zap.Error(err))
		return nil, fmt.Errorf("renewal invoice failed: %w", err)
	}
	logger.Info("renewal invoice generated", zap.String("invoice_id", invoice.InvoiceID.String()))

	// 2. Now proceed with subscription extension in its own transaction
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("renew-%s", req.SubscriptionID.String()))
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription")
		return cached, nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		return nil, err
	}

	// Determine new end date
	plan, err := s.planRepo.GetByID(ctx, tx, req.CompanyID, sub.PlanID)
	if err != nil {
		return nil, errors.ErrPlanNotFound
	}
	var newEndDate time.Time
	if req.NewEndDate != nil {
		newEndDate = *req.NewEndDate
	} else {
		base := sub.EndDate
		if base == nil {
			base = &sub.StartDate
		}
		newEndDate = base.AddDate(0, 0, plan.DurationDays)
	}

	if err := s.validationService.ValidateRenew(ctx, sub, newEndDate); err != nil {
		return nil, err
	}

	oldEndDate := sub.EndDate
	sub.EndDate = &newEndDate
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return nil, err
	}

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventRenewed,
		PerformedBy:    &req.RenewedBy,
		Metadata: map[string]interface{}{
			"old_end_date": oldEndDate,
			"new_end_date": newEndDate,
			"invoice_id":   invoice.InvoiceID.String(),
		},
		CreatedAt: time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return nil, err
	}

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, events.EventSubscriptionRenewed, payload); err != nil {
		logger.Warn("failed to emit renew event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "subscription", "renew", "subscription",
			&sub.SubscriptionID, "user", &req.RenewedBy, nil, nil, map[string]interface{}{
				"new_end_date": newEndDate,
			})
	}
	return sub, nil
}

func (s *subscriptionLifecycleService) Expire(ctx context.Context, req *ExpireSubscriptionRequest) (*models.Subscription, error) {
	logger := s.logger.With(zap.String("method", "Expire"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("expire-%s", req.SubscriptionID.String()))
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription")
		return cached, nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		return nil, err
	}

	if err := s.validationService.ValidateExpire(ctx, sub); err != nil {
		return nil, err
	}

	oldStatus := sub.Status
	sub.Status = enums.SubStatusExpired
	sub.EndDate = &req.EndDate
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return nil, err
	}

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventExpired,
		OldStatus:      &oldStatus,
		NewStatus:      &sub.Status,
		PerformedBy:    &req.ExpiredBy,
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return nil, err
	}

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, events.EventSubscriptionExpired, payload); err != nil {
		logger.Warn("failed to emit expire event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "subscription", "expire", "subscription",
			&sub.SubscriptionID, "user", &req.ExpiredBy, nil, nil, nil)
	}
	return sub, nil
}

// ----------------------------------------------------------------------------
// Plan Changes
// ----------------------------------------------------------------------------

// Upgrade upgrades the subscription to a new plan.

// Downgrade downgrades the subscription to a new plan.
func (s *subscriptionLifecycleService) Downgrade(ctx context.Context, req *DowngradeSubscriptionRequest) (*models.Subscription, error) {
	db := s.pgClient.DB

	oldSub, err := s.subRepo.GetByID(ctx, db, req.CompanyID, req.SubscriptionID)
	if err != nil {
		s.logger.Error("failed to get subscription for downgrade", zap.Error(err))
		return nil, err
	}
	if oldSub == nil {
		return nil, errors.ErrNotFound
	}

	oldPlan, err := s.planRepo.GetByID(ctx, db, req.CompanyID, oldSub.PlanID)
	if err != nil {
		s.logger.Error("failed to get old plan for downgrade", zap.Error(err))
		return nil, errors.ErrPlanNotFound
	}
	if oldPlan == nil {
		return nil, errors.ErrPlanNotFound
	}

	_, err = s.billingEngine.GenerateDowngradeInvoice(ctx, req.CompanyID, req.SubscriptionID, oldPlan.PlanID, req.NewPlanID, time.Now())
	if err != nil {
		s.logger.Error("downgrade invoice generation failed", zap.Error(err))
		return nil, fmt.Errorf("downgrade invoice failed: %w", err)
	}

	return s.changePlan(ctx, req.CompanyID, req.SubscriptionID, req.NewPlanID, req.DowngradedBy, events.EventSubscriptionDowngraded, req.Metadata)
}

// ChangePlan handles a general plan change (without upgrade/downgrade semantics).
func (s *subscriptionLifecycleService) ChangePlan(ctx context.Context, req *ChangeSubscriptionPlanRequest) (*models.Subscription, error) {
	db := s.pgClient.DB

	// 1. Get subscription to know the current plan
	sub, err := s.subRepo.GetByID(ctx, db, req.CompanyID, req.SubscriptionID)
	if err != nil {
		s.logger.Error("failed to get subscription for change plan", zap.Error(err))
		return nil, err
	}
	if sub == nil {
		return nil, errors.ErrNotFound
	}
	oldPlanID := sub.PlanID

	// 2. Get total prices for both plans
	oldPrice, err := s.planRepo.GetPlanTotalPrice(ctx, db, req.CompanyID, oldPlanID)
	if err != nil {
		s.logger.Error("failed to get old plan total price", zap.Error(err))
		return nil, err
	}
	newPrice, err := s.planRepo.GetPlanTotalPrice(ctx, db, req.CompanyID, req.NewPlanID)
	if err != nil {
		s.logger.Error("failed to get new plan total price", zap.Error(err))
		return nil, err
	}

	// 3. Generate the appropriate invoice
	var invoiceErr error
	switch {
	case newPrice.GreaterThan(oldPrice):
		_, invoiceErr = s.billingEngine.GenerateUpgradeInvoice(ctx, req.CompanyID, req.SubscriptionID, oldPlanID, req.NewPlanID, time.Now())
	case newPrice.LessThan(oldPrice):
		_, invoiceErr = s.billingEngine.GenerateDowngradeInvoice(ctx, req.CompanyID, req.SubscriptionID, oldPlanID, req.NewPlanID, time.Now())
	default:
		// Same price – generate a “change” invoice (or skip)
		_, invoiceErr = s.billingEngine.GenerateUpgradeInvoice(ctx, req.CompanyID, req.SubscriptionID, oldPlanID, req.NewPlanID, time.Now())
	}
	if invoiceErr != nil {
		s.logger.Error("plan change invoice generation failed", zap.Error(invoiceErr))
		return nil, fmt.Errorf("plan change invoice failed: %w", invoiceErr)
	}

	// 4. Proceed with the plan change
	return s.changePlan(ctx, req.CompanyID, req.SubscriptionID, req.NewPlanID, req.ChangedBy, events.EventSubscriptionChanged, req.Metadata)
}

// changePlan is the internal method for plan changes (after invoice generated).

// ----------------------------------------------------------------------------
// Cancellation
// ----------------------------------------------------------------------------

func (s *subscriptionLifecycleService) Cancel(ctx context.Context, req *CancelSubscriptionRequest) (*models.Subscription, error) {
	logger := s.logger.With(zap.String("method", "Cancel"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("cancel-%s", req.SubscriptionID.String()))
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription")
		return cached, nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.SubscriptionID)
	if err != nil {
		return nil, err
	}

	if err := s.validationService.ValidateCancel(ctx, sub); err != nil {
		return nil, err
	}

	oldStatus := sub.Status
	sub.Status = enums.SubStatusCancelled
	sub.CancellationReason = req.Reason
	now := time.Now()
	sub.CancelledAt = &now
	if req.Immediate {
		sub.EndDate = &now
	}
	sub.UpdatedAt = now
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return nil, err
	}

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventCancelled,
		OldStatus:      &oldStatus,
		NewStatus:      &sub.Status,
		PerformedBy:    &req.CancelledBy,
		CreatedAt:      now,
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		return nil, err
	}

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, events.EventSubscriptionCancelled, payload); err != nil {
		logger.Warn("failed to emit cancel event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "subscription", "cancel", "subscription",
			&sub.SubscriptionID, "user", &req.CancelledBy, nil, nil, map[string]interface{}{
				"reason": req.Reason,
			})
	}
	return sub, nil
}

// ----------------------------------------------------------------------------
// Background Operations
// ----------------------------------------------------------------------------

func (s *subscriptionLifecycleService) ProcessExpiredSubscriptions(ctx context.Context, asOf time.Time) error {
	db := s.pgClient.DB
	statuses := []enums.SubscriptionStatus{enums.SubStatusActive, enums.SubStatusTrial, enums.SubStatusPaused}
	for _, status := range statuses {
		subs, err := s.subRepo.GetByStatus(ctx, db, uuid.Nil, status)
		if err != nil {
			s.logger.Warn("failed to get subscriptions by status", zap.String("status", string(status)), zap.Error(err))
			continue
		}
		for _, sub := range subs {
			if sub.EndDate != nil && sub.EndDate.Before(asOf) && sub.Status != enums.SubStatusExpired && sub.Status != enums.SubStatusCancelled {
				req := &ExpireSubscriptionRequest{
					CompanyID:      sub.CompanyID,
					SubscriptionID: sub.SubscriptionID,
					ExpiredBy:      uuid.Nil,
					EndDate:        *sub.EndDate,
				}
				_, err := s.Expire(ctx, req)
				if err != nil {
					s.logger.Warn("failed to expire subscription", zap.String("sub_id", sub.SubscriptionID.String()), zap.Error(err))
				}
			}
		}
	}
	return nil
}

func (s *subscriptionLifecycleService) ProcessRenewals(ctx context.Context, asOf time.Time) error {
	db := s.pgClient.DB
	subs, err := s.subRepo.GetByStatus(ctx, db, uuid.Nil, enums.SubStatusActive)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if sub.AutoRenew && sub.EndDate != nil && sub.EndDate.Before(asOf) {
			req := &RenewSubscriptionRequest{
				CompanyID:      sub.CompanyID,
				SubscriptionID: sub.SubscriptionID,
				RenewedBy:      uuid.Nil,
			}
			_, err := s.Renew(ctx, req)
			if err != nil {
				s.logger.Warn("failed to renew subscription", zap.String("sub_id", sub.SubscriptionID.String()), zap.Error(err))
			}
		}
	}
	return nil
}

func (s *subscriptionLifecycleService) ProcessTrialExpirations(ctx context.Context, asOf time.Time) error {
	db := s.pgClient.DB
	trials, err := s.trialRepo.GetExpiredBefore(ctx, db, asOf)
	if err != nil {
		return err
	}
	for _, trial := range trials {
		sub, err := s.subRepo.GetByID(ctx, db, uuid.Nil, trial.SubscriptionID)
		if err != nil {
			s.logger.Warn("failed to get subscription for trial expiry", zap.String("trial_id", trial.TrialID.String()), zap.Error(err))
			continue
		}
		if sub.Status == enums.SubStatusTrial {
			req := &ExpireSubscriptionRequest{
				CompanyID:      sub.CompanyID,
				SubscriptionID: sub.SubscriptionID,
				ExpiredBy:      uuid.Nil,
				EndDate:        *trial.EndedAt,
			}
			_, err := s.Expire(ctx, req)
			if err != nil {
				s.logger.Warn("failed to expire trial", zap.String("trial_id", trial.TrialID.String()), zap.Error(err))
			}
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func getIDempotencyKey(ctx context.Context, fallback string) string {
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		return key
	}
	return fallback
}

func buildSubscriptionPayload(sub *models.Subscription) events.SubscriptionPayload {
	payload := events.SubscriptionPayload{
		SubscriptionID: sub.SubscriptionID.String(),
		CompanyID:      sub.CompanyID.String(),
		CustomerID:     sub.CustomerID.String(),
		PlanID:         sub.PlanID.String(),
		Status:         string(sub.Status),
		StartDate:      sub.StartDate.Format(time.RFC3339),
		AutoRenew:      sub.AutoRenew,
		Version:        sub.Version,
	}
	if sub.EndDate != nil {
		payload.EndDate = sub.EndDate.Format(time.RFC3339)
	}
	if sub.TrialEnd != nil {
		payload.TrialEnd = sub.TrialEnd.Format(time.RFC3339)
	}
	if sub.ContractNumber != nil {
		payload.ContractNumber = *sub.ContractNumber
	}
	if sub.CouponID != nil {
		payload.CouponID = sub.CouponID.String()
	}
	if sub.SalesOrderID != nil {
		payload.SalesOrderID = sub.SalesOrderID.String()
	}
	return payload
}

// Upgrade upgrades the subscription to a new plan.
func (s *subscriptionLifecycleService) Upgrade(ctx context.Context, req *UpgradeSubscriptionRequest) (*models.Subscription, error) {
	db := s.pgClient.DB
	logger := s.logger.With(
		zap.String("method", "Upgrade"),
		zap.String("subscription_id", req.SubscriptionID.String()),
		zap.String("new_plan_id", req.NewPlanID.String()),
	)
	logger.Info("starting upgrade")

	oldSub, err := s.subRepo.GetByID(ctx, db, req.CompanyID, req.SubscriptionID)
	if err != nil {
		logger.Error("failed to get subscription for upgrade", zap.Error(err))
		return nil, err
	}
	if oldSub == nil {
		logger.Error("subscription not found for upgrade")
		return nil, errors.ErrNotFound
	}
	logger.Info("retrieved existing subscription", zap.String("current_plan_id", oldSub.PlanID.String()))

	oldPlan, err := s.planRepo.GetByID(ctx, db, req.CompanyID, oldSub.PlanID)
	if err != nil {
		logger.Error("failed to get old plan for upgrade", zap.Error(err))
		return nil, errors.ErrPlanNotFound
	}
	if oldPlan == nil {
		logger.Error("old plan not found for upgrade")
		return nil, errors.ErrPlanNotFound
	}
	logger.Info("retrieved old plan", zap.String("old_plan_name", oldPlan.Name))

	_, err = s.billingEngine.GenerateUpgradeInvoice(ctx, req.CompanyID, req.SubscriptionID, oldPlan.PlanID, req.NewPlanID, time.Now())
	if err != nil {
		logger.Error("upgrade invoice generation failed", zap.Error(err))
		return nil, fmt.Errorf("upgrade invoice failed: %w", err)
	}
	logger.Info("upgrade invoice generated successfully")

	logger.Info("calling changePlan")
	sub, err := s.changePlan(ctx, req.CompanyID, req.SubscriptionID, req.NewPlanID, req.UpgradedBy, events.EventSubscriptionUpgraded, req.Metadata)
	if err != nil {
		logger.Error("changePlan failed", zap.Error(err))
		return nil, err
	}
	if sub == nil {
		logger.Error("changePlan returned nil subscription without error")
		return nil, errors.ErrNotFound
	}
	logger.Info("upgrade completed successfully", zap.String("new_plan_id", sub.PlanID.String()))
	return sub, nil
}

// changePlan is the internal method for plan changes (after invoice generated).
// changePlan is the internal method for plan changes (after invoice generated).
func (s *subscriptionLifecycleService) changePlan(
	ctx context.Context,
	companyID, subscriptionID, newPlanID uuid.UUID,
	changedBy uuid.UUID,
	eventType string,
	metadata map[string]interface{},
) (*models.Subscription, error) {
	logger := s.logger.With(
		zap.String("method", "changePlan"),
		zap.String("subscription_id", subscriptionID.String()),
		zap.String("new_plan_id", newPlanID.String()),
	)
	logger.Info("starting changePlan")

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("changeplan-%s", subscriptionID.String()))
	logger.Info("idempotency key used", zap.String("key", idempKey)) // ✅ Log at Info level

	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		// 🔥 FIX: Skip cache if it's the zero placeholder
		if cached.SubscriptionID != uuid.Nil {
			logger.Info("idempotent – returning cached subscription",
				zap.String("cached_subscription_id", cached.SubscriptionID.String()),
				zap.String("cached_plan_id", cached.PlanID.String()),
				zap.String("cached_status", string(cached.Status)),
			)
			return cached, nil
		}
		logger.Warn("cached subscription is zero placeholder, ignoring and proceeding with update",
			zap.String("cached_subscription_id", cached.SubscriptionID.String()),
		)
	}
	logger.Debug("no valid idempotency cache hit, proceeding")

	targetPlan, err := s.validationService.ValidatePlan(ctx, companyID, newPlanID)
	if err != nil {
		logger.Error("target plan validation failed", zap.Error(err))
		return nil, err
	}
	if targetPlan == nil {
		logger.Error("target plan validation returned nil")
		return nil, errors.ErrPlanNotFound
	}
	logger.Info("target plan validated", zap.String("target_plan_name", targetPlan.Name))

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		logger.Error("failed to get subscription for update", zap.Error(err))
		return nil, err
	}
	if sub == nil {
		logger.Error("subscription not found for update")
		return nil, errors.ErrNotFound
	}
	logger.Info("retrieved subscription for update", zap.String("current_plan_id", sub.PlanID.String()))

	// Validate based on event type
	switch eventType {
	case events.EventSubscriptionUpgraded:
		if err := s.validationService.ValidateUpgrade(ctx, sub, targetPlan); err != nil {
			logger.Error("upgrade validation failed", zap.Error(err))
			return nil, err
		}
	case events.EventSubscriptionDowngraded:
		if err := s.validationService.ValidateDowngrade(ctx, sub, targetPlan); err != nil {
			logger.Error("downgrade validation failed", zap.Error(err))
			return nil, err
		}
	default:
		if err := s.validationService.ValidatePlanChange(ctx, sub, targetPlan); err != nil {
			logger.Error("plan change validation failed", zap.Error(err))
			return nil, err
		}
	}
	logger.Info("validation passed")

	oldPlanID := sub.PlanID
	sub.PlanID = newPlanID
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		logger.Error("failed to update subscription plan", zap.Error(err))
		return nil, err
	}
	logger.Info("subscription plan updated", zap.String("old_plan_id", oldPlanID.String()))

	timeline := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: sub.SubscriptionID,
		EventType:      enums.EventChanged,
		PerformedBy:    &changedBy,
		Metadata: map[string]interface{}{
			"old_plan_id": oldPlanID,
			"new_plan_id": newPlanID,
			"change_type": eventType,
		},
		CreatedAt: time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, timeline); err != nil {
		logger.Error("failed to create timeline", zap.Error(err))
		return nil, err
	}
	logger.Info("timeline created")

	payload := buildSubscriptionPayload(sub)
	if err := s.emitEvent(ctx, tx, sub.SubscriptionID, eventType, payload); err != nil {
		logger.Warn("failed to emit plan change event", zap.Error(err))
	}

	// Store the updated subscription in idempotency cache
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, sub); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("plan changed successfully",
		zap.String("old_plan_id", oldPlanID.String()),
		zap.String("new_plan_id", newPlanID.String()),
	)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "subscription", "change_plan", "subscription",
			&sub.SubscriptionID, "user", &changedBy, nil, nil, map[string]interface{}{
				"old_plan_id": oldPlanID,
				"new_plan_id": newPlanID,
			})
	}

	return sub, nil
}
