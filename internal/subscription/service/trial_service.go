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

// -------------------------------------------------------------------------
// TrialService Interface
// -------------------------------------------------------------------------

type TrialService interface {
	// CRUD
	Create(ctx context.Context, companyID uuid.UUID, trial *models.Trial) error
	Update(ctx context.Context, trial *models.Trial) error
	Delete(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error
	GetByID(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) (*models.Trial, error)
	GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) (*models.Trial, error)

	// Lifecycle
	Start(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error
	End(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error
	Extend(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, additionalDays int) error
	Convert(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error
	Expire(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error
	Cancel(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error

	// Trial Configuration
	UpdateTrialDays(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, days int) error
	UpdateStartDate(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, startDate time.Time) error
	UpdateEndDate(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, endDate time.Time) error
	UpdateUsage(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, usage models.JSONB) error
	UpdateFeatures(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, features models.JSONB) error

	// Validation
	Validate(ctx context.Context, trial *models.Trial) error
	Exists(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) (bool, error)
	IsEligible(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, planID uuid.UUID) (bool, error)
	CanExtend(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error
	CanConvert(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error

	// Query
	List(ctx context.Context, filter repository.TrialFilter, p repository.Pagination, s repository.Sort) ([]*models.Trial, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Trial, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Trial, error)
	GetExpired(ctx context.Context, companyID uuid.UUID) ([]*models.Trial, error)
	GetConverted(ctx context.Context, companyID uuid.UUID) ([]*models.Trial, error)
	GetExpiring(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Trial, error)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type trialService struct {
	trialRepo        repository.TrialRepository
	subRepo          repository.SubscriptionRepository
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewTrialService(
	trialRepo repository.TrialRepository,
	subRepo repository.SubscriptionRepository,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) TrialService {
	return &trialService{
		trialRepo:        trialRepo,
		subRepo:          subRepo,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		pgClient:         pgClient,
		logger:           logger.Named("trial_service"),
	}
}

// helpers
func (s *trialService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *trialService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "trial",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func getTrialIdempotencyKey(ctx context.Context, fallback string) string {
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		return key
	}
	return fallback
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

// Create now requires companyID to verify subscription ownership.
func (s *trialService) Create(ctx context.Context, companyID uuid.UUID, trial *models.Trial) error {
	logger := s.logger.With(zap.String("method", "Create"), zap.String("company_id", companyID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.Validate(ctx, trial); err != nil {
		return err
	}

	// Ensure TrialID is set
	if trial.TrialID == uuid.Nil {
		trial.TrialID = uuid.New()
		logger.Debug("generated new trial ID", zap.String("trial_id", trial.TrialID.String()))
	}

	// Set timestamps if not already set
	now := time.Now()
	if trial.CreatedAt.IsZero() {
		trial.CreatedAt = now
	}
	if trial.UpdatedAt.IsZero() {
		trial.UpdatedAt = now
	}

	// Verify subscription exists and belongs to the company
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil {
		return err
	}
	if sub == nil || sub.CompanyID != companyID {
		logger.Warn("subscription not found or does not belong to company",
			zap.String("subscription_id", trial.SubscriptionID.String()))
		return errors.ErrSubscriptionNotFound
	}

	if err := s.trialRepo.Create(ctx, tx, trial); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "create", "trial",
			&trial.TrialID, "system", nil, nil, nil, map[string]interface{}{
				"subscription_id": trial.SubscriptionID,
				"trial_days":      trial.TrialDays,
			})
	}
	return nil
}

func (s *trialService) Update(ctx context.Context, trial *models.Trial) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.Validate(ctx, trial); err != nil {
		return err
	}

	trial.UpdatedAt = time.Now()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("update-trial-%s", trial.TrialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping update")
		return nil
	}

	if err := s.trialRepo.Update(ctx, tx, trial); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "trial", "update", "trial",
			&trial.TrialID, "system", nil, nil, nil, map[string]interface{}{
				"trial_days": trial.TrialDays,
			})
	}
	return nil
}

func (s *trialService) Delete(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("delete-trial-%s", trialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping delete")
		return nil
	}

	trial, err := s.trialRepo.GetByID(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	if err := s.trialRepo.Delete(ctx, tx, trialID); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "delete", "trial",
			&trialID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *trialService) GetByID(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) (*models.Trial, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	trial, err := s.trialRepo.GetByID(ctx, tx, trialID)
	if err != nil {
		return nil, err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return nil, errors.ErrPermissionDenied
	}
	return trial, nil
}

func (s *trialService) GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) (*models.Trial, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	return s.trialRepo.GetBySubscription(ctx, tx, subscriptionID)
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (s *trialService) Start(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Start"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("start-trial-%s", trialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping start")
		return nil
	}

	trial, err := s.trialRepo.GetByIDForUpdate(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	if trial.Status != enums.TrialActive {
		return errors.ErrInvalidState
	}

	if err := s.trialRepo.Start(ctx, tx, trialID, time.Now()); err != nil {
		return err
	}

	payload := buildTrialPayload(trial)
	if err := s.emitEvent(ctx, tx, trial.TrialID, events.EventTrialStarted, payload); err != nil {
		logger.Warn("failed to emit trial started event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "start", "trial",
			&trialID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *trialService) End(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	return s.Expire(ctx, companyID, trialID)
}

// 🔥 FIXED: Extend with nil check on EndedAt
func (s *trialService) Extend(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, additionalDays int) error {
	logger := s.logger.With(zap.String("method", "Extend"))
	if additionalDays <= 0 {
		return errors.ErrInvalidInput
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("extend-trial-%s-%d", trialID.String(), additionalDays))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping extend")
		return nil
	}

	trial, err := s.trialRepo.GetByIDForUpdate(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	if err := s.CanExtend(ctx, companyID, trialID); err != nil {
		return err
	}

	// ✅ FIX: If EndedAt is nil, set it to now before adding days.
	if trial.EndedAt == nil {
		now := time.Now()
		trial.EndedAt = &now
	}

	newEnd := trial.EndedAt.AddDate(0, 0, additionalDays)
	trial.EndedAt = &newEnd
	trial.TrialDays += additionalDays
	trial.UpdatedAt = time.Now()
	if err := s.trialRepo.Update(ctx, tx, trial); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "extend", "trial",
			&trialID, "system", nil, nil, nil, map[string]interface{}{
				"additional_days": additionalDays,
				"new_end_date":    newEnd,
			})
	}
	return nil
}

func (s *trialService) Convert(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Convert"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("convert-trial-%s", trialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping convert")
		return nil
	}

	trial, err := s.trialRepo.GetByIDForUpdate(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	if err := s.CanConvert(ctx, companyID, trialID); err != nil {
		return err
	}

	trial.Status = enums.TrialConverted
	now := time.Now()
	trial.EndedAt = &now
	trial.UpdatedAt = now
	if err := s.trialRepo.Update(ctx, tx, trial); err != nil {
		return err
	}

	if sub.Status == enums.SubStatusTrial {
		sub.Status = enums.SubStatusActive
		sub.StartDate = now
		if err := s.subRepo.Update(ctx, tx, sub); err != nil {
			return err
		}
	}

	payload := buildTrialPayload(trial)
	if err := s.emitEvent(ctx, tx, trial.TrialID, events.EventTrialConverted, payload); err != nil {
		logger.Warn("failed to emit trial converted event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "convert", "trial",
			&trialID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *trialService) Expire(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Expire"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("expire-trial-%s", trialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping expire")
		return nil
	}

	trial, err := s.trialRepo.GetByIDForUpdate(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	if trial.Status != enums.TrialActive {
		return errors.ErrTrialNotActive
	}

	now := time.Now()
	trial.Status = enums.TrialExpired
	trial.EndedAt = &now
	trial.UpdatedAt = now
	if err := s.trialRepo.Update(ctx, tx, trial); err != nil {
		return err
	}

	if sub.Status == enums.SubStatusTrial {
		sub.Status = enums.SubStatusExpired
		sub.EndDate = &now
		if err := s.subRepo.Update(ctx, tx, sub); err != nil {
			return err
		}
	}

	payload := buildTrialPayload(trial)
	if err := s.emitEvent(ctx, tx, trial.TrialID, events.EventTrialEnded, payload); err != nil {
		logger.Warn("failed to emit trial ended event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "expire", "trial",
			&trialID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *trialService) Cancel(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Cancel"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("cancel-trial-%s", trialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping cancel")
		return nil
	}

	trial, err := s.trialRepo.GetByIDForUpdate(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	if trial.Status != enums.TrialActive {
		return errors.ErrTrialNotActive
	}

	trial.Status = enums.TrialCancelled
	now := time.Now()
	trial.EndedAt = &now
	trial.UpdatedAt = now
	if err := s.trialRepo.Update(ctx, tx, trial); err != nil {
		return err
	}

	if sub.Status == enums.SubStatusTrial {
		sub.Status = enums.SubStatusCancelled
		sub.CancelledAt = &now
		if err := s.subRepo.Update(ctx, tx, sub); err != nil {
			return err
		}
	}

	payload := buildTrialPayload(trial)
	if err := s.emitEvent(ctx, tx, trial.TrialID, events.EventTrialCancelled, payload); err != nil {
		logger.Warn("failed to emit trial cancelled event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", "cancel", "trial",
			&trialID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Trial Configuration
// -------------------------------------------------------------------------

func (s *trialService) UpdateTrialDays(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, days int) error {
	if days <= 0 {
		return errors.ErrInvalidInput
	}
	return s.updateTrialField(ctx, companyID, trialID, func(trial *models.Trial) {
		trial.TrialDays = days
	}, "update_trial_days")
}

func (s *trialService) UpdateStartDate(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, startDate time.Time) error {
	return s.updateTrialField(ctx, companyID, trialID, func(trial *models.Trial) {
		trial.StartedAt = startDate
	}, "update_start_date")
}

func (s *trialService) UpdateEndDate(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, endDate time.Time) error {
	return s.updateTrialField(ctx, companyID, trialID, func(trial *models.Trial) {
		trial.EndedAt = &endDate
	}, "update_end_date")
}

func (s *trialService) UpdateUsage(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, usage models.JSONB) error {
	return s.updateTrialField(ctx, companyID, trialID, func(trial *models.Trial) {
		trial.UsageConsumed = usage
	}, "update_usage")
}

func (s *trialService) UpdateFeatures(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, features models.JSONB) error {
	return s.updateTrialField(ctx, companyID, trialID, func(trial *models.Trial) {
		trial.FeaturesEnabled = features
	}, "update_features")
}

func (s *trialService) updateTrialField(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID, updateFn func(*models.Trial), action string) error {
	logger := s.logger.With(zap.String("method", action))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getTrialIdempotencyKey(ctx, fmt.Sprintf("%s-%s", action, trialID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – skipping update")
		return nil
	}

	trial, err := s.trialRepo.GetByIDForUpdate(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}

	updateFn(trial)
	trial.UpdatedAt = time.Now()
	if err := s.trialRepo.Update(ctx, tx, trial); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "trial", action, "trial",
			&trialID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (s *trialService) Validate(ctx context.Context, trial *models.Trial) error {
	if trial.TrialDays <= 0 {
		return errors.ErrInvalidInput
	}
	if trial.SubscriptionID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	if !trial.Status.IsValid() {
		return errors.ErrInvalidStatus
	}
	if trial.EndedAt != nil && trial.EndedAt.Before(trial.StartedAt) {
		return errors.ErrInvalidInput
	}
	return nil
}

func (s *trialService) Exists(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) (bool, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exists, err := s.trialRepo.Exists(ctx, tx, trialID)
	if err != nil || !exists {
		return false, err
	}
	trial, err := s.trialRepo.GetByID(ctx, tx, trialID)
	if err != nil {
		return false, err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return false, nil
	}
	return true, nil
}

func (s *trialService) IsEligible(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, planID uuid.UUID) (bool, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	subs, err := s.subRepo.GetByCustomer(ctx, tx, companyID, customerID)
	if err != nil {
		return false, err
	}
	for _, sub := range subs {
		if sub.PlanID == planID {
			trial, err := s.trialRepo.GetBySubscription(ctx, tx, sub.SubscriptionID)
			if err == nil && trial != nil && trial.Status == enums.TrialActive {
				return false, nil
			}
		}
	}
	return true, nil
}

func (s *trialService) CanExtend(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	trial, err := s.trialRepo.GetByID(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}
	if trial.Status != enums.TrialActive {
		return errors.ErrTrialNotActive
	}
	return nil
}

func (s *trialService) CanConvert(ctx context.Context, companyID uuid.UUID, trialID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	trial, err := s.trialRepo.GetByID(ctx, tx, trialID)
	if err != nil {
		return err
	}
	sub, err := s.subRepo.GetByID(ctx, tx, companyID, trial.SubscriptionID)
	if err != nil || sub.CompanyID != companyID {
		return errors.ErrPermissionDenied
	}
	if trial.Status != enums.TrialActive {
		return errors.ErrTrialNotActive
	}
	if sub.Status != enums.SubStatusTrial {
		return errors.ErrInvalidState
	}
	return nil
}

// -------------------------------------------------------------------------
// Query
// -------------------------------------------------------------------------

func (s *trialService) List(ctx context.Context, filter repository.TrialFilter, p repository.Pagination, srt repository.Sort) ([]*models.Trial, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	return s.trialRepo.List(ctx, tx, filter, p, srt)
}

func (s *trialService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Trial, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	all, _, err := s.trialRepo.Search(ctx, tx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	var filtered []*models.Trial
	for _, t := range all {
		sub, err := s.subRepo.GetByID(ctx, tx, companyID, t.SubscriptionID)
		if err == nil && sub.CompanyID == companyID {
			filtered = append(filtered, t)
		}
	}
	return filtered, int64(len(filtered)), nil
}

func (s *trialService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Trial, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	all, err := s.trialRepo.GetActive(ctx, tx)
	if err != nil {
		return nil, err
	}
	var result []*models.Trial
	for _, t := range all {
		sub, err := s.subRepo.GetByID(ctx, tx, companyID, t.SubscriptionID)
		if err == nil && sub.CompanyID == companyID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (s *trialService) GetExpired(ctx context.Context, companyID uuid.UUID) ([]*models.Trial, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	all, err := s.trialRepo.GetExpiredBefore(ctx, tx, time.Now())
	if err != nil {
		return nil, err
	}
	var result []*models.Trial
	for _, t := range all {
		sub, err := s.subRepo.GetByID(ctx, tx, companyID, t.SubscriptionID)
		if err == nil && sub.CompanyID == companyID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (s *trialService) GetConverted(ctx context.Context, companyID uuid.UUID) ([]*models.Trial, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	filter := repository.TrialFilter{
		Status: func() *enums.TrialStatus { s := enums.TrialConverted; return &s }(),
	}
	all, _, err := s.trialRepo.List(ctx, tx, filter, repository.Pagination{Limit: 1000}, repository.Sort{})
	if err != nil {
		return nil, err
	}
	var result []*models.Trial
	for _, t := range all {
		sub, err := s.subRepo.GetByID(ctx, tx, companyID, t.SubscriptionID)
		if err == nil && sub.CompanyID == companyID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (s *trialService) GetExpiring(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Trial, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	all, err := s.trialRepo.GetExpiringBetween(ctx, tx, time.Now(), before)
	if err != nil {
		return nil, err
	}
	var result []*models.Trial
	for _, t := range all {
		sub, err := s.subRepo.GetByID(ctx, tx, companyID, t.SubscriptionID)
		if err == nil && sub.CompanyID == companyID {
			result = append(result, t)
		}
	}
	return result, nil
}

// -------------------------------------------------------------------------
// Helper
// -------------------------------------------------------------------------

func buildTrialPayload(trial *models.Trial) events.TrialPayload {
	payload := events.TrialPayload{
		TrialID:        trial.TrialID.String(),
		SubscriptionID: trial.SubscriptionID.String(),
		StartedAt:      trial.StartedAt.Format(time.RFC3339),
		TrialDays:      trial.TrialDays,
		Status:         string(trial.Status),
	}
	if trial.EndedAt != nil {
		payload.EndedAt = trial.EndedAt.Format(time.RFC3339)
	}
	return payload
}
