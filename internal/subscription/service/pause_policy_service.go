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
	"auth-service/internal/subscription/repository"
)

// PausePolicyService defines the pause policy business operations.
type PausePolicyService interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(
		ctx context.Context,
		policy *models.PausePolicy,
	) error

	Update(
		ctx context.Context,
		policy *models.PausePolicy,
	) error

	Delete(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
	) error

	GetByID(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
	) (*models.PausePolicy, error)

	GetByName(
		ctx context.Context,
		companyID uuid.UUID,
		name string,
	) (*models.PausePolicy, error)

	// -------------------------------------------------------------------------
	// Lifecycle
	// -------------------------------------------------------------------------

	Activate(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
	) error

	Deactivate(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
	) error

	Restore(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
	) error

	// -------------------------------------------------------------------------
	// Pause Configuration
	// -------------------------------------------------------------------------

	UpdateMaxPauseDays(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
		maxPauseDays int,
	) error

	UpdateFreezeDays(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
		freezeDays int,
	) error

	AddAllowedReason(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
		reason string,
	) error

	RemoveAllowedReason(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
		reason string,
	) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Validate(
		ctx context.Context,
		policy *models.PausePolicy,
	) error

	Exists(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
	) (bool, error)

	IsReasonAllowed(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
		reason string,
	) (bool, error)

	CanPause(
		ctx context.Context,
		companyID uuid.UUID,
		pausePolicyID uuid.UUID,
		requestedDays int,
	) error

	// -------------------------------------------------------------------------
	// Query
	// -------------------------------------------------------------------------

	List(
		ctx context.Context,
		filter repository.PausePolicyFilter,
		p repository.Pagination,
		s repository.Sort,
	) ([]*models.PausePolicy, int64, error)

	Search(
		ctx context.Context,
		companyID uuid.UUID,
		query string,
		limit,
		offset int,
	) ([]*models.PausePolicy, int64, error)

	GetActive(
		ctx context.Context,
		companyID uuid.UUID,
	) ([]*models.PausePolicy, error)

	GetByMaxPauseDays(
		ctx context.Context,
		companyID uuid.UUID,
		maxPauseDays int,
	) ([]*models.PausePolicy, error)

	GetByAllowedReason(
		ctx context.Context,
		companyID uuid.UUID,
		reason string,
	) ([]*models.PausePolicy, error)
}

// pausePolicyService implements PausePolicyService.
type pausePolicyService struct {
	repo             repository.PausePolicyRepository
	planRepo         repository.PlanRepository
	idempotencyStore idempotency.Store
	outboxRepo       outbox.Repository
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewPausePolicyService creates a new PausePolicyService.
func NewPausePolicyService(
	repo repository.PausePolicyRepository,
	planRepo repository.PlanRepository,
	idempotencyStore idempotency.Store,
	outboxRepo outbox.Repository,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PausePolicyService {
	return &pausePolicyService{
		repo:             repo,
		planRepo:         planRepo,
		idempotencyStore: idempotencyStore,
		outboxRepo:       outboxRepo,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("pause_policy_service"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

// getIDempotencyKey extracts the idempotency key from the context or uses a fallback.

func (s *pausePolicyService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *pausePolicyService) emitEvent(ctx context.Context, tx repository.DBTX, companyID, policyID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "pause_policy",
		AggregateID:   policyID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *pausePolicyService) buildPayload(policy *models.PausePolicy) events.PausePolicyPayload {
	return events.PausePolicyPayload{
		PausePolicyID:  policy.PausePolicyID.String(),
		CompanyID:      policy.CompanyID.String(),
		Name:           policy.Name,
		MaxPauseDays:   policy.MaxPauseDays,
		AllowedReasons: policy.AllowedReasons,
		FreezeDays:     policy.FreezeDays,
		IsActive:       policy.IsActive,
		CreatedAt:      policy.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      policy.UpdatedAt.Format(time.RFC3339),
	}
}

func (s *pausePolicyService) validatePolicy(policy *models.PausePolicy) error {
	if policy.Name == "" {
		return errors.ErrInvalidInput
	}
	if policy.MaxPauseDays < 0 {
		return errors.ErrInvalidInput
	}
	if policy.FreezeDays < 0 {
		return errors.ErrInvalidInput
	}
	// Additional validations if needed
	return nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (s *pausePolicyService) Create(ctx context.Context, policy *models.PausePolicy) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_create_%s_%s", policy.CompanyID.String(), policy.Name))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – create already processed")
		// Retrieve the existing policy and overwrite the input pointer.
		existing, err := s.repo.GetByName(ctx, tx, policy.CompanyID, policy.Name)
		if err != nil {
			return err
		}
		if existing == nil {
			// Should not happen because the idempotency key says it exists, but handle gracefully.
			return errors.ErrNotFound
		}
		*policy = *existing
		return nil
	}

	if policy.AllowedReasons == nil {
		policy.AllowedReasons = []string{} // ensure not null in DB
	}

	if err := s.validatePolicy(policy); err != nil {
		return err
	}

	exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrDuplicate
	}

	policy.PausePolicyID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.IsActive = true // default active

	if err := s.repo.Create(ctx, tx, policy); err != nil {
		return err
	}

	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, policy.CompanyID, policy.PausePolicyID, events.EventPausePolicyCreated, payload); err != nil {
		logger.Warn("failed to emit created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "pause_policy", "create", "pause_policy",
			&policy.PausePolicyID, "system", nil, nil, nil, map[string]interface{}{
				"name": policy.Name,
			})
	}
	return nil
}

func (s *pausePolicyService) Update(ctx context.Context, policy *models.PausePolicy) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_update_%s_%s", policy.CompanyID.String(), policy.PausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update already processed")
		// Retrieve the existing policy and overwrite the input pointer.
		existing, err := s.repo.GetByID(ctx, tx, policy.CompanyID, policy.PausePolicyID)
		if err != nil {
			return err
		}
		if existing == nil {
			return errors.ErrNotFound
		}
		*policy = *existing
		return nil
	}

	if policy.AllowedReasons == nil {
		policy.AllowedReasons = []string{}
	}

	if err := s.validatePolicy(policy); err != nil {
		return err
	}

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, policy.CompanyID, policy.PausePolicyID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.ErrNotFound
	}

	// Check if name changed and conflict
	if existing.Name != policy.Name {
		exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
		if err != nil {
			return err
		}
		if exists {
			return errors.ErrDuplicate
		}
	}

	// Preserve fields that are not allowed to change via this method (e.g., company id)
	policy.CompanyID = existing.CompanyID
	policy.PausePolicyID = existing.PausePolicyID
	policy.CreatedAt = existing.CreatedAt
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, policy.CompanyID, policy.PausePolicyID, events.EventPausePolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "pause_policy", "update", "pause_policy",
			&policy.PausePolicyID, "system", nil, nil, nil, map[string]interface{}{
				"name": policy.Name,
			})
	}
	return nil
}

func (s *pausePolicyService) Delete(ctx context.Context, companyID, pausePolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_delete_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – delete already processed")
		return nil
	}

	// Check if policy is referenced by any plan
	plans, err := s.planRepo.GetByPausePolicy(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if len(plans) > 0 {
		return fmt.Errorf("pause policy is in use by %d plan(s): %w", len(plans), errors.ErrConflict)
	}

	if err := s.repo.Delete(ctx, tx, companyID, pausePolicyID); err != nil {
		return err
	}

	payload := map[string]string{"pause_policy_id": pausePolicyID.String()}
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyDeleted, payload); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "delete", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Read methods – now pass pgClient.DB instead of nil and handle nil results
// -------------------------------------------------------------------------

func (s *pausePolicyService) GetByID(ctx context.Context, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, pausePolicyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

func (s *pausePolicyService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.PausePolicy, error) {
	policy, err := s.repo.GetByName(ctx, s.pgClient.DB, companyID, name)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

func (s *pausePolicyService) List(ctx context.Context, filter repository.PausePolicyFilter, p repository.Pagination, srt repository.Sort) ([]*models.PausePolicy, int64, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *pausePolicyService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.PausePolicy, int64, error) {
	return s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *pausePolicyService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.PausePolicy, error) {
	return s.repo.GetActive(ctx, s.pgClient.DB, companyID)
}

func (s *pausePolicyService) GetByMaxPauseDays(ctx context.Context, companyID uuid.UUID, maxPauseDays int) ([]*models.PausePolicy, error) {
	return s.repo.GetByMaxPauseDays(ctx, s.pgClient.DB, companyID, maxPauseDays)
}

func (s *pausePolicyService) GetByAllowedReason(ctx context.Context, companyID uuid.UUID, reason string) ([]*models.PausePolicy, error) {
	return s.repo.GetByAllowedReason(ctx, s.pgClient.DB, companyID, reason)
}

func (s *pausePolicyService) Exists(ctx context.Context, companyID, pausePolicyID uuid.UUID) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, pausePolicyID)
}

func (s *pausePolicyService) IsReasonAllowed(ctx context.Context, companyID, pausePolicyID uuid.UUID, reason string) (bool, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, pausePolicyID)
	if err != nil {
		return false, err
	}
	if policy == nil {
		return false, errors.ErrNotFound
	}
	for _, r := range policy.AllowedReasons {
		if r == reason {
			return true, nil
		}
	}
	return false, nil
}

func (s *pausePolicyService) CanPause(ctx context.Context, companyID, pausePolicyID uuid.UUID, requestedDays int) error {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	if !policy.IsActive {
		return fmt.Errorf("pause policy is not active: %w", errors.ErrInvalidState)
	}
	if requestedDays > policy.MaxPauseDays {
		return fmt.Errorf("requested pause days %d exceeds max allowed %d: %w", requestedDays, policy.MaxPauseDays, errors.ErrInvalidInput)
	}
	return nil
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (s *pausePolicyService) Activate(ctx context.Context, companyID, pausePolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_activate_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – activate already processed")
		return nil
	}

	if err := s.repo.Activate(ctx, tx, companyID, pausePolicyID); err != nil {
		return err
	}

	policy, err := s.repo.GetByID(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyActivated, payload); err != nil {
		logger.Warn("failed to emit activate event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "activate", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *pausePolicyService) Deactivate(ctx context.Context, companyID, pausePolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_deactivate_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – deactivate already processed")
		return nil
	}

	if err := s.repo.Deactivate(ctx, tx, companyID, pausePolicyID); err != nil {
		return err
	}

	policy, err := s.repo.GetByID(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyDeactivated, payload); err != nil {
		logger.Warn("failed to emit deactivate event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "deactivate", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *pausePolicyService) Restore(ctx context.Context, companyID, pausePolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_restore_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – restore already processed")
		return nil
	}

	if err := s.repo.Restore(ctx, tx, companyID, pausePolicyID); err != nil {
		return err
	}

	policy, err := s.repo.GetByID(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyRestored, payload); err != nil {
		logger.Warn("failed to emit restore event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "restore", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Pause Configuration
// -------------------------------------------------------------------------

func (s *pausePolicyService) UpdateMaxPauseDays(ctx context.Context, companyID, pausePolicyID uuid.UUID, maxPauseDays int) error {
	logger := s.logger.With(zap.String("method", "UpdateMaxPauseDays"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_maxdays_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update max pause days already processed")
		// No need to return policy; just ack success.
		return nil
	}

	if maxPauseDays < 0 {
		return errors.ErrInvalidInput
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.MaxPauseDays = maxPauseDays
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "update_max_days", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, map[string]interface{}{
				"max_pause_days": maxPauseDays,
			})
	}
	return nil
}

func (s *pausePolicyService) UpdateFreezeDays(ctx context.Context, companyID, pausePolicyID uuid.UUID, freezeDays int) error {
	logger := s.logger.With(zap.String("method", "UpdateFreezeDays"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_freeze_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update freeze days already processed")
		return nil
	}

	if freezeDays < 0 {
		return errors.ErrInvalidInput
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.FreezeDays = freezeDays
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "update_freeze_days", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, map[string]interface{}{
				"freeze_days": freezeDays,
			})
	}
	return nil
}

func (s *pausePolicyService) AddAllowedReason(ctx context.Context, companyID, pausePolicyID uuid.UUID, reason string) error {
	if reason == "" {
		return fmt.Errorf("reason cannot be empty: %w", errors.ErrInvalidInput)
	}
	logger := s.logger.With(zap.String("method", "AddAllowedReason"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_addreason_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – add allowed reason already processed")
		return nil
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	// Avoid duplicates
	for _, r := range policy.AllowedReasons {
		if r == reason {
			return nil // already exists, no-op
		}
	}
	policy.AllowedReasons = append(policy.AllowedReasons, reason)
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "add_allowed_reason", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, map[string]interface{}{
				"reason": reason,
			})
	}
	return nil
}

func (s *pausePolicyService) RemoveAllowedReason(ctx context.Context, companyID, pausePolicyID uuid.UUID, reason string) error {
	if reason == "" {
		return fmt.Errorf("reason cannot be empty: %w", errors.ErrInvalidInput)
	}
	logger := s.logger.With(zap.String("method", "RemoveAllowedReason"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pause_policy_removereason_%s_%s", companyID.String(), pausePolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – remove allowed reason already processed")
		return nil
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, pausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	found := false
	newReasons := make([]string, 0, len(policy.AllowedReasons))
	for _, r := range policy.AllowedReasons {
		if r == reason {
			found = true
			continue
		}
		newReasons = append(newReasons, r)
	}
	if !found {
		return fmt.Errorf("reason '%s' not found: %w", reason, errors.ErrNotFound)
	}
	policy.AllowedReasons = newReasons
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := s.buildPayload(policy)
	if err := s.emitEvent(ctx, tx, companyID, pausePolicyID, events.EventPausePolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "pause_policy", "remove_allowed_reason", "pause_policy",
			&pausePolicyID, "system", nil, nil, nil, map[string]interface{}{
				"reason": reason,
			})
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation (no changes)
// -------------------------------------------------------------------------

func (s *pausePolicyService) Validate(ctx context.Context, policy *models.PausePolicy) error {
	return s.validatePolicy(policy)
}
