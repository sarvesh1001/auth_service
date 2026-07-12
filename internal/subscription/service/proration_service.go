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

// ProrationPolicyService defines the interface for managing proration policies.
type ProrationPolicyService interface {
	// CRUD
	Create(ctx context.Context, policy *models.ProrationPolicy) error
	Update(ctx context.Context, policy *models.ProrationPolicy) error
	Delete(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error
	GetByID(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.ProrationPolicy, error)

	// Lifecycle
	Activate(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error
	Deactivate(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error
	Restore(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error

	// Proration Configuration
	UpdateUpgradeType(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID, upgradeType enums.UpgradeType) error
	UpdateDowngradeType(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID, downgradeType enums.DowngradeType) error

	// Validation
	Validate(ctx context.Context, policy *models.ProrationPolicy) error
	Exists(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (bool, error)
	CanUpgrade(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (bool, error)
	CanDowngrade(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (bool, error)

	// Query
	List(ctx context.Context, filter repository.ProrationPolicyFilter, p repository.Pagination, s repository.Sort) ([]*models.ProrationPolicy, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.ProrationPolicy, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.ProrationPolicy, error)
	GetByUpgradeType(ctx context.Context, companyID uuid.UUID, upgradeType enums.UpgradeType) ([]*models.ProrationPolicy, error)
	GetByDowngradeType(ctx context.Context, companyID uuid.UUID, downgradeType enums.DowngradeType) ([]*models.ProrationPolicy, error)
}

// prorationPolicyService is the concrete implementation.
type prorationPolicyService struct {
	repo             repository.ProrationPolicyRepository
	planRepo         repository.PlanRepository
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewProrationPolicyService creates a new instance.
func NewProrationPolicyService(
	repo repository.ProrationPolicyRepository,
	planRepo repository.PlanRepository,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) ProrationPolicyService {
	return &prorationPolicyService{
		repo:             repo,
		planRepo:         planRepo,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		pgClient:         pgClient,
		logger:           logger.Named("proration_policy_service"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

// getIDempotencyKey extracts the idempotency key from the context or uses a fallback.

func (s *prorationPolicyService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *prorationPolicyService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "proration_policy",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func buildProrationPolicyPayload(policy *models.ProrationPolicy) events.ProrationPolicyPayload {
	return events.ProrationPolicyPayload{
		ProrationPolicyID: policy.ProrationPolicyID.String(),
		CompanyID:         policy.CompanyID.String(),
		Name:              policy.Name,
		UpgradeType:       string(policy.UpgradeType),
		DowngradeType:     string(policy.DowngradeType),
		IsActive:          policy.IsActive,
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (s *prorationPolicyService) Create(ctx context.Context, policy *models.ProrationPolicy) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_create_%s_%s", policy.CompanyID.String(), policy.Name))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – create already processed")
		// ✅ Fetch existing policy (including soft-deleted) and copy into input pointer
		existing, err := s.repo.GetByNameWithDeleted(ctx, tx, policy.CompanyID, policy.Name)
		if err != nil {
			return err
		}
		if existing == nil {
			// This should not happen if the cache is valid, but handle gracefully.
			return errors.ErrNotFound
		}
		*policy = *existing
		return nil
	}

	// Validation
	if err := s.Validate(ctx, policy); err != nil {
		return err
	}
	// Check name uniqueness (excluding soft-deleted)
	exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrDuplicate
	}

	// Ensure new policy has a UUID
	if policy.ProrationPolicyID == uuid.Nil {
		policy.ProrationPolicyID = uuid.New()
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.IsActive = true // default

	if err := s.repo.Create(ctx, tx, policy); err != nil {
		return err
	}

	// Emit event
	payload := buildProrationPolicyPayload(policy)
	if err := s.emitEvent(ctx, tx, policy.ProrationPolicyID, events.EventProrationPolicyCreated, payload); err != nil {
		logger.Warn("failed to emit created event", zap.Error(err))
	}

	// Store idempotency
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "proration_policy", "create", "proration_policy",
			&policy.ProrationPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"name": policy.Name,
			})
	}
	return nil
}

func (s *prorationPolicyService) Update(ctx context.Context, policy *models.ProrationPolicy) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_update_%s_%s", policy.CompanyID.String(), policy.ProrationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update already processed")
		// ✅ Fetch existing and copy into pointer
		existing, err := s.repo.GetByID(ctx, tx, policy.CompanyID, policy.ProrationPolicyID)
		if err != nil {
			return err
		}
		if existing == nil {
			return errors.ErrNotFound
		}
		*policy = *existing
		return nil
	}

	// Fetch existing to preserve fields not passed?
	existing, err := s.repo.GetByIDForUpdate(ctx, tx, policy.CompanyID, policy.ProrationPolicyID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.ErrNotFound
	}
	// Validation
	if err := s.Validate(ctx, policy); err != nil {
		return err
	}
	// Check name uniqueness (if changed)
	if existing.Name != policy.Name {
		exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
		if err != nil {
			return err
		}
		if exists {
			return errors.ErrDuplicate
		}
	}

	// Update fields (keep ID, company, timestamps)
	existing.Name = policy.Name
	existing.UpgradeType = policy.UpgradeType
	existing.DowngradeType = policy.DowngradeType
	existing.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return err
	}

	// Emit event
	payload := buildProrationPolicyPayload(existing)
	if err := s.emitEvent(ctx, tx, existing.ProrationPolicyID, events.EventProrationPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "proration_policy", "update", "proration_policy",
			&policy.ProrationPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"name":           policy.Name,
				"upgrade_type":   policy.UpgradeType,
				"downgrade_type": policy.DowngradeType,
			})
	}
	return nil
}

func (s *prorationPolicyService) Delete(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_delete_%s_%s", companyID.String(), prorationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – delete already processed")
		return nil
	}

	// Check if policy is referenced by any plan
	plans, err := s.planRepo.GetByProrationPolicy(ctx, tx, companyID, prorationPolicyID)
	if err != nil {
		return err
	}
	if len(plans) > 0 {
		return fmt.Errorf("proration policy is in use by %d plan(s): %w", len(plans), errors.ErrConflict)
	}

	// Soft delete
	if err := s.repo.SoftDelete(ctx, tx, companyID, prorationPolicyID); err != nil {
		return err
	}

	// Emit event
	payload := map[string]interface{}{
		"proration_policy_id": prorationPolicyID.String(),
		"company_id":          companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, prorationPolicyID, events.EventProrationPolicyDeleted, payload); err != nil {
		logger.Warn("failed to emit deleted event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "proration_policy", "delete", "proration_policy",
			&prorationPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Read methods – now handle nil and return ErrNotFound
// -------------------------------------------------------------------------

func (s *prorationPolicyService) GetByID(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, prorationPolicyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

func (s *prorationPolicyService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.ProrationPolicy, error) {
	policy, err := s.repo.GetByName(ctx, s.pgClient.DB, companyID, name)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (s *prorationPolicyService) Activate(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_activate_%s_%s", companyID.String(), prorationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – activate already processed")
		return nil
	}

	// Check existence
	exists, err := s.repo.Exists(ctx, tx, companyID, prorationPolicyID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}

	if err := s.repo.Activate(ctx, tx, companyID, prorationPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"proration_policy_id": prorationPolicyID.String(),
		"company_id":          companyID.String(),
		"status":              "active",
	}
	if err := s.emitEvent(ctx, tx, prorationPolicyID, events.EventProrationPolicyActivated, payload); err != nil {
		logger.Warn("failed to emit activated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "proration_policy", "activate", "proration_policy",
			&prorationPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *prorationPolicyService) Deactivate(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_deactivate_%s_%s", companyID.String(), prorationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – deactivate already processed")
		return nil
	}

	exists, err := s.repo.Exists(ctx, tx, companyID, prorationPolicyID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}

	if err := s.repo.Deactivate(ctx, tx, companyID, prorationPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"proration_policy_id": prorationPolicyID.String(),
		"company_id":          companyID.String(),
		"status":              "inactive",
	}
	if err := s.emitEvent(ctx, tx, prorationPolicyID, events.EventProrationPolicyDeactivated, payload); err != nil {
		logger.Warn("failed to emit deactivated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "proration_policy", "deactivate", "proration_policy",
			&prorationPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *prorationPolicyService) Restore(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_restore_%s_%s", companyID.String(), prorationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – restore already processed")
		return nil
	}

	if err := s.repo.Restore(ctx, tx, companyID, prorationPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"proration_policy_id": prorationPolicyID.String(),
		"company_id":          companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, prorationPolicyID, events.EventProrationPolicyRestored, payload); err != nil {
		logger.Warn("failed to emit restored event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "proration_policy", "restore", "proration_policy",
			&prorationPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

func (s *prorationPolicyService) UpdateUpgradeType(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID, upgradeType enums.UpgradeType) error {
	logger := s.logger.With(zap.String("method", "UpdateUpgradeType"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_upgrade_type_%s_%s", companyID.String(), prorationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update upgrade type already processed")
		return nil
	}

	if !upgradeType.IsValid() {
		return errors.ErrInvalidInput
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, prorationPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.UpgradeType = upgradeType
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := buildProrationPolicyPayload(policy)
	if err := s.emitEvent(ctx, tx, policy.ProrationPolicyID, events.EventProrationPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "proration_policy", "update_upgrade_type", "proration_policy",
			&prorationPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"upgrade_type": upgradeType,
			})
	}
	return nil
}

func (s *prorationPolicyService) UpdateDowngradeType(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID, downgradeType enums.DowngradeType) error {
	logger := s.logger.With(zap.String("method", "UpdateDowngradeType"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("proration_policy_downgrade_type_%s_%s", companyID.String(), prorationPolicyID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update downgrade type already processed")
		return nil
	}

	if !downgradeType.IsValid() {
		return errors.ErrInvalidInput
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, prorationPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.DowngradeType = downgradeType
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := buildProrationPolicyPayload(policy)
	if err := s.emitEvent(ctx, tx, policy.ProrationPolicyID, events.EventProrationPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "proration_policy", "update_downgrade_type", "proration_policy",
			&prorationPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"downgrade_type": downgradeType,
			})
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (s *prorationPolicyService) Validate(ctx context.Context, policy *models.ProrationPolicy) error {
	if policy == nil {
		return errors.ErrInvalidInput
	}
	if policy.Name == "" {
		return fmt.Errorf("%w: name is required", errors.ErrInvalidInput)
	}
	if !policy.UpgradeType.IsValid() {
		return fmt.Errorf("%w: invalid upgrade type", errors.ErrInvalidInput)
	}
	if !policy.DowngradeType.IsValid() {
		return fmt.Errorf("%w: invalid downgrade type", errors.ErrInvalidInput)
	}
	// Additional business rules can be added here
	return nil
}

func (s *prorationPolicyService) Exists(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, prorationPolicyID)
}

func (s *prorationPolicyService) CanUpgrade(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (bool, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, prorationPolicyID)
	if err != nil {
		if err == errors.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	if policy == nil {
		return false, nil
	}
	return policy.IsActive && policy.UpgradeType != "", nil
}

func (s *prorationPolicyService) CanDowngrade(ctx context.Context, companyID uuid.UUID, prorationPolicyID uuid.UUID) (bool, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, prorationPolicyID)
	if err != nil {
		if err == errors.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	if policy == nil {
		return false, nil
	}
	return policy.IsActive && policy.DowngradeType != "", nil
}

// -------------------------------------------------------------------------
// Query
// -------------------------------------------------------------------------

func (s *prorationPolicyService) List(ctx context.Context, filter repository.ProrationPolicyFilter, p repository.Pagination, srt repository.Sort) ([]*models.ProrationPolicy, int64, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *prorationPolicyService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.ProrationPolicy, int64, error) {
	return s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *prorationPolicyService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.ProrationPolicy, error) {
	return s.repo.GetActive(ctx, s.pgClient.DB, companyID)
}

func (s *prorationPolicyService) GetByUpgradeType(ctx context.Context, companyID uuid.UUID, upgradeType enums.UpgradeType) ([]*models.ProrationPolicy, error) {
	return s.repo.GetByUpgradeType(ctx, s.pgClient.DB, companyID, upgradeType)
}

func (s *prorationPolicyService) GetByDowngradeType(ctx context.Context, companyID uuid.UUID, downgradeType enums.DowngradeType) ([]*models.ProrationPolicy, error) {
	return s.repo.GetByDowngradeType(ctx, s.pgClient.DB, companyID, downgradeType)
}
