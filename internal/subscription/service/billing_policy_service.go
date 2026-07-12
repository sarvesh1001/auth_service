// file: service/billing_policy_service.go
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
	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
)

// BillingPolicyService defines the business operations for billing policies.
type BillingPolicyService interface {
	// CRUD
	Create(ctx context.Context, policy *models.BillingPolicy) error
	Update(ctx context.Context, policy *models.BillingPolicy) error
	Delete(ctx context.Context, companyID, billingPolicyID uuid.UUID) error
	GetByID(ctx context.Context, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.BillingPolicy, error)

	// Lifecycle
	Activate(ctx context.Context, companyID, billingPolicyID uuid.UUID) error
	Deactivate(ctx context.Context, companyID, billingPolicyID uuid.UUID) error
	Restore(ctx context.Context, companyID, billingPolicyID uuid.UUID) error

	// Business Configuration
	UpdateFrequency(ctx context.Context, companyID, billingPolicyID uuid.UUID, frequencyID int16) error
	UpdateBillingModel(ctx context.Context, companyID, billingPolicyID uuid.UUID, modelID int16) error
	UpdateBillingInterval(ctx context.Context, companyID, billingPolicyID uuid.UUID, interval int) error
	UpdateAdvanceBillingDays(ctx context.Context, companyID, billingPolicyID uuid.UUID, days int) error

	// Validation
	Validate(ctx context.Context, policy *models.BillingPolicy) error
	Exists(ctx context.Context, companyID, billingPolicyID uuid.UUID) (bool, error)

	// Query
	List(ctx context.Context, filter repository.BillingPolicyFilter, p repository.Pagination, s repository.Sort) ([]*models.BillingPolicy, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.BillingPolicy, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.BillingPolicy, error)
}

type billingPolicyService struct {
	repo             repository.BillingPolicyRepository
	lookupRepo       repository.LookupRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewBillingPolicyService(
	repo repository.BillingPolicyRepository,
	lookupRepo repository.LookupRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) BillingPolicyService {
	return &billingPolicyService{
		repo:             repo,
		lookupRepo:       lookupRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("billing_policy_service"),
	}
}

// ---- helpers ----

func (s *billingPolicyService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *billingPolicyService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "billing_policy",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func buildBillingPolicyPayload(policy *models.BillingPolicy) map[string]interface{} {
	return map[string]interface{}{
		"billing_policy_id": policy.BillingPolicyID.String(),
		"company_id":        policy.CompanyID.String(),
		"name":              policy.Name,
		"frequency_id":      policy.FrequencyID,
		"billing_interval":  policy.BillingInterval,
		"model_id":          policy.ModelID,
		"advance_days":      policy.AdvanceDays,
		"is_active":         policy.IsActive,
	}
}

func (s *billingPolicyService) validateLookups(ctx context.Context, tx repository.DBTX, frequencyID, modelID int16) error {
	freq, err := s.lookupRepo.GetBillingFrequencyByID(ctx, tx, frequencyID)
	if err != nil || freq == nil {
		return subErrors.ErrInvalidInput
	}
	model, err := s.lookupRepo.GetPricingModelByID(ctx, tx, modelID)
	if err != nil || model == nil {
		return subErrors.ErrInvalidInput
	}
	return nil
}

// ---- Idempotency key helper (local) ----
func getBillingPolicyIdempotencyKey(ctx context.Context, fallback string) string {
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		return key
	}
	return fallback
}

// ---- CRUD ----

func (s *billingPolicyService) Create(ctx context.Context, policy *models.BillingPolicy) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-create-%s-%s", policy.CompanyID.String(), policy.Name))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – billing policy create already processed")
		return nil
	}

	// 1. Validate foreign key references (frequency, model) using transaction
	if err := s.validateLookups(ctx, tx, policy.FrequencyID, policy.ModelID); err != nil {
		return err
	}

	// 2. Check duplicate name
	exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
	if err != nil {
		return err
	}
	if exists {
		return subErrors.ErrDuplicate
	}

	// 3. Apply business validation (name, interval, advance_days, lookups again – safe)
	if err := s.Validate(ctx, policy); err != nil {
		return err
	}

	policy.BillingPolicyID = uuid.New()
	policy.IsActive = true
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	if err := s.repo.Create(ctx, tx, policy); err != nil {
		return err
	}

	payload := buildBillingPolicyPayload(policy)
	if err := s.emitEvent(ctx, tx, policy.BillingPolicyID, events.EventBillingPolicyCreated, payload); err != nil {
		logger.Warn("failed to emit create event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "billing_policy", "create", "billing_policy",
			&policy.BillingPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"name": policy.Name,
			})
	}
	return nil
}

func (s *billingPolicyService) Update(ctx context.Context, policy *models.BillingPolicy) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-update-%s", policy.BillingPolicyID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – billing policy update already processed")
		return nil
	}

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, policy.CompanyID, policy.BillingPolicyID)
	if err != nil {
		return err
	}
	// ✅ FIX: handle not found
	if existing == nil {
		return subErrors.ErrNotFound
	}

	// Validate foreign keys
	if err := s.validateLookups(ctx, tx, policy.FrequencyID, policy.ModelID); err != nil {
		return err
	}

	// Check duplicate name if changed
	if existing.Name != policy.Name {
		exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
		if err != nil {
			return err
		}
		if exists {
			return subErrors.ErrDuplicate
		}
	}

	// Apply business validation to the updated policy
	if err := s.Validate(ctx, policy); err != nil {
		return err
	}

	// Merge changes
	existing.Name = policy.Name
	existing.FrequencyID = policy.FrequencyID
	existing.BillingInterval = policy.BillingInterval
	existing.ModelID = policy.ModelID
	existing.AdvanceDays = policy.AdvanceDays
	existing.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return err
	}

	payload := buildBillingPolicyPayload(existing)
	if err := s.emitEvent(ctx, tx, existing.BillingPolicyID, events.EventBillingPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "billing_policy", "update", "billing_policy",
			&policy.BillingPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"name": policy.Name,
			})
	}
	return nil
}

func (s *billingPolicyService) Delete(ctx context.Context, companyID, billingPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-delete-%s", billingPolicyID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – billing policy delete already processed")
		return nil
	}

	if err := s.repo.SoftDelete(ctx, tx, companyID, billingPolicyID); err != nil {
		// If the policy is not found or already deleted, return ErrNotFound
		if err.Error() == "billing policy not found or already deleted" {
			return subErrors.ErrNotFound
		}
		return err
	}

	payload := map[string]interface{}{
		"billing_policy_id": billingPolicyID.String(),
		"company_id":        companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, billingPolicyID, events.EventBillingPolicyDeleted, payload); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "billing_policy", "delete", "billing_policy",
			&billingPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}
func (s *billingPolicyService) GetByID(ctx context.Context, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error) {
	return s.repo.GetByID(ctx, s.pgClient.DB, companyID, billingPolicyID)
}

func (s *billingPolicyService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.BillingPolicy, error) {
	return s.repo.GetByName(ctx, s.pgClient.DB, companyID, name)
}

// ---- Lifecycle ----

func (s *billingPolicyService) Activate(ctx context.Context, companyID, billingPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-activate-%s", billingPolicyID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – activation already processed")
		return nil
	}

	if err := s.repo.Activate(ctx, tx, companyID, billingPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"billing_policy_id": billingPolicyID.String(),
		"company_id":        companyID.String(),
		"is_active":         true,
	}
	if err := s.emitEvent(ctx, tx, billingPolicyID, events.EventBillingPolicyActivated, payload); err != nil {
		logger.Warn("failed to emit activate event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "billing_policy", "activate", "billing_policy",
			&billingPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *billingPolicyService) Deactivate(ctx context.Context, companyID, billingPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-deactivate-%s", billingPolicyID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – deactivation already processed")
		return nil
	}

	if err := s.repo.Deactivate(ctx, tx, companyID, billingPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"billing_policy_id": billingPolicyID.String(),
		"company_id":        companyID.String(),
		"is_active":         false,
	}
	if err := s.emitEvent(ctx, tx, billingPolicyID, events.EventBillingPolicyDeactivated, payload); err != nil {
		logger.Warn("failed to emit deactivate event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "billing_policy", "deactivate", "billing_policy",
			&billingPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *billingPolicyService) Restore(ctx context.Context, companyID, billingPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-restore-%s", billingPolicyID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – restore already processed")
		return nil
	}

	if err := s.repo.Restore(ctx, tx, companyID, billingPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"billing_policy_id": billingPolicyID.String(),
		"company_id":        companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, billingPolicyID, events.EventBillingPolicyRestored, payload); err != nil {
		logger.Warn("failed to emit restore event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "billing_policy", "restore", "billing_policy",
			&billingPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// ---- Business Configuration Updates ----

// UpdateFrequency updates the frequency_id of a billing policy.
func (s *billingPolicyService) UpdateFrequency(ctx context.Context, companyID, billingPolicyID uuid.UUID, frequencyID int16) error {
	return s.updateField(ctx, companyID, billingPolicyID, func(p *models.BillingPolicy) error {
		freq, err := s.lookupRepo.GetBillingFrequencyByID(ctx, s.pgClient.DB, frequencyID)
		if err != nil || freq == nil {
			return subErrors.ErrInvalidInput
		}
		p.FrequencyID = frequencyID
		return nil
	}, "frequency_id", frequencyID)
}

// UpdateBillingModel updates the model_id of a billing policy.
func (s *billingPolicyService) UpdateBillingModel(ctx context.Context, companyID, billingPolicyID uuid.UUID, modelID int16) error {
	return s.updateField(ctx, companyID, billingPolicyID, func(p *models.BillingPolicy) error {
		model, err := s.lookupRepo.GetPricingModelByID(ctx, s.pgClient.DB, modelID)
		if err != nil || model == nil {
			return subErrors.ErrInvalidInput
		}
		p.ModelID = modelID
		return nil
	}, "model_id", modelID)
}
func (s *billingPolicyService) UpdateBillingInterval(ctx context.Context, companyID, billingPolicyID uuid.UUID, interval int) error {
	if interval <= 0 {
		return subErrors.ErrInvalidInput
	}
	return s.updateField(ctx, companyID, billingPolicyID, func(p *models.BillingPolicy) error {
		p.BillingInterval = interval
		return nil
	}, "billing_interval", interval)
}

func (s *billingPolicyService) UpdateAdvanceBillingDays(ctx context.Context, companyID, billingPolicyID uuid.UUID, days int) error {
	if days < 0 {
		return subErrors.ErrInvalidInput
	}
	return s.updateField(ctx, companyID, billingPolicyID, func(p *models.BillingPolicy) error {
		p.AdvanceDays = days
		return nil
	}, "advance_days", days)
}

func (s *billingPolicyService) updateField(ctx context.Context, companyID, billingPolicyID uuid.UUID, updateFn func(*models.BillingPolicy) error, fieldName string, newValue interface{}) error {
	logger := s.logger.With(zap.String("method", "updateField"), zap.String("field", fieldName))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getBillingPolicyIdempotencyKey(ctx, fmt.Sprintf("billingpolicy-updatefield-%s-%s", billingPolicyID.String(), fieldName))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – field update already processed")
		return nil
	}

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, billingPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return subErrors.ErrNotFound
	}

	if err := updateFn(policy); err != nil {
		return err
	}
	policy.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := buildBillingPolicyPayload(policy)
	if err := s.emitEvent(ctx, tx, billingPolicyID, events.EventBillingPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "billing_policy", "update_field", "billing_policy",
			&billingPolicyID, "system", nil, nil, nil, map[string]interface{}{
				"field": fieldName,
				"value": newValue,
			})
	}
	return nil
}

// ---- Validation ----

func (s *billingPolicyService) Validate(ctx context.Context, policy *models.BillingPolicy) error {
	if policy.Name == "" {
		return subErrors.ErrInvalidInput
	}
	if policy.BillingInterval <= 0 {
		return subErrors.ErrInvalidInput
	}
	if policy.AdvanceDays < 0 {
		return subErrors.ErrInvalidInput
	}
	if _, err := s.lookupRepo.GetBillingFrequencyByID(ctx, s.pgClient.DB, policy.FrequencyID); err != nil {
		return subErrors.ErrInvalidInput
	}
	if _, err := s.lookupRepo.GetPricingModelByID(ctx, s.pgClient.DB, policy.ModelID); err != nil {
		return subErrors.ErrInvalidInput
	}
	return nil
}

func (s *billingPolicyService) Exists(ctx context.Context, companyID, billingPolicyID uuid.UUID) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, billingPolicyID)
}

// ---- Query ----

func (s *billingPolicyService) List(ctx context.Context, filter repository.BillingPolicyFilter, p repository.Pagination, srt repository.Sort) ([]*models.BillingPolicy, int64, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *billingPolicyService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.BillingPolicy, int64, error) {
	return s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *billingPolicyService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.BillingPolicy, error) {
	return s.repo.GetActive(ctx, s.pgClient.DB, companyID)
}
