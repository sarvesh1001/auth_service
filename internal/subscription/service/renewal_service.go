package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
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

// RenewalPolicyService defines the business operations for managing renewal policies.
type RenewalPolicyService interface {
	Create(ctx context.Context, policy *models.RenewalPolicy) error
	Update(ctx context.Context, policy *models.RenewalPolicy) error
	Delete(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error
	GetByID(ctx context.Context, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.RenewalPolicy, error)
	Activate(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error
	Deactivate(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error
	Restore(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error
	UpdateAutoRenew(ctx context.Context, companyID, renewalPolicyID uuid.UUID, autoRenew bool) error
	UpdateGracePeriod(ctx context.Context, companyID, renewalPolicyID uuid.UUID, graceDays int) error
	UpdateLateFee(ctx context.Context, companyID, renewalPolicyID uuid.UUID, lateFeePercent float64) error
	UpdateNoticePeriod(ctx context.Context, companyID, renewalPolicyID uuid.UUID, noticeDays int) error
	Validate(ctx context.Context, policy *models.RenewalPolicy) error
	Exists(ctx context.Context, companyID, renewalPolicyID uuid.UUID) (bool, error)
	CanAutoRenew(ctx context.Context, companyID, renewalPolicyID uuid.UUID) (bool, error)
	List(ctx context.Context, filter repository.RenewalPolicyFilter, p Pagination, s Sort) ([]*models.RenewalPolicy, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.RenewalPolicy, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.RenewalPolicy, error)
	GetAutoRenewPolicies(ctx context.Context, companyID uuid.UUID) ([]*models.RenewalPolicy, error)
	GetManualRenewPolicies(ctx context.Context, companyID uuid.UUID) ([]*models.RenewalPolicy, error)
}

// Pagination and Sort (redefined here, but in practice they'd be in a common package)
type Pagination struct {
	Limit  int
	Offset int
}

type Sort struct {
	Field     string
	Direction string
}

type renewalPolicyService struct {
	repo             repository.RenewalPolicyRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
}

func NewRenewalPolicyService(
	repo repository.RenewalPolicyRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
) RenewalPolicyService {
	return &renewalPolicyService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("renewal_policy_service"),
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
	}
}

// Helper to extract *sql.Tx from a DBTX
func (s *renewalPolicyService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

// emitEvent stores an outbox event using the subscription-events topic.
func (s *renewalPolicyService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "renewal_policy",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// Validate performs business rule validation.
func (s *renewalPolicyService) Validate(ctx context.Context, policy *models.RenewalPolicy) error {
	if policy.Name == "" {
		return errors.ErrInvalidInput
	}
	if policy.GraceDays < 0 {
		return errors.ErrInvalidInput
	}
	if policy.NoticeDays < 0 {
		return errors.ErrInvalidInput
	}
	if policy.LateFeePercent.Sign() < 0 || policy.LateFeePercent.GreaterThanOrEqual(decimal.NewFromInt(100)) {
		return errors.ErrInvalidInput
	}
	return nil
}

// Create creates a new renewal policy.
func (s *renewalPolicyService) Create(ctx context.Context, policy *models.RenewalPolicy) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("create-renewal-policy-%s", policy.Name))
	var cached *models.RenewalPolicy
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached policy")
		*policy = *cached
		return nil
	}

	if err := s.Validate(ctx, policy); err != nil {
		return err
	}

	exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrDuplicate
	}

	if !policy.IsActive {
		policy.IsActive = true
	}
	policy.RenewalPolicyID = uuid.New()
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	if err := s.repo.Create(ctx, tx, policy); err != nil {
		return err
	}

	payload := events.RenewalPolicyPayload{
		RenewalPolicyID: policy.RenewalPolicyID.String(),
		CompanyID:       policy.CompanyID.String(),
		Name:            policy.Name,
		AutoRenew:       policy.AutoRenew,
		GraceDays:       policy.GraceDays,
		LateFeePercent:  policy.LateFeePercent.InexactFloat64(),
		NoticeDays:      policy.NoticeDays,
		IsActive:        policy.IsActive,
	}
	if err := s.emitEvent(ctx, tx, policy.RenewalPolicyID, events.EventRenewalPolicyCreated, payload); err != nil {
		logger.Warn("failed to emit create event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, policy); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &policy.CompanyID, "renewal_policy", "create", "renewal_policy",
			&policy.RenewalPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// Update updates an existing renewal policy.
func (s *renewalPolicyService) Update(ctx context.Context, policy *models.RenewalPolicy) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-renewal-policy-%s", policy.RenewalPolicyID.String()))
	var cached *models.RenewalPolicy
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached policy")
		*policy = *cached
		return nil
	}

	if err := s.Validate(ctx, policy); err != nil {
		return err
	}

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, policy.CompanyID, policy.RenewalPolicyID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.ErrNotFound
	}

	if existing.Name != policy.Name {
		exists, err := s.repo.ExistsByName(ctx, tx, policy.CompanyID, policy.Name)
		if err != nil {
			return err
		}
		if exists {
			return errors.ErrDuplicate
		}
	}

	existing.Name = policy.Name
	existing.AutoRenew = policy.AutoRenew
	existing.GraceDays = policy.GraceDays
	existing.LateFeePercent = policy.LateFeePercent
	existing.NoticeDays = policy.NoticeDays
	existing.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return err
	}

	payload := events.RenewalPolicyPayload{
		RenewalPolicyID: existing.RenewalPolicyID.String(),
		CompanyID:       existing.CompanyID.String(),
		Name:            existing.Name,
		AutoRenew:       existing.AutoRenew,
		GraceDays:       existing.GraceDays,
		LateFeePercent:  existing.LateFeePercent.InexactFloat64(),
		NoticeDays:      existing.NoticeDays,
		IsActive:        existing.IsActive,
	}
	if err := s.emitEvent(ctx, tx, existing.RenewalPolicyID, events.EventRenewalPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, existing); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &policy.CompanyID, "renewal_policy", "update", "renewal_policy",
			&policy.RenewalPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// Delete soft-deletes a renewal policy (only if not referenced by any plan).
func (s *renewalPolicyService) Delete(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check if any plan references this renewal policy
	var count int64
	query := `SELECT COUNT(*) FROM subscription.plans WHERE company_id = $1 AND renewal_policy_id = $2 AND deleted_at IS NULL`
	err = tx.QueryRowContext(ctx, query, companyID, renewalPolicyID).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check plan references: %w", err)
	}
	if count > 0 {
		return errors.ErrConflict
	}

	if err := s.repo.SoftDelete(ctx, tx, companyID, renewalPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"company_id":        companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyDeleted, payload); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "renewal_policy", "delete", "renewal_policy",
			&renewalPolicyID, "system", nil, nil, nil, nil)
	}
	return nil
}

// GetByID retrieves a policy by ID.
func (s *renewalPolicyService) GetByID(ctx context.Context, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, renewalPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by id: %w", err)
	}
	if policy == nil {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

// GetByName retrieves a policy by name.
func (s *renewalPolicyService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.RenewalPolicy, error) {
	policy, err := s.repo.GetByName(ctx, s.pgClient.DB, companyID, name)
	if err != nil {
		return nil, fmt.Errorf("get by name: %w", err)
	}
	if policy == nil {
		return nil, errors.ErrNotFound
	}
	return policy, nil
}

// Activate sets the policy to active.
func (s *renewalPolicyService) Activate(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Activate(ctx, tx, companyID, renewalPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"company_id":        companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyActivated, payload); err != nil {
		logger.Warn("failed to emit activate event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Deactivate sets the policy to inactive.
func (s *renewalPolicyService) Deactivate(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Deactivate(ctx, tx, companyID, renewalPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"company_id":        companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyDeactivated, payload); err != nil {
		logger.Warn("failed to emit deactivate event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Restore restores a soft-deleted policy.
func (s *renewalPolicyService) Restore(ctx context.Context, companyID, renewalPolicyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Restore(ctx, tx, companyID, renewalPolicyID); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"company_id":        companyID.String(),
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyRestored, payload); err != nil {
		logger.Warn("failed to emit restore event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// UpdateAutoRenew updates only the auto-renew flag.
func (s *renewalPolicyService) UpdateAutoRenew(ctx context.Context, companyID, renewalPolicyID uuid.UUID, autoRenew bool) error {
	logger := s.logger.With(zap.String("method", "UpdateAutoRenew"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, renewalPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.AutoRenew = autoRenew
	policy.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"auto_renew":        autoRenew,
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// UpdateGracePeriod updates the grace days.
func (s *renewalPolicyService) UpdateGracePeriod(ctx context.Context, companyID, renewalPolicyID uuid.UUID, graceDays int) error {
	if graceDays < 0 {
		return errors.ErrInvalidInput
	}
	logger := s.logger.With(zap.String("method", "UpdateGracePeriod"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, renewalPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.GraceDays = graceDays
	policy.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"grace_days":        graceDays,
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// UpdateLateFee updates the late fee percentage.
func (s *renewalPolicyService) UpdateLateFee(ctx context.Context, companyID, renewalPolicyID uuid.UUID, lateFeePercent float64) error {
	if lateFeePercent < 0 || lateFeePercent >= 100 {
		return errors.ErrInvalidInput
	}
	logger := s.logger.With(zap.String("method", "UpdateLateFee"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, renewalPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.LateFeePercent = decimal.NewFromFloat(lateFeePercent)
	policy.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"late_fee_percent":  lateFeePercent,
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// UpdateNoticePeriod updates the notice days.
func (s *renewalPolicyService) UpdateNoticePeriod(ctx context.Context, companyID, renewalPolicyID uuid.UUID, noticeDays int) error {
	if noticeDays < 0 {
		return errors.ErrInvalidInput
	}
	logger := s.logger.With(zap.String("method", "UpdateNoticePeriod"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetByIDForUpdate(ctx, tx, companyID, renewalPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.ErrNotFound
	}
	policy.NoticeDays = noticeDays
	policy.UpdatedAt = time.Now()
	if err := s.repo.Update(ctx, tx, policy); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"renewal_policy_id": renewalPolicyID.String(),
		"notice_days":       noticeDays,
	}
	if err := s.emitEvent(ctx, tx, renewalPolicyID, events.EventRenewalPolicyUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Exists checks if a policy exists.
func (s *renewalPolicyService) Exists(ctx context.Context, companyID, renewalPolicyID uuid.UUID) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, renewalPolicyID)
}

// CanAutoRenew returns true if policy is active and auto-renew is enabled.
func (s *renewalPolicyService) CanAutoRenew(ctx context.Context, companyID, renewalPolicyID uuid.UUID) (bool, error) {
	policy, err := s.repo.GetByID(ctx, s.pgClient.DB, companyID, renewalPolicyID)
	if err != nil {
		return false, err
	}
	if policy == nil {
		return false, errors.ErrNotFound
	}
	return policy.IsActive && policy.AutoRenew, nil
}

// List returns a paginated list of policies matching the filter.
func (s *renewalPolicyService) List(ctx context.Context, filter repository.RenewalPolicyFilter, p Pagination, sort Sort) ([]*models.RenewalPolicy, int64, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: p.Limit, Offset: p.Offset}, repository.Sort{Field: sort.Field, Direction: sort.Direction})
}

// Search performs a full-text search.
func (s *renewalPolicyService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.RenewalPolicy, int64, error) {
	return s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

// GetActive returns all active policies.
func (s *renewalPolicyService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	return s.repo.GetActive(ctx, s.pgClient.DB, companyID)
}

// GetAutoRenewPolicies returns policies with auto-renew enabled.
func (s *renewalPolicyService) GetAutoRenewPolicies(ctx context.Context, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	return s.repo.GetAutoRenewPolicies(ctx, s.pgClient.DB, companyID)
}

// GetManualRenewPolicies returns policies with auto-renew disabled.
func (s *renewalPolicyService) GetManualRenewPolicies(ctx context.Context, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	return s.repo.GetManualRenewPolicies(ctx, s.pgClient.DB, companyID)
}
