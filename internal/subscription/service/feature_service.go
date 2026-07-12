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

// FeatureService defines the interface for managing feature definitions.
// Note: Feature key is the primary identifier (string), not UUID.
type FeatureService interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, feature *models.FeatureRegistry) error
	Update(ctx context.Context, feature *models.FeatureRegistry) error
	Delete(ctx context.Context, companyID uuid.UUID, featureKey string) error
	GetByKey(ctx context.Context, companyID uuid.UUID, featureKey string) (*models.FeatureRegistry, error)

	// -------------------------------------------------------------------------
	// Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, companyID uuid.UUID, featureKey string) error
	Deactivate(ctx context.Context, companyID uuid.UUID, featureKey string) error

	// -------------------------------------------------------------------------
	// Configuration (partial updates)
	// -------------------------------------------------------------------------

	UpdateModule(ctx context.Context, companyID uuid.UUID, featureKey string, module string) error
	UpdateFeatureGroup(ctx context.Context, companyID uuid.UUID, featureKey string, featureGroup *string) error
	UpdatePermissionScope(ctx context.Context, companyID uuid.UUID, featureKey string, permissionScope *string) error
	UpdateDescription(ctx context.Context, companyID uuid.UUID, featureKey string, description *string) error
	UpdateDefaultLimit(ctx context.Context, companyID uuid.UUID, featureKey string, defaultLimit *decimal.Decimal) error
	UpdateDependsOn(ctx context.Context, companyID uuid.UUID, featureKey string, dependsOn []string) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Validate(ctx context.Context, feature *models.FeatureRegistry) error
	Exists(ctx context.Context, companyID uuid.UUID, featureKey string) (bool, error)
	KeyExists(ctx context.Context, companyID uuid.UUID, featureKey string) (bool, error) // alias
	IsActive(ctx context.Context, companyID uuid.UUID, featureKey string) (bool, error)

	// -------------------------------------------------------------------------
	// Query
	// -------------------------------------------------------------------------

	List(ctx context.Context, filter repository.FeatureFilter, p repository.Pagination, s repository.Sort) ([]*models.FeatureRegistry, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.FeatureRegistry, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.FeatureRegistry, error)
	GetByModule(ctx context.Context, companyID uuid.UUID, module string) ([]*models.FeatureRegistry, error)
	GetByFeatureGroup(ctx context.Context, companyID uuid.UUID, featureGroup string) ([]*models.FeatureRegistry, error)
	GetByPermissionScope(ctx context.Context, companyID uuid.UUID, permissionScope string) ([]*models.FeatureRegistry, error)
}

// featureService is the concrete implementation.
type featureService struct {
	repo             repository.FeatureRepository
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewFeatureService creates a new instance.
func NewFeatureService(
	repo repository.FeatureRepository,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) FeatureService {
	return &featureService{
		repo:             repo,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		pgClient:         pgClient,
		logger:           logger.Named("feature_service"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (s *featureService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *featureService) emitEvent(ctx context.Context, tx repository.DBTX, featureKey string, eventType string, payload interface{}) error {
	sqlTx, err := s.getSQLTx(tx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// Generate a deterministic UUID from the feature key.
	aggregateID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(featureKey)).String()
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "feature",
		AggregateID:   aggregateID, // now a valid UUID string
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}
func buildFeaturePayload(feature *models.FeatureRegistry) events.FeaturePayload {
	payload := events.FeaturePayload{
		FeatureKey: feature.FeatureKey,
		Module:     feature.Module,
		IsActive:   feature.IsActive,
		Version:    feature.Version,
		CreatedAt:  feature.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  feature.UpdatedAt.Format(time.RFC3339),
	}
	if feature.FeatureGroup != nil {
		payload.FeatureGroup = *feature.FeatureGroup
	}
	if feature.PermissionScope != nil {
		payload.PermissionScope = *feature.PermissionScope
	}
	if feature.Description != nil {
		payload.Description = *feature.Description
	}
	if feature.DefaultLimit != nil {
		payload.DefaultLimit = feature.DefaultLimit.String()
	}
	if feature.DependsOn != nil {
		payload.DependsOn = feature.DependsOn
	}
	return payload
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (s *featureService) Create(ctx context.Context, feature *models.FeatureRegistry) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("create-feature-%s", feature.FeatureKey))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – operation already performed, skipping create")
		return nil
	}

	if err := s.Validate(ctx, feature); err != nil {
		return err
	}
	exists, err := s.repo.Exists(ctx, tx, feature.FeatureKey)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrDuplicate
	}

	feature.CreatedAt = time.Now()
	feature.UpdatedAt = time.Now()
	feature.IsActive = true // default

	if err := s.repo.Create(ctx, tx, feature); err != nil {
		return err
	}

	payload := buildFeaturePayload(feature)
	if err := s.emitEvent(ctx, tx, feature.FeatureKey, events.EventFeatureCreated, payload); err != nil {
		logger.Warn("failed to emit created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "feature", "create", "feature",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"feature_key": feature.FeatureKey,
				"module":      feature.Module,
			})
	}
	return nil
}

func (s *featureService) Update(ctx context.Context, feature *models.FeatureRegistry) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-feature-%s", feature.FeatureKey))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update already performed")
		return nil
	}

	existing, err := s.repo.GetByKeyForUpdate(ctx, tx, feature.FeatureKey)
	if err != nil {
		return err
	}

	if err := s.Validate(ctx, feature); err != nil {
		return err
	}

	// Update fields (key is immutable)
	existing.Module = feature.Module
	existing.FeatureGroup = feature.FeatureGroup
	existing.PermissionScope = feature.PermissionScope
	existing.Description = feature.Description
	existing.DefaultLimit = feature.DefaultLimit
	existing.DependsOn = feature.DependsOn
	existing.Version = feature.Version
	existing.IsActive = feature.IsActive
	existing.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return err
	}

	payload := buildFeaturePayload(existing)
	if err := s.emitEvent(ctx, tx, existing.FeatureKey, events.EventFeatureUpdated, payload); err != nil {
		logger.Warn("failed to emit updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "feature", "update", "feature",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"feature_key": feature.FeatureKey,
			})
	}
	return nil
}

func (s *featureService) Delete(ctx context.Context, companyID uuid.UUID, featureKey string) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("delete-feature-%s", featureKey))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – delete already performed")
		return nil
	}

	exists, err := s.repo.Exists(ctx, tx, featureKey)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}

	if err := s.repo.Delete(ctx, tx, featureKey); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"feature_key": featureKey,
	}
	if err := s.emitEvent(ctx, tx, featureKey, events.EventFeatureDeleted, payload); err != nil {
		logger.Warn("failed to emit deleted event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "feature", "delete", "feature",
			nil, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *featureService) GetByKey(ctx context.Context, companyID uuid.UUID, featureKey string) (*models.FeatureRegistry, error) {
	return s.repo.GetByKey(ctx, s.pgClient.DB, featureKey)
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (s *featureService) Activate(ctx context.Context, companyID uuid.UUID, featureKey string) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("activate-feature-%s", featureKey))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – activate already performed")
		return nil
	}

	if err := s.repo.Activate(ctx, tx, featureKey); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"feature_key": featureKey,
		"status":      "active",
	}
	if err := s.emitEvent(ctx, tx, featureKey, events.EventFeatureActivated, payload); err != nil {
		logger.Warn("failed to emit activated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "feature", "activate", "feature",
			nil, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *featureService) Deactivate(ctx context.Context, companyID uuid.UUID, featureKey string) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("deactivate-feature-%s", featureKey))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – deactivate already performed")
		return nil
	}

	if err := s.repo.Deactivate(ctx, tx, featureKey); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"feature_key": featureKey,
		"status":      "inactive",
	}
	if err := s.emitEvent(ctx, tx, featureKey, events.EventFeatureDeactivated, payload); err != nil {
		logger.Warn("failed to emit deactivated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "feature", "deactivate", "feature",
			nil, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Configuration (partial updates)
// -------------------------------------------------------------------------

func (s *featureService) UpdateModule(ctx context.Context, companyID uuid.UUID, featureKey string, module string) error {
	return s.updateField(ctx, companyID, featureKey, "module", module)
}

func (s *featureService) UpdateFeatureGroup(ctx context.Context, companyID uuid.UUID, featureKey string, featureGroup *string) error {
	return s.updateField(ctx, companyID, featureKey, "feature_group", featureGroup)
}

func (s *featureService) UpdatePermissionScope(ctx context.Context, companyID uuid.UUID, featureKey string, permissionScope *string) error {
	return s.updateField(ctx, companyID, featureKey, "permission_scope", permissionScope)
}

func (s *featureService) UpdateDescription(ctx context.Context, companyID uuid.UUID, featureKey string, description *string) error {
	return s.updateField(ctx, companyID, featureKey, "description", description)
}

func (s *featureService) UpdateDefaultLimit(ctx context.Context, companyID uuid.UUID, featureKey string, defaultLimit *decimal.Decimal) error {
	return s.updateField(ctx, companyID, featureKey, "default_limit", defaultLimit)
}

func (s *featureService) UpdateDependsOn(ctx context.Context, companyID uuid.UUID, featureKey string, dependsOn []string) error {
	return s.updateField(ctx, companyID, featureKey, "depends_on", dependsOn)
}

// updateField is a generic helper for partial updates.
func (s *featureService) updateField(ctx context.Context, companyID uuid.UUID, featureKey string, field string, value interface{}) error {
	logger := s.logger.With(zap.String("method", "updateField"), zap.String("field", field))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-feature-%s-%s", featureKey, field))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update already performed")
		return nil
	}

	feature, err := s.repo.GetByKeyForUpdate(ctx, tx, featureKey)
	if err != nil {
		return err
	}

	switch field {
	case "module":
		feature.Module = value.(string)
	case "feature_group":
		feature.FeatureGroup = value.(*string)
	case "permission_scope":
		feature.PermissionScope = value.(*string)
	case "description":
		feature.Description = value.(*string)
	case "default_limit":
		feature.DefaultLimit = value.(*decimal.Decimal)
	case "depends_on":
		feature.DependsOn = value.([]string)
	default:
		return fmt.Errorf("%w: unknown field %s", errors.ErrInvalidInput, field)
	}
	feature.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, tx, feature); err != nil {
		return err
	}

	payload := buildFeaturePayload(feature)
	if err := s.emitEvent(ctx, tx, featureKey, events.EventFeatureUpdated, payload); err != nil {
		logger.Warn("failed to emit update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "feature", "update_"+field, "feature",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"feature_key": featureKey,
				field:         value,
			})
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (s *featureService) Validate(ctx context.Context, feature *models.FeatureRegistry) error {
	if feature == nil {
		return errors.ErrInvalidInput
	}
	if feature.FeatureKey == "" {
		return fmt.Errorf("%w: feature key is required", errors.ErrInvalidInput)
	}
	if feature.Module == "" {
		return fmt.Errorf("%w: module is required", errors.ErrInvalidInput)
	}
	// Additional validation (e.g., key format, dependencies) can be added.
	return nil
}

func (s *featureService) Exists(ctx context.Context, companyID uuid.UUID, featureKey string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, featureKey)
}

func (s *featureService) KeyExists(ctx context.Context, companyID uuid.UUID, featureKey string) (bool, error) {
	return s.Exists(ctx, companyID, featureKey)
}

func (s *featureService) IsActive(ctx context.Context, companyID uuid.UUID, featureKey string) (bool, error) {
	return s.repo.IsActive(ctx, s.pgClient.DB, featureKey)
}

// -------------------------------------------------------------------------
// Query
// -------------------------------------------------------------------------

func (s *featureService) List(ctx context.Context, filter repository.FeatureFilter, p repository.Pagination, srt repository.Sort) ([]*models.FeatureRegistry, int64, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *featureService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.FeatureRegistry, int64, error) {
	return s.repo.Search(ctx, s.pgClient.DB, query, limit, offset)
}

func (s *featureService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.FeatureRegistry, error) {
	return s.repo.GetActive(ctx, s.pgClient.DB)
}

func (s *featureService) GetByModule(ctx context.Context, companyID uuid.UUID, module string) ([]*models.FeatureRegistry, error) {
	return s.repo.GetByModule(ctx, s.pgClient.DB, module)
}

func (s *featureService) GetByFeatureGroup(ctx context.Context, companyID uuid.UUID, featureGroup string) ([]*models.FeatureRegistry, error) {
	return s.repo.GetByFeatureGroup(ctx, s.pgClient.DB, featureGroup)
}

func (s *featureService) GetByPermissionScope(ctx context.Context, companyID uuid.UUID, permissionScope string) ([]*models.FeatureRegistry, error) {
	return s.repo.GetByPermissionScope(ctx, s.pgClient.DB, permissionScope)
}
