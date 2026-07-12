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
// Interface Definition
// ----------------------------------------------------------------------------

type BenefitService interface {
	Create(ctx context.Context, benefit *models.Benefit) error
	BulkCreate(ctx context.Context, benefits []*models.Benefit) error
	Update(ctx context.Context, benefit *models.Benefit) error
	Delete(ctx context.Context, benefitID uuid.UUID) error
	GetByID(ctx context.Context, benefitID uuid.UUID) (*models.Benefit, error)
	ReplaceByPlanItem(ctx context.Context, planItemID uuid.UUID, benefits []*models.Benefit) error
	DeleteByPlanItem(ctx context.Context, planItemID uuid.UUID) error
	CopyToPlanItem(ctx context.Context, sourcePlanItemID, targetPlanItemID uuid.UUID) error
	Validate(ctx context.Context, benefit *models.Benefit) error
	Exists(ctx context.Context, benefitID uuid.UUID) (bool, error)
	ExistsByType(ctx context.Context, planItemID uuid.UUID, benefitType enums.BenefitType) (bool, error)
	List(ctx context.Context, filter repository.BenefitFilter, p repository.Pagination, s repository.Sort) ([]*models.Benefit, int64, error)
	Search(ctx context.Context, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Benefit, int64, error)
	GetByPlanItem(ctx context.Context, planItemID uuid.UUID) ([]*models.Benefit, error)
	GetByType(ctx context.Context, benefitType enums.BenefitType) ([]*models.Benefit, error)
}

// ----------------------------------------------------------------------------
// Implementation
// ----------------------------------------------------------------------------

type benefitService struct {
	benefitRepo      repository.BenefitRepository
	planItemRepo     repository.PlanItemRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	auditService     *audit.AuditService
}

func NewBenefitService(
	benefitRepo repository.BenefitRepository,
	planItemRepo repository.PlanItemRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	auditService *audit.AuditService,
) BenefitService {
	return &benefitService{
		benefitRepo:      benefitRepo,
		planItemRepo:     planItemRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		pgClient:         pgClient,
		logger:           logger.Named("benefit_service"),
		auditService:     auditService,
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (s *benefitService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func getIdempotencyKey(ctx context.Context, fallback string) string {
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		return key
	}
	return fallback
}

func (s *benefitService) emitBenefitEvent(ctx context.Context, tx repository.DBTX, benefit *models.Benefit, eventType string) error {
	sqlTx, err := s.getSQLTx(tx)
	if err != nil {
		return err
	}
	payload := events.BenefitPayload{
		BenefitID:          benefit.BenefitID.String(),
		PlanItemID:         benefit.PlanItemID.String(),
		BenefitType:        string(benefit.BenefitType),
		BenefitDescription: benefit.BenefitDescription,
		Value:              benefit.Value,
		CreatedAt:          benefit.CreatedAt.Format(time.RFC3339),
		UpdatedAt:          benefit.UpdatedAt.Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "benefit",
		AggregateID:   benefit.BenefitID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// ----------------------------------------------------------------------------
// CRUD with idempotency and validation
// ----------------------------------------------------------------------------

// Create – with validation, duplicate check, timestamps, and idempotency.
func (s *benefitService) Create(ctx context.Context, benefit *models.Benefit) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, fmt.Sprintf("benefit-create-%s", benefit.BenefitID.String()))
	var existingBenefitID string
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &existingBenefitID); err == nil && existingBenefitID != "" {
		logger.Info("idempotent – benefit already created, fetching existing")
		existingUUID, parseErr := uuid.Parse(existingBenefitID)
		if parseErr != nil {
			return fmt.Errorf("invalid existing benefit ID in idempotency store: %w", parseErr)
		}
		existing, getErr := s.benefitRepo.GetByID(ctx, tx, existingUUID)
		if getErr != nil || existing == nil {
			return errors.ErrNotFound
		}
		// Populate the passed pointer with existing data
		benefit.BenefitID = existing.BenefitID
		benefit.PlanItemID = existing.PlanItemID
		benefit.BenefitType = existing.BenefitType
		benefit.BenefitDescription = existing.BenefitDescription
		benefit.Value = existing.Value
		benefit.CreatedAt = existing.CreatedAt
		benefit.UpdatedAt = existing.UpdatedAt
		return nil
	}

	// --- Validation ---
	if err := s.Validate(ctx, benefit); err != nil {
		return err
	}
	// --- Duplicate check: marshal value to JSON for repository ---
	valueJSON, err := json.Marshal(benefit.Value)
	if err != nil {
		return fmt.Errorf("marshal benefit value: %w", err)
	}
	dup, err := s.benefitRepo.ExistsByPlanItemTypeAndValue(ctx, tx, benefit.PlanItemID, benefit.BenefitType, valueJSON)
	if err != nil {
		return err
	}
	if dup {
		return errors.ErrDuplicate
	}
	// --- Plan item existence ---
	exists, err := s.planItemRepo.Exists(ctx, tx, benefit.PlanItemID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}
	// --- Set timestamps ---
	now := time.Now()
	benefit.CreatedAt = now
	benefit.UpdatedAt = now

	if err := s.benefitRepo.Create(ctx, tx, benefit); err != nil {
		return err
	}
	if err := s.emitBenefitEvent(ctx, tx, benefit, events.EventBenefitCreated); err != nil {
		logger.Warn("failed to emit benefit created event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, benefit.BenefitID.String()); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "create", benefit.BenefitID.String(),
			&benefit.BenefitID, "system", nil, nil, nil, map[string]interface{}{
				"plan_item_id": benefit.PlanItemID,
				"type":         benefit.BenefitType,
			})
	}
	return nil
}

// BulkCreate – with validation, duplicate check, timestamps, and idempotency.
func (s *benefitService) BulkCreate(ctx context.Context, benefits []*models.Benefit) error {
	if len(benefits) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, "benefit-bulk-create")
	var storedData string
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &storedData); err == nil && storedData != "" {
		logger.Info("idempotent – bulk creation already processed, fetching existing benefits")
		var ids []string
		if err := json.Unmarshal([]byte(storedData), &ids); err != nil {
			return fmt.Errorf("invalid idempotency data: %w", err)
		}
		for i, idStr := range ids {
			if i >= len(benefits) {
				break
			}
			benefitUUID, parseErr := uuid.Parse(idStr)
			if parseErr != nil {
				return fmt.Errorf("invalid benefit ID in idempotency store: %w", parseErr)
			}
			existing, getErr := s.benefitRepo.GetByID(ctx, tx, benefitUUID)
			if getErr != nil || existing == nil {
				return errors.ErrNotFound
			}
			benefits[i].BenefitID = existing.BenefitID
			benefits[i].PlanItemID = existing.PlanItemID
			benefits[i].BenefitType = existing.BenefitType
			benefits[i].BenefitDescription = existing.BenefitDescription
			benefits[i].Value = existing.Value
			benefits[i].CreatedAt = existing.CreatedAt
			benefits[i].UpdatedAt = existing.UpdatedAt
		}
		return nil
	}

	// --- Validate each benefit, check duplicates, check plan items ---
	for _, b := range benefits {
		if err := s.Validate(ctx, b); err != nil {
			return err
		}
		valueJSON, err := json.Marshal(b.Value)
		if err != nil {
			return fmt.Errorf("marshal benefit value: %w", err)
		}
		dup, err := s.benefitRepo.ExistsByPlanItemTypeAndValue(ctx, tx, b.PlanItemID, b.BenefitType, valueJSON)
		if err != nil {
			return err
		}
		if dup {
			return errors.ErrDuplicate
		}
		exists, err := s.planItemRepo.Exists(ctx, tx, b.PlanItemID)
		if err != nil {
			return err
		}
		if !exists {
			return errors.ErrNotFound
		}
	}
	// Set timestamps and assign IDs if needed (already set by handler, but we ensure)
	now := time.Now()
	for _, b := range benefits {
		if b.BenefitID == uuid.Nil {
			b.BenefitID = uuid.New()
		}
		b.CreatedAt = now
		b.UpdatedAt = now
	}
	if err := s.benefitRepo.BulkCreate(ctx, tx, benefits); err != nil {
		return err
	}
	// Collect IDs and store
	ids := make([]string, len(benefits))
	for i, b := range benefits {
		ids[i] = b.BenefitID.String()
		if err := s.emitBenefitEvent(ctx, tx, b, events.EventBenefitBulkCreated); err != nil {
			logger.Warn("failed to emit benefit bulk created event", zap.Error(err))
		}
	}
	data, _ := json.Marshal(ids)
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, string(data)); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "bulk_create", "",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"count": len(benefits),
			})
	}
	return nil
}

// Update – with validation, timestamp update, and idempotency.
func (s *benefitService) Update(ctx context.Context, benefit *models.Benefit) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, fmt.Sprintf("benefit-update-%s", benefit.BenefitID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – benefit update already processed")
		existing, getErr := s.benefitRepo.GetByID(ctx, tx, benefit.BenefitID)
		if getErr == nil && existing != nil {
			benefit.BenefitType = existing.BenefitType
			benefit.BenefitDescription = existing.BenefitDescription
			benefit.Value = existing.Value
			benefit.UpdatedAt = existing.UpdatedAt
		}
		return nil
	}

	if err := s.Validate(ctx, benefit); err != nil {
		return err
	}
	exists, err := s.benefitRepo.Exists(ctx, tx, benefit.BenefitID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}
	// Update timestamp
	benefit.UpdatedAt = time.Now()

	if err := s.benefitRepo.Update(ctx, tx, benefit); err != nil {
		return err
	}
	if err := s.emitBenefitEvent(ctx, tx, benefit, events.EventBenefitUpdated); err != nil {
		logger.Warn("failed to emit benefit updated event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "update", benefit.BenefitID.String(),
			&benefit.BenefitID, "system", nil, nil, nil, map[string]interface{}{
				"updated_fields": "benefit details",
			})
	}
	return nil
}

// Delete – idempotent (store boolean).
func (s *benefitService) Delete(ctx context.Context, benefitID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, fmt.Sprintf("benefit-delete-%s", benefitID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – benefit deletion already processed")
		return nil
	}

	exists, err := s.benefitRepo.Exists(ctx, tx, benefitID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}
	benefit, err := s.benefitRepo.GetByID(ctx, tx, benefitID)
	if err != nil {
		logger.Warn("failed to fetch benefit for delete event", zap.Error(err))
	}
	if err := s.benefitRepo.Delete(ctx, tx, benefitID); err != nil {
		return err
	}
	if benefit != nil {
		if err := s.emitBenefitEvent(ctx, tx, benefit, events.EventBenefitDeleted); err != nil {
			logger.Warn("failed to emit benefit deleted event", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "delete", benefitID.String(),
			&benefitID, "system", nil, nil, nil, nil)
	}
	return nil
}

// GetByID – returns NotFound when benefit is nil.
func (s *benefitService) GetByID(ctx context.Context, benefitID uuid.UUID) (*models.Benefit, error) {
	db := s.pgClient.DB
	benefit, err := s.benefitRepo.GetByID(ctx, db, benefitID)
	if err != nil {
		return nil, err
	}
	if benefit == nil {
		return nil, errors.ErrNotFound
	}
	return benefit, nil
}

// ----------------------------------------------------------------------------
// Plan Item Operations (idempotency with boolean marker, no data return)
// ----------------------------------------------------------------------------

func (s *benefitService) ReplaceByPlanItem(ctx context.Context, planItemID uuid.UUID, benefits []*models.Benefit) error {
	logger := s.logger.With(zap.String("method", "ReplaceByPlanItem"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, fmt.Sprintf("benefit-replace-%s", planItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – replacement already processed")
		return nil
	}

	// Validate all incoming benefits
	for _, b := range benefits {
		if err := s.Validate(ctx, b); err != nil {
			return err
		}
	}
	// Check plan item exists
	exists, err := s.planItemRepo.Exists(ctx, tx, planItemID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}
	// Set timestamps and assign IDs if needed
	now := time.Now()
	for _, b := range benefits {
		if b.BenefitID == uuid.Nil {
			b.BenefitID = uuid.New()
		}
		b.CreatedAt = now
		b.UpdatedAt = now
	}
	if err := s.benefitRepo.ReplaceByPlanItem(ctx, tx, planItemID, benefits); err != nil {
		return err
	}
	for _, b := range benefits {
		if err := s.emitBenefitEvent(ctx, tx, b, events.EventBenefitBulkCreated); err != nil {
			logger.Warn("failed to emit benefit event during replace", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "replace_by_plan_item", planItemID.String(),
			&planItemID, "system", nil, nil, nil, map[string]interface{}{
				"benefit_count": len(benefits),
			})
	}
	return nil
}

func (s *benefitService) DeleteByPlanItem(ctx context.Context, planItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteByPlanItem"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, fmt.Sprintf("benefit-delete-planitem-%s", planItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – deletion by plan item already processed")
		return nil
	}

	benefits, err := s.benefitRepo.GetByPlanItem(ctx, tx, planItemID)
	if err != nil {
		return err
	}
	if err := s.benefitRepo.DeleteByPlanItem(ctx, tx, planItemID); err != nil {
		return err
	}
	for _, b := range benefits {
		if err := s.emitBenefitEvent(ctx, tx, b, events.EventBenefitDeleted); err != nil {
			logger.Warn("failed to emit benefit deleted event", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "delete_by_plan_item", planItemID.String(),
			&planItemID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *benefitService) CopyToPlanItem(ctx context.Context, sourcePlanItemID, targetPlanItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CopyToPlanItem"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIdempotencyKey(ctx, fmt.Sprintf("benefit-copy-%s-%s", sourcePlanItemID.String(), targetPlanItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – copy already processed")
		return nil
	}

	srcBenefits, err := s.benefitRepo.GetByPlanItem(ctx, tx, sourcePlanItemID)
	if err != nil {
		return err
	}
	var newBenefits []*models.Benefit
	now := time.Now()
	for _, b := range srcBenefits {
		newBenefit := &models.Benefit{
			BenefitID:          uuid.New(),
			PlanItemID:         targetPlanItemID,
			BenefitType:        b.BenefitType,
			BenefitDescription: b.BenefitDescription,
			Value:              b.Value,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		newBenefits = append(newBenefits, newBenefit)
	}
	if len(newBenefits) > 0 {
		if err := s.benefitRepo.BulkCreate(ctx, tx, newBenefits); err != nil {
			return err
		}
	}
	for _, b := range newBenefits {
		if err := s.emitBenefitEvent(ctx, tx, b, events.EventBenefitCopied); err != nil {
			logger.Warn("failed to emit benefit copied event", zap.Error(err))
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "benefit", "copy_to_plan_item", targetPlanItemID.String(),
			&targetPlanItemID, "system", nil, nil, nil, map[string]interface{}{
				"source_plan_item_id": sourcePlanItemID,
				"count":               len(newBenefits),
			})
	}
	return nil
}

// ----------------------------------------------------------------------------
// Validation – extended to check value structure
// ----------------------------------------------------------------------------

func (s *benefitService) Validate(ctx context.Context, benefit *models.Benefit) error {
	if benefit == nil {
		return errors.ErrInvalidInput
	}
	if !benefit.BenefitType.IsValid() {
		return errors.ErrInvalidInput
	}
	switch benefit.BenefitType {
	case enums.BenefitDiscount:
		if _, ok := benefit.Value["percentage"]; !ok {
			return fmt.Errorf("%w: discount requires 'percentage'", errors.ErrInvalidInput)
		}
		if _, ok := benefit.Value["duration_months"]; !ok {
			return fmt.Errorf("%w: discount requires 'duration_months'", errors.ErrInvalidInput)
		}
	case enums.BenefitAccess:
		if _, ok := benefit.Value["feature"]; !ok {
			return fmt.Errorf("%w: access requires 'feature'", errors.ErrInvalidInput)
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Query methods
// ----------------------------------------------------------------------------

func (s *benefitService) Exists(ctx context.Context, benefitID uuid.UUID) (bool, error) {
	db := s.pgClient.DB
	return s.benefitRepo.Exists(ctx, db, benefitID)
}

func (s *benefitService) ExistsByType(ctx context.Context, planItemID uuid.UUID, benefitType enums.BenefitType) (bool, error) {
	db := s.pgClient.DB
	return s.benefitRepo.ExistsByType(ctx, db, planItemID, benefitType)
}

func (s *benefitService) List(ctx context.Context, filter repository.BenefitFilter, p repository.Pagination, sort repository.Sort) ([]*models.Benefit, int64, error) {
	db := s.pgClient.DB
	return s.benefitRepo.List(ctx, db, filter, p, sort)
}

func (s *benefitService) Search(ctx context.Context, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Benefit, int64, error) {
	db := s.pgClient.DB
	return s.benefitRepo.Search(ctx, db, planItemID, query, limit, offset)
}

func (s *benefitService) GetByPlanItem(ctx context.Context, planItemID uuid.UUID) ([]*models.Benefit, error) {
	db := s.pgClient.DB
	return s.benefitRepo.GetByPlanItem(ctx, db, planItemID)
}

func (s *benefitService) GetByType(ctx context.Context, benefitType enums.BenefitType) ([]*models.Benefit, error) {
	db := s.pgClient.DB
	return s.benefitRepo.GetByType(ctx, db, benefitType)
}
