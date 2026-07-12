package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// PlanService defines the interface for plan management.
type PlanService interface {
	// CRUD
	Create(ctx context.Context, plan *models.Plan) error
	Update(ctx context.Context, plan *models.Plan) error
	Delete(ctx context.Context, companyID, planID uuid.UUID) error
	GetByID(ctx context.Context, companyID, planID uuid.UUID) (*models.Plan, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Plan, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.Plan, error)

	// Lifecycle
	Activate(ctx context.Context, companyID, planID uuid.UUID) error
	Deactivate(ctx context.Context, companyID, planID uuid.UUID) error
	Archive(ctx context.Context, companyID, planID uuid.UUID) error
	Restore(ctx context.Context, companyID, planID uuid.UUID) error

	// Configuration
	UpdatePrice(ctx context.Context, companyID, planID uuid.UUID, price decimal.Decimal, currency string) error
	UpdateDuration(ctx context.Context, companyID, planID uuid.UUID, durationDays int) error
	UpdateBillingPolicy(ctx context.Context, companyID, planID, billingPolicyID uuid.UUID) error
	UpdateRenewalPolicy(ctx context.Context, companyID, planID, renewalPolicyID uuid.UUID) error
	UpdatePausePolicy(ctx context.Context, companyID, planID, pausePolicyID uuid.UUID) error
	UpdateProrationPolicy(ctx context.Context, companyID, planID, prorationPolicyID uuid.UUID) error

	// Validation
	Validate(ctx context.Context, plan *models.Plan) error
	Exists(ctx context.Context, companyID, planID uuid.UUID) (bool, error)
	CodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	NameExists(ctx context.Context, companyID uuid.UUID, name string) (bool, error)
	CanDelete(ctx context.Context, companyID, planID uuid.UUID) error

	// Query
	List(ctx context.Context, filter repository.PlanFilter, p Pagination, s Sort) ([]*models.Plan, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Plan, int64, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Plan, error)
	GetArchived(ctx context.Context, companyID uuid.UUID) ([]*models.Plan, error)
	GetByBillingPolicy(ctx context.Context, companyID, billingPolicyID uuid.UUID) ([]*models.Plan, error)
	GetByRenewalPolicy(ctx context.Context, companyID, renewalPolicyID uuid.UUID) ([]*models.Plan, error)
	GetByPausePolicy(ctx context.Context, companyID, pausePolicyID uuid.UUID) ([]*models.Plan, error)
	GetByProrationPolicy(ctx context.Context, companyID, prorationPolicyID uuid.UUID) ([]*models.Plan, error)
}

// PlanValidationService handles validation logic for plans.
type PlanValidationService interface {
	ValidateCreate(ctx context.Context, db repository.DBTX, plan *models.Plan) error
	ValidateUpdate(ctx context.Context, db repository.DBTX, plan *models.Plan, existing *models.Plan) error
	ValidateActivation(ctx context.Context, db repository.DBTX, plan *models.Plan) error
	ValidateDeactivation(ctx context.Context, db repository.DBTX, plan *models.Plan) error
	ValidateArchive(ctx context.Context, db repository.DBTX, plan *models.Plan) error
	ValidateRestore(ctx context.Context, db repository.DBTX, plan *models.Plan) error
	ValidateDeletion(ctx context.Context, db repository.DBTX, plan *models.Plan) error
	ValidatePolicyUpdate(ctx context.Context, db repository.DBTX, companyID, policyID uuid.UUID, policyType string) error
}

// planValidationService is the default implementation.
type planValidationService struct {
	planRepo            repository.PlanRepository
	billingPolicyRepo   repository.BillingPolicyRepository
	renewalPolicyRepo   repository.RenewalPolicyRepository
	pausePolicyRepo     repository.PausePolicyRepository
	prorationPolicyRepo repository.ProrationPolicyRepository
	logger              *zap.Logger
}

func NewPlanValidationService(
	planRepo repository.PlanRepository,
	billingPolicyRepo repository.BillingPolicyRepository,
	renewalPolicyRepo repository.RenewalPolicyRepository,
	pausePolicyRepo repository.PausePolicyRepository,
	prorationPolicyRepo repository.ProrationPolicyRepository,
	logger *zap.Logger,
) PlanValidationService {
	return &planValidationService{
		planRepo:            planRepo,
		billingPolicyRepo:   billingPolicyRepo,
		renewalPolicyRepo:   renewalPolicyRepo,
		pausePolicyRepo:     pausePolicyRepo,
		prorationPolicyRepo: prorationPolicyRepo,
		logger:              logger.Named("plan_validation_service"),
	}
}

func (v *planValidationService) ValidateCreate(ctx context.Context, db repository.DBTX, plan *models.Plan) error {
	logger := v.logger.With(zap.String("method", "ValidateCreate"))

	if plan.CompanyID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	if plan.Name == "" {
		return errors.ErrInvalidInput
	}

	// Check name uniqueness – log the result
	exists, err := v.planRepo.ExistsByName(ctx, db, plan.CompanyID, plan.Name)
	if err != nil {
		logger.Error("failed to check existence by name", zap.Error(err))
		return err
	}
	logger.Info("name uniqueness check",
		zap.String("company_id", plan.CompanyID.String()),
		zap.String("name", plan.Name),
		zap.Bool("exists", exists),
	)
	if exists {
		return errors.ErrDuplicate
	}

	// Validate policies exist and are active
	if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.BillingPolicyID, "billing"); err != nil {
		return err
	}
	if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.RenewalPolicyID, "renewal"); err != nil {
		return err
	}
	if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.PausePolicyID, "pause"); err != nil {
		return err
	}
	if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.ProrationPolicyID, "proration"); err != nil {
		return err
	}

	if !plan.PlanType.IsValid() {
		return errors.ErrInvalidInput
	}
	return nil
}
func (v *planValidationService) ValidateUpdate(ctx context.Context, db repository.DBTX, plan *models.Plan, existing *models.Plan) error {
	logger := v.logger.With(zap.String("method", "ValidateUpdate"))

	if plan.CompanyID != existing.CompanyID {
		return errors.ErrPermissionDenied
	}

	// If name changed, check uniqueness
	if plan.Name != existing.Name {
		exists, err := v.planRepo.ExistsByName(ctx, db, plan.CompanyID, plan.Name)
		if err != nil {
			return err
		}
		logger.Info("name uniqueness check on update",
			zap.String("company_id", plan.CompanyID.String()),
			zap.String("new_name", plan.Name),
			zap.Bool("exists", exists),
		)
		if exists {
			return errors.ErrDuplicate
		}
	}

	// Validate policy changes
	if plan.BillingPolicyID != existing.BillingPolicyID {
		if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.BillingPolicyID, "billing"); err != nil {
			return err
		}
	}
	if plan.RenewalPolicyID != existing.RenewalPolicyID {
		if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.RenewalPolicyID, "renewal"); err != nil {
			return err
		}
	}
	if plan.PausePolicyID != existing.PausePolicyID {
		if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.PausePolicyID, "pause"); err != nil {
			return err
		}
	}
	if plan.ProrationPolicyID != existing.ProrationPolicyID {
		if err := v.ValidatePolicyUpdate(ctx, db, plan.CompanyID, plan.ProrationPolicyID, "proration"); err != nil {
			return err
		}
	}

	if !plan.PlanType.IsValid() {
		return errors.ErrInvalidInput
	}
	// Version is managed by the service – no validation here
	return nil
}

func (v *planValidationService) ValidateActivation(ctx context.Context, db repository.DBTX, plan *models.Plan) error {
	if plan.DeletedAt != nil {
		return errors.ErrInvalidState
	}
	if plan.IsActive {
		return errors.ErrInvalidState // already active
	}
	return nil
}

func (v *planValidationService) ValidateDeactivation(ctx context.Context, db repository.DBTX, plan *models.Plan) error {
	if plan.DeletedAt != nil {
		return errors.ErrInvalidState
	}
	if !plan.IsActive {
		return errors.ErrInvalidState
	}
	return nil
}

func (v *planValidationService) ValidateArchive(ctx context.Context, db repository.DBTX, plan *models.Plan) error {
	if plan.DeletedAt != nil {
		return errors.ErrInvalidState
	}
	return nil
}

func (v *planValidationService) ValidateRestore(ctx context.Context, db repository.DBTX, plan *models.Plan) error {
	if plan.DeletedAt == nil {
		return errors.ErrInvalidState
	}
	return nil
}

func (v *planValidationService) ValidateDeletion(ctx context.Context, db repository.DBTX, plan *models.Plan) error {
	if plan.DeletedAt == nil {
		return errors.ErrInvalidState
	}
	return nil
}

func (v *planValidationService) ValidatePolicyUpdate(ctx context.Context, db repository.DBTX, companyID, policyID uuid.UUID, policyType string) error {
	if policyID == uuid.Nil {
		return fmt.Errorf("%w: policy ID cannot be empty", errors.ErrInvalidInput)
	}
	var exists bool
	var err error
	switch policyType {
	case "billing":
		exists, err = v.billingPolicyRepo.Exists(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: billing policy not found", errors.ErrNotFound)
		}
		active, err := v.billingPolicyRepo.IsActive(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: billing policy is not active", errors.ErrInvalidInput)
		}
	case "renewal":
		exists, err = v.renewalPolicyRepo.Exists(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: renewal policy not found", errors.ErrNotFound)
		}
		active, err := v.renewalPolicyRepo.IsActive(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: renewal policy is not active", errors.ErrInvalidInput)
		}
	case "pause":
		exists, err = v.pausePolicyRepo.Exists(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: pause policy not found", errors.ErrNotFound)
		}
		active, err := v.pausePolicyRepo.IsActive(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: pause policy is not active", errors.ErrInvalidInput)
		}
	case "proration":
		exists, err = v.prorationPolicyRepo.Exists(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: proration policy not found", errors.ErrNotFound)
		}
		active, err := v.prorationPolicyRepo.IsActive(ctx, db, companyID, policyID)
		if err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: proration policy is not active", errors.ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: unknown policy type %s", errors.ErrInvalidInput, policyType)
	}
	return nil
}

// planService implements PlanService.
type planService struct {
	planRepo          repository.PlanRepository
	planItemRepo      repository.PlanItemRepository
	subscriptionRepo  repository.SubscriptionRepository
	validationService PlanValidationService
	auditService      *audit.AuditService
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	pgClient          *client.PostgresClient
	logger            *zap.Logger
}

// NewPlanService creates a new PlanService instance.
func NewPlanService(
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository,
	subscriptionRepo repository.SubscriptionRepository,
	validationService PlanValidationService,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PlanService {
	return &planService{
		planRepo:          planRepo,
		planItemRepo:      planItemRepo,
		subscriptionRepo:  subscriptionRepo,
		validationService: validationService,
		auditService:      auditService,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		pgClient:          pgClient,
		logger:            logger.Named("plan_service"),
	}
}

// helper to extract idempotency key from context or fallback.
// helper to emit outbox event.
func (s *planService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "plan",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (s *planService) Create(ctx context.Context, plan *models.Plan) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency key based on business key (company + name)
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("create-plan-%s-%s", plan.CompanyID.String(), plan.Name))
	var cachedPlan *models.Plan
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cachedPlan); err == nil && cachedPlan != nil {
		logger.Info("idempotent – returning cached plan")
		*plan = *cachedPlan
		return nil
	}

	// Validate – will log existence check
	if err := s.validationService.ValidateCreate(ctx, tx, plan); err != nil {
		logger.Warn("validation failed", zap.Error(err))
		return err
	}

	// Set initial fields
	plan.Version = 1
	plan.CreatedAt = time.Now()
	plan.UpdatedAt = plan.CreatedAt
	plan.IsActive = false
	plan.DeletedAt = nil

	if err := s.planRepo.Create(ctx, tx, plan); err != nil {
		// Check for PostgreSQL unique violation
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return errors.ErrDuplicate
		}
		return err
	}

	// Emit event
	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, plan.PlanID, events.EventPlanCreated, payload); err != nil {
		logger.Warn("failed to emit plan created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, plan); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &plan.CompanyID, "plan", "create", "plan",
			&plan.PlanID, "system", nil, nil, nil, map[string]interface{}{
				"name": plan.Name,
			})
	}
	return nil
}
func (s *planService) Update(ctx context.Context, plan *models.Plan) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency key based on plan ID (unique per plan)
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-plan-%s", plan.PlanID.String()))
	var cachedPlan *models.Plan
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cachedPlan); err == nil && cachedPlan != nil {
		logger.Info("idempotent – returning cached plan")
		*plan = *cachedPlan
		return nil
	}

	existing, err := s.planRepo.GetByIDForUpdate(ctx, tx, plan.CompanyID, plan.PlanID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.ErrNotFound
	}
	if err := s.validationService.ValidateUpdate(ctx, tx, plan, existing); err != nil {
		return err
	}

	// Preserve non‑updatable fields
	plan.CreatedAt = existing.CreatedAt
	plan.Version = existing.Version + 1
	plan.UpdatedAt = time.Now()
	plan.DeletedAt = existing.DeletedAt
	plan.IsActive = existing.IsActive

	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		// Check for unique violation (if name changed and collides)
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return errors.ErrDuplicate
		}
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, plan.PlanID, events.EventPlanUpdated, payload); err != nil {
		logger.Warn("failed to emit plan updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, plan); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &plan.CompanyID, "plan", "update", "plan",
			&plan.PlanID, "system", nil, nil, nil, map[string]interface{}{
				"version": plan.Version,
			})
	}
	return nil
}

func (s *planService) Delete(ctx context.Context, companyID, planID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("delete-plan-%s", planID.String()))
	var deleted bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &deleted); err == nil && deleted {
		logger.Info("idempotent – already deleted")
		return nil
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	if err := s.validationService.ValidateDeletion(ctx, tx, plan); err != nil {
		return err
	}
	if err := s.CanDelete(ctx, companyID, planID); err != nil {
		return err
	}

	if err := s.planRepo.Delete(ctx, tx, companyID, planID); err != nil {
		return err
	}

	// Emit event
	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanDeleted, payload); err != nil {
		logger.Warn("failed to emit plan deleted event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "delete", "plan",
			&planID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *planService) GetByID(ctx context.Context, companyID, planID uuid.UUID) (*models.Plan, error) {
	return s.planRepo.GetByID(ctx, s.pgClient.DB, companyID, planID)
}

func (s *planService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Plan, error) {
	// No code field; treat as name or return error
	return nil, errors.ErrInvalidInput
}

func (s *planService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.Plan, error) {
	return s.planRepo.GetByName(ctx, s.pgClient.DB, companyID, name)
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (s *planService) Activate(ctx context.Context, companyID, planID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("activate-plan-%s", planID.String()))
	var activated bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &activated); err == nil && activated {
		logger.Info("idempotent – already activated")
		return nil
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	if err := s.validationService.ValidateActivation(ctx, tx, plan); err != nil {
		return err
	}

	plan.IsActive = true
	plan.UpdatedAt = time.Now()
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanActivated, payload); err != nil {
		logger.Warn("failed to emit plan activated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "activate", "plan",
			&planID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *planService) Deactivate(ctx context.Context, companyID, planID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("deactivate-plan-%s", planID.String()))
	var deactivated bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &deactivated); err == nil && deactivated {
		logger.Info("idempotent – already deactivated")
		return nil
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	if err := s.validationService.ValidateDeactivation(ctx, tx, plan); err != nil {
		return err
	}

	plan.IsActive = false
	plan.UpdatedAt = time.Now()
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanDeactivated, payload); err != nil {
		logger.Warn("failed to emit plan deactivated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "deactivate", "plan",
			&planID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *planService) Archive(ctx context.Context, companyID, planID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Archive"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("archive-plan-%s", planID.String()))
	var archived bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &archived); err == nil && archived {
		logger.Info("idempotent – already archived")
		return nil
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	if err := s.validationService.ValidateArchive(ctx, tx, plan); err != nil {
		return err
	}

	now := time.Now()
	plan.DeletedAt = &now
	plan.IsActive = false
	plan.UpdatedAt = now
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanArchived, payload); err != nil {
		logger.Warn("failed to emit plan archived event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "archive", "plan",
			&planID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *planService) Restore(ctx context.Context, companyID, planID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("restore-plan-%s", planID.String()))
	var restored bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &restored); err == nil && restored {
		logger.Info("idempotent – already restored")
		return nil
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	if err := s.validationService.ValidateRestore(ctx, tx, plan); err != nil {
		return err
	}

	plan.DeletedAt = nil
	plan.UpdatedAt = time.Now()
	// Optionally reactivate? Usually restore keeps it inactive.
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanRestored, payload); err != nil {
		logger.Warn("failed to emit plan restored event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "restore", "plan",
			&planID, "system", nil, nil, nil, nil)
	}
	return nil
}

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

func (s *planService) UpdatePrice(ctx context.Context, companyID, planID uuid.UUID, price decimal.Decimal, currency string) error {
	logger := s.logger.With(zap.String("method", "UpdatePrice"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-price-%s-%s", planID.String(), price.String()))
	var updated bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &updated); err == nil && updated {
		logger.Info("idempotent – price already updated")
		return nil
	}

	// Get plan to ensure existence
	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	// Find base item
	items, err := s.planItemRepo.GetByType(ctx, tx, planID, enums.ItemTypeBase)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("%w: no base plan item found for plan", errors.ErrInvalidState)
	}
	baseItem := items[0]
	// Update price
	if err := s.planItemRepo.UpdatePrice(ctx, tx, baseItem.PlanItemID, price, currency); err != nil {
		return err
	}

	// Increment plan version
	plan.Version++
	plan.UpdatedAt = time.Now()
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanPriceUpdated, payload); err != nil {
		logger.Warn("failed to emit plan price updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "update_price", "plan",
			&planID, "system", nil, nil, nil, map[string]interface{}{
				"price":    price.String(),
				"currency": currency,
			})
	}
	return nil
}

func (s *planService) UpdateDuration(ctx context.Context, companyID, planID uuid.UUID, durationDays int) error {
	logger := s.logger.With(zap.String("method", "UpdateDuration"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-duration-%s-%d", planID.String(), durationDays))
	var updated bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &updated); err == nil && updated {
		logger.Info("idempotent – duration already updated")
		return nil
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}
	plan.DurationDays = durationDays
	plan.Version++
	plan.UpdatedAt = time.Now()
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, events.EventPlanUpdated, payload); err != nil {
		logger.Warn("failed to emit plan updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "update_duration", "plan",
			&planID, "system", nil, nil, nil, map[string]interface{}{
				"duration_days": durationDays,
			})
	}
	return nil
}

// Helper for policy updates.
func (s *planService) updatePolicy(ctx context.Context, companyID, planID, policyID uuid.UUID, policyType, fieldName string, eventType string) error {
	logger := s.logger.With(zap.String("method", "updatePolicy"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("update-%s-%s", fieldName, planID.String()))
	var updated bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &updated); err == nil && updated {
		logger.Info("idempotent – policy already updated")
		return nil
	}

	// Validate policy exists and is active
	if err := s.validationService.ValidatePolicyUpdate(ctx, tx, companyID, policyID, policyType); err != nil {
		return err
	}

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return errors.ErrNotFound
	}

	// Update the appropriate field
	switch fieldName {
	case "BillingPolicyID":
		plan.BillingPolicyID = policyID
	case "RenewalPolicyID":
		plan.RenewalPolicyID = policyID
	case "PausePolicyID":
		plan.PausePolicyID = policyID
	case "ProrationPolicyID":
		plan.ProrationPolicyID = policyID
	default:
		return fmt.Errorf("%w: unknown policy field", errors.ErrInvalidInput)
	}
	plan.Version++
	plan.UpdatedAt = time.Now()
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	payload := buildPlanPayload(plan)
	if err := s.emitEvent(ctx, tx, planID, eventType, payload); err != nil {
		logger.Warn("failed to emit policy updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "plan", "update_policy", "plan",
			&planID, "system", nil, nil, nil, map[string]interface{}{
				fieldName: policyID.String(),
			})
	}
	return nil
}

func (s *planService) UpdateBillingPolicy(ctx context.Context, companyID, planID, billingPolicyID uuid.UUID) error {
	return s.updatePolicy(ctx, companyID, planID, billingPolicyID, "billing", "BillingPolicyID", events.EventPlanUpdated)
}

func (s *planService) UpdateRenewalPolicy(ctx context.Context, companyID, planID, renewalPolicyID uuid.UUID) error {
	return s.updatePolicy(ctx, companyID, planID, renewalPolicyID, "renewal", "RenewalPolicyID", events.EventPlanUpdated)
}

func (s *planService) UpdatePausePolicy(ctx context.Context, companyID, planID, pausePolicyID uuid.UUID) error {
	return s.updatePolicy(ctx, companyID, planID, pausePolicyID, "pause", "PausePolicyID", events.EventPlanUpdated)
}

func (s *planService) UpdateProrationPolicy(ctx context.Context, companyID, planID, prorationPolicyID uuid.UUID) error {
	return s.updatePolicy(ctx, companyID, planID, prorationPolicyID, "proration", "ProrationPolicyID", events.EventPlanUpdated)
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (s *planService) Validate(ctx context.Context, plan *models.Plan) error {
	// Use a read-only connection; no transaction needed.
	return s.validationService.ValidateCreate(ctx, s.pgClient.DB, plan)
}

func (s *planService) Exists(ctx context.Context, companyID, planID uuid.UUID) (bool, error) {
	return s.planRepo.Exists(ctx, s.pgClient.DB, companyID, planID)
}

func (s *planService) CodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	// Not implemented; maybe use name.
	return false, nil
}

func (s *planService) NameExists(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	return s.planRepo.ExistsByName(ctx, s.pgClient.DB, companyID, name)
}

func (s *planService) CanDelete(ctx context.Context, companyID, planID uuid.UUID) error {
	// Check if any active subscriptions use this plan.
	activeStatuses := []enums.SubscriptionStatus{
		enums.SubStatusActive,
		enums.SubStatusTrial,
		enums.SubStatusPaused,
	}
	for _, status := range activeStatuses {
		subs, err := s.subscriptionRepo.GetByStatus(ctx, s.pgClient.DB, companyID, status)
		if err != nil {
			return err
		}
		for _, sub := range subs {
			if sub.PlanID == planID {
				return fmt.Errorf("%w: plan is in use by active subscription %s", errors.ErrInvalidState, sub.SubscriptionID)
			}
		}
	}
	return nil
}

// -------------------------------------------------------------------------
// Query
// -------------------------------------------------------------------------

func (s *planService) List(ctx context.Context, filter repository.PlanFilter, p Pagination, srt Sort) ([]*models.Plan, int64, error) {
	repoSort := repository.Sort{Field: srt.Field, Direction: srt.Direction}
	repoPagination := repository.Pagination{Limit: p.Limit, Offset: p.Offset}
	return s.planRepo.List(ctx, s.pgClient.DB, filter, repoPagination, repoSort)
}

func (s *planService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Plan, int64, error) {
	return s.planRepo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *planService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Plan, error) {
	return s.planRepo.GetActive(ctx, s.pgClient.DB, companyID)
}

func (s *planService) GetArchived(ctx context.Context, companyID uuid.UUID) ([]*models.Plan, error) {
	// Use PlanFilter with Deleted = true to get soft-deleted records.
	filter := repository.PlanFilter{
		CompanyID: companyID,
		Deleted:   true, // include soft-deleted
	}
	// We need to list all archived; set a large limit.
	plans, _, err := s.planRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 10000, Offset: 0}, repository.Sort{})
	return plans, err
}

func (s *planService) GetByBillingPolicy(ctx context.Context, companyID, billingPolicyID uuid.UUID) ([]*models.Plan, error) {
	return s.planRepo.GetByBillingPolicy(ctx, s.pgClient.DB, companyID, billingPolicyID)
}

func (s *planService) GetByRenewalPolicy(ctx context.Context, companyID, renewalPolicyID uuid.UUID) ([]*models.Plan, error) {
	return s.planRepo.GetByRenewalPolicy(ctx, s.pgClient.DB, companyID, renewalPolicyID)
}

func (s *planService) GetByPausePolicy(ctx context.Context, companyID, pausePolicyID uuid.UUID) ([]*models.Plan, error) {
	return s.planRepo.GetByPausePolicy(ctx, s.pgClient.DB, companyID, pausePolicyID)
}

func (s *planService) GetByProrationPolicy(ctx context.Context, companyID, prorationPolicyID uuid.UUID) ([]*models.Plan, error) {
	return s.planRepo.GetByProrationPolicy(ctx, s.pgClient.DB, companyID, prorationPolicyID)
}
