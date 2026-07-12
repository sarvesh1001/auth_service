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

// PlanCloneService clones plans and all dependent resources.
type PlanCloneService interface {
	ClonePlan(ctx context.Context, companyID, planID uuid.UUID, req *ClonePlanRequest) (*models.Plan, error)
	CloneItems(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	CloneBenefits(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	CloneEntitlements(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	CloneBillingPolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	CloneRenewalPolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	ClonePausePolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	CloneProrationPolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	CloneEverything(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
	PreviewClone(ctx context.Context, planID uuid.UUID) (*PlanClonePreview, error)
	ValidateClone(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error
}

type planCloneService struct {
	planRepo            repository.PlanRepository
	planItemRepo        repository.PlanItemRepository
	benefitRepo         repository.BenefitRepository
	entitlementRepo     repository.EntitlementRepository
	billingPolicyRepo   repository.BillingPolicyRepository
	renewalPolicyRepo   repository.RenewalPolicyRepository
	pausePolicyRepo     repository.PausePolicyRepository
	prorationPolicyRepo repository.ProrationPolicyRepository
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	pgClient            *client.PostgresClient
	logger              *zap.Logger
}

func NewPlanCloneService(
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository,
	benefitRepo repository.BenefitRepository,
	entitlementRepo repository.EntitlementRepository,
	billingPolicyRepo repository.BillingPolicyRepository,
	renewalPolicyRepo repository.RenewalPolicyRepository,
	pausePolicyRepo repository.PausePolicyRepository,
	prorationPolicyRepo repository.ProrationPolicyRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PlanCloneService {
	return &planCloneService{
		planRepo:            planRepo,
		planItemRepo:        planItemRepo,
		benefitRepo:         benefitRepo,
		entitlementRepo:     entitlementRepo,
		billingPolicyRepo:   billingPolicyRepo,
		renewalPolicyRepo:   renewalPolicyRepo,
		pausePolicyRepo:     pausePolicyRepo,
		prorationPolicyRepo: prorationPolicyRepo,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		pgClient:            pgClient,
		logger:              logger.Named("plan_clone_service"),
	}
}

// ----------------------------------------------------------------------------
// Helpers (getSQLTx, emitEvent, getIDempotencyKey are defined elsewhere)
// ----------------------------------------------------------------------------

func (s *planCloneService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *planCloneService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "plan",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func buildPlanPayload(plan *models.Plan) events.PlanPayload {
	return events.PlanPayload{
		PlanID:            plan.PlanID.String(),
		CompanyID:         plan.CompanyID.String(),
		Name:              plan.Name,
		PlanType:          string(plan.PlanType),
		BillingPolicyID:   plan.BillingPolicyID.String(),
		RenewalPolicyID:   plan.RenewalPolicyID.String(),
		PausePolicyID:     plan.PausePolicyID.String(),
		ProrationPolicyID: plan.ProrationPolicyID.String(),
		DurationDays:      plan.DurationDays,
		IsActive:          plan.IsActive,
		Version:           plan.Version,
	}
}

func (s *planCloneService) logAudit(ctx context.Context, companyID *uuid.UUID, action, entityType string, entityID *uuid.UUID, userID *uuid.UUID, oldState, newState interface{}, changes map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	var oldBytes, newBytes []byte
	if oldState != nil {
		oldBytes, _ = json.Marshal(oldState)
	}
	if newState != nil {
		newBytes, _ = json.Marshal(newState)
	}
	_ = s.auditService.LogAction(ctx, nil, companyID, "subscription", action, entityType, entityID, "user", userID, oldBytes, newBytes, changes)
}

// ----------------------------------------------------------------------------
// Complete Clone
// ----------------------------------------------------------------------------

func (s *planCloneService) ClonePlan(ctx context.Context, companyID, planID uuid.UUID, req *ClonePlanRequest) (*models.Plan, error) {
	logger := s.logger.With(zap.String("method", "ClonePlan"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-plan-%s", planID.String()))
	var cachedPlan *models.Plan
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cachedPlan); err == nil && cachedPlan != nil {
		logger.Info("idempotent – returning cached plan")
		return cachedPlan, nil
	}

	source, err := s.planRepo.GetByID(ctx, tx, companyID, planID)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	if source.DeletedAt != nil {
		return nil, fmt.Errorf("%w: source plan is deleted", errors.ErrInvalidState)
	}

	// Create new plan
	newPlan := &models.Plan{
		PlanID:             uuid.New(),
		CompanyID:          companyID,
		Name:               req.Name,
		PlanType:           source.PlanType,
		Description:        source.Description,
		BillingPolicyID:    source.BillingPolicyID,
		RenewalPolicyID:    source.RenewalPolicyID,
		PausePolicyID:      source.PausePolicyID,
		ProrationPolicyID:  source.ProrationPolicyID,
		DurationDays:       source.DurationDays,
		CancellationPolicy: source.CancellationPolicy,
		Metadata:           source.Metadata,
		IsActive:           true,
		Version:            1,
		PublishedAt:        nil,
		PublishedBy:        nil,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := s.planRepo.Create(ctx, tx, newPlan); err != nil {
		return nil, err
	}

	// Clone components – pass companyID to policy clones
	if req.CloneItems {
		if err := s.cloneItems(ctx, tx, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
	}
	if req.CloneBenefits {
		if err := s.cloneBenefits(ctx, tx, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
	}
	if req.CloneEntitlements {
		if err := s.cloneEntitlements(ctx, tx, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
	}
	if req.ClonePolicies {
		if err := s.cloneBillingPolicy(ctx, tx, companyID, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
		if err := s.cloneRenewalPolicy(ctx, tx, companyID, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
		if err := s.clonePausePolicy(ctx, tx, companyID, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
		if err := s.cloneProrationPolicy(ctx, tx, companyID, source.PlanID, newPlan.PlanID); err != nil {
			return nil, err
		}
	}

	// Emit event, store idempotency, commit
	payload := buildPlanPayload(newPlan)
	if err := s.emitEvent(ctx, tx, newPlan.PlanID, events.EventPlanCloned, payload); err != nil {
		logger.Warn("failed to emit plan cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, newPlan); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	s.logAudit(ctx, &companyID, "clone_plan", "plan", &newPlan.PlanID, &req.CreatedBy, source, newPlan, map[string]interface{}{
		"source_plan_id":     source.PlanID.String(),
		"new_plan_id":        newPlan.PlanID.String(),
		"clone_items":        req.CloneItems,
		"clone_benefits":     req.CloneBenefits,
		"clone_entitlements": req.CloneEntitlements,
		"clone_policies":     req.ClonePolicies,
	})
	return newPlan, nil
}

// ----------------------------------------------------------------------------
// Internal clone helpers (accept companyID where needed)
// ----------------------------------------------------------------------------

func (s *planCloneService) cloneItems(ctx context.Context, tx repository.DBTX, sourcePlanID, targetPlanID uuid.UUID) error {
	items, err := s.planItemRepo.GetByPlan(ctx, tx, sourcePlanID)
	if err != nil {
		return err
	}
	for _, item := range items {
		newItem := &models.PlanItem{
			PlanItemID:      uuid.New(),
			PlanID:          targetPlanID,
			ItemType:        item.ItemType,
			Name:            item.Name,
			Description:     item.Description,
			FeatureKey:      item.FeatureKey,
			BillingPolicyID: item.BillingPolicyID,
			Price:           item.Price,
			Currency:        item.Currency,
			EffectiveFrom:   item.EffectiveFrom,
			EffectiveTo:     item.EffectiveTo,
			IsMandatory:     item.IsMandatory,
			IsActive:        item.IsActive,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		if err := s.planItemRepo.Create(ctx, tx, newItem); err != nil {
			return err
		}
	}
	return nil
}

func (s *planCloneService) cloneBenefits(ctx context.Context, tx repository.DBTX, sourcePlanID, targetPlanID uuid.UUID) error {
	sourceItems, err := s.planItemRepo.GetByPlan(ctx, tx, sourcePlanID)
	if err != nil {
		return err
	}
	targetItems, err := s.planItemRepo.GetByPlan(ctx, tx, targetPlanID)
	if err != nil {
		return err
	}
	if len(sourceItems) != len(targetItems) {
		return fmt.Errorf("%w: source and target items count mismatch", errors.ErrInvalidState)
	}
	for i, srcItem := range sourceItems {
		tgtItem := targetItems[i]
		benefits, err := s.benefitRepo.GetByPlanItem(ctx, tx, srcItem.PlanItemID)
		if err != nil {
			return err
		}
		for _, ben := range benefits {
			newBen := &models.Benefit{
				BenefitID:          uuid.New(),
				PlanItemID:         tgtItem.PlanItemID,
				BenefitType:        ben.BenefitType,
				BenefitDescription: ben.BenefitDescription,
				Value:              ben.Value,
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			}
			if err := s.benefitRepo.Create(ctx, tx, newBen); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *planCloneService) cloneEntitlements(ctx context.Context, tx repository.DBTX, sourcePlanID, targetPlanID uuid.UUID) error {
	sourceItems, err := s.planItemRepo.GetByPlan(ctx, tx, sourcePlanID)
	if err != nil {
		return err
	}
	targetItems, err := s.planItemRepo.GetByPlan(ctx, tx, targetPlanID)
	if err != nil {
		return err
	}
	if len(sourceItems) != len(targetItems) {
		return fmt.Errorf("%w: source and target items count mismatch", errors.ErrInvalidState)
	}
	for i, srcItem := range sourceItems {
		tgtItem := targetItems[i]
		ents, err := s.entitlementRepo.GetByPlanItem(ctx, tx, srcItem.PlanItemID)
		if err != nil {
			return err
		}
		for _, ent := range ents {
			newEnt := &models.Entitlement{
				EntitlementID: uuid.New(),
				PlanItemID:    tgtItem.PlanItemID,
				FeatureKey:    ent.FeatureKey,
				LimitValue:    ent.LimitValue,
				LimitPeriod:   ent.LimitPeriod,
				IsEnabled:     ent.IsEnabled,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			if err := s.entitlementRepo.Create(ctx, tx, newEnt); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- Policy clones with explicit companyID and nil checks ----------

func (s *planCloneService) cloneBillingPolicy(ctx context.Context, tx repository.DBTX, companyID, sourcePlanID, targetPlanID uuid.UUID) error {
	// Fetch source plan
	sourcePlan, err := s.planRepo.GetByID(ctx, tx, companyID, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	// Fetch target plan
	targetPlan, err := s.planRepo.GetByID(ctx, tx, companyID, targetPlanID)
	if err != nil {
		return err
	}
	if targetPlan == nil {
		return fmt.Errorf("%w: target plan not found", errors.ErrNotFound)
	}
	// Fetch the source policy
	policy, err := s.billingPolicyRepo.GetByID(ctx, tx, companyID, sourcePlan.BillingPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("%w: source billing policy not found", errors.ErrNotFound)
	}
	// Create a new policy with a cloned name
	newPolicy := &models.BillingPolicy{
		BillingPolicyID: uuid.New(),
		CompanyID:       companyID,
		Name:            policy.Name + "_clone",
		FrequencyID:     policy.FrequencyID,
		BillingInterval: policy.BillingInterval,
		ModelID:         policy.ModelID,
		AdvanceDays:     policy.AdvanceDays,
		IsActive:        policy.IsActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := s.billingPolicyRepo.Create(ctx, tx, newPolicy); err != nil {
		return err
	}
	// Update target plan with new policy ID
	targetPlan.BillingPolicyID = newPolicy.BillingPolicyID
	return s.planRepo.Update(ctx, tx, targetPlan)
}

func (s *planCloneService) cloneRenewalPolicy(ctx context.Context, tx repository.DBTX, companyID, sourcePlanID, targetPlanID uuid.UUID) error {
	sourcePlan, err := s.planRepo.GetByID(ctx, tx, companyID, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	targetPlan, err := s.planRepo.GetByID(ctx, tx, companyID, targetPlanID)
	if err != nil {
		return err
	}
	if targetPlan == nil {
		return fmt.Errorf("%w: target plan not found", errors.ErrNotFound)
	}
	policy, err := s.renewalPolicyRepo.GetByID(ctx, tx, companyID, sourcePlan.RenewalPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("%w: source renewal policy not found", errors.ErrNotFound)
	}
	newPolicy := &models.RenewalPolicy{
		RenewalPolicyID: uuid.New(),
		CompanyID:       companyID,
		Name:            policy.Name + "_clone",
		AutoRenew:       policy.AutoRenew,
		GraceDays:       policy.GraceDays,
		LateFeePercent:  policy.LateFeePercent,
		NoticeDays:      policy.NoticeDays,
		IsActive:        policy.IsActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := s.renewalPolicyRepo.Create(ctx, tx, newPolicy); err != nil {
		return err
	}
	targetPlan.RenewalPolicyID = newPolicy.RenewalPolicyID
	return s.planRepo.Update(ctx, tx, targetPlan)
}

func (s *planCloneService) clonePausePolicy(ctx context.Context, tx repository.DBTX, companyID, sourcePlanID, targetPlanID uuid.UUID) error {
	sourcePlan, err := s.planRepo.GetByID(ctx, tx, companyID, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	targetPlan, err := s.planRepo.GetByID(ctx, tx, companyID, targetPlanID)
	if err != nil {
		return err
	}
	if targetPlan == nil {
		return fmt.Errorf("%w: target plan not found", errors.ErrNotFound)
	}
	policy, err := s.pausePolicyRepo.GetByID(ctx, tx, companyID, sourcePlan.PausePolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("%w: source pause policy not found", errors.ErrNotFound)
	}
	newPolicy := &models.PausePolicy{
		PausePolicyID:  uuid.New(),
		CompanyID:      companyID,
		Name:           policy.Name + "_clone",
		MaxPauseDays:   policy.MaxPauseDays,
		AllowedReasons: policy.AllowedReasons,
		FreezeDays:     policy.FreezeDays,
		IsActive:       policy.IsActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := s.pausePolicyRepo.Create(ctx, tx, newPolicy); err != nil {
		return err
	}
	targetPlan.PausePolicyID = newPolicy.PausePolicyID
	return s.planRepo.Update(ctx, tx, targetPlan)
}

func (s *planCloneService) cloneProrationPolicy(ctx context.Context, tx repository.DBTX, companyID, sourcePlanID, targetPlanID uuid.UUID) error {
	sourcePlan, err := s.planRepo.GetByID(ctx, tx, companyID, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	targetPlan, err := s.planRepo.GetByID(ctx, tx, companyID, targetPlanID)
	if err != nil {
		return err
	}
	if targetPlan == nil {
		return fmt.Errorf("%w: target plan not found", errors.ErrNotFound)
	}
	policy, err := s.prorationPolicyRepo.GetByID(ctx, tx, companyID, sourcePlan.ProrationPolicyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("%w: source proration policy not found", errors.ErrNotFound)
	}
	newPolicy := &models.ProrationPolicy{
		ProrationPolicyID: uuid.New(),
		CompanyID:         companyID,
		Name:              policy.Name + "_clone",
		UpgradeType:       policy.UpgradeType,
		DowngradeType:     policy.DowngradeType,
		IsActive:          policy.IsActive,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	if err := s.prorationPolicyRepo.Create(ctx, tx, newPolicy); err != nil {
		return err
	}
	targetPlan.ProrationPolicyID = newPolicy.ProrationPolicyID
	return s.planRepo.Update(ctx, tx, targetPlan)
}

// ----------------------------------------------------------------------------
// Public interface methods – these now use the internal helpers with companyID
// ----------------------------------------------------------------------------

func (s *planCloneService) CloneItems(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneItems"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-items-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – items already cloned")
		return nil
	}

	if err := s.cloneItems(ctx, tx, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventPlanItemsCloned, payload); err != nil {
		logger.Warn("failed to emit items cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) CloneBenefits(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneBenefits"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-benefits-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – benefits already cloned")
		return nil
	}

	if err := s.cloneBenefits(ctx, tx, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventPlanBenefitsCloned, payload); err != nil {
		logger.Warn("failed to emit benefits cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) CloneEntitlements(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneEntitlements"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-entitlements-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – entitlements already cloned")
		return nil
	}

	if err := s.cloneEntitlements(ctx, tx, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventPlanEntitlementsCloned, payload); err != nil {
		logger.Warn("failed to emit entitlements cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) CloneBillingPolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneBillingPolicy"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Need companyID – fetch source plan first
	sourcePlan, err := s.planRepo.GetByID(ctx, tx, uuid.Nil, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	companyID := sourcePlan.CompanyID

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-billingpolicy-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – billing policy already cloned")
		return nil
	}

	if err := s.cloneBillingPolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventBillingPolicyCloned, payload); err != nil {
		logger.Warn("failed to emit billing policy cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) CloneRenewalPolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneRenewalPolicy"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	sourcePlan, err := s.planRepo.GetByID(ctx, tx, uuid.Nil, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	companyID := sourcePlan.CompanyID

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-renewalpolicy-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – renewal policy already cloned")
		return nil
	}

	if err := s.cloneRenewalPolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventRenewalPolicyCloned, payload); err != nil {
		logger.Warn("failed to emit renewal policy cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) ClonePausePolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ClonePausePolicy"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	sourcePlan, err := s.planRepo.GetByID(ctx, tx, uuid.Nil, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	companyID := sourcePlan.CompanyID

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-pausepolicy-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – pause policy already cloned")
		return nil
	}

	if err := s.clonePausePolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventPausePolicyCloned, payload); err != nil {
		logger.Warn("failed to emit pause policy cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) CloneProrationPolicy(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneProrationPolicy"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	sourcePlan, err := s.planRepo.GetByID(ctx, tx, uuid.Nil, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	companyID := sourcePlan.CompanyID

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-prorationpolicy-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – proration policy already cloned")
		return nil
	}

	if err := s.cloneProrationPolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, events.EventProrationPolicyCloned, payload); err != nil {
		logger.Warn("failed to emit proration policy cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// CloneEverything and others
// ----------------------------------------------------------------------------

func (s *planCloneService) CloneEverything(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CloneEverything"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Need companyID for policy clones
	sourcePlan, err := s.planRepo.GetByID(ctx, tx, uuid.Nil, sourcePlanID)
	if err != nil {
		return err
	}
	if sourcePlan == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	companyID := sourcePlan.CompanyID

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-everything-%s-%s", sourcePlanID.String(), targetPlanID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – everything already cloned")
		return nil
	}

	if err := s.cloneItems(ctx, tx, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	if err := s.cloneBenefits(ctx, tx, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	if err := s.cloneEntitlements(ctx, tx, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	if err := s.cloneBillingPolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	if err := s.cloneRenewalPolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	if err := s.clonePausePolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}
	if err := s.cloneProrationPolicy(ctx, tx, companyID, sourcePlanID, targetPlanID); err != nil {
		return err
	}

	payload := map[string]string{
		"source_plan_id": sourcePlanID.String(),
		"target_plan_id": targetPlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, targetPlanID, "subscription.plan.everything_cloned", payload); err != nil {
		logger.Warn("failed to emit everything cloned event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planCloneService) PreviewClone(ctx context.Context, planID uuid.UUID) (*PlanClonePreview, error) {
	db := s.pgClient.DB
	items, err := s.planItemRepo.GetByPlan(ctx, db, planID)
	if err != nil {
		return nil, err
	}
	benefitsCount := 0
	entitlementsCount := 0
	for _, item := range items {
		benefits, _ := s.benefitRepo.GetByPlanItem(ctx, db, item.PlanItemID)
		benefitsCount += len(benefits)
		ents, _ := s.entitlementRepo.GetByPlanItem(ctx, db, item.PlanItemID)
		entitlementsCount += len(ents)
	}
	preview := &PlanClonePreview{
		Items:          len(items),
		Benefits:       benefitsCount,
		Entitlements:   entitlementsCount,
		Policies:       4,
		EstimatedSteps: len(items) + benefitsCount + entitlementsCount + 4,
	}
	return preview, nil
}

func (s *planCloneService) ValidateClone(ctx context.Context, sourcePlanID, targetPlanID uuid.UUID) error {
	db := s.pgClient.DB
	source, err := s.planRepo.GetByID(ctx, db, uuid.Nil, sourcePlanID)
	if err != nil {
		return err
	}
	if source == nil {
		return fmt.Errorf("%w: source plan not found", errors.ErrNotFound)
	}
	target, err := s.planRepo.GetByID(ctx, db, uuid.Nil, targetPlanID)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("%w: target plan not found", errors.ErrNotFound)
	}
	if source.CompanyID != target.CompanyID {
		return fmt.Errorf("%w: source and target plans must be in same company", errors.ErrInvalidInput)
	}
	if source.DeletedAt != nil || target.DeletedAt != nil {
		return fmt.Errorf("%w: cannot clone deleted plans", errors.ErrInvalidState)
	}
	return nil
}
