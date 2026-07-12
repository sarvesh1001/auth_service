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
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// PlanVersionService manages the complete lifecycle of plan versions.
type PlanVersionService interface {
	CreateVersion(ctx context.Context, planID uuid.UUID, version *models.PlanVersion) error
	Publish(ctx context.Context, companyID, versionID, publishedBy uuid.UUID) error
	Unpublish(ctx context.Context, companyID, versionID uuid.UUID) error
	Restore(ctx context.Context, companyID, versionID uuid.UUID) error
	Archive(ctx context.Context, companyID, versionID uuid.UUID) error
	CloneVersion(ctx context.Context, companyID, sourceVersionID uuid.UUID, newVersion int, createdBy uuid.UUID) (*models.PlanVersion, error)
	Rollback(ctx context.Context, companyID, planID uuid.UUID, version int, performedBy uuid.UUID) (*models.PlanVersion, error)
	Compare(ctx context.Context, companyID, leftVersionID, rightVersionID uuid.UUID) (*PlanVersionComparison, error)
	GetLatest(ctx context.Context, companyID, planID uuid.UUID) (*models.PlanVersion, error)
	GetPublished(ctx context.Context, companyID, planID uuid.UUID) (*models.PlanVersion, error)
	ValidatePublish(ctx context.Context, versionID uuid.UUID) error
	ValidateRollback(ctx context.Context, versionID uuid.UUID) error
}

// planVersionSnapshot holds the complete plan configuration for a version.
type planVersionSnapshot struct {
	Plan struct {
		PlanID             uuid.UUID    `json:"plan_id"`
		CompanyID          uuid.UUID    `json:"company_id"`
		Name               string       `json:"name"`
		PlanType           string       `json:"plan_type"`
		Description        *string      `json:"description,omitempty"`
		BillingPolicyID    uuid.UUID    `json:"billing_policy_id"`
		RenewalPolicyID    uuid.UUID    `json:"renewal_policy_id"`
		PausePolicyID      uuid.UUID    `json:"pause_policy_id"`
		ProrationPolicyID  uuid.UUID    `json:"proration_policy_id"`
		DurationDays       int          `json:"duration_days"`
		CancellationPolicy *string      `json:"cancellation_policy,omitempty"`
		Metadata           models.JSONB `json:"metadata,omitempty"`
	} `json:"plan"`
	Items []struct {
		PlanItemID      uuid.UUID      `json:"plan_item_id"`
		ItemType        enums.ItemType `json:"item_type"`
		Name            string         `json:"name"`
		Description     *string        `json:"description,omitempty"`
		FeatureKey      *string        `json:"feature_key,omitempty"`
		BillingPolicyID *uuid.UUID     `json:"billing_policy_id,omitempty"`
		Price           string         `json:"price"`
		Currency        string         `json:"currency"`
		EffectiveFrom   time.Time      `json:"effective_from"`
		EffectiveTo     *time.Time     `json:"effective_to,omitempty"`
		IsMandatory     bool           `json:"is_mandatory"`
		Benefits        []struct {
			BenefitID          uuid.UUID         `json:"benefit_id"`
			BenefitType        enums.BenefitType `json:"benefit_type"`
			BenefitDescription *string           `json:"benefit_description,omitempty"`
			Value              models.JSONB      `json:"value"`
		} `json:"benefits,omitempty"`
		Entitlements []struct {
			EntitlementID uuid.UUID         `json:"entitlement_id"`
			FeatureKey    string            `json:"feature_key"`
			LimitValue    *string           `json:"limit_value,omitempty"`
			LimitPeriod   enums.LimitPeriod `json:"limit_period"`
			IsEnabled     bool              `json:"is_enabled"`
		} `json:"entitlements,omitempty"`
	} `json:"items"`
}

type planVersionService struct {
	planRepo            repository.PlanRepository
	versionRepo         repository.VersionRepository
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

func NewPlanVersionService(
	planRepo repository.PlanRepository,
	versionRepo repository.VersionRepository,
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
) PlanVersionService {
	return &planVersionService{
		planRepo:            planRepo,
		versionRepo:         versionRepo,
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
		logger:              logger.Named("plan_version_service"),
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (s *planVersionService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *planVersionService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "plan_version",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *planVersionService) logAudit(ctx context.Context, companyID *uuid.UUID, action, entityType string, entityID *uuid.UUID, userID *uuid.UUID, oldState, newState interface{}, changes map[string]interface{}) {
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

func buildVersionPayload(version *models.PlanVersion) events.PlanVersionPayload {
	return events.PlanVersionPayload{
		VersionID:     version.VersionID.String(),
		PlanID:        version.PlanID.String(),
		CompanyID:     version.CompanyID.String(),
		VersionNumber: version.VersionNumber,
		IsPublished:   version.IsPublished,
	}
}

// ----------------------------------------------------------------------------
// Version Management
// ----------------------------------------------------------------------------

func (s *planVersionService) CreateVersion(ctx context.Context, planID uuid.UUID, version *models.PlanVersion) error {
	logger := s.logger.With(zap.String("method", "CreateVersion"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("create-version-%s-%d", planID.String(), version.VersionNumber))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – version already created")
		return nil
	}

	plan, err := s.planRepo.GetByID(ctx, tx, version.CompanyID, planID)
	if err != nil {
		return err
	}
	if plan == nil {
		return fmt.Errorf("%w: plan not found", errors.ErrNotFound)
	}

	versions, err := s.versionRepo.GetByPlan(ctx, tx, version.CompanyID, planID)
	if err != nil {
		return err
	}
	nextVersion := len(versions) + 1
	if version.VersionNumber == 0 {
		version.VersionNumber = nextVersion
	} else {
		for _, v := range versions {
			if v.VersionNumber == version.VersionNumber {
				return fmt.Errorf("%w: version number %d already exists for plan", errors.ErrDuplicate, version.VersionNumber)
			}
		}
	}

	snapshot, err := s.buildSnapshot(ctx, tx, plan)
	if err != nil {
		return err
	}
	snapshotData, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	version.Snapshot = models.JSONB{}
	if err := json.Unmarshal(snapshotData, &version.Snapshot); err != nil {
		return err
	}
	version.VersionID = uuid.New()
	version.CreatedAt = time.Now()
	version.UpdatedAt = time.Now()

	if err := s.versionRepo.Create(ctx, tx, version); err != nil {
		return err
	}

	payload := buildVersionPayload(version)
	if err := s.emitEvent(ctx, tx, version.VersionID, events.EventPlanVersionCreated, payload); err != nil {
		logger.Warn("failed to emit version created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	s.logAudit(ctx, &version.CompanyID, "create_version", "plan_version", &version.VersionID, nil, nil, version, map[string]interface{}{
		"plan_id":        planID.String(),
		"version_number": version.VersionNumber,
	})
	return nil
}

func (s *planVersionService) Publish(ctx context.Context, companyID, versionID, publishedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Publish"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("publish-version-%s", versionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – version already published")
		return nil
	}

	version, err := s.versionRepo.GetByID(ctx, tx, companyID, versionID)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("%w: version not found", errors.ErrNotFound)
	}
	if version.IsPublished {
		return fmt.Errorf("%w: version already published", errors.ErrInvalidState)
	}
	if version.DeletedAt != nil {
		return fmt.Errorf("%w: version is archived", errors.ErrInvalidState)
	}

	var snapshot planVersionSnapshot
	snapshotBytes, err := json.Marshal(version.Snapshot)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(snapshotBytes, &snapshot); err != nil {
		return err
	}

	plan, err := s.planRepo.GetByID(ctx, tx, companyID, version.PlanID)
	if err != nil {
		return err
	}
	if plan == nil {
		return fmt.Errorf("%w: plan not found", errors.ErrNotFound)
	}
	oldPlan := *plan // copy for audit

	plan.Name = snapshot.Plan.Name
	plan.PlanType = enums.PlanType(snapshot.Plan.PlanType)
	plan.Description = snapshot.Plan.Description
	plan.BillingPolicyID = snapshot.Plan.BillingPolicyID
	plan.RenewalPolicyID = snapshot.Plan.RenewalPolicyID
	plan.PausePolicyID = snapshot.Plan.PausePolicyID
	plan.ProrationPolicyID = snapshot.Plan.ProrationPolicyID
	plan.DurationDays = snapshot.Plan.DurationDays
	plan.CancellationPolicy = snapshot.Plan.CancellationPolicy
	plan.Metadata = snapshot.Plan.Metadata
	now := time.Now()
	plan.PublishedAt = &now
	plan.PublishedBy = &publishedBy
	plan.UpdatedAt = now
	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return err
	}

	// Replace plan items
	if err := s.planItemRepo.DeleteByPlan(ctx, tx, version.PlanID); err != nil {
		return err
	}
	for _, itemData := range snapshot.Items {
		price, err := decimal.NewFromString(itemData.Price)
		if err != nil {
			return fmt.Errorf("invalid price %s: %w", itemData.Price, err)
		}
		newItem := &models.PlanItem{
			PlanItemID:      uuid.New(),
			PlanID:          version.PlanID,
			ItemType:        itemData.ItemType,
			Name:            itemData.Name,
			Description:     itemData.Description,
			FeatureKey:      itemData.FeatureKey,
			BillingPolicyID: itemData.BillingPolicyID,
			Price:           price,
			Currency:        itemData.Currency,
			EffectiveFrom:   itemData.EffectiveFrom,
			EffectiveTo:     itemData.EffectiveTo,
			IsMandatory:     itemData.IsMandatory,
			IsActive:        true,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		if err := s.planItemRepo.Create(ctx, tx, newItem); err != nil {
			return err
		}
		for _, benData := range itemData.Benefits {
			benefit := &models.Benefit{
				BenefitID:          uuid.New(),
				PlanItemID:         newItem.PlanItemID,
				BenefitType:        benData.BenefitType,
				BenefitDescription: benData.BenefitDescription,
				Value:              benData.Value,
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			}
			if err := s.benefitRepo.Create(ctx, tx, benefit); err != nil {
				return err
			}
		}
		for _, entData := range itemData.Entitlements {
			var limit *decimal.Decimal
			if entData.LimitValue != nil {
				val, err := decimal.NewFromString(*entData.LimitValue)
				if err != nil {
					return fmt.Errorf("invalid limit value %s: %w", *entData.LimitValue, err)
				}
				limit = &val
			}
			entitlement := &models.Entitlement{
				EntitlementID: uuid.New(),
				PlanItemID:    newItem.PlanItemID,
				FeatureKey:    entData.FeatureKey,
				LimitValue:    limit,
				LimitPeriod:   entData.LimitPeriod,
				IsEnabled:     entData.IsEnabled,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			if err := s.entitlementRepo.Create(ctx, tx, entitlement); err != nil {
				return err
			}
		}
	}

	// Mark version as published
	version.IsPublished = true
	now2 := time.Now()
	version.PublishedAt = &now2
	version.PublishedBy = &publishedBy
	version.UpdatedAt = now2
	if err := s.versionRepo.Update(ctx, tx, version); err != nil {
		return err
	}

	payload := buildVersionPayload(version)
	if err := s.emitEvent(ctx, tx, version.VersionID, events.EventPlanVersionPublished, payload); err != nil {
		logger.Warn("failed to emit version published event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	s.logAudit(ctx, &companyID, "publish_version", "plan_version", &version.VersionID, &publishedBy, oldPlan, plan, map[string]interface{}{
		"version_id": versionID.String(),
		"plan_id":    version.PlanID.String(),
	})
	return nil
}

func (s *planVersionService) Unpublish(ctx context.Context, companyID, versionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Unpublish"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("unpublish-version-%s", versionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – version already unpublished")
		return nil
	}

	version, err := s.versionRepo.GetByID(ctx, tx, companyID, versionID)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("%w: version not found", errors.ErrNotFound)
	}
	if !version.IsPublished {
		return fmt.Errorf("%w: version is not published", errors.ErrInvalidState)
	}
	version.IsPublished = false
	version.PublishedAt = nil
	version.PublishedBy = nil
	version.UpdatedAt = time.Now()
	if err := s.versionRepo.Update(ctx, tx, version); err != nil {
		return err
	}

	payload := buildVersionPayload(version)
	if err := s.emitEvent(ctx, tx, version.VersionID, events.EventPlanVersionUnpublished, payload); err != nil {
		logger.Warn("failed to emit version unpublished event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	s.logAudit(ctx, &companyID, "unpublish_version", "plan_version", &version.VersionID, nil, nil, version, nil)
	return nil
}

// Restore – now uses GetByIDIncludingDeleted to fetch archived versions
func (s *planVersionService) Restore(ctx context.Context, companyID, versionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("restore-version-%s", versionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – version already restored")
		return nil
	}

	// Use GetByIDIncludingDeleted so archived versions can be retrieved
	version, err := s.versionRepo.GetByIDIncludingDeleted(ctx, tx, companyID, versionID)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("%w: version not found", errors.ErrNotFound)
	}
	if version.DeletedAt == nil {
		return fmt.Errorf("%w: version is not archived", errors.ErrInvalidState)
	}
	version.DeletedAt = nil
	version.UpdatedAt = time.Now()
	if err := s.versionRepo.Update(ctx, tx, version); err != nil {
		return err
	}

	payload := buildVersionPayload(version)
	if err := s.emitEvent(ctx, tx, version.VersionID, events.EventPlanVersionRestored, payload); err != nil {
		logger.Warn("failed to emit version restored event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	s.logAudit(ctx, &companyID, "restore_version", "plan_version", &version.VersionID, nil, nil, version, nil)
	return nil
}

func (s *planVersionService) Archive(ctx context.Context, companyID, versionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Archive"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("archive-version-%s", versionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – version already archived")
		return nil
	}

	version, err := s.versionRepo.GetByID(ctx, tx, companyID, versionID)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("%w: version not found", errors.ErrNotFound)
	}
	if version.IsPublished {
		return fmt.Errorf("%w: cannot archive a published version", errors.ErrInvalidState)
	}
	now := time.Now()
	version.DeletedAt = &now
	version.UpdatedAt = now
	if err := s.versionRepo.Update(ctx, tx, version); err != nil {
		return err
	}

	payload := buildVersionPayload(version)
	if err := s.emitEvent(ctx, tx, version.VersionID, events.EventPlanVersionArchived, payload); err != nil {
		logger.Warn("failed to emit version archived event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	s.logAudit(ctx, &companyID, "archive_version", "plan_version", &version.VersionID, nil, nil, version, nil)
	return nil
}

// ----------------------------------------------------------------------------
// Version Operations
// ----------------------------------------------------------------------------

func (s *planVersionService) CloneVersion(ctx context.Context, companyID, sourceVersionID uuid.UUID, newVersion int, createdBy uuid.UUID) (*models.PlanVersion, error) {
	logger := s.logger.With(zap.String("method", "CloneVersion"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("clone-version-%s-%d", sourceVersionID.String(), newVersion))
	var cached *models.PlanVersion
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached cloned version")
		return cached, nil
	}

	source, err := s.versionRepo.GetByID(ctx, tx, companyID, sourceVersionID)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("%w: source version not found", errors.ErrNotFound)
	}
	if source.DeletedAt != nil {
		return nil, fmt.Errorf("%w: source version is archived", errors.ErrInvalidState)
	}

	version := &models.PlanVersion{
		VersionID:     uuid.New(),
		CompanyID:     companyID,
		PlanID:        source.PlanID,
		VersionNumber: newVersion,
		Snapshot:      source.Snapshot,
		IsPublished:   false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := s.versionRepo.Create(ctx, tx, version); err != nil {
		return nil, err
	}

	payload := buildVersionPayload(version)
	if err := s.emitEvent(ctx, tx, version.VersionID, events.EventPlanVersionCloned, payload); err != nil {
		logger.Warn("failed to emit version cloned event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, version); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.logAudit(ctx, &companyID, "clone_version", "plan_version", &version.VersionID, &createdBy, source, version, map[string]interface{}{
		"source_version_id": sourceVersionID.String(),
		"new_version":       newVersion,
	})
	return version, nil
}

func (s *planVersionService) Rollback(ctx context.Context, companyID, planID uuid.UUID, version int, performedBy uuid.UUID) (*models.PlanVersion, error) {
	logger := s.logger.With(zap.String("method", "Rollback"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("rollback-%s-%d", planID.String(), version))
	var cached *models.PlanVersion
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached rollback result")
		return cached, nil
	}

	versions, err := s.versionRepo.GetByPlan(ctx, tx, companyID, planID)
	if err != nil {
		return nil, err
	}
	var target *models.PlanVersion
	for _, v := range versions {
		if v.VersionNumber == version && v.DeletedAt == nil {
			target = v
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("%w: version %d not found", errors.ErrNotFound, version)
	}
	if err := s.Publish(ctx, companyID, target.VersionID, performedBy); err != nil {
		return nil, err
	}

	// Refresh target after publish
	target, err = s.versionRepo.GetByID(ctx, tx, companyID, target.VersionID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, fmt.Errorf("%w: published version not found", errors.ErrNotFound)
	}

	payload := buildVersionPayload(target)
	if err := s.emitEvent(ctx, tx, target.VersionID, events.EventPlanVersionRollback, payload); err != nil {
		logger.Warn("failed to emit rollback event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, target); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.logAudit(ctx, &companyID, "rollback_version", "plan_version", &target.VersionID, &performedBy, nil, target, map[string]interface{}{
		"plan_id":      planID.String(),
		"version":      version,
		"performed_by": performedBy.String(),
	})
	return target, nil
}

// ----------------------------------------------------------------------------
// Retrieval
// ----------------------------------------------------------------------------

func (s *planVersionService) GetLatest(ctx context.Context, companyID, planID uuid.UUID) (*models.PlanVersion, error) {
	db := s.pgClient.DB
	versions, err := s.versionRepo.GetByPlan(ctx, db, companyID, planID)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, errors.ErrNotFound
	}
	latest := versions[0]
	for _, v := range versions {
		if v.VersionNumber > latest.VersionNumber && v.DeletedAt == nil {
			latest = v
		}
	}
	return latest, nil
}

func (s *planVersionService) GetPublished(ctx context.Context, companyID, planID uuid.UUID) (*models.PlanVersion, error) {
	db := s.pgClient.DB
	versions, err := s.versionRepo.GetByPlan(ctx, db, companyID, planID)
	if err != nil {
		return nil, err
	}
	for _, v := range versions {
		if v.IsPublished && v.DeletedAt == nil {
			return v, nil
		}
	}
	return nil, errors.ErrNotFound
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

func (s *planVersionService) ValidatePublish(ctx context.Context, versionID uuid.UUID) error {
	db := s.pgClient.DB
	version, err := s.versionRepo.GetByID(ctx, db, uuid.Nil, versionID)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("%w: version not found", errors.ErrNotFound)
	}
	if version.IsPublished {
		return fmt.Errorf("%w: version already published", errors.ErrInvalidState)
	}
	if version.DeletedAt != nil {
		return fmt.Errorf("%w: version is archived", errors.ErrInvalidState)
	}
	return nil
}

func (s *planVersionService) ValidateRollback(ctx context.Context, versionID uuid.UUID) error {
	db := s.pgClient.DB
	version, err := s.versionRepo.GetByID(ctx, db, uuid.Nil, versionID)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("%w: version not found", errors.ErrNotFound)
	}
	if version.DeletedAt != nil {
		return fmt.Errorf("%w: version is archived", errors.ErrInvalidState)
	}
	if !version.IsPublished {
		return fmt.Errorf("%w: version is not published; cannot rollback to unpublished version", errors.ErrInvalidState)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Helper: buildSnapshot
// ----------------------------------------------------------------------------

func (s *planVersionService) buildSnapshot(ctx context.Context, tx repository.DBTX, plan *models.Plan) (*planVersionSnapshot, error) {
	snapshot := &planVersionSnapshot{}
	snapshot.Plan.PlanID = plan.PlanID
	snapshot.Plan.CompanyID = plan.CompanyID
	snapshot.Plan.Name = plan.Name
	snapshot.Plan.PlanType = string(plan.PlanType)
	snapshot.Plan.Description = plan.Description
	snapshot.Plan.BillingPolicyID = plan.BillingPolicyID
	snapshot.Plan.RenewalPolicyID = plan.RenewalPolicyID
	snapshot.Plan.PausePolicyID = plan.PausePolicyID
	snapshot.Plan.ProrationPolicyID = plan.ProrationPolicyID
	snapshot.Plan.DurationDays = plan.DurationDays
	snapshot.Plan.CancellationPolicy = plan.CancellationPolicy
	snapshot.Plan.Metadata = plan.Metadata

	items, err := s.planItemRepo.GetByPlan(ctx, tx, plan.PlanID)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		itemData := struct {
			PlanItemID      uuid.UUID      `json:"plan_item_id"`
			ItemType        enums.ItemType `json:"item_type"`
			Name            string         `json:"name"`
			Description     *string        `json:"description,omitempty"`
			FeatureKey      *string        `json:"feature_key,omitempty"`
			BillingPolicyID *uuid.UUID     `json:"billing_policy_id,omitempty"`
			Price           string         `json:"price"`
			Currency        string         `json:"currency"`
			EffectiveFrom   time.Time      `json:"effective_from"`
			EffectiveTo     *time.Time     `json:"effective_to,omitempty"`
			IsMandatory     bool           `json:"is_mandatory"`
			Benefits        []struct {
				BenefitID          uuid.UUID         `json:"benefit_id"`
				BenefitType        enums.BenefitType `json:"benefit_type"`
				BenefitDescription *string           `json:"benefit_description,omitempty"`
				Value              models.JSONB      `json:"value"`
			} `json:"benefits,omitempty"`
			Entitlements []struct {
				EntitlementID uuid.UUID         `json:"entitlement_id"`
				FeatureKey    string            `json:"feature_key"`
				LimitValue    *string           `json:"limit_value,omitempty"`
				LimitPeriod   enums.LimitPeriod `json:"limit_period"`
				IsEnabled     bool              `json:"is_enabled"`
			} `json:"entitlements,omitempty"`
		}{
			PlanItemID:      item.PlanItemID,
			ItemType:        item.ItemType,
			Name:            item.Name,
			Description:     item.Description,
			FeatureKey:      item.FeatureKey,
			BillingPolicyID: item.BillingPolicyID,
			Price:           item.Price.String(),
			Currency:        item.Currency,
			EffectiveFrom:   item.EffectiveFrom,
			EffectiveTo:     item.EffectiveTo,
			IsMandatory:     item.IsMandatory,
		}
		benefits, err := s.benefitRepo.GetByPlanItem(ctx, tx, item.PlanItemID)
		if err != nil {
			return nil, err
		}
		for _, ben := range benefits {
			benData := struct {
				BenefitID          uuid.UUID         `json:"benefit_id"`
				BenefitType        enums.BenefitType `json:"benefit_type"`
				BenefitDescription *string           `json:"benefit_description,omitempty"`
				Value              models.JSONB      `json:"value"`
			}{
				BenefitID:          ben.BenefitID,
				BenefitType:        ben.BenefitType,
				BenefitDescription: ben.BenefitDescription,
				Value:              ben.Value,
			}
			itemData.Benefits = append(itemData.Benefits, benData)
		}
		entitlements, err := s.entitlementRepo.GetByPlanItem(ctx, tx, item.PlanItemID)
		if err != nil {
			return nil, err
		}
		for _, ent := range entitlements {
			var limitStr *string
			if ent.LimitValue != nil {
				s := ent.LimitValue.String()
				limitStr = &s
			}
			entData := struct {
				EntitlementID uuid.UUID         `json:"entitlement_id"`
				FeatureKey    string            `json:"feature_key"`
				LimitValue    *string           `json:"limit_value,omitempty"`
				LimitPeriod   enums.LimitPeriod `json:"limit_period"`
				IsEnabled     bool              `json:"is_enabled"`
			}{
				EntitlementID: ent.EntitlementID,
				FeatureKey:    ent.FeatureKey,
				LimitValue:    limitStr,
				LimitPeriod:   ent.LimitPeriod,
				IsEnabled:     ent.IsEnabled,
			}
			itemData.Entitlements = append(itemData.Entitlements, entData)
		}
		snapshot.Items = append(snapshot.Items, itemData)
	}
	return snapshot, nil
}
func (s *planVersionService) Compare(ctx context.Context, companyID, leftVersionID, rightVersionID uuid.UUID) (*PlanVersionComparison, error) {
	db := s.pgClient.DB
	left, err := s.versionRepo.GetByID(ctx, db, companyID, leftVersionID)
	if err != nil {
		return nil, err
	}
	if left == nil {
		return nil, fmt.Errorf("%w: left version not found", errors.ErrNotFound)
	}
	right, err := s.versionRepo.GetByID(ctx, db, companyID, rightVersionID)
	if err != nil {
		return nil, err
	}
	if right == nil {
		return nil, fmt.Errorf("%w: right version not found", errors.ErrNotFound)
	}
	var leftSnap, rightSnap planVersionSnapshot
	leftBytes, _ := json.Marshal(left.Snapshot)
	rightBytes, _ := json.Marshal(right.Snapshot)
	if err := json.Unmarshal(leftBytes, &leftSnap); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rightBytes, &rightSnap); err != nil {
		return nil, err
	}
	comparison := &PlanVersionComparison{
		LeftVersion:  left,
		RightVersion: right,
		Changes:      []PlanChange{},
	}
	// Compare plan fields
	if leftSnap.Plan.Name != rightSnap.Plan.Name {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "name", Old: leftSnap.Plan.Name, New: rightSnap.Plan.Name})
	}
	if leftSnap.Plan.PlanType != rightSnap.Plan.PlanType {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "plan_type", Old: leftSnap.Plan.PlanType, New: rightSnap.Plan.PlanType})
	}
	if leftSnap.Plan.BillingPolicyID != rightSnap.Plan.BillingPolicyID {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "billing_policy_id", Old: leftSnap.Plan.BillingPolicyID, New: rightSnap.Plan.BillingPolicyID})
	}
	if leftSnap.Plan.RenewalPolicyID != rightSnap.Plan.RenewalPolicyID {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "renewal_policy_id", Old: leftSnap.Plan.RenewalPolicyID, New: rightSnap.Plan.RenewalPolicyID})
	}
	if leftSnap.Plan.PausePolicyID != rightSnap.Plan.PausePolicyID {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "pause_policy_id", Old: leftSnap.Plan.PausePolicyID, New: rightSnap.Plan.PausePolicyID})
	}
	if leftSnap.Plan.ProrationPolicyID != rightSnap.Plan.ProrationPolicyID {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "proration_policy_id", Old: leftSnap.Plan.ProrationPolicyID, New: rightSnap.Plan.ProrationPolicyID})
	}
	if leftSnap.Plan.DurationDays != rightSnap.Plan.DurationDays {
		comparison.PlanChanged = true
		comparison.Changes = append(comparison.Changes, PlanChange{Entity: "plan", Field: "duration_days", Old: leftSnap.Plan.DurationDays, New: rightSnap.Plan.DurationDays})
	}
	// Compare items count and details (simplified)
	if len(leftSnap.Items) != len(rightSnap.Items) {
		comparison.ItemsChanged = true
	} else {
		for i := range leftSnap.Items {
			leftItem := leftSnap.Items[i]
			rightItem := rightSnap.Items[i]
			if leftItem.PlanItemID != rightItem.PlanItemID ||
				leftItem.Name != rightItem.Name ||
				leftItem.Price != rightItem.Price {
				comparison.ItemsChanged = true
				break
			}
		}
	}
	return comparison, nil
}
