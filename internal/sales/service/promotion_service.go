package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/repository"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// =============================================================================
// PromotionService Interface (full definition)
// =============================================================================

type PromotionService interface {
	CreatePromotion(ctx context.Context, req *CreatePromotionRequest) (*discount.Promotion, error)
	UpdatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, req *UpdatePromotionRequest) (*discount.Promotion, error)
	DeletePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, deletedBy uuid.UUID) error
	GetPromotionByID(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (*discount.Promotion, error)
	GetPromotionByCode(ctx context.Context, companyID uuid.UUID, code string) (*discount.Promotion, error)
	GetPromotionByName(ctx context.Context, companyID uuid.UUID, name string) (*discount.Promotion, error)
	ListPromotions(ctx context.Context, filter PromotionListFilter, p Pagination, s Sort) ([]*discount.Promotion, int64, error)
	SearchPromotions(ctx context.Context, companyID uuid.UUID, query string, limit int, offset int) ([]*discount.Promotion, int64, error)
	GetActivePromotions(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error)
	ActivatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, updatedBy uuid.UUID) error
	DeactivatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, updatedBy uuid.UUID) error
	ExpirePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, expiredBy uuid.UUID) error
	IsPromotionActive(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, at time.Time) (bool, error)

	CreatePromotionRule(ctx context.Context, req *CreatePromotionRuleRequest) (*discount.PromotionRule, error)
	UpdatePromotionRule(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID, req *UpdatePromotionRuleRequest) (*discount.PromotionRule, error)
	DeletePromotionRule(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID, deletedBy uuid.UUID) error
	GetPromotionRuleByID(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID) (*discount.PromotionRule, error)
	GetPromotionRules(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) ([]*discount.PromotionRule, error)
	ValidatePromotionRule(ctx context.Context, rule *discount.PromotionRule) error

	EvaluatePromotion(ctx context.Context, req *EvaluatePromotionRequest) (*PromotionEvaluationResult, error)
	EvaluatePromotionRules(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, quantities map[uuid.UUID]decimal.Decimal, orderAmount decimal.Decimal, at time.Time) (*PromotionRuleEvaluationResult, error)

	ValidatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error
	ValidatePromotionDates(ctx context.Context, promotion *discount.Promotion, at time.Time) error
	ValidatePromotionUsageLimit(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) error
	ValidateCustomerPromotionUsageLimit(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID) error
	ValidatePromotionProducts(ctx context.Context, companyID, promotionID uuid.UUID, productIDs []uuid.UUID) error // UPDATED: added companyID
	ValidatePromotionCategories(ctx context.Context, promotionID uuid.UUID, categoryIDs []uuid.UUID) error
	CanCustomerUsePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID, at time.Time) (bool, error)

	GetApplicablePromotions(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error)
	GetAutomaticPromotions(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error)
	GetBestPromotion(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error)
	ApplyBestPromotions(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, appliedBy uuid.UUID) (*PromotionApplicationResult, error)

	CalculatePromotionDiscount(ctx context.Context, promotionID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error)
	CalculateBXGYDiscount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, items []*PromotionItemCalculationInput) (decimal.Decimal, error)
	CalculateCategoryDiscount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, categoryAmounts map[uuid.UUID]decimal.Decimal) (decimal.Decimal, error)
	CalculateTieredDiscount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error)

	ApplyPromotionToOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error)
	ApplyPromotionToQuote(ctx context.Context, companyID uuid.UUID, quoteID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error)
	ApplyPromotionToInvoice(ctx context.Context, companyID uuid.UUID, invoiceID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error)

	RemovePromotionFromOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error
	RemovePromotionFromQuote(ctx context.Context, companyID uuid.UUID, quoteID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error
	RemovePromotionFromInvoice(ctx context.Context, companyID uuid.UUID, invoiceID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error
	ClearPromotions(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, clearedBy uuid.UUID) error

	RecordPromotionUsage(ctx context.Context, req *RecordPromotionUsageRequest) error
	RecordOrderPromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, orderID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error
	RecordQuotePromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, quoteID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error
	RecordInvoicePromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, invoiceID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error

	GetPromotionUsageCount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (int64, error)
	GetCustomerPromotionUsageCount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID) (int64, error)
	GetPromotionUsageHistory(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, p Pagination, s Sort) ([]*discount.DiscountApplication, int64, error)

	CanStackPromotion(ctx context.Context, companyID uuid.UUID, firstPromotionID uuid.UUID, secondPromotionID uuid.UUID) (bool, error)
	ValidatePromotionStacking(ctx context.Context, companyID uuid.UUID, promotionIDs []uuid.UUID) error
	GetStackablePromotions(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) ([]uuid.UUID, error)

	// GetTopPromotions returns the top N promotions by usage count with metrics.
	GetTopPromotions(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*PromotionWithMetrics, error)

	// GetMostUsedPromotions is an alias for GetTopPromotions.
	GetMostUsedPromotions(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*PromotionWithMetrics, error)

	// GetHighestRevenuePromotions returns the top N promotions by total discount amount with metrics.
	GetHighestRevenuePromotions(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*PromotionWithMetrics, error)
	GetTotalPromotionDiscountAmount(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetPromotionConversionImpact(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetPromotionRedemptionRate(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)

	PromotionExists(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (bool, error)
	PromotionCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	PromotionRuleExists(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID) (bool, error)
	IsPromotionExpired(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, at time.Time) (bool, error)
	IsPromotionUsageLimitReached(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (bool, error)
	IsCustomerPromotionUsageLimitReached(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID) (bool, error)
}

// =============================================================================
// Request/Response DTOs (including new fields)
// =============================================================================

// =============================================================================
// Implementation
// =============================================================================

type promotionService struct {
	promotionRepo     repository.PromotionRepository
	discountUsageRepo repository.DiscountUsageRepository
	stackingRuleRepo  repository.StackingRuleRepository
	orderRepo         repository.OrderRepository
	quoteRepo         repository.QuoteRepository
	invoiceRepo       repository.InvoiceRepository
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
}

func NewPromotionService(
	promotionRepo repository.PromotionRepository,
	discountUsageRepo repository.DiscountUsageRepository,
	stackingRuleRepo repository.StackingRuleRepository,
	orderRepo repository.OrderRepository,
	quoteRepo repository.QuoteRepository,
	invoiceRepo repository.InvoiceRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) PromotionService {
	return &promotionService{
		promotionRepo:     promotionRepo,
		discountUsageRepo: discountUsageRepo,
		stackingRuleRepo:  stackingRuleRepo,
		orderRepo:         orderRepo,
		quoteRepo:         quoteRepo,
		invoiceRepo:       invoiceRepo,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		logger:            logger.Named("promotion_service"),
	}
}

// ---------- helpers ----------

func stringPtr(s string) *string     { return &s }
func timePtr(t time.Time) *time.Time { return &t }

func toDiscountType(et enums.DiscountType) discount.DiscountType {
	return discount.DiscountType(et)
}

func toEnumsDiscountType(dt discount.DiscountType) enums.DiscountType {
	return enums.DiscountType(dt)
}

func marshalConfig(config map[string]interface{}) (datatypes.JSON, error) {
	if config == nil {
		return nil, nil
	}
	b, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return datatypes.JSON(b), nil
}

func unmarshalConfig(data datatypes.JSON) (map[string]interface{}, error) {
	if data == nil {
		return nil, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ---------- event emission ----------

func (s *promotionService) emitPromotionEvent(ctx context.Context, tx *sql.Tx, promotion *discount.Promotion, eventType string) error {
	payload := map[string]interface{}{
		"promotion_id": promotion.PromotionID.String(),
		"company_id":   promotion.CompanyID.String(),
		"name":         promotion.Name,
		"is_active":    promotion.IsActive,
		"start_date":   promotion.StartDate.Format(time.RFC3339),
		"end_date":     promotion.EndDate.Format(time.RFC3339),
	}
	if promotion.Priority != nil {
		payload["priority"] = *promotion.Priority
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "promotion",
		AggregateID:   promotion.PromotionID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *promotionService) emitPromotionAppliedEvent(ctx context.Context, tx *sql.Tx, companyID, promotionID uuid.UUID, entityType, entityID string, discountAmount decimal.Decimal) error {
	payload := map[string]interface{}{
		"company_id":      companyID.String(),
		"promotion_id":    promotionID.String(),
		"entity_type":     entityType,
		"entity_id":       entityID,
		"discount_amount": discountAmount.String(),
		"applied_at":      time.Now().Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "promotion",
		AggregateID:   promotionID.String(),
		EventType:     salesEvents.EventPromotionApplied,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// =============================================================================
// CRUD with idempotency
// =============================================================================

func (s *promotionService) CreatePromotion(ctx context.Context, req *CreatePromotionRequest) (*discount.Promotion, error) {
	logger := s.logger.With(zap.String("method", "CreatePromotion"))

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = uuid.New().String()
	}
	logger.Info("processing create promotion", zap.String("idempotency_key", idempKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check idempotency cache
	var cached *discount.Promotion
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached promotion",
			zap.String("promotion_id", cached.PromotionID.String()),
			zap.String("name", cached.Name),
			zap.Int("rules_count", 0), // cached promotion doesn't include rules in this store
		)
		return cached, nil
	}
	logger.Info("no cache found, creating new promotion")

	// Input validation
	if req.CompanyID == uuid.Nil || req.Name == "" {
		logger.Error("company_id or name missing")
		return nil, fmt.Errorf("%w: company_id and name required", salesErrors.ErrInvalidInput)
	}
	if req.StartDate.IsZero() || req.EndDate.IsZero() || req.EndDate.Before(req.StartDate) {
		logger.Error("invalid start/end date",
			zap.Time("start", req.StartDate),
			zap.Time("end", req.EndDate))
		return nil, fmt.Errorf("%w: invalid start/end date", salesErrors.ErrInvalidInput)
	}

	// Stacking type
	stackingType := req.StackingType
	if stackingType == "" {
		stackingType = "stackable"
	}
	allowed := map[string]bool{"stackable": true, "exclusive": true, "none": true}
	if !allowed[stackingType] {
		logger.Error("invalid stacking_type", zap.String("stacking_type", stackingType))
		return nil, fmt.Errorf("%w: stacking_type must be one of 'stackable', 'exclusive', 'none'", salesErrors.ErrInvalidInput)
	}

	// ---- Convert rules ----
	var rules []*discount.PromotionRule
	for idx, ruleDTO := range req.Rules {
		configJSON, err := marshalConfig(ruleDTO.RuleConfig)
		if err != nil {
			logger.Error("failed to marshal rule config", zap.Int("rule_index", idx), zap.Error(err))
			return nil, fmt.Errorf("marshal rule config: %w", err)
		}
		enumDT := toEnumsDiscountType(ruleDTO.DiscountType)
		if !enumDT.IsValid() {
			logger.Error("invalid discount_type", zap.Int("rule_index", idx), zap.String("discount_type", string(ruleDTO.DiscountType)))
			return nil, fmt.Errorf("%w: invalid discount_type %s", salesErrors.ErrInvalidInput, ruleDTO.DiscountType)
		}
		rule := &discount.PromotionRule{
			RuleID:        uuid.New(),
			PromotionID:   uuid.Nil, // will be set after promotion is created
			RuleType:      ruleDTO.RuleType,
			RuleConfig:    configJSON,
			DiscountType:  enumDT,
			DiscountValue: ruleDTO.DiscountValue,
			MaxDiscount:   ruleDTO.MaxDiscount,
		}
		rules = append(rules, rule)
		logger.Debug("converted rule",
			zap.Int("index", idx),
			zap.String("rule_id", rule.RuleID.String()),
			zap.String("rule_type", rule.RuleType),
			zap.String("discount_value", rule.DiscountValue.String()),
		)
	}
	logger.Info("converted rules from request", zap.Int("rule_count", len(rules)))
	// ---------------------------------

	// Build promotion entity
	promotion := &discount.Promotion{
		PromotionID:  uuid.New(),
		CompanyID:    req.CompanyID,
		Name:         req.Name,
		Description:  req.Description,
		StartDate:    req.StartDate,
		EndDate:      req.EndDate,
		IsActive:     req.IsActive,
		Priority:     req.Priority,
		StackingType: stackingType,
		UsageLimit:   req.UsageLimit,
		PerUserLimit: req.PerUserLimit,
		CreatedBy:    req.CreatedBy,
		UpdatedBy:    req.CreatedBy,
	}
	logger.Info("created promotion entity",
		zap.String("promotion_id", promotion.PromotionID.String()),
		zap.String("name", promotion.Name))

	// ---- Save to repository ----
	if err := s.promotionRepo.Create(ctx, tx, promotion, rules); err != nil {
		logger.Error("failed to create promotion in repository", zap.Error(err))
		return nil, fmt.Errorf("create promotion: %w", err)
	}
	logger.Info("successfully saved promotion and rules to database",
		zap.String("promotion_id", promotion.PromotionID.String()),
		zap.Int("rules_saved", len(rules)))
	// -----------------------------

	// Emit event
	if err := s.emitPromotionEvent(ctx, tx, promotion, salesEvents.EventPromotionCreated); err != nil {
		logger.Warn("failed to emit promotion created event", zap.Error(err))
	}

	// Store idempotency cache
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, promotion); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_promotion", "promotion",
			&promotion.PromotionID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"name":           promotion.Name,
				"usage_limit":    promotion.UsageLimit,
				"per_user_limit": promotion.PerUserLimit,
				"rule_count":     len(rules),
			})
	}
	logger.Info("promotion created successfully",
		zap.String("promotion_id", promotion.PromotionID.String()),
		zap.Int("rules_created", len(rules)))
	return promotion, nil
}
func (s *promotionService) UpdatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, req *UpdatePromotionRequest) (*discount.Promotion, error) {
	logger := s.logger.With(zap.String("method", "UpdatePromotion"))

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = promotionID.String()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *discount.Promotion
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached promotion")
		return cached, nil
	}

	if companyID == uuid.Nil || promotionID == uuid.Nil {
		return nil, salesErrors.ErrInvalidInput
	}

	promo, err := s.promotionRepo.GetByIDForUpdate(ctx, tx, companyID, promotionID)
	if err != nil {
		return nil, err
	}
	if promo.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	changes := make(map[string]interface{})
	if req.Name != nil && *req.Name != promo.Name {
		changes["name"] = map[string]string{"old": promo.Name, "new": *req.Name}
		promo.Name = *req.Name
	}
	if req.Description != nil {
		promo.Description = req.Description
	}
	if req.StartDate != nil {
		changes["start_date"] = *req.StartDate
		promo.StartDate = *req.StartDate
	}
	if req.EndDate != nil {
		changes["end_date"] = *req.EndDate
		promo.EndDate = *req.EndDate
	}
	if req.IsActive != nil && *req.IsActive != promo.IsActive {
		changes["is_active"] = *req.IsActive
		promo.IsActive = *req.IsActive
	}
	if req.Priority != nil && (promo.Priority == nil || *req.Priority != *promo.Priority) {
		changes["priority"] = *req.Priority
		promo.Priority = req.Priority
	}
	if req.StackingType != nil && *req.StackingType != promo.StackingType {
		allowed := map[string]bool{"stackable": true, "exclusive": true, "none": true}
		if !allowed[*req.StackingType] {
			return nil, fmt.Errorf("%w: stacking_type must be one of 'stackable', 'exclusive', 'none'", salesErrors.ErrInvalidInput)
		}
		changes["stacking_type"] = map[string]string{"old": promo.StackingType, "new": *req.StackingType}
		promo.StackingType = *req.StackingType
	}
	if req.UsageLimit != nil && (promo.UsageLimit == nil || *req.UsageLimit != *promo.UsageLimit) {
		changes["usage_limit"] = *req.UsageLimit
		promo.UsageLimit = req.UsageLimit
	}
	if req.PerUserLimit != nil && (promo.PerUserLimit == nil || *req.PerUserLimit != *promo.PerUserLimit) {
		changes["per_user_limit"] = *req.PerUserLimit
		promo.PerUserLimit = req.PerUserLimit
	}
	promo.UpdatedBy = req.UpdatedBy

	// -------------------- DATE VALIDATION FIX --------------------
	// After applying start_date and end_date updates, validate that start_date <= end_date
	if promo.StartDate.After(promo.EndDate) {
		return nil, fmt.Errorf("%w: start_date (%s) cannot be after end_date (%s)",
			salesErrors.ErrInvalidInput,
			promo.StartDate.Format(time.RFC3339),
			promo.EndDate.Format(time.RFC3339))
	}
	// -------------------------------------------------------------

	if err := s.promotionRepo.Update(ctx, tx, promo); err != nil {
		return nil, fmt.Errorf("update promotion: %w", err)
	}
	if err := s.emitPromotionEvent(ctx, tx, promo, salesEvents.EventPromotionUpdated); err != nil {
		logger.Warn("failed to emit promotion updated event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, promo); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_promotion", "promotion",
			&promotionID, "user", req.UpdatedBy, nil, nil, changes)
	}
	return promo, nil
}

func (s *promotionService) DeletePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeletePromotion"))

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = promotionID.String()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	promo, err := s.promotionRepo.GetByID(ctx, tx, companyID, promotionID)
	if err != nil {
		return err
	}
	if promo.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.promotionRepo.Delete(ctx, tx, companyID, promotionID); err != nil {
		return fmt.Errorf("delete promotion: %w", err)
	}
	if err := s.emitPromotionEvent(ctx, tx, promo, salesEvents.EventPromotionDeleted); err != nil {
		logger.Warn("failed to emit promotion deleted event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_promotion", "promotion",
			&promotionID, "user", &deletedBy, nil, nil, nil)
	}
	return nil
}

// ---------- Read methods ----------

func (s *promotionService) GetPromotionByID(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (*discount.Promotion, error) {
	return s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, promotionID)
}

func (s *promotionService) GetPromotionByCode(ctx context.Context, companyID uuid.UUID, code string) (*discount.Promotion, error) {
	return nil, fmt.Errorf("%w: promotions are identified by ID, not by code", salesErrors.ErrInvalidInput)
}

func (s *promotionService) GetPromotionByName(ctx context.Context, companyID uuid.UUID, name string) (*discount.Promotion, error) {
	filter := repository.PromotionFilter{
		CompanyID: companyID,
		Name:      &name,
	}
	list, _, err := s.promotionRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 1, Offset: 0}, repository.Sort{Field: "created_at", Direction: "desc"})
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, salesErrors.ErrNotFound
	}
	return list[0], nil
}

func (s *promotionService) ListPromotions(ctx context.Context, filter PromotionListFilter, p Pagination, srt Sort) ([]*discount.Promotion, int64, error) {
	repoFilter := repository.PromotionFilter{
		CompanyID:    filter.CompanyID,
		IsActive:     filter.IsActive,
		Name:         filter.Name,
		PromotionIDs: filter.PromotionIDs,
	}
	return s.promotionRepo.List(ctx, s.pgClient.DB, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *promotionService) SearchPromotions(ctx context.Context, companyID uuid.UUID, query string, limit int, offset int) ([]*discount.Promotion, int64, error) {
	return s.promotionRepo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *promotionService) GetActivePromotions(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error) {
	return s.promotionRepo.GetActivePromotions(ctx, s.pgClient.DB, companyID, at)
}

// ---------- Status management ----------

func (s *promotionService) setPromotionActiveStatus(ctx context.Context, companyID, promotionID uuid.UUID, active bool, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "setPromotionActiveStatus"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("status-%s", promotionID.String())
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – status already set")
		return nil
	}

	if err := s.promotionRepo.SetActiveStatus(ctx, tx, companyID, promotionID, active, updatedBy); err != nil {
		return err
	}
	promo, _ := s.promotionRepo.GetByID(ctx, tx, companyID, promotionID)
	if promo != nil {
		_ = s.emitPromotionEvent(ctx, tx, promo, salesEvents.EventPromotionUpdated)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *promotionService) ActivatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setPromotionActiveStatus(ctx, companyID, promotionID, true, &updatedBy)
}

func (s *promotionService) DeactivatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, updatedBy uuid.UUID) error {
	return s.setPromotionActiveStatus(ctx, companyID, promotionID, false, &updatedBy)
}

func (s *promotionService) ExpirePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, expiredBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ExpirePromotion"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("expire-%s", promotionID.String())
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already expired")
		return nil
	}

	promo, err := s.promotionRepo.GetByIDForUpdate(ctx, tx, companyID, promotionID)
	if err != nil {
		return err
	}
	now := time.Now()
	promo.EndDate = now
	promo.IsActive = false
	promo.UpdatedBy = &expiredBy
	if err := s.promotionRepo.Update(ctx, tx, promo); err != nil {
		return err
	}
	_ = s.emitPromotionEvent(ctx, tx, promo, salesEvents.EventPromotionUpdated)
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *promotionService) IsPromotionActive(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, at time.Time) (bool, error) {
	active, err := s.promotionRepo.IsActive(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil || !active {
		return false, err
	}
	expired, err := s.promotionRepo.IsExpired(ctx, s.pgClient.DB, companyID, promotionID, at)
	if err != nil {
		return false, err
	}
	return !expired, nil
}

// ---------- Promotion Rules ----------

func (s *promotionService) CreatePromotionRule(ctx context.Context, req *CreatePromotionRuleRequest) (*discount.PromotionRule, error) {
	logger := s.logger.With(zap.String("method", "CreatePromotionRule"))

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = uuid.New().String()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *discount.PromotionRule
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached rule")
		return cached, nil
	}

	if req.PromotionID == uuid.Nil {
		return nil, fmt.Errorf("%w: promotion_id is required", salesErrors.ErrInvalidInput)
	}
	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", salesErrors.ErrInvalidInput)
	}
	if req.RuleType == "" {
		return nil, fmt.Errorf("%w: rule_type is required", salesErrors.ErrInvalidInput)
	}
	if req.DiscountValue.IsZero() || req.DiscountValue.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: discount_value must be positive", salesErrors.ErrInvalidInput)
	}

	enumDT := toEnumsDiscountType(req.DiscountType)
	if !enumDT.IsValid() {
		return nil, fmt.Errorf("%w: invalid discount_type (must be percentage, fixed_amount, or buy_x_get_y)", salesErrors.ErrInvalidInput)
	}
	if enumDT == enums.DiscountTypePercentage && req.DiscountValue.GreaterThan(decimal.NewFromInt(100)) {
		return nil, fmt.Errorf("%w: percentage discount cannot exceed 100", salesErrors.ErrInvalidInput)
	}

	configJSON, err := marshalConfig(req.RuleConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal rule config: %w", err)
	}

	rule := &discount.PromotionRule{
		RuleID:        uuid.New(),
		PromotionID:   req.PromotionID,
		RuleType:      req.RuleType,
		RuleConfig:    configJSON,
		DiscountType:  enumDT,
		DiscountValue: req.DiscountValue,
		MaxDiscount:   req.MaxDiscount,
	}

	if err := s.promotionRepo.AddRules(ctx, tx, req.CompanyID, req.PromotionID, []*discount.PromotionRule{rule}); err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, rule); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return rule, nil
}

func (s *promotionService) UpdatePromotionRule(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID, req *UpdatePromotionRuleRequest) (*discount.PromotionRule, error) {
	logger := s.logger.With(zap.String("method", "UpdatePromotionRule"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = ruleID.String()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *discount.PromotionRule
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached rule")
		return cached, nil
	}

	var promotionID uuid.UUID
	query := `SELECT promotion_id FROM sales.promotion_rules WHERE rule_id = $1`
	err = tx.QueryRowContext(ctx, query, ruleID).Scan(&promotionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("get promotion_id for rule: %w", err)
	}

	rule, err := s.promotionRepo.GetRuleByID(ctx, tx, companyID, promotionID, ruleID)
	if err != nil {
		return nil, err
	}

	if req.RuleType != nil {
		rule.RuleType = *req.RuleType
	}
	if req.RuleConfig != nil {
		configJSON, err := marshalConfig(req.RuleConfig)
		if err != nil {
			return nil, fmt.Errorf("marshal rule config: %w", err)
		}
		rule.RuleConfig = configJSON
	}
	if req.DiscountType != nil {
		rule.DiscountType = toEnumsDiscountType(*req.DiscountType)
	}
	if req.DiscountValue != nil {
		rule.DiscountValue = *req.DiscountValue
	}
	if req.MaxDiscount != nil {
		rule.MaxDiscount = req.MaxDiscount
	}

	if err := s.promotionRepo.DeleteRule(ctx, tx, companyID, promotionID, ruleID); err != nil {
		return nil, fmt.Errorf("delete old rule: %w", err)
	}
	if err := s.promotionRepo.AddRules(ctx, tx, companyID, promotionID, []*discount.PromotionRule{rule}); err != nil {
		return nil, fmt.Errorf("re-create rule: %w", err)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, rule); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return rule, nil
}

func (s *promotionService) DeletePromotionRule(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeletePromotionRule"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = ruleID.String()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – rule already deleted")
		return nil
	}

	var promotionID uuid.UUID
	query := `SELECT promotion_id FROM sales.promotion_rules WHERE rule_id = $1`
	err = tx.QueryRowContext(ctx, query, ruleID).Scan(&promotionID)
	if err != nil {
		return fmt.Errorf("get promotion_id for rule: %w", err)
	}
	if err := s.promotionRepo.DeleteRule(ctx, tx, companyID, promotionID, ruleID); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *promotionService) GetPromotionRuleByID(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID) (*discount.PromotionRule, error) {
	var promotionID uuid.UUID
	query := `SELECT promotion_id FROM sales.promotion_rules WHERE rule_id = $1 AND company_id = $2`
	if err := s.pgClient.DB.QueryRowContext(ctx, query, ruleID, companyID).Scan(&promotionID); err != nil {
		return nil, err
	}
	return s.promotionRepo.GetRuleByID(ctx, s.pgClient.DB, companyID, promotionID, ruleID)
}

func (s *promotionService) GetPromotionRules(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) ([]*discount.PromotionRule, error) {
	return s.promotionRepo.GetRules(ctx, s.pgClient.DB, companyID, promotionID)
}

func (s *promotionService) ValidatePromotionRule(ctx context.Context, rule *discount.PromotionRule) error {
	if rule.RuleType == "" {
		return fmt.Errorf("%w: rule_type required", salesErrors.ErrInvalidInput)
	}
	if !rule.DiscountType.IsValid() {
		return fmt.Errorf("%w: invalid discount_type", salesErrors.ErrInvalidInput)
	}
	if rule.DiscountValue.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: discount_value must be positive", salesErrors.ErrInvalidInput)
	}
	if rule.DiscountType == enums.DiscountTypePercentage && rule.DiscountValue.GreaterThan(decimal.NewFromInt(100)) {
		return fmt.Errorf("%w: percentage discount cannot exceed 100", salesErrors.ErrInvalidInput)
	}
	return nil
}

// =============================================================================
// Evaluation (with helper functions)
// =============================================================================

func (s *promotionService) EvaluatePromotion(ctx context.Context, req *EvaluatePromotionRequest) (*PromotionEvaluationResult, error) {
	logger := s.logger.With(zap.String("method", "EvaluatePromotion"))

	_, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, req.CompanyID, req.PromotionID)
	if err != nil {
		return nil, err
	}
	if err := s.ValidatePromotion(ctx, req.CompanyID, req.PromotionID, req.CustomerID, nil, req.OrderAmount, req.At); err != nil {
		return &PromotionEvaluationResult{Applicable: false, Reason: err.Error()}, nil
	}

	rules, err := s.promotionRepo.GetRules(ctx, s.pgClient.DB, req.CompanyID, req.PromotionID)
	if err != nil {
		return nil, err
	}
	logger.Info("evaluating rules", zap.Int("rule_count", len(rules)))

	totalDiscount := decimal.Zero
	for i, rule := range rules {
		disc, err := s.evaluateSingleRule(ctx, rule, req)
		if err != nil {
			logger.Warn("error evaluating rule", zap.Int("index", i), zap.Error(err))
			continue
		}
		logger.Info("rule evaluated",
			zap.Int("index", i),
			zap.String("rule_type", rule.RuleType),
			zap.String("discount", disc.String()),
		)
		totalDiscount = totalDiscount.Add(disc)
	}
	if totalDiscount.GreaterThan(req.OrderAmount) {
		totalDiscount = req.OrderAmount
	}
	logger.Info("total discount", zap.String("total_discount", totalDiscount.String()))
	return &PromotionEvaluationResult{Applicable: true, DiscountAmount: totalDiscount}, nil
}

// ---------- evaluation helpers ----------

func (s *promotionService) evaluateSingleRule(ctx context.Context, rule *discount.PromotionRule, req *EvaluatePromotionRequest) (decimal.Decimal, error) {
	config, err := unmarshalConfig(rule.RuleConfig)
	if err != nil {
		return decimal.Zero, err
	}

	logger := s.logger.With(
		zap.String("rule_id", rule.RuleID.String()),
		zap.String("rule_type", rule.RuleType),
		zap.String("discount_type", rule.DiscountType.String()),
		zap.String("discount_value", rule.DiscountValue.String()),
		zap.Any("config", config),
	)
	logger.Info("evaluateSingleRule called")

	switch rule.RuleType {
	case "order_amount":
		logger.Info("processing order_amount rule")
		var minAmount decimal.Decimal
		if v, ok := config["min_amount"]; ok {
			minAmount = toDecimal(v)
		} else if v, ok := config["min_order_amount"]; ok {
			minAmount = toDecimal(v)
		} else {
			logger.Warn("min_amount or min_order_amount not found in config")
			return decimal.Zero, nil
		}
		if req.OrderAmount.LessThan(minAmount) {
			logger.Info("order amount below minimum", zap.String("min", minAmount.String()))
			return decimal.Zero, nil
		}
		disc := calculateDiscountByType(rule.DiscountType, rule.DiscountValue, req.OrderAmount, rule.MaxDiscount)
		logger.Info("calculated discount", zap.String("discount", disc.String()))
		return disc, nil
	case "product_quantity":
		logger.Info("processing product_quantity rule")
		minQtyRaw, ok := config["min_quantity"]
		if !ok {
			logger.Warn("min_quantity not found in config")
			return decimal.Zero, nil
		}
		minQty := toDecimal(minQtyRaw)
		var totalQty decimal.Decimal
		applicableProducts := getApplicableProductIDsFromRule(config)
		for _, item := range req.Items {
			if isProductApplicable(applicableProducts, item.ProductID) {
				totalQty = totalQty.Add(item.Quantity)
			}
		}
		if totalQty.LessThan(minQty) {
			logger.Info("total quantity below minimum", zap.String("min", minQty.String()))
			return decimal.Zero, nil
		}
		disc := calculateDiscountByType(rule.DiscountType, rule.DiscountValue, req.OrderAmount, rule.MaxDiscount)
		logger.Info("calculated discount", zap.String("discount", disc.String()))
		return disc, nil
	case "buy_x_get_y":
		logger.Info("processing buy_x_get_y rule")
		buyRaw, ok1 := config["buy"]
		getRaw, ok2 := config["get"]
		if !ok1 || !ok2 {
			logger.Warn("buy or get not found in config")
			return decimal.Zero, nil
		}
		buy := toInt(buyRaw)
		get := toInt(getRaw)
		if buy <= 0 || get <= 0 {
			logger.Warn("buy and get must be positive", zap.Int("buy", buy), zap.Int("get", get))
			return decimal.Zero, nil
		}
		var discount decimal.Decimal
		applicableProducts := getApplicableProductIDsFromRule(config)
		for _, item := range req.Items {
			if isProductApplicable(applicableProducts, item.ProductID) {
				freeUnits := item.Quantity.Div(decimal.NewFromInt(int64(buy))).Floor().Mul(decimal.NewFromInt(int64(get)))
				discount = discount.Add(freeUnits.Mul(item.UnitPrice))
			}
		}
		if rule.MaxDiscount != nil && discount.GreaterThan(*rule.MaxDiscount) {
			discount = *rule.MaxDiscount
		}
		logger.Info("calculated discount", zap.String("discount", discount.String()))
		return discount, nil
	case "category_discount":
		logger.Info("processing category_discount rule")
		categoryAmountsRaw, ok := config["category_amounts"]
		if !ok {
			logger.Warn("category_amounts not found in config")
			return decimal.Zero, nil
		}
		categoryAmounts := make(map[uuid.UUID]decimal.Decimal)
		if m, ok := categoryAmountsRaw.(map[string]interface{}); ok {
			for k, v := range m {
				id, err := uuid.Parse(k)
				if err != nil {
					continue
				}
				categoryAmounts[id] = toDecimal(v)
			}
		}
		var eligibleAmount decimal.Decimal
		for _, amount := range categoryAmounts {
			eligibleAmount = eligibleAmount.Add(amount)
		}
		disc := calculateDiscountByType(rule.DiscountType, rule.DiscountValue, eligibleAmount, rule.MaxDiscount)
		logger.Info("calculated discount", zap.String("discount", disc.String()))
		return disc, nil
	case "tiered_discount":
		logger.Info("processing tiered_discount rule")
		tiersRaw, ok := config["tiers"]
		if !ok {
			logger.Warn("tiers not found in config")
			return decimal.Zero, nil
		}
		tiersList, ok := tiersRaw.([]interface{})
		if !ok {
			logger.Warn("tiers is not a list")
			return decimal.Zero, nil
		}
		for _, tierRaw := range tiersList {
			tierMap, ok := tierRaw.(map[string]interface{})
			if !ok {
				continue
			}
			threshold := toDecimal(tierMap["threshold"])
			rate := toDecimal(tierMap["rate"])
			if req.OrderAmount.GreaterThanOrEqual(threshold) {
				disc := calculateDiscountByType(enums.DiscountTypePercentage, rate, req.OrderAmount, rule.MaxDiscount)
				logger.Info("calculated discount", zap.String("discount", disc.String()))
				return disc, nil
			}
		}
		logger.Info("no tier matched")
		return decimal.Zero, nil
	case "percentage":
		logger.Info("processing percentage rule")
		discountPercentRaw, ok := config["discount_percent"]
		if !ok {
			logger.Warn("missing discount_percent in config")
			return decimal.Zero, nil
		}
		discountPercent := toDecimal(discountPercentRaw)
		logger.Info("discount_percent parsed", zap.String("value", discountPercent.String()))
		if discountPercent.LessThanOrEqual(decimal.Zero) || discountPercent.GreaterThan(decimal.NewFromInt(100)) {
			logger.Warn("invalid discount_percent", zap.String("value", discountPercent.String()))
			return decimal.Zero, nil
		}
		if minAmountRaw, ok := config["min_order_amount"]; ok {
			minAmount := toDecimal(minAmountRaw)
			logger.Info("min_order_amount found", zap.String("value", minAmount.String()))
			if req.OrderAmount.LessThan(minAmount) {
				logger.Info("order amount below minimum",
					zap.String("order_amount", req.OrderAmount.String()),
					zap.String("min_amount", minAmount.String()),
				)
				return decimal.Zero, nil
			}
		}
		disc := req.OrderAmount.Mul(discountPercent).Div(decimal.NewFromInt(100))
		if rule.MaxDiscount != nil && disc.GreaterThan(*rule.MaxDiscount) {
			disc = *rule.MaxDiscount
		}
		logger.Info("calculated discount", zap.String("discount", disc.String()))
		return disc, nil
	default:
		logger.Warn("unknown rule type, returning 0")
		return decimal.Zero, nil
	}
}

func calculateDiscountByType(dt enums.DiscountType, value, base decimal.Decimal, max *decimal.Decimal) decimal.Decimal {
	var disc decimal.Decimal
	switch dt {
	case enums.DiscountTypePercentage:
		disc = base.Mul(value).Div(decimal.NewFromInt(100))
	case enums.DiscountTypeFixed:
		disc = value
	default:
		return decimal.Zero
	}
	if max != nil && disc.GreaterThan(*max) {
		disc = *max
	}
	if disc.GreaterThan(base) {
		disc = base
	}
	return disc
}

func getApplicableProductIDsFromRule(config map[string]interface{}) []uuid.UUID {
	productIDsRaw, ok := config["product_ids"]
	if !ok {
		return nil
	}
	slice, ok := productIDsRaw.([]interface{})
	if !ok {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(slice))
	for _, p := range slice {
		if str, ok := p.(string); ok {
			if id, err := uuid.Parse(str); err == nil {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func isProductApplicable(applicableProducts []uuid.UUID, productID uuid.UUID) bool {
	if len(applicableProducts) == 0 {
		return true
	}
	for _, id := range applicableProducts {
		if id == productID {
			return true
		}
	}
	return false
}

func toDecimal(v interface{}) decimal.Decimal {
	switch val := v.(type) {
	case float64:
		return decimal.NewFromFloat(val)
	case int:
		return decimal.NewFromInt(int64(val))
	case string:
		d, _ := decimal.NewFromString(val)
		return d
	case decimal.Decimal:
		return val
	default:
		return decimal.Zero
	}
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case decimal.Decimal:
		return int(val.IntPart())
	default:
		return 0
	}
}

func (s *promotionService) EvaluatePromotionRules(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, quantities map[uuid.UUID]decimal.Decimal, orderAmount decimal.Decimal, at time.Time) (*PromotionRuleEvaluationResult, error) {
	rules, err := s.promotionRepo.GetRules(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return nil, err
	}
	applicable := make([]*discount.PromotionRule, 0)
	totalDisc := decimal.Zero
	items := make([]PromotionItemInput, 0, len(productIDs))
	for _, pid := range productIDs {
		qty := quantities[pid]
		items = append(items, PromotionItemInput{ProductID: pid, Quantity: qty})
	}
	evalReq := &EvaluatePromotionRequest{
		CompanyID:   companyID,
		PromotionID: promotionID,
		CustomerID:  customerID,
		Items:       items,
		OrderAmount: orderAmount,
		At:          at,
	}
	for _, r := range rules {
		disc, err := s.evaluateSingleRule(ctx, r, evalReq)
		if err != nil {
			continue
		}
		if disc.GreaterThan(decimal.Zero) {
			totalDisc = totalDisc.Add(disc)
			applicable = append(applicable, r)
		}
	}
	return &PromotionRuleEvaluationResult{ApplicableRules: applicable, DiscountAmount: totalDisc}, nil
}

// ---------- Validation ----------

func (s *promotionService) ValidatePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error {
	promo, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return err
	}
	if err := s.ValidatePromotionDates(ctx, promo, at); err != nil {
		return err
	}
	if !promo.IsActive {
		return salesErrors.ErrPromotionInactive
	}
	if err := s.ValidatePromotionUsageLimit(ctx, companyID, promotionID); err != nil {
		return err
	}
	if customerID != nil && *customerID != uuid.Nil {
		if err := s.ValidateCustomerPromotionUsageLimit(ctx, companyID, promotionID, *customerID); err != nil {
			return err
		}
	}
	if len(productIDs) > 0 {
		// UPDATED: pass companyID
		if err := s.ValidatePromotionProducts(ctx, companyID, promotionID, productIDs); err != nil {
			return err
		}
	}
	return nil
}

func (s *promotionService) ValidatePromotionDates(ctx context.Context, promotion *discount.Promotion, at time.Time) error {
	if at.Before(promotion.StartDate) || at.After(promotion.EndDate) {
		return fmt.Errorf("%w: promotion not active at %v", salesErrors.ErrInvalidInput, at)
	}
	return nil
}

// ----- NEW: ValidatePromotionUsageLimit -----
func (s *promotionService) ValidatePromotionUsageLimit(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) error {
	promo, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return err
	}
	if promo.UsageLimit == nil {
		return nil
	}
	count, err := s.GetPromotionUsageCount(ctx, companyID, promotionID)
	if err != nil {
		return err
	}
	if count >= int64(*promo.UsageLimit) {
		return fmt.Errorf("%w: promotion usage limit reached", salesErrors.ErrInvalidInput)
	}
	return nil
}

// ----- NEW: ValidateCustomerPromotionUsageLimit -----
func (s *promotionService) ValidateCustomerPromotionUsageLimit(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID) error {
	promo, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return err
	}
	if promo.PerUserLimit == nil {
		return nil
	}
	count, err := s.GetCustomerPromotionUsageCount(ctx, companyID, promotionID, customerID)
	if err != nil {
		return err
	}
	if count >= int64(*promo.PerUserLimit) {
		return fmt.Errorf("%w: customer usage limit reached", salesErrors.ErrInvalidInput)
	}
	return nil
}

// ----- UPDATED: ValidatePromotionProducts with companyID -----
func (s *promotionService) ValidatePromotionProducts(ctx context.Context, companyID, promotionID uuid.UUID, productIDs []uuid.UUID) error {
	// Fetch the promotion with proper companyID
	_, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return err
	}
	rules, err := s.promotionRepo.GetRules(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		config, err := unmarshalConfig(rule.RuleConfig)
		if err != nil {
			continue
		}
		allowed, ok := config["product_ids"].([]interface{})
		if !ok || len(allowed) == 0 {
			continue
		}
		allowedSet := make(map[uuid.UUID]bool)
		for _, p := range allowed {
			if str, ok := p.(string); ok {
				if id, err := uuid.Parse(str); err == nil {
					allowedSet[id] = true
				}
			}
		}
		if len(allowedSet) == 0 {
			continue
		}
		for _, pid := range productIDs {
			if !allowedSet[pid] {
				return fmt.Errorf("%w: product %s not eligible for this promotion", salesErrors.ErrInvalidInput, pid)
			}
		}
	}
	return nil
}

// ----- NEW: ValidatePromotionCategories (placeholder – implement if needed) -----
func (s *promotionService) ValidatePromotionCategories(ctx context.Context, promotionID uuid.UUID, categoryIDs []uuid.UUID) error {
	// Similar to ValidatePromotionProducts but checks category restrictions.
	// For now, return nil (not implemented).
	return nil
}

func (s *promotionService) CanCustomerUsePromotion(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID, at time.Time) (bool, error) {
	err := s.ValidatePromotion(ctx, companyID, promotionID, &customerID, nil, decimal.Zero, at)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// ---------- Applicable Promotions ----------

func (s *promotionService) GetApplicablePromotions(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error) {
	return s.promotionRepo.GetApplicablePromotions(ctx, s.pgClient.DB, companyID, customerID, productIDs, orderAmount, at)
}

func (s *promotionService) GetAutomaticPromotions(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error) {
	// No "automatic" flag – we treat all active promotions as "automatic" for now.
	return s.promotionRepo.GetActivePromotions(ctx, s.pgClient.DB, companyID, at)
}

func (s *promotionService) GetBestPromotion(ctx context.Context, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (*discount.Promotion, decimal.Decimal, error) {
	promos, err := s.GetApplicablePromotions(ctx, companyID, customerID, productIDs, orderAmount, at)
	if err != nil {
		return nil, decimal.Zero, err
	}
	var bestPromo *discount.Promotion
	bestDisc := decimal.Zero
	for _, p := range promos {
		disc, err := s.calculatePromotionDiscountWithCompany(ctx, companyID, p.PromotionID, orderAmount, productIDs)
		if err != nil {
			continue
		}
		if disc.GreaterThan(bestDisc) {
			bestDisc = disc
			bestPromo = p
		}
	}
	return bestPromo, bestDisc, nil
}

// ---------- Apply Best (idempotent) ----------

func (s *promotionService) ApplyBestPromotions(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, appliedBy uuid.UUID) (*PromotionApplicationResult, error) {
	logger := s.logger.With(zap.String("method", "ApplyBestPromotions"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("best-%s-%s", entityType, entityID.String())
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *PromotionApplicationResult
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached result")
		return cached, nil
	}

	var orderAmount decimal.Decimal
	var productIDs []uuid.UUID
	var customerID *uuid.UUID

	switch entityType {
	case "order":
		order, err := s.orderRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		orderAmount = order.Subtotal
		items, _ := s.orderRepo.GetItems(ctx, tx, companyID, entityID)
		for _, it := range items {
			productIDs = append(productIDs, it.ProductID)
		}
		customerID = &order.CustomerID
	case "invoice":
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		orderAmount = invoice.Subtotal
		items, _ := s.invoiceRepo.GetItems(ctx, tx, companyID, entityID)
		for _, it := range items {
			if it.ProductID != nil {
				productIDs = append(productIDs, *it.ProductID)
			}
		}
		customerID = &invoice.CustomerID
	default:
		return nil, fmt.Errorf("%w: unsupported entity type for auto-apply (only order/invoice)", salesErrors.ErrInvalidInput)
	}

	bestPromo, bestDisc, err := s.GetBestPromotion(ctx, companyID, customerID, productIDs, orderAmount, time.Now())
	if err != nil || bestPromo == nil || bestDisc.IsZero() {
		res := &PromotionApplicationResult{AppliedPromotions: []*discount.Promotion{}, TotalDiscount: decimal.Zero}
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, res)
		_ = tx.Commit()
		return res, nil
	}

	var appliedPromo *discount.Promotion
	var appliedDisc decimal.Decimal
	switch entityType {
	case "order":
		appliedPromo, appliedDisc, err = s.ApplyPromotionToOrder(ctx, companyID, entityID, bestPromo.PromotionID, appliedBy)
	case "invoice":
		appliedPromo, appliedDisc, err = s.ApplyPromotionToInvoice(ctx, companyID, entityID, bestPromo.PromotionID, appliedBy)
	}
	if err != nil {
		return nil, err
	}
	result := &PromotionApplicationResult{AppliedPromotions: []*discount.Promotion{appliedPromo}, TotalDiscount: appliedDisc}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, result); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return result, nil
}

// ---------- Discount Calculation (internal with companyID) ----------

func (s *promotionService) calculatePromotionDiscountWithCompany(ctx context.Context, companyID, promotionID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	rules, err := s.promotionRepo.GetRules(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil || len(rules) == 0 {
		return decimal.Zero, nil
	}
	items := make([]PromotionItemInput, len(productIDs))
	for i, pid := range productIDs {
		items[i] = PromotionItemInput{
			ProductID: pid,
			Quantity:  decimal.NewFromInt(1),
			UnitPrice: decimal.Zero,
		}
	}
	evalReq := &EvaluatePromotionRequest{
		CompanyID:   companyID,
		PromotionID: promotionID,
		Items:       items,
		OrderAmount: subtotal,
		At:          time.Now(),
	}
	totalDisc := decimal.Zero
	for _, rule := range rules {
		disc, err := s.evaluateSingleRule(ctx, rule, evalReq)
		if err != nil {
			continue
		}
		totalDisc = totalDisc.Add(disc)
	}
	if totalDisc.GreaterThan(subtotal) {
		totalDisc = subtotal
	}
	return totalDisc, nil
}

// Public CalculatePromotionDiscount – requires companyID.
// To avoid breaking existing interface, we'll try to fetch promotion to get companyID, but this may fail.
// Better: change interface to include companyID. For now, we'll fetch promotion by ID (assuming repo allows).
func (s *promotionService) CalculatePromotionDiscount(ctx context.Context, promotionID uuid.UUID, subtotal decimal.Decimal, productIDs []uuid.UUID) (decimal.Decimal, error) {
	promo, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, uuid.Nil, promotionID)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get promotion for company: %w", err)
	}
	return s.calculatePromotionDiscountWithCompany(ctx, promo.CompanyID, promotionID, subtotal, productIDs)
}

func (s *promotionService) CalculateBXGYDiscount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, items []*PromotionItemCalculationInput) (decimal.Decimal, error) {
	rules, err := s.promotionRepo.GetRules(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return decimal.Zero, err
	}
	for _, rule := range rules {
		if rule.RuleType == "buy_x_get_y" {
			evalItems := make([]PromotionItemInput, len(items))
			for i, it := range items {
				evalItems[i] = PromotionItemInput{
					ProductID: it.ProductID,
					Quantity:  it.Quantity,
					UnitPrice: it.UnitPrice,
				}
			}
			evalReq := &EvaluatePromotionRequest{
				CompanyID:   companyID,
				PromotionID: promotionID,
				Items:       evalItems,
				At:          time.Now(),
			}
			return s.evaluateSingleRule(ctx, rule, evalReq)
		}
	}
	return decimal.Zero, nil
}

func (s *promotionService) CalculateCategoryDiscount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, categoryAmounts map[uuid.UUID]decimal.Decimal) (decimal.Decimal, error) {
	config := map[string]interface{}{"category_amounts": categoryAmounts}
	rule := &discount.PromotionRule{
		RuleType:   "category_discount",
		RuleConfig: datatypes.JSON(mustMarshal(config)),
	}
	evalReq := &EvaluatePromotionRequest{
		CompanyID:   companyID,
		PromotionID: promotionID,
		At:          time.Now(),
	}
	return s.evaluateSingleRule(ctx, rule, evalReq)
}

func (s *promotionService) CalculateTieredDiscount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error) {
	rules, err := s.promotionRepo.GetRules(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return decimal.Zero, err
	}
	for _, r := range rules {
		if r.RuleType == "tiered_discount" {
			evalReq := &EvaluatePromotionRequest{
				CompanyID:   companyID,
				PromotionID: promotionID,
				OrderAmount: orderAmount,
				At:          time.Now(),
			}
			return s.evaluateSingleRule(ctx, r, evalReq)
		}
	}
	return decimal.Zero, nil
}

// ---------- Apply/Remove (idempotent) ----------

func (s *promotionService) applyPromotionToEntity(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error) {
	logger := s.logger.With(zap.String("method", "applyPromotionToEntity"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("apply-%s-%s-%s", entityType, entityID.String(), promotionID.String())
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Cache the result (promotion + amount)
	var cachedResult struct {
		Promotion      *discount.Promotion
		DiscountAmount decimal.Decimal
	}
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cachedResult); err == nil && cachedResult.Promotion != nil {
		logger.Info("idempotent – returning cached application result")
		return cachedResult.Promotion, cachedResult.DiscountAmount, nil
	}

	if entityType != "order" && entityType != "invoice" {
		return nil, decimal.Zero, fmt.Errorf("%w: promotions can only be applied to orders or invoices", salesErrors.ErrInvalidInput)
	}

	promo, err := s.promotionRepo.GetByID(ctx, tx, companyID, promotionID)
	if err != nil {
		return nil, decimal.Zero, err
	}

	var subtotal decimal.Decimal
	var productIDs []uuid.UUID
	var customerID uuid.UUID

	switch entityType {
	case "order":
		order, err := s.orderRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, decimal.Zero, err
		}
		subtotal = order.Subtotal
		items, _ := s.orderRepo.GetItems(ctx, tx, companyID, entityID)
		for _, it := range items {
			productIDs = append(productIDs, it.ProductID)
		}
		customerID = order.CustomerID
	case "invoice":
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, decimal.Zero, err
		}
		subtotal = invoice.Subtotal
		items, _ := s.invoiceRepo.GetItems(ctx, tx, companyID, entityID)
		for _, it := range items {
			if it.ProductID != nil {
				productIDs = append(productIDs, *it.ProductID)
			}
		}
		customerID = invoice.CustomerID
	}

	// ---- FIX: Validate promotion (active, dates, usage limits, products) ----
	if err := s.ValidatePromotion(ctx, companyID, promotionID, &customerID, productIDs, subtotal, time.Now()); err != nil {
		return nil, decimal.Zero, err
	}

	discountAmount, err := s.calculatePromotionDiscountWithCompany(ctx, companyID, promotionID, subtotal, productIDs)
	if err != nil {
		return nil, decimal.Zero, err
	}
	if discountAmount.IsZero() {
		// Cache zero result
		zeroResult := struct {
			Promotion      *discount.Promotion
			DiscountAmount decimal.Decimal
		}{promo, decimal.Zero}
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, zeroResult)
		_ = tx.Commit()
		return promo, decimal.Zero, nil
	}

	discountName := promo.Name
	app := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     companyID,
		DiscountType:  "promotion",
		DiscountID:    &promotionID,
		DiscountName:  &discountName,
		Amount:        discountAmount,
	}
	if customerID != uuid.Nil {
		app.CustomerID = &customerID
	}
	switch entityType {
	case "order":
		app.OrderID = &entityID
	case "invoice":
		app.InvoiceID = &entityID
	}
	if err := s.discountUsageRepo.Create(ctx, tx, app); err != nil {
		return nil, decimal.Zero, err
	}
	if err := s.emitPromotionAppliedEvent(ctx, tx, companyID, promotionID, entityType, entityID.String(), discountAmount); err != nil {
		logger.Warn("failed to emit promotion applied event", zap.Error(err))
	}
	cachedResult.Promotion = promo
	cachedResult.DiscountAmount = discountAmount
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, cachedResult); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, decimal.Zero, fmt.Errorf("commit tx: %w", err)
	}
	return promo, discountAmount, nil
}
func (s *promotionService) ApplyPromotionToOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error) {
	return s.applyPromotionToEntity(ctx, companyID, "order", orderID, promotionID, appliedBy)
}

func (s *promotionService) ApplyPromotionToQuote(ctx context.Context, companyID uuid.UUID, quoteID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error) {
	return nil, decimal.Zero, fmt.Errorf("promotions cannot be applied to quotes")
}

func (s *promotionService) ApplyPromotionToInvoice(ctx context.Context, companyID uuid.UUID, invoiceID uuid.UUID, promotionID uuid.UUID, appliedBy uuid.UUID) (*discount.Promotion, decimal.Decimal, error) {
	return s.applyPromotionToEntity(ctx, companyID, "invoice", invoiceID, promotionID, appliedBy)
}

func (s *promotionService) removePromotionFromEntity(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "removePromotionFromEntity"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("remove-%s-%s-%s", entityType, entityID.String(), promotionID.String())
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – removal already done")
		return nil
	}

	if entityType != "order" && entityType != "invoice" {
		return fmt.Errorf("%w: only orders and invoices supported", salesErrors.ErrInvalidInput)
	}

	var apps []*discount.DiscountApplication
	switch entityType {
	case "order":
		apps, err = s.discountUsageRepo.GetByOrder(ctx, tx, companyID, entityID)
	case "invoice":
		apps, err = s.discountUsageRepo.GetByInvoice(ctx, tx, companyID, entityID)
	}
	if err != nil {
		return err
	}
	found := false
	for _, app := range apps {
		if app.DiscountID != nil && *app.DiscountID == promotionID && app.DiscountType == "promotion" {
			if err := s.discountUsageRepo.Delete(ctx, tx, app.ApplicationID); err != nil {
				return err
			}
			found = true
			break
		}
	}
	if !found {
		return salesErrors.ErrNotFound
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *promotionService) RemovePromotionFromOrder(ctx context.Context, companyID uuid.UUID, orderID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error {
	return s.removePromotionFromEntity(ctx, companyID, "order", orderID, promotionID, removedBy)
}

func (s *promotionService) RemovePromotionFromQuote(ctx context.Context, companyID uuid.UUID, quoteID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error {
	return fmt.Errorf("promotions on quotes are not supported")
}

func (s *promotionService) RemovePromotionFromInvoice(ctx context.Context, companyID uuid.UUID, invoiceID uuid.UUID, promotionID uuid.UUID, removedBy uuid.UUID) error {
	return s.removePromotionFromEntity(ctx, companyID, "invoice", invoiceID, promotionID, removedBy)
}

func (s *promotionService) ClearPromotions(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, clearedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ClearPromotions"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("clear-%s-%s", entityType, entityID.String())
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – clear already done")
		return nil
	}

	if entityType != "order" && entityType != "invoice" {
		return fmt.Errorf("%w: only orders and invoices supported", salesErrors.ErrInvalidInput)
	}

	var apps []*discount.DiscountApplication
	switch entityType {
	case "order":
		apps, err = s.discountUsageRepo.GetByOrder(ctx, tx, companyID, entityID)
	case "invoice":
		apps, err = s.discountUsageRepo.GetByInvoice(ctx, tx, companyID, entityID)
	}
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.DiscountType == "promotion" {
			if err := s.discountUsageRepo.Delete(ctx, tx, app.ApplicationID); err != nil {
				return err
			}
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ---------- Usage Recording ----------

func (s *promotionService) RecordPromotionUsage(ctx context.Context, req *RecordPromotionUsageRequest) error {
	logger := s.logger.With(zap.String("method", "RecordPromotionUsage"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = uuid.New().String()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Check idempotency for the *same* key – returns 200 OK if already processed
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – usage already recorded with this key")
		return nil
	}

	// 2. Check for existing usage (duplicate) – for a *different* key, return 409 Conflict
	var existing []*discount.DiscountApplication
	switch req.EntityType {
	case "order":
		existing, err = s.discountUsageRepo.GetByOrder(ctx, tx, req.CompanyID, req.EntityID)
	case "invoice":
		existing, err = s.discountUsageRepo.GetByInvoice(ctx, tx, req.CompanyID, req.EntityID)
	default:
		return fmt.Errorf("%w: unsupported entity type", salesErrors.ErrInvalidInput)
	}
	if err != nil && err != salesErrors.ErrNotFound {
		return err
	}
	for _, app := range existing {
		if app.DiscountID != nil && *app.DiscountID == req.PromotionID && app.DiscountType == "promotion" {
			// Duplicate found with a different idempotency key – reject with 409 Conflict
			return salesErrors.ErrDuplicate
		}
	}

	// 3. No duplicate – create the usage record
	app := &discount.DiscountApplication{
		ApplicationID: uuid.New(),
		CompanyID:     req.CompanyID,
		DiscountType:  "promotion",
		DiscountID:    &req.PromotionID,
		Amount:        req.DiscountAmount,
	}
	if req.CustomerID != nil {
		app.CustomerID = req.CustomerID
	}
	switch req.EntityType {
	case "order":
		app.OrderID = &req.EntityID
	case "invoice":
		app.InvoiceID = &req.EntityID
	default:
		return fmt.Errorf("%w: unsupported entity type", salesErrors.ErrInvalidInput)
	}
	if err := s.discountUsageRepo.Create(ctx, tx, app); err != nil {
		return fmt.Errorf("create usage: %w", err)
	}

	// 4. Store idempotency for this key (success)
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	return tx.Commit()
}
func (s *promotionService) RecordOrderPromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, orderID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	return s.RecordPromotionUsage(ctx, &RecordPromotionUsageRequest{
		CompanyID:      companyID,
		PromotionID:    promotionID,
		EntityType:     "order",
		EntityID:       orderID,
		CustomerID:     customerID,
		DiscountAmount: discountAmount,
		UsedAt:         usedAt,
	})
}

func (s *promotionService) RecordQuotePromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, quoteID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	return fmt.Errorf("quote promotion usage not supported")
}

func (s *promotionService) RecordInvoicePromotionUsage(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, invoiceID uuid.UUID, customerID *uuid.UUID, discountAmount decimal.Decimal, usedAt time.Time) error {
	return s.RecordPromotionUsage(ctx, &RecordPromotionUsageRequest{
		CompanyID:      companyID,
		PromotionID:    promotionID,
		EntityType:     "invoice",
		EntityID:       invoiceID,
		CustomerID:     customerID,
		DiscountAmount: discountAmount,
		UsedAt:         usedAt,
	})
}

// ---------- Usage Queries ----------

func (s *promotionService) GetPromotionUsageCount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (int64, error) {
	filter := repository.DiscountUsageFilter{
		CompanyID:    companyID,
		DiscountType: stringPtr("promotion"),
		DiscountID:   &promotionID,
	}
	_, total, err := s.discountUsageRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 1, Offset: 0}, repository.Sort{Field: "created_at", Direction: "desc"})
	return total, err
}

func (s *promotionService) GetCustomerPromotionUsageCount(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID) (int64, error) {
	filter := repository.DiscountUsageFilter{
		CompanyID:    companyID,
		CustomerID:   &customerID,
		DiscountID:   &promotionID,
		DiscountType: stringPtr("promotion"),
	}
	_, total, err := s.discountUsageRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 1, Offset: 0}, repository.Sort{Field: "created_at", Direction: "desc"})
	return total, err
}

func (s *promotionService) GetPromotionUsageHistory(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, p Pagination, srt Sort) ([]*discount.DiscountApplication, int64, error) {
	filter := repository.DiscountUsageFilter{
		CompanyID:    companyID,
		DiscountType: stringPtr("promotion"),
		DiscountID:   &promotionID,
	}
	return s.discountUsageRepo.List(ctx, s.pgClient.DB, filter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

// ---------- Stacking ----------

func (s *promotionService) CanStackPromotion(ctx context.Context, companyID uuid.UUID, firstPromotionID uuid.UUID, secondPromotionID uuid.UUID) (bool, error) {
	p1, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, firstPromotionID)
	if err != nil {
		return false, err
	}
	p2, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, secondPromotionID)
	if err != nil {
		return false, err
	}
	if p1.StackingType == "exclusive" || p2.StackingType == "exclusive" {
		return false, nil
	}
	if p1.StackingType == "stackable" && p2.StackingType == "stackable" {
		return true, nil
	}
	if p1.StackingType == "none" || p2.StackingType == "none" {
		return false, nil
	}
	return true, nil
}

func (s *promotionService) ValidatePromotionStacking(ctx context.Context, companyID uuid.UUID, promotionIDs []uuid.UUID) error {
	for i := 0; i < len(promotionIDs); i++ {
		for j := i + 1; j < len(promotionIDs); j++ {
			ok, err := s.CanStackPromotion(ctx, companyID, promotionIDs[i], promotionIDs[j])
			if err != nil {
				// Wrap underlying error for context
				return fmt.Errorf("failed to check stacking for promotions %s and %s: %w", promotionIDs[i], promotionIDs[j], err)
			}
			if !ok {
				// Return a specific error that maps to 400 Bad Request
				return fmt.Errorf("%w: promotions %s and %s cannot be stacked", salesErrors.ErrStackingConflict, promotionIDs[i], promotionIDs[j])
			}
		}
	}
	return nil
}
func (s *promotionService) GetStackablePromotions(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) ([]uuid.UUID, error) {
	all, err := s.GetActivePromotions(ctx, companyID, time.Now())
	if err != nil {
		return nil, err
	}
	var result []uuid.UUID
	for _, p := range all {
		if p.PromotionID == promotionID {
			continue
		}
		ok, err := s.CanStackPromotion(ctx, companyID, promotionID, p.PromotionID)
		if err != nil {
			continue
		}
		if ok {
			result = append(result, p.PromotionID)
		}
	}
	return result, nil
}

// ---------- Analytics ----------

func (s *promotionService) GetTotalPromotionDiscountAmount(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error) {
	return s.promotionRepo.GetTotalDiscountGiven(ctx, s.pgClient.DB, companyID, from, to)
}

// ---- NEW: GetPromotionConversionImpact ----
func (s *promotionService) GetPromotionConversionImpact(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error) {
	// Placeholder: could compute lift by comparing conversion rates with/without promotion.
	// For now, return 0.
	return decimal.Zero, nil
}

// ---- NEW: GetPromotionRedemptionRate ----
func (s *promotionService) GetPromotionRedemptionRate(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error) {
	promo, err := s.promotionRepo.GetByID(ctx, s.pgClient.DB, companyID, promotionID)
	if err != nil {
		return decimal.Zero, err
	}
	if promo.UsageLimit == nil || *promo.UsageLimit == 0 {
		return decimal.Zero, nil
	}
	used, err := s.GetPromotionUsageCount(ctx, companyID, promotionID)
	if err != nil {
		return decimal.Zero, err
	}
	rate := decimal.NewFromInt(used).Div(decimal.NewFromInt(int64(*promo.UsageLimit))).Mul(decimal.NewFromInt(100))
	return rate, nil
}

// ---------- Existence ----------

func (s *promotionService) PromotionExists(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (bool, error) {
	return s.promotionRepo.Exists(ctx, s.pgClient.DB, companyID, promotionID)
}

func (s *promotionService) PromotionCodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return false, nil
}

func (s *promotionService) PromotionRuleExists(ctx context.Context, companyID uuid.UUID, ruleID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.promotion_rules WHERE rule_id = $1 AND company_id = $2)`
	err := s.pgClient.DB.QueryRowContext(ctx, query, ruleID, companyID).Scan(&exists)
	return exists, err
}

func (s *promotionService) IsPromotionExpired(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, at time.Time) (bool, error) {
	return s.promotionRepo.IsExpired(ctx, s.pgClient.DB, companyID, promotionID, at)
}

// ---- NEW: IsPromotionUsageLimitReached ----
func (s *promotionService) IsPromotionUsageLimitReached(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID) (bool, error) {
	err := s.ValidatePromotionUsageLimit(ctx, companyID, promotionID)
	if err == nil {
		return false, nil
	}
	if strings.Contains(err.Error(), "usage limit reached") {
		return true, nil
	}
	return false, err
}

// ---- NEW: IsCustomerPromotionUsageLimitReached ----
func (s *promotionService) IsCustomerPromotionUsageLimitReached(ctx context.Context, companyID uuid.UUID, promotionID uuid.UUID, customerID uuid.UUID) (bool, error) {
	err := s.ValidateCustomerPromotionUsageLimit(ctx, companyID, promotionID, customerID)
	if err == nil {
		return false, nil
	}
	if strings.Contains(err.Error(), "customer usage limit") {
		return true, nil
	}
	return false, err
}

// GetTopPromotions returns the top N promotions by usage count with metrics.
func (s *promotionService) GetTopPromotions(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*PromotionWithMetrics, error) {
	aggregates, err := s.promotionRepo.GetTopPromotionsByUsage(ctx, s.pgClient.DB, companyID, limit, from, to)
	if err != nil {
		return nil, err
	}

	result := make([]*PromotionWithMetrics, len(aggregates))
	for i, agg := range aggregates {
		result[i] = &PromotionWithMetrics{
			Promotion:  agg.Promotion,
			UsageCount: agg.UsageCount,
		}
	}
	return result, nil
}

// GetMostUsedPromotions is an alias for GetTopPromotions.
func (s *promotionService) GetMostUsedPromotions(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*PromotionWithMetrics, error) {
	return s.GetTopPromotions(ctx, companyID, limit, from, to)
}

// GetHighestRevenuePromotions returns the top N promotions by total discount amount with metrics.
func (s *promotionService) GetHighestRevenuePromotions(ctx context.Context, companyID uuid.UUID, limit int, from *time.Time, to *time.Time) ([]*PromotionWithMetrics, error) {
	aggregates, err := s.promotionRepo.GetTopPromotionsByDiscountAmount(ctx, s.pgClient.DB, companyID, limit, from, to)
	if err != nil {
		return nil, err
	}

	result := make([]*PromotionWithMetrics, len(aggregates))
	for i, agg := range aggregates {
		result[i] = &PromotionWithMetrics{
			Promotion:     agg.Promotion,
			TotalDiscount: agg.TotalDiscount,
		}
	}
	return result, nil
}
