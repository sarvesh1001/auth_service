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
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/repository"
)

// ---------- Request / response types ----------
type CommissionTrendPoint = repository.CommissionTrendPoint

// ---------- Service interface ----------

type SalesRepCommissionService interface {
	CreateCommissionPlan(ctx context.Context, req *CreateCommissionPlanRequest) (*models.CommissionPlan, error)
	UpdateCommissionPlan(ctx context.Context, companyID, planID uuid.UUID, req *UpdateCommissionPlanRequest) (*models.CommissionPlan, error)
	DeleteCommissionPlan(ctx context.Context, companyID, planID uuid.UUID, deletedBy uuid.UUID) error
	GetCommissionPlanByID(ctx context.Context, companyID, planID uuid.UUID) (*models.CommissionPlan, error)
	GetCommissionPlanByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.CommissionPlan, error)
	ListCommissionPlans(ctx context.Context, filter CommissionPlanListFilter, p Pagination, s Sort) ([]*models.CommissionPlan, int64, error)
	GetActiveCommissionPlans(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*models.CommissionPlan, error)

	CreateCommissionRule(ctx context.Context, req *CreateCommissionRuleRequest) (*models.CommissionRule, error)
	UpdateCommissionRule(ctx context.Context, companyID, ruleID uuid.UUID, req *UpdateCommissionRuleRequest) (*models.CommissionRule, error)
	DeleteCommissionRule(ctx context.Context, companyID, ruleID uuid.UUID, deletedBy uuid.UUID) error
	GetCommissionRuleByID(ctx context.Context, companyID, ruleID uuid.UUID) (*models.CommissionRule, error)
	GetCommissionRules(ctx context.Context, companyID, planID uuid.UUID) ([]*models.CommissionRule, error)
	ValidateCommissionRule(ctx context.Context, rule *models.CommissionRule) error

	AssignCommissionPlan(ctx context.Context, companyID, salesRepID, planID uuid.UUID, effectiveFrom time.Time, assignedBy uuid.UUID) error
	RemoveCommissionPlan(ctx context.Context, companyID, salesRepID uuid.UUID, removedBy uuid.UUID) error
	GetSalesRepCommissionPlan(ctx context.Context, companyID, salesRepID uuid.UUID, at time.Time) (*models.CommissionPlan, error)

	CalculateOrderCommission(ctx context.Context, companyID, orderID uuid.UUID) (*models.SalesCommission, error)
	CalculateInvoiceCommission(ctx context.Context, companyID, invoiceID uuid.UUID) (*models.SalesCommission, error)
	CalculatePaymentCommission(ctx context.Context, companyID, paymentID uuid.UUID) (*models.SalesCommission, error)
	CalculateCommissionForPeriod(ctx context.Context, companyID, salesRepID uuid.UUID, from, to time.Time) ([]*models.SalesCommission, decimal.Decimal, error)
	PreviewCommission(ctx context.Context, req *CommissionPreviewRequest) (*CommissionPreviewResult, error)

	ProcessOrderCompletedCommission(ctx context.Context, companyID, orderID uuid.UUID, triggeredBy uuid.UUID) (*models.SalesCommission, error)
	ProcessInvoicePaidCommission(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) (*models.SalesCommission, error)
	ProcessPaymentReceivedCommission(ctx context.Context, companyID, paymentID uuid.UUID, triggeredBy uuid.UUID) (*models.SalesCommission, error)
	RecalculateCommission(ctx context.Context, companyID, commissionID uuid.UUID, recalculatedBy uuid.UUID) error
	ReverseCommission(ctx context.Context, companyID, commissionID uuid.UUID, reason string, reversedBy uuid.UUID) error

	CreateCommissionRecord(ctx context.Context, req *CreateSalesCommissionRequest) (*models.SalesCommission, error)
	UpdateCommissionRecord(ctx context.Context, companyID, commissionID uuid.UUID, req *UpdateSalesCommissionRequest) (*models.SalesCommission, error)
	GetCommissionByID(ctx context.Context, companyID, commissionID uuid.UUID) (*models.SalesCommission, error)
	GetCommissionByReference(ctx context.Context, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) ([]*models.SalesCommission, error)
	ListCommissions(ctx context.Context, filter SalesCommissionListFilter, p Pagination, s Sort) ([]*models.SalesCommission, int64, error)
	GetSalesRepCommissions(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time, p Pagination, s Sort) ([]*models.SalesCommission, int64, error)

	MarkCommissionPending(ctx context.Context, companyID, commissionID uuid.UUID, updatedBy uuid.UUID) error
	ApproveCommission(ctx context.Context, companyID, commissionID uuid.UUID, approvedBy uuid.UUID) error
	RejectCommission(ctx context.Context, companyID, commissionID uuid.UUID, reason string, rejectedBy uuid.UUID) error
	MarkCommissionPaid(ctx context.Context, companyID, commissionID uuid.UUID, paidAt time.Time, paidBy uuid.UUID) error
	GetPendingCommissions(ctx context.Context, companyID uuid.UUID) ([]*models.SalesCommission, error)
	GetApprovedCommissions(ctx context.Context, companyID uuid.UUID) ([]*models.SalesCommission, error)
	GetUnpaidCommissions(ctx context.Context, companyID uuid.UUID) ([]*models.SalesCommission, error)

	ValidateCommissionPlan(ctx context.Context, plan *models.CommissionPlan) error
	ValidateCommissionCalculation(ctx context.Context, req *CommissionCalculationValidationRequest) error
	ValidateCommissionStatusTransition(ctx context.Context, current, next enums.CommissionStatus) error
	CanGenerateCommission(ctx context.Context, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) (bool, error)

	GetTotalCommissionAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalPaidCommission(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetOutstandingCommissionLiability(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error)
	GetTopSalesRepCommissions(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesCommission, error)
	GetCommissionSummaryBySalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (*SalesRepCommissionSummary, error)
	GetCommissionTrend(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*CommissionTrendPoint, error)

	CommissionPlanExists(ctx context.Context, companyID, planID uuid.UUID) (bool, error)
	CommissionRuleExists(ctx context.Context, companyID, ruleID uuid.UUID) (bool, error)
	CommissionRecordExists(ctx context.Context, companyID, commissionID uuid.UUID) (bool, error)
	CommissionAlreadyGenerated(ctx context.Context, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) (bool, error)
}

// ---------- Service implementation ----------

type salesRepCommissionService struct {
	planRepo         repository.CommissionPlanRepository
	ruleRepo         repository.CommissionRuleRepository
	commissionRepo   repository.SalesCommissionRepository
	salesRepRepo     repository.SalesRepRepository
	orderRepo        repository.OrderRepository
	invoiceRepo      repository.InvoiceRepository
	paymentRepo      repository.PaymentRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewSalesRepCommissionService(
	planRepo repository.CommissionPlanRepository,
	ruleRepo repository.CommissionRuleRepository,
	commissionRepo repository.SalesCommissionRepository,
	salesRepRepo repository.SalesRepRepository,
	orderRepo repository.OrderRepository,
	invoiceRepo repository.InvoiceRepository,
	paymentRepo repository.PaymentRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) SalesRepCommissionService {
	return &salesRepCommissionService{
		planRepo:         planRepo,
		ruleRepo:         ruleRepo,
		commissionRepo:   commissionRepo,
		salesRepRepo:     salesRepRepo,
		orderRepo:        orderRepo,
		invoiceRepo:      invoiceRepo,
		paymentRepo:      paymentRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("sales_rep_commission_service"),
	}
}

// -----------------------------------------------------------------------------
// Commission Plan management
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) CreateCommissionPlan(ctx context.Context, req *CreateCommissionPlanRequest) (*models.CommissionPlan, error) {
	if err := s.validateCreatePlan(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	plan := &models.CommissionPlan{
		PlanID:        uuid.New(),
		CompanyID:     req.CompanyID,
		Code:          req.Code,
		Name:          req.Name,
		Description:   req.Description,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		IsActive:      req.IsActive,
		CreatedBy:     req.CreatedBy,
		UpdatedBy:     req.CreatedBy,
	}
	if err := s.planRepo.Create(ctx, tx, plan); err != nil {
		return nil, fmt.Errorf("create plan: %w", err)
	}

	for _, r := range req.Rules {
		rule := &models.CommissionRule{
			RuleID:       uuid.New(),
			CompanyID:    req.CompanyID,
			PlanID:       plan.PlanID,
			RuleType:     r.RuleType,
			AppliesTo:    r.AppliesTo,
			ProductID:    r.ProductID,
			TierMin:      r.TierMin,
			TierMax:      r.TierMax,
			Rate:         r.Rate,
			IsPercentage: r.IsPercentage,
			Priority:     r.Priority,
			CreatedBy:    req.CreatedBy,
		}
		if err := s.ruleRepo.Create(ctx, tx, rule); err != nil {
			return nil, fmt.Errorf("create rule: %w", err)
		}
	}

	if err := s.emitCommissionEvent(ctx, tx, plan, "commission_plan.created"); err != nil {
		s.logger.Warn("failed to emit commission plan created event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_commission_plan", "commission_plan",
			&plan.PlanID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"code": plan.Code, "name": plan.Name,
			})
	}
	return plan, nil
}

func (s *salesRepCommissionService) UpdateCommissionPlan(ctx context.Context, companyID, planID uuid.UUID, req *UpdateCommissionPlanRequest) (*models.CommissionPlan, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	plan, err := s.planRepo.GetByIDForUpdate(ctx, tx, companyID, planID)
	if err != nil {
		return nil, err
	}
	if plan.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	if req.Name != nil {
		plan.Name = *req.Name
	}
	if req.Description != nil {
		plan.Description = req.Description
	}
	if req.EffectiveFrom != nil {
		plan.EffectiveFrom = *req.EffectiveFrom
	}
	if req.EffectiveTo != nil {
		plan.EffectiveTo = req.EffectiveTo
	}
	if req.IsActive != nil {
		plan.IsActive = *req.IsActive
	}
	plan.UpdatedBy = req.UpdatedBy

	if err := s.planRepo.Update(ctx, tx, plan); err != nil {
		return nil, fmt.Errorf("update plan: %w", err)
	}

	_ = s.emitCommissionEvent(ctx, tx, plan, "commission_plan.updated")

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_commission_plan", "commission_plan",
			&planID, "user", req.UpdatedBy, nil, nil, nil)
	}
	return plan, nil
}

func (s *salesRepCommissionService) DeleteCommissionPlan(ctx context.Context, companyID, planID uuid.UUID, deletedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	plan, err := s.planRepo.GetByID(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if plan.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}
	if err := s.planRepo.Delete(ctx, tx, companyID, planID); err != nil {
		return err
	}
	if err := s.ruleRepo.DeleteByPlan(ctx, tx, companyID, planID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_commission_plan", "commission_plan",
			&planID, "user", &deletedBy, nil, nil, nil)
	}
	return nil
}

func (s *salesRepCommissionService) GetCommissionPlanByID(ctx context.Context, companyID, planID uuid.UUID) (*models.CommissionPlan, error) {
	return s.planRepo.GetByID(ctx, nil, companyID, planID)
}

func (s *salesRepCommissionService) GetCommissionPlanByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.CommissionPlan, error) {
	return s.planRepo.GetByCode(ctx, nil, companyID, code)
}

func (s *salesRepCommissionService) ListCommissionPlans(ctx context.Context, filter CommissionPlanListFilter, p Pagination, srt Sort) ([]*models.CommissionPlan, int64, error) {
	repoFilter := repository.CommissionPlanFilter{
		CompanyID: filter.CompanyID,
		IsActive:  filter.IsActive,
		Code:      filter.Code,
		Name:      filter.Name,
		Effective: filter.Effective,
	}
	return s.planRepo.List(ctx, nil, repoFilter, repository.Pagination{Limit: p.Limit, Offset: p.Offset}, repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *salesRepCommissionService) GetActiveCommissionPlans(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*models.CommissionPlan, error) {
	return s.planRepo.GetActivePlans(ctx, nil, companyID, at)
}

// -----------------------------------------------------------------------------
// Commission Rule management
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) CreateCommissionRule(ctx context.Context, req *CreateCommissionRuleRequest) (*models.CommissionRule, error) {
	if err := s.validateCreateRule(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	plan, err := s.planRepo.GetByID(ctx, tx, req.CompanyID, req.PlanID)
	if err != nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}
	if plan.CompanyID != req.CompanyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	rule := &models.CommissionRule{
		RuleID:       uuid.New(),
		CompanyID:    req.CompanyID,
		PlanID:       req.PlanID,
		RuleType:     req.RuleType,
		AppliesTo:    req.AppliesTo,
		ProductID:    req.ProductID,
		TierMin:      req.TierMin,
		TierMax:      req.TierMax,
		Rate:         req.Rate,
		IsPercentage: req.IsPercentage,
		Priority:     req.Priority,
		CreatedBy:    req.CreatedBy,
		UpdatedBy:    req.CreatedBy,
	}
	if err := s.ruleRepo.Create(ctx, tx, rule); err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return rule, nil
}

func (s *salesRepCommissionService) UpdateCommissionRule(ctx context.Context, companyID, ruleID uuid.UUID, req *UpdateCommissionRuleRequest) (*models.CommissionRule, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	rule, err := s.ruleRepo.GetByIDForUpdate(ctx, tx, companyID, ruleID)
	if err != nil {
		return nil, err
	}
	if rule.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}
	if req.RuleType != nil {
		rule.RuleType = *req.RuleType
	}
	if req.AppliesTo != nil {
		rule.AppliesTo = *req.AppliesTo
	}
	if req.ProductID != nil {
		rule.ProductID = req.ProductID
	}
	if req.TierMin != nil {
		rule.TierMin = req.TierMin
	}
	if req.TierMax != nil {
		rule.TierMax = req.TierMax
	}
	if req.Rate != nil {
		rule.Rate = *req.Rate
	}
	if req.IsPercentage != nil {
		rule.IsPercentage = *req.IsPercentage
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	rule.UpdatedBy = req.UpdatedBy

	if err := s.ruleRepo.Update(ctx, tx, rule); err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return rule, nil
}

func (s *salesRepCommissionService) DeleteCommissionRule(ctx context.Context, companyID, ruleID uuid.UUID, deletedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.ruleRepo.Delete(ctx, tx, companyID, ruleID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *salesRepCommissionService) GetCommissionRuleByID(ctx context.Context, companyID, ruleID uuid.UUID) (*models.CommissionRule, error) {
	return s.ruleRepo.GetByID(ctx, nil, companyID, ruleID)
}

func (s *salesRepCommissionService) GetCommissionRules(ctx context.Context, companyID, planID uuid.UUID) ([]*models.CommissionRule, error) {
	return s.ruleRepo.GetByPlan(ctx, nil, companyID, planID)
}

func (s *salesRepCommissionService) ValidateCommissionRule(ctx context.Context, rule *models.CommissionRule) error {
	if rule.Rate.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: rate must be >= 0", salesErrors.ErrInvalidInput)
	}
	if rule.IsPercentage && rule.Rate.GreaterThan(decimal.NewFromInt(100)) {
		return fmt.Errorf("%w: percentage rate cannot exceed 100", salesErrors.ErrInvalidInput)
	}
	if rule.TierMin != nil && rule.TierMax != nil && rule.TierMin.GreaterThan(*rule.TierMax) {
		return fmt.Errorf("%w: tier_min > tier_max", salesErrors.ErrInvalidInput)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Assignment of plans to sales reps
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) AssignCommissionPlan(ctx context.Context, companyID, salesRepID, planID uuid.UUID, effectiveFrom time.Time, assignedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	plan, err := s.planRepo.GetByID(ctx, tx, companyID, planID)
	if err != nil {
		return err
	}
	if !plan.IsActive || (plan.EffectiveTo != nil && plan.EffectiveTo.Before(effectiveFrom)) {
		return fmt.Errorf("%w: plan not active at effective date", salesErrors.ErrInvalidInput)
	}

	if err := s.commissionRepo.DeactivateCurrentAssignment(ctx, tx, companyID, salesRepID, effectiveFrom); err != nil {
		return err
	}

	assignment := &models.SalesRepCommissionAssignment{
		AssignmentID:  uuid.New(),
		CompanyID:     companyID,
		SalesRepID:    salesRepID,
		PlanID:        planID,
		EffectiveFrom: effectiveFrom,
		EffectiveTo:   nil,
		AssignedBy:    &assignedBy,
	}
	if err := s.commissionRepo.CreateAssignment(ctx, tx, assignment); err != nil {
		return fmt.Errorf("create assignment: %w", err)
	}

	// Emit assignment event for analytics
	if err := s.emitCommissionAssignmentEvent(ctx, tx, companyID, salesRepID, planID, effectiveFrom, assignedBy, "assign"); err != nil {
		s.logger.Warn("failed to emit commission assignment event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *salesRepCommissionService) RemoveCommissionPlan(ctx context.Context, companyID, salesRepID uuid.UUID, removedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.commissionRepo.DeactivateCurrentAssignment(ctx, tx, companyID, salesRepID, time.Now()); err != nil {
		return err
	}

	// Emit removal event (we need the plan ID; we can fetch it from the active assignment before deactivation)
	assignment, err := s.commissionRepo.GetAssignmentAt(ctx, tx, companyID, salesRepID, time.Now())
	if err == nil && assignment != nil {
		_ = s.emitCommissionAssignmentEvent(ctx, tx, companyID, salesRepID, assignment.PlanID, time.Now(), removedBy, "remove")
	}

	return tx.Commit()
}

func (s *salesRepCommissionService) GetSalesRepCommissionPlan(ctx context.Context, companyID, salesRepID uuid.UUID, at time.Time) (*models.CommissionPlan, error) {
	assignment, err := s.commissionRepo.GetAssignmentAt(ctx, nil, companyID, salesRepID, at)
	if err != nil {
		return nil, err
	}
	if assignment == nil {
		return nil, nil
	}
	return s.planRepo.GetByID(ctx, nil, companyID, assignment.PlanID)
}

// -----------------------------------------------------------------------------
// Commission calculation
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) CalculateOrderCommission(ctx context.Context, companyID, orderID uuid.UUID) (*models.SalesCommission, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByID(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	if order.SalesRepID == nil {
		return nil, fmt.Errorf("%w: order has no assigned sales rep", salesErrors.ErrInvalidInput)
	}
	salesRepID := *order.SalesRepID

	plan, err := s.GetSalesRepCommissionPlan(ctx, companyID, salesRepID, order.OrderDate)
	if err != nil || plan == nil {
		return nil, fmt.Errorf("no active commission plan for sales rep: %w", err)
	}

	baseAmount := s.getBaseAmountForOrder(order)
	rate, ruleID, err := s.getApplicableRate(ctx, tx, companyID, plan.PlanID, salesRepID, enums.CommissionReferenceTypeOrder, orderID, baseAmount)
	if err != nil {
		return nil, err
	}
	commissionAmount := s.calculateCommissionAmount(baseAmount, rate)

	comm := &models.SalesCommission{
		CommissionID:     uuid.New(),
		CompanyID:        companyID,
		SalesRepID:       salesRepID,
		ReferenceType:    enums.CommissionReferenceTypeOrder,
		ReferenceID:      orderID,
		CommissionBase:   baseAmount,
		CommissionRate:   rate,
		CommissionAmount: commissionAmount,
		Status:           enums.CommissionStatusPending,
		EarnedAt:         order.OrderDate,
		RuleID:           ruleID,
	}
	if err := s.commissionRepo.Create(ctx, tx, comm); err != nil {
		return nil, err
	}

	// Emit commission created event for analytics
	if err := s.emitCommissionCreatedEvent(ctx, tx, comm, plan.PlanID, ruleID); err != nil {
		s.logger.Warn("failed to emit commission created event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return comm, nil
}

func (s *salesRepCommissionService) CalculateInvoiceCommission(ctx context.Context, companyID, invoiceID uuid.UUID) (*models.SalesCommission, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	if invoice.SalesRepID == nil {
		return nil, fmt.Errorf("%w: invoice has no assigned sales rep", salesErrors.ErrInvalidInput)
	}
	salesRepID := *invoice.SalesRepID

	plan, err := s.GetSalesRepCommissionPlan(ctx, companyID, salesRepID, invoice.InvoiceDate)
	if err != nil || plan == nil {
		return nil, fmt.Errorf("no active commission plan for sales rep: %w", err)
	}

	baseAmount := s.getBaseAmountForInvoice(invoice)
	rate, ruleID, err := s.getApplicableRate(ctx, tx, companyID, plan.PlanID, salesRepID, enums.CommissionReferenceTypeInvoice, invoiceID, baseAmount)
	if err != nil {
		return nil, err
	}
	commissionAmount := s.calculateCommissionAmount(baseAmount, rate)

	comm := &models.SalesCommission{
		CommissionID:     uuid.New(),
		CompanyID:        companyID,
		SalesRepID:       salesRepID,
		ReferenceType:    enums.CommissionReferenceTypeInvoice,
		ReferenceID:      invoiceID,
		CommissionBase:   baseAmount,
		CommissionRate:   rate,
		CommissionAmount: commissionAmount,
		Status:           enums.CommissionStatusPending,
		EarnedAt:         invoice.InvoiceDate,
		RuleID:           ruleID,
	}
	if err := s.commissionRepo.Create(ctx, tx, comm); err != nil {
		return nil, err
	}

	if err := s.emitCommissionCreatedEvent(ctx, tx, comm, plan.PlanID, ruleID); err != nil {
		s.logger.Warn("failed to emit commission created event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return comm, nil
}

func (s *salesRepCommissionService) CalculatePaymentCommission(ctx context.Context, companyID, paymentID uuid.UUID) (*models.SalesCommission, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	payment, err := s.paymentRepo.GetByID(ctx, tx, companyID, paymentID)
	if err != nil {
		return nil, err
	}
	salesRepID, err := s.getSalesRepForPayment(ctx, tx, companyID, paymentID)
	if err != nil {
		return nil, err
	}
	if salesRepID == nil {
		return nil, fmt.Errorf("%w: no sales rep associated with payment", salesErrors.ErrInvalidInput)
	}

	plan, err := s.GetSalesRepCommissionPlan(ctx, companyID, *salesRepID, payment.PaymentDate)
	if err != nil || plan == nil {
		return nil, fmt.Errorf("no active commission plan for sales rep: %w", err)
	}

	baseAmount := payment.Amount
	rate, ruleID, err := s.getApplicableRate(ctx, tx, companyID, plan.PlanID, *salesRepID, enums.CommissionReferenceTypePayment, paymentID, baseAmount)
	if err != nil {
		return nil, err
	}
	commissionAmount := s.calculateCommissionAmount(baseAmount, rate)

	comm := &models.SalesCommission{
		CommissionID:     uuid.New(),
		CompanyID:        companyID,
		SalesRepID:       *salesRepID,
		ReferenceType:    enums.CommissionReferenceTypePayment,
		ReferenceID:      paymentID,
		CommissionBase:   baseAmount,
		CommissionRate:   rate,
		CommissionAmount: commissionAmount,
		Status:           enums.CommissionStatusPending,
		EarnedAt:         payment.PaymentDate,
		RuleID:           ruleID,
	}
	if err := s.commissionRepo.Create(ctx, tx, comm); err != nil {
		return nil, err
	}

	if err := s.emitCommissionCreatedEvent(ctx, tx, comm, plan.PlanID, ruleID); err != nil {
		s.logger.Warn("failed to emit commission created event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return comm, nil
}

func (s *salesRepCommissionService) CalculateCommissionForPeriod(ctx context.Context, companyID, salesRepID uuid.UUID, from, to time.Time) ([]*models.SalesCommission, decimal.Decimal, error) {
	commissions, err := s.commissionRepo.GetBySalesRepAndPeriod(ctx, nil, companyID, salesRepID, from, to)
	if err != nil {
		return nil, decimal.Zero, err
	}
	total := decimal.Zero
	for _, c := range commissions {
		total = total.Add(c.CommissionAmount)
	}
	return commissions, total, nil
}

func (s *salesRepCommissionService) PreviewCommission(ctx context.Context, req *CommissionPreviewRequest) (*CommissionPreviewResult, error) {
	plan, err := s.GetSalesRepCommissionPlan(ctx, req.CompanyID, req.SalesRepID, req.CalculationAt)
	if err != nil || plan == nil {
		return nil, fmt.Errorf("no active commission plan")
	}
	var baseAmount decimal.Decimal
	switch req.ReferenceType {
	case enums.CommissionReferenceTypeOrder:
		order, err := s.orderRepo.GetByID(ctx, nil, req.CompanyID, req.ReferenceID)
		if err != nil {
			return nil, err
		}
		baseAmount = s.getBaseAmountForOrder(order)
	case enums.CommissionReferenceTypeInvoice:
		inv, err := s.invoiceRepo.GetByID(ctx, nil, req.CompanyID, req.ReferenceID)
		if err != nil {
			return nil, err
		}
		baseAmount = s.getBaseAmountForInvoice(inv)
	case enums.CommissionReferenceTypePayment:
		pay, err := s.paymentRepo.GetByID(ctx, nil, req.CompanyID, req.ReferenceID)
		if err != nil {
			return nil, err
		}
		baseAmount = pay.Amount
	default:
		return nil, fmt.Errorf("%w: unknown reference type", salesErrors.ErrInvalidInput)
	}
	rate, ruleID, err := s.getApplicableRate(ctx, nil, req.CompanyID, plan.PlanID, req.SalesRepID, req.ReferenceType, req.ReferenceID, baseAmount)
	if err != nil {
		return nil, err
	}
	return &CommissionPreviewResult{
		BaseAmount:       baseAmount,
		ApplicableRate:   rate,
		CommissionAmount: s.calculateCommissionAmount(baseAmount, rate),
		RuleID:           ruleID,
	}, nil
}

// -----------------------------------------------------------------------------
// Automated commission processing
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) ProcessOrderCompletedCommission(ctx context.Context, companyID, orderID uuid.UUID, triggeredBy uuid.UUID) (*models.SalesCommission, error) {
	return s.CalculateOrderCommission(ctx, companyID, orderID)
}

func (s *salesRepCommissionService) ProcessInvoicePaidCommission(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) (*models.SalesCommission, error) {
	return s.CalculateInvoiceCommission(ctx, companyID, invoiceID)
}

func (s *salesRepCommissionService) ProcessPaymentReceivedCommission(ctx context.Context, companyID, paymentID uuid.UUID, triggeredBy uuid.UUID) (*models.SalesCommission, error) {
	return s.CalculatePaymentCommission(ctx, companyID, paymentID)
}

func (s *salesRepCommissionService) RecalculateCommission(ctx context.Context, companyID, commissionID uuid.UUID, recalculatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	comm, err := s.commissionRepo.GetByIDForUpdate(ctx, tx, companyID, commissionID)
	if err != nil {
		return err
	}
	if comm.Status != enums.CommissionStatusPending && comm.Status != enums.CommissionStatusRejected {
		return fmt.Errorf("%w: can only recalc pending or rejected commissions", salesErrors.ErrInvalidState)
	}
	var newBase decimal.Decimal
	var rate decimal.Decimal
	var ruleID *uuid.UUID
	switch comm.ReferenceType {
	case enums.CommissionReferenceTypeOrder:
		order, err := s.orderRepo.GetByID(ctx, tx, companyID, comm.ReferenceID)
		if err != nil {
			return err
		}
		newBase = s.getBaseAmountForOrder(order)
	case enums.CommissionReferenceTypeInvoice:
		inv, err := s.invoiceRepo.GetByID(ctx, tx, companyID, comm.ReferenceID)
		if err != nil {
			return err
		}
		newBase = s.getBaseAmountForInvoice(inv)
	case enums.CommissionReferenceTypePayment:
		pay, err := s.paymentRepo.GetByID(ctx, tx, companyID, comm.ReferenceID)
		if err != nil {
			return err
		}
		newBase = pay.Amount
	default:
		return fmt.Errorf("%w: unknown reference type", salesErrors.ErrInvalidInput)
	}
	plan, err := s.GetSalesRepCommissionPlan(ctx, companyID, comm.SalesRepID, comm.EarnedAt)
	if err != nil || plan == nil {
		return fmt.Errorf("no active commission plan for sales rep")
	}
	rate, ruleID, err = s.getApplicableRate(ctx, tx, companyID, plan.PlanID, comm.SalesRepID, comm.ReferenceType, comm.ReferenceID, newBase)
	if err != nil {
		return err
	}
	newAmount := s.calculateCommissionAmount(newBase, rate)
	comm.CommissionBase = newBase
	comm.CommissionRate = rate
	comm.CommissionAmount = newAmount
	comm.RuleID = ruleID
	comm.UpdatedBy = &recalculatedBy

	if err := s.commissionRepo.Update(ctx, tx, comm); err != nil {
		return fmt.Errorf("update commission: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *salesRepCommissionService) ReverseCommission(ctx context.Context, companyID, commissionID uuid.UUID, reason string, reversedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	comm, err := s.commissionRepo.GetByIDForUpdate(ctx, tx, companyID, commissionID)
	if err != nil {
		return err
	}
	if comm.Status == enums.CommissionStatusPaid || comm.Status == enums.CommissionStatusReversed {
		return fmt.Errorf("%w: cannot reverse paid or already reversed commission", salesErrors.ErrInvalidState)
	}
	comm.Status = enums.CommissionStatusReversed
	comm.Notes = &reason
	comm.UpdatedBy = &reversedBy
	if err := s.commissionRepo.Update(ctx, tx, comm); err != nil {
		return err
	}
	return tx.Commit()
}

// -----------------------------------------------------------------------------
// CRUD for SalesCommission records
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) CreateCommissionRecord(ctx context.Context, req *CreateSalesCommissionRequest) (*models.SalesCommission, error) {
	comm := &models.SalesCommission{
		CommissionID:     uuid.New(),
		CompanyID:        req.CompanyID,
		SalesRepID:       req.SalesRepID,
		ReferenceType:    req.ReferenceType,
		ReferenceID:      req.ReferenceID,
		CommissionBase:   req.CommissionBase,
		CommissionRate:   req.CommissionRate,
		CommissionAmount: req.CommissionAmount,
		EarnedAt:         req.EarnedAt,
		Status:           req.Status,
		CreatedBy:        req.CreatedBy,
		UpdatedBy:        req.CreatedBy,
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.commissionRepo.Create(ctx, tx, comm); err != nil {
		return nil, err
	}
	// Emit event (plan ID and rule ID unknown here, but analytics will work with what's available)
	if err := s.emitCommissionCreatedEvent(ctx, tx, comm, uuid.Nil, nil); err != nil {
		s.logger.Warn("failed to emit commission created event", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return comm, nil
}

func (s *salesRepCommissionService) UpdateCommissionRecord(ctx context.Context, companyID, commissionID uuid.UUID, req *UpdateSalesCommissionRequest) (*models.SalesCommission, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	comm, err := s.commissionRepo.GetByIDForUpdate(ctx, tx, companyID, commissionID)
	if err != nil {
		return nil, err
	}
	if comm.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}
	if req.Status != nil {
		if err := s.ValidateCommissionStatusTransition(ctx, comm.Status, *req.Status); err != nil {
			return nil, err
		}
		comm.Status = *req.Status
	}
	if req.PaidAt != nil {
		comm.PaidAt = req.PaidAt
	}
	if req.ApprovedAt != nil {
		comm.ApprovedAt = req.ApprovedAt
	}
	if req.RejectedAt != nil {
		comm.RejectedAt = req.RejectedAt
	}
	if req.RejectReason != nil {
		comm.RejectReason = req.RejectReason
	}
	comm.UpdatedBy = req.UpdatedBy

	if err := s.commissionRepo.Update(ctx, tx, comm); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return comm, nil
}

func (s *salesRepCommissionService) GetCommissionByID(ctx context.Context, companyID, commissionID uuid.UUID) (*models.SalesCommission, error) {
	return s.commissionRepo.GetByID(ctx, nil, companyID, commissionID)
}

func (s *salesRepCommissionService) GetCommissionByReference(ctx context.Context, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) ([]*models.SalesCommission, error) {
	return s.commissionRepo.GetByReference(ctx, nil, companyID, referenceType, referenceID)
}

func (s *salesRepCommissionService) ListCommissions(ctx context.Context, filter SalesCommissionListFilter, p Pagination, srt Sort) ([]*models.SalesCommission, int64, error) {
	repoFilter := repository.SalesCommissionFilter{
		CompanyID:     filter.CompanyID,
		SalesRepID:    filter.SalesRepID,
		ReferenceType: filter.ReferenceType,
		ReferenceID:   filter.ReferenceID,
		Status:        filter.Status,
		EarnedFrom:    filter.EarnedFrom,
		EarnedTo:      filter.EarnedTo,
	}
	return s.commissionRepo.List(ctx, nil, repoFilter, repository.Pagination{Limit: p.Limit, Offset: p.Offset}, repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *salesRepCommissionService) GetSalesRepCommissions(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time, p Pagination, srt Sort) ([]*models.SalesCommission, int64, error) {
	filter := SalesCommissionListFilter{
		CompanyID:  companyID,
		SalesRepID: &salesRepID,
		EarnedFrom: from,
		EarnedTo:   to,
	}
	return s.ListCommissions(ctx, filter, p, srt)
}

// -----------------------------------------------------------------------------
// Commission lifecycle actions
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) MarkCommissionPending(ctx context.Context, companyID, commissionID uuid.UUID, updatedBy uuid.UUID) error {
	return s.updateCommissionStatus(ctx, companyID, commissionID, enums.CommissionStatusPending, updatedBy)
}

func (s *salesRepCommissionService) ApproveCommission(ctx context.Context, companyID, commissionID uuid.UUID, approvedBy uuid.UUID) error {
	err := s.updateCommissionStatus(ctx, companyID, commissionID, enums.CommissionStatusApproved, approvedBy)
	if err != nil {
		return err
	}
	// Emit approved event
	return s.emitCommissionStatusEvent(ctx, companyID, commissionID, enums.CommissionStatusApproved, "", approvedBy)
}

func (s *salesRepCommissionService) RejectCommission(ctx context.Context, companyID, commissionID uuid.UUID, reason string, rejectedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	comm, err := s.commissionRepo.GetByIDForUpdate(ctx, tx, companyID, commissionID)
	if err != nil {
		return err
	}
	if comm.Status != enums.CommissionStatusPending && comm.Status != enums.CommissionStatusApproved {
		return fmt.Errorf("%w: can only reject pending or approved commissions", salesErrors.ErrInvalidState)
	}
	comm.Status = enums.CommissionStatusRejected
	comm.RejectReason = &reason
	now := time.Now()
	comm.RejectedAt = &now
	comm.UpdatedBy = &rejectedBy
	if err := s.commissionRepo.Update(ctx, tx, comm); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	// Emit rejected event
	return s.emitCommissionStatusEvent(ctx, companyID, commissionID, enums.CommissionStatusRejected, reason, rejectedBy)
}

func (s *salesRepCommissionService) MarkCommissionPaid(ctx context.Context, companyID, commissionID uuid.UUID, paidAt time.Time, paidBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	comm, err := s.commissionRepo.GetByIDForUpdate(ctx, tx, companyID, commissionID)
	if err != nil {
		return err
	}
	if comm.Status != enums.CommissionStatusApproved {
		return fmt.Errorf("%w: only approved commissions can be marked paid", salesErrors.ErrInvalidState)
	}
	comm.Status = enums.CommissionStatusPaid
	comm.PaidAt = &paidAt
	comm.UpdatedBy = &paidBy
	if err := s.commissionRepo.Update(ctx, tx, comm); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	// Emit paid event
	return s.emitCommissionStatusEvent(ctx, companyID, commissionID, enums.CommissionStatusPaid, "", paidBy)
}

func (s *salesRepCommissionService) GetPendingCommissions(ctx context.Context, companyID uuid.UUID) ([]*models.SalesCommission, error) {
	return s.commissionRepo.GetByStatus(ctx, nil, companyID, enums.CommissionStatusPending)
}

func (s *salesRepCommissionService) GetApprovedCommissions(ctx context.Context, companyID uuid.UUID) ([]*models.SalesCommission, error) {
	return s.commissionRepo.GetByStatus(ctx, nil, companyID, enums.CommissionStatusApproved)
}

func (s *salesRepCommissionService) GetUnpaidCommissions(ctx context.Context, companyID uuid.UUID) ([]*models.SalesCommission, error) {
	return s.commissionRepo.GetUnpaid(ctx, nil, companyID)
}

// -----------------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) ValidateCommissionPlan(ctx context.Context, plan *models.CommissionPlan) error {
	if plan.Code == "" || plan.Name == "" {
		return fmt.Errorf("%w: code and name required", salesErrors.ErrInvalidInput)
	}
	if plan.EffectiveFrom.IsZero() {
		return fmt.Errorf("%w: effective_from required", salesErrors.ErrInvalidInput)
	}
	if plan.EffectiveTo != nil && plan.EffectiveTo.Before(plan.EffectiveFrom) {
		return fmt.Errorf("%w: effective_to before effective_from", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *salesRepCommissionService) ValidateCommissionCalculation(ctx context.Context, req *CommissionCalculationValidationRequest) error {
	comm, err := s.GetCommissionByReference(ctx, req.CompanyID, req.ReferenceType, req.ReferenceID)
	if err != nil {
		return err
	}
	if len(comm) == 0 {
		return fmt.Errorf("no commission record found")
	}
	for _, c := range comm {
		if c.CommissionAmount.Equal(req.CalculatedAmount) {
			return nil
		}
	}
	return fmt.Errorf("calculated amount does not match any existing commission")
}

func (s *salesRepCommissionService) ValidateCommissionStatusTransition(ctx context.Context, current, next enums.CommissionStatus) error {
	validTransitions := map[enums.CommissionStatus][]enums.CommissionStatus{
		enums.CommissionStatusPending:  {enums.CommissionStatusApproved, enums.CommissionStatusRejected},
		enums.CommissionStatusApproved: {enums.CommissionStatusPaid, enums.CommissionStatusRejected},
		enums.CommissionStatusPaid:     {},
		enums.CommissionStatusRejected: {enums.CommissionStatusPending},
		enums.CommissionStatusReversed: {},
	}
	allowed, ok := validTransitions[current]
	if !ok {
		return fmt.Errorf("%w: unknown status %s", salesErrors.ErrInvalidState, current)
	}
	for _, a := range allowed {
		if a == next {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %s to %s", salesErrors.ErrInvalidState, current, next)
}

func (s *salesRepCommissionService) CanGenerateCommission(ctx context.Context, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) (bool, error) {
	existing, err := s.commissionRepo.GetByReference(ctx, nil, companyID, referenceType, referenceID)
	if err != nil {
		return false, err
	}
	for _, e := range existing {
		if e.Status != enums.CommissionStatusRejected && e.Status != enums.CommissionStatusReversed {
			return false, nil
		}
	}
	return true, nil
}

// -----------------------------------------------------------------------------
// Reporting and analytics
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) GetTotalCommissionAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.commissionRepo.GetTotalCommission(ctx, nil, companyID, from, to, nil, nil)
}

func (s *salesRepCommissionService) GetTotalPaidCommission(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	status := enums.CommissionStatusPaid
	return s.commissionRepo.GetTotalCommission(ctx, nil, companyID, from, to, &status, nil)
}

func (s *salesRepCommissionService) GetOutstandingCommissionLiability(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	approved, err := s.commissionRepo.GetTotalCommission(ctx, nil, companyID, nil, nil, &[]enums.CommissionStatus{enums.CommissionStatusApproved}[0], nil)
	if err != nil {
		return decimal.Zero, err
	}
	paid, err := s.commissionRepo.GetTotalCommission(ctx, nil, companyID, nil, nil, &[]enums.CommissionStatus{enums.CommissionStatusPaid}[0], nil)
	if err != nil {
		return decimal.Zero, err
	}
	return approved.Sub(paid), nil
}

func (s *salesRepCommissionService) GetTopSalesRepCommissions(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesCommission, error) {
	return s.commissionRepo.GetTopByAmount(ctx, nil, companyID, limit, from, to)
}

func (s *salesRepCommissionService) GetCommissionSummaryBySalesRep(ctx context.Context, companyID, salesRepID uuid.UUID, from, to *time.Time) (*SalesRepCommissionSummary, error) {
	totalEarned, _ := s.commissionRepo.GetTotalCommission(ctx, nil, companyID, from, to, nil, &salesRepID)
	totalApproved, _ := s.commissionRepo.GetTotalCommission(ctx, nil, companyID, from, to, &[]enums.CommissionStatus{enums.CommissionStatusApproved}[0], &salesRepID)
	totalPaid, _ := s.commissionRepo.GetTotalCommission(ctx, nil, companyID, from, to, &[]enums.CommissionStatus{enums.CommissionStatusPaid}[0], &salesRepID)
	pendingCount, _ := s.commissionRepo.CountByStatus(ctx, nil, companyID, enums.CommissionStatusPending, &salesRepID)
	approvedCount, _ := s.commissionRepo.CountByStatus(ctx, nil, companyID, enums.CommissionStatusApproved, &salesRepID)
	paidCount, _ := s.commissionRepo.CountByStatus(ctx, nil, companyID, enums.CommissionStatusPaid, &salesRepID)
	rejectedCount, _ := s.commissionRepo.CountByStatus(ctx, nil, companyID, enums.CommissionStatusRejected, &salesRepID)

	return &SalesRepCommissionSummary{
		SalesRepID:    salesRepID,
		TotalEarned:   totalEarned,
		TotalApproved: totalApproved,
		TotalPaid:     totalPaid,
		PendingCount:  int(pendingCount),
		ApprovedCount: int(approvedCount),
		PaidCount:     int(paidCount),
		RejectedCount: int(rejectedCount),
	}, nil
}

func (s *salesRepCommissionService) GetCommissionTrend(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*CommissionTrendPoint, error) {
	return s.commissionRepo.GetTrend(ctx, nil, companyID, from, to)
}

// -----------------------------------------------------------------------------
// Existence checks
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) CommissionPlanExists(ctx context.Context, companyID, planID uuid.UUID) (bool, error) {
	return s.planRepo.Exists(ctx, nil, companyID, planID)
}
func (s *salesRepCommissionService) CommissionRuleExists(ctx context.Context, companyID, ruleID uuid.UUID) (bool, error) {
	return s.ruleRepo.Exists(ctx, nil, companyID, ruleID)
}
func (s *salesRepCommissionService) CommissionRecordExists(ctx context.Context, companyID, commissionID uuid.UUID) (bool, error) {
	return s.commissionRepo.Exists(ctx, nil, companyID, commissionID)
}
func (s *salesRepCommissionService) CommissionAlreadyGenerated(ctx context.Context, companyID uuid.UUID, referenceType enums.CommissionReferenceType, referenceID uuid.UUID) (bool, error) {
	existing, err := s.commissionRepo.GetByReference(ctx, nil, companyID, referenceType, referenceID)
	if err != nil {
		return false, err
	}
	for _, e := range existing {
		if e.Status != enums.CommissionStatusRejected && e.Status != enums.CommissionStatusReversed {
			return true, nil
		}
	}
	return false, nil
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) validateCreatePlan(req *CreateCommissionPlanRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", salesErrors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	if req.EffectiveFrom.IsZero() {
		return fmt.Errorf("%w: effective_from required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *salesRepCommissionService) validateCreateRule(req *CreateCommissionRuleRequest) error {
	if req.CompanyID == uuid.Nil || req.PlanID == uuid.Nil {
		return fmt.Errorf("%w: company_id and plan_id required", salesErrors.ErrInvalidInput)
	}
	if req.Rate.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: rate must be >= 0", salesErrors.ErrInvalidInput)
	}
	if req.IsPercentage && req.Rate.GreaterThan(decimal.NewFromInt(100)) {
		return fmt.Errorf("%w: percentage rate cannot exceed 100", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *salesRepCommissionService) getBaseAmountForOrder(order *models.Order) decimal.Decimal {
	return order.GrandTotal
}

func (s *salesRepCommissionService) getBaseAmountForInvoice(invoice *models.Invoice) decimal.Decimal {
	return invoice.GrandTotal
}

func (s *salesRepCommissionService) getSalesRepForPayment(ctx context.Context, tx repository.DBTX, companyID, paymentID uuid.UUID) (*uuid.UUID, error) {
	allocations, err := s.paymentRepo.GetAllocations(ctx, tx, companyID, paymentID)
	if err != nil || len(allocations) == 0 {
		return nil, err
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, allocations[0].InvoiceID)
	if err != nil {
		return nil, err
	}
	return invoice.SalesRepID, nil
}

func (s *salesRepCommissionService) getApplicableRate(ctx context.Context, tx repository.DBTX, companyID, planID, salesRepID uuid.UUID, refType enums.CommissionReferenceType, refID uuid.UUID, baseAmount decimal.Decimal) (decimal.Decimal, *uuid.UUID, error) {
	rules, err := s.ruleRepo.GetByPlan(ctx, tx, companyID, planID)
	if err != nil {
		return decimal.Zero, nil, err
	}
	for _, rule := range rules {
		// Check applicability – this is a simplified example.
		if rule.AppliesTo == enums.CommissionBaseRevenue && refType == enums.CommissionReferenceTypeOrder {
			if rule.TierMin != nil && baseAmount.LessThan(*rule.TierMin) {
				continue
			}
			if rule.TierMax != nil && baseAmount.GreaterThan(*rule.TierMax) {
				continue
			}
			return rule.Rate, &rule.RuleID, nil
		}
		// Add other conditions for invoice/payment and product rules.
	}
	return decimal.Zero, nil, fmt.Errorf("no applicable commission rule found")
}

func (s *salesRepCommissionService) calculateCommissionAmount(base, rate decimal.Decimal) decimal.Decimal {
	// Assume rate is a percentage (e.g., 10.5 means 10.5%)
	return base.Mul(rate.Div(decimal.NewFromInt(100))).Round(2)
}

func (s *salesRepCommissionService) updateCommissionStatus(ctx context.Context, companyID, commissionID uuid.UUID, newStatus enums.CommissionStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	comm, err := s.commissionRepo.GetByIDForUpdate(ctx, tx, companyID, commissionID)
	if err != nil {
		return err
	}
	if err := s.ValidateCommissionStatusTransition(ctx, comm.Status, newStatus); err != nil {
		return err
	}
	comm.Status = newStatus
	if newStatus == enums.CommissionStatusApproved {
		now := time.Now()
		comm.ApprovedAt = &now
	}
	if newStatus == enums.CommissionStatusPaid {
		now := time.Now()
		comm.PaidAt = &now
	}
	comm.UpdatedBy = &updatedBy
	if err := s.commissionRepo.Update(ctx, tx, comm); err != nil {
		return err
	}
	return tx.Commit()
}

// -----------------------------------------------------------------------------
// Event emission helpers
// -----------------------------------------------------------------------------

func (s *salesRepCommissionService) emitCommissionEvent(ctx context.Context, tx repository.DBTX, plan *models.CommissionPlan, eventType string) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not *sql.Tx")
	}
	payload := map[string]interface{}{
		"plan_id":    plan.PlanID.String(),
		"company_id": plan.CompanyID.String(),
		"code":       plan.Code,
		"name":       plan.Name,
		"is_active":  plan.IsActive,
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "commission_plan",
		AggregateID:   plan.PlanID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *salesRepCommissionService) emitCommissionAssignmentEvent(ctx context.Context, tx repository.DBTX, companyID, salesRepID, planID uuid.UUID, effectiveDate time.Time, actor uuid.UUID, action string) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not *sql.Tx")
	}
	var eventType string
	if action == "assign" {
		eventType = salesEvents.EventCommissionPlanAssigned
	} else {
		eventType = salesEvents.EventCommissionPlanRemoved
	}
	payload := map[string]interface{}{
		"company_id":     companyID.String(),
		"sales_rep_id":   salesRepID.String(),
		"plan_id":        planID.String(),
		"effective_from": effectiveDate.Format(time.RFC3339),
		"assigned_by":    actor.String(),
	}
	if action == "remove" {
		payload["removed_at"] = effectiveDate.Format(time.RFC3339)
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "commission_assignment",
		AggregateID:   salesRepID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *salesRepCommissionService) emitCommissionCreatedEvent(ctx context.Context, tx repository.DBTX, comm *models.SalesCommission, planID uuid.UUID, ruleID *uuid.UUID) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not *sql.Tx")
	}
	payload := salesEvents.CommissionPayload{
		CommissionID:     comm.CommissionID.String(),
		CompanyID:        comm.CompanyID.String(),
		SalesRepID:       comm.SalesRepID.String(),
		ReferenceType:    string(comm.ReferenceType),
		ReferenceID:      comm.ReferenceID.String(),
		CommissionBase:   comm.CommissionBase.String(),
		CommissionRate:   comm.CommissionRate.String(),
		CommissionAmount: comm.CommissionAmount.String(),
		EarnedAt:         comm.EarnedAt.Format(time.RFC3339),
		Status:           string(comm.Status),
		PlanID:           planID.String(),
	}
	if ruleID != nil {
		payload.RuleID = ruleID.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "sales_commission",
		AggregateID:   comm.CommissionID.String(),
		EventType:     salesEvents.EventCommissionCreated,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *salesRepCommissionService) emitCommissionStatusEvent(ctx context.Context, companyID, commissionID uuid.UUID, status enums.CommissionStatus, reason string, actor uuid.UUID) error {
	// This method is called after the status has been updated in the database.
	// We need a transaction to emit the event. We'll start a new transaction.
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for status event: %w", err)
	}
	defer tx.Rollback()

	eventType := ""
	switch status {
	case enums.CommissionStatusApproved:
		eventType = salesEvents.EventCommissionApproved
	case enums.CommissionStatusPaid:
		eventType = salesEvents.EventCommissionPaid
	case enums.CommissionStatusRejected:
		eventType = salesEvents.EventCommissionRejected
	default:
		return nil
	}
	payload := salesEvents.CommissionStatusPayload{
		CommissionID: commissionID.String(),
		CompanyID:    companyID.String(),
		UpdatedAt:    time.Now().Format(time.RFC3339),
		Reason:       reason,
		// Actor: actor.String(), // if you add Actor field to CommissionStatusPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "sales_commission",
		AggregateID:   commissionID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	if err := s.outboxRepo.Store(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
