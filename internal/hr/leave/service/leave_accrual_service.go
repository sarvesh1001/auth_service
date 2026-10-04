package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

type LeaveAccrualService interface {
	AccrueMonthlyLeave(ctx context.Context, companyID uuid.UUID, accrualDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (int, error)
	RecalculateEntitlement(ctx context.Context, entitlementID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveBalance, error)
	GetAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error)
	ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (int, error)
}

type leaveAccrualService struct {
	repo             repository.LeaveRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLeaveAccrualService(
	repo repository.LeaveRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LeaveAccrualService {
	return &leaveAccrualService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

func (s *leaveAccrualService) AccrueMonthlyLeave(
	ctx context.Context,
	companyID uuid.UUID,
	accrualDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (int, error) {

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("accrue_monthly-%s-%s", companyID.String(), accrualDate.Format("2006-01-02"))
	}
	var processed int
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil {
		return processed, nil
	}

	processed, err := s.repo.ProcessLeaveAccruals(ctx, companyID, accrualDate)
	if err != nil {
		return 0, fmt.Errorf("failed to process monthly accruals: %w", err)
	}

	// Audit
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"company_id":   companyID.String(),
		"accrual_date": accrualDate,
		"processed":    processed,
		"ip":           ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"leave",
		"accrual.monthly",
		"leave_accrual",
		nil,
		actorType,
		&actorID,
		[]byte("{}"),
		[]byte(fmt.Sprintf(`{"processed":%d}`, processed)),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, processed)

	return processed, nil
}

func (s *leaveAccrualService) RecalculateEntitlement(
	ctx context.Context,
	entitlementID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveBalance, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("recalc_ent-%s", entitlementID.String())
	}
	var cached *models.LeaveBalance
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	entitlement, err := s.repo.GetLeaveEntitlementByID(ctx, entitlementID)
	if err != nil {
		return nil, fmt.Errorf("failed to get entitlement: %w", err)
	}
	if entitlement == nil {
		return nil, fmt.Errorf("entitlement not found")
	}

	ledgerEntries, err := s.repo.GetLeaveLedgerEntriesByEntitlement(ctx, entitlementID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ledger entries: %w", err)
	}

	var totalAccrued, totalConsumed float64
	for _, entry := range ledgerEntries {
		switch entry.EntryType {
		case "accrual", "reversal":
			totalAccrued += float64(entry.Days)
		case "consumption":
			totalConsumed += float64(entry.Days)
		}
	}

	leaveType, err := s.repo.GetLeaveTypeByID(ctx, entitlement.LeaveTypeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}
	if leaveType == nil {
		return nil, fmt.Errorf("leave type not found")
	}

	// Carry-forward limit comes from the effective policy rule, not the
	// leave type. If the entitlement is policy-sourced we look up the
	// rule; for manual entitlements there is no rule so the limit is nil.
	var carryForward *int
	if entitlement.PolicyID != nil {
		rules, err := s.repo.GetPolicyRules(ctx, *entitlement.PolicyID)
		if err == nil {
			for _, r := range rules {
				if r.LeaveTypeID == entitlement.LeaveTypeID {
					carryForward = r.CarryForwardLimit
					break
				}
			}
		}
	}

	balance := &models.LeaveBalance{
		UserID:        entitlement.UserID,
		LeaveTypeID:   entitlement.LeaveTypeID,
		LeaveTypeCode: leaveType.Code,
		LeaveTypeName: leaveType.Name,
		TotalEntitled: float64(entitlement.TotalDays),
		Accrued:       totalAccrued,
		Consumed:      totalConsumed,
		Balance:       totalAccrued - totalConsumed,
		CarryForward:  carryForward,
	}

	// Audit
	ip, _ := ctx.Value("ip_address").(string)
	afterJSON, _ := json.Marshal(balance)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"entitlement_id": entitlementID.String(),
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&entitlement.CompanyID,
		"leave",
		"entitlement.recalculate",
		"leave_entitlement",
		&entitlementID,
		actorType,
		&actorID,
		nil,
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, balance)

	return balance, nil
}

func (s *leaveAccrualService) GetAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error) {
	// read-only, no idempotency needed, but can audit if required (optional)
	return s.repo.GetLeaveAccrualsByDate(ctx, companyID, date)
}

func (s *leaveAccrualService) ProcessLeaveAccruals(
	ctx context.Context,
	companyID uuid.UUID,
	accrualDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (int, error) {
	// This is the same as AccrueMonthlyLeave, but can be used separately.
	// We'll just delegate to AccrueMonthlyLeave.
	return s.AccrueMonthlyLeave(ctx, companyID, accrualDate, actorType, actorID, metadata)
}

// helper
func mergeMeta(base, extra map[string]interface{}) map[string]interface{} {
	if base == nil {
		base = make(map[string]interface{})
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}
