package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

// PayrollAdjustmentService defines the interface for payroll adjustment operations.
type PayrollAdjustmentService interface {
	Create(ctx context.Context, input *models.CreatePayrollAdjustmentInput) (*models.PayrollAdjustment, error)
	BulkCreate(ctx context.Context, inputs []*models.CreatePayrollAdjustmentInput) error
	Update(ctx context.Context, input *models.UpdatePayrollAdjustmentInput) (*models.PayrollAdjustment, error)
	Delete(ctx context.Context, adjustmentID uuid.UUID, actorID uuid.UUID) error
	Get(ctx context.Context, adjustmentID uuid.UUID) (*models.PayrollAdjustment, error)
	List(ctx context.Context, filter models.PayrollAdjustmentFilter) ([]*models.PayrollAdjustment, int64, error)
	GetEmployeeAdjustmentsForPeriod(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		periodStart, periodEnd time.Time,
	) ([]*models.PayrollAdjustment, error)
	ValidateAllowed(
		ctx context.Context,
		companyID uuid.UUID,
		applicableMonth time.Time,
	) error
}

type payrollAdjustmentService struct {
	repo             repository.PayrollRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewPayrollAdjustmentService(
	repo repository.PayrollRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
) PayrollAdjustmentService {
	return &payrollAdjustmentService{
		repo:             repo,
		employeeRepo:     employeeRepo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
	}
}

// ensureEmployeeInScope — same pattern.
func (s *payrollAdjustmentService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, targetUserID)
	if err != nil {
		return err
	}
	if empLoc == nil {
		return ErrEmployeeHasNoLocation
	}
	if *empLoc != *locCtx.LocationID {
		return ErrEmployeeOutsideScope
	}
	return nil
}

// ValidateAllowed checks if adjustments are allowed for the given month.
func (s *payrollAdjustmentService) ValidateAllowed(
	ctx context.Context,
	companyID uuid.UUID,
	applicableMonth time.Time,
) error {
	if applicableMonth.IsZero() {
		return errors.New("invalid applicable month")
	}
	monthStart := time.Date(
		applicableMonth.Year(),
		applicableMonth.Month(),
		1, 0, 0, 0, 0,
		time.UTC,
	)
	monthEnd := monthStart.AddDate(0, 1, -1)

	locked, err := s.repo.IsPayrollPeriodLockedRange(ctx, companyID, monthStart, monthEnd)
	if err != nil {
		return err
	}
	if locked {
		return errors.New("adjustment not allowed: payroll period locked")
	}

	run, err := s.repo.GetPayrollRunByPeriod(ctx, companyID, monthStart, monthEnd)
	if err != nil {
		return err
	}
	if run != nil &&
		(run.Status == models.PayrollStatusApproved ||
			run.Status == models.PayrollStatusPaid) {
		return errors.New("adjustment not allowed: payroll already approved or paid")
	}
	return nil
}

// Create adds a new payroll adjustment with location scope, idempotency, and audit.
func (s *payrollAdjustmentService) Create(
	ctx context.Context,
	input *models.CreatePayrollAdjustmentInput,
) (*models.PayrollAdjustment, error) {
	if input == nil {
		return nil, errors.New("nil input")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("pay_adj_create-%s-%s", input.UserID.String(), input.ApplicableMonth.Format("2006-01"))
	}
	var cached *models.PayrollAdjustment
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if input.Amount == 0 {
		return nil, errors.New("amount cannot be zero")
	}
	if err := s.ValidateAllowed(ctx, input.CompanyID, input.ApplicableMonth); err != nil {
		return nil, err
	}
	component, err := s.repo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, err
	}
	if component == nil || !component.IsActive {
		return nil, errors.New("invalid or inactive component")
	}

	var reason *string
	if input.Reason != "" {
		reason = &input.Reason
	}

	adj := &models.PayrollAdjustment{
		AdjustmentID:    uuid.New(),
		CompanyID:       input.CompanyID,
		UserID:          input.UserID,
		ComponentCode:   input.ComponentCode,
		Amount:          input.Amount,
		AdjustmentType:  input.AdjustmentType,
		Reason:          reason,
		ApplicableMonth: input.ApplicableMonth,
		CreatedAt:       time.Now().UTC(),
		CreatedBy:       &input.CreatedBy,
	}

	beforeState := []byte("{}")
	afterState, _ := json.Marshal(adj)

	if err := s.repo.CreatePayrollAdjustment(ctx, adj); err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &adj.CompanyID, "payroll", "adjustment_created", "payroll_adjustment",
		&adj.AdjustmentID, "user", adj.CreatedBy, beforeState, afterState,
		map[string]interface{}{
			"component_code":   adj.ComponentCode,
			"applicable_month": adj.ApplicableMonth,
			"ip":               ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, adj)
	return adj, nil
}

// BulkCreate — location scope for each input.
func (s *payrollAdjustmentService) BulkCreate(
	ctx context.Context,
	inputs []*models.CreatePayrollAdjustmentInput,
) error {
	if len(inputs) == 0 {
		return nil
	}

	// 👇 Location scope check for every input
	for _, input := range inputs {
		if input == nil {
			return errors.New("nil input in bulk")
		}
		if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
			return fmt.Errorf("user %s: %w", input.UserID.String(), err)
		}
	}

	first := inputs[0]
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("pay_adj_bulk-%s-%s", first.CompanyID.String(), first.ApplicableMonth.Format("2006-01"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	tx, err := s.repo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	auditEntries := make([]map[string]interface{}, 0, len(inputs))

	for _, input := range inputs {
		if input.Amount == 0 {
			err = errors.New("amount cannot be zero")
			return err
		}
		if err = s.ValidateAllowed(ctx, input.CompanyID, input.ApplicableMonth); err != nil {
			return err
		}
		component, err2 := s.repo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
		if err2 != nil {
			err = err2
			return err
		}
		if component == nil || !component.IsActive {
			err = errors.New("invalid or inactive component")
			return err
		}

		var reason *string
		if input.Reason != "" {
			reason = &input.Reason
		}

		adj := &models.PayrollAdjustment{
			AdjustmentID:    uuid.New(),
			CompanyID:       input.CompanyID,
			UserID:          input.UserID,
			ComponentCode:   input.ComponentCode,
			Amount:          input.Amount,
			AdjustmentType:  input.AdjustmentType,
			Reason:          reason,
			ApplicableMonth: input.ApplicableMonth,
			CreatedAt:       time.Now().UTC(),
			CreatedBy:       &input.CreatedBy,
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO payroll.payroll_adjustment (
				adjustment_id, company_id, user_id, component_code,
				amount, adjustment_type, reason, applicable_month,
				created_at, created_by
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		`,
			adj.AdjustmentID, adj.CompanyID, adj.UserID, adj.ComponentCode,
			adj.Amount, adj.AdjustmentType, adj.Reason, adj.ApplicableMonth,
			adj.CreatedAt, adj.CreatedBy,
		)
		if err != nil {
			return err
		}
		afterState, _ := json.Marshal(adj)
		auditEntries = append(auditEntries, map[string]interface{}{
			"adjustment_id":  adj.AdjustmentID.String(),
			"user_id":        adj.UserID.String(),
			"component_code": adj.ComponentCode,
			"amount":         adj.Amount,
			"after_state":    string(afterState),
		})
	}
	if err = tx.Commit(); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &first.CompanyID, "payroll", "adjustment_bulk_created", "payroll_adjustment",
		nil, "user", &first.CreatedBy, nil,
		[]byte(`{"count":`+fmt.Sprintf("%d", len(auditEntries))+`}`),
		map[string]interface{}{
			"ip":      ip,
			"count":   len(auditEntries),
			"month":   first.ApplicableMonth.Format("2006-01"),
			"entries": auditEntries,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// Update — location scope + idempotency + audit.
func (s *payrollAdjustmentService) Update(
	ctx context.Context,
	input *models.UpdatePayrollAdjustmentInput,
) (*models.PayrollAdjustment, error) {
	if input == nil {
		return nil, errors.New("nil input")
	}

	existing, err := s.repo.GetPayrollAdjustmentByID(ctx, input.AdjustmentID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, errors.New("adjustment not found")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("pay_adj_update-%s", input.AdjustmentID.String())
	}
	var cached *models.PayrollAdjustment
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if err := s.ValidateAllowed(ctx, existing.CompanyID, existing.ApplicableMonth); err != nil {
		return nil, err
	}

	beforeState, _ := json.Marshal(existing)

	if input.Amount != nil {
		existing.Amount = *input.Amount
	}
	if input.Reason != nil {
		if *input.Reason == "" {
			existing.Reason = nil
		} else {
			existing.Reason = input.Reason
		}
	}

	if err := s.repo.UpdatePayrollAdjustment(ctx, existing); err != nil {
		return nil, err
	}
	afterState, _ := json.Marshal(existing)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &existing.CompanyID, "payroll", "adjustment_updated", "payroll_adjustment",
		&existing.AdjustmentID, "user", &input.UpdatedBy, beforeState, afterState,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, existing)
	return existing, nil
}

// Delete — location scope + idempotency + audit.
func (s *payrollAdjustmentService) Delete(
	ctx context.Context,
	adjustmentID uuid.UUID,
	actorID uuid.UUID,
) error {
	existing, err := s.repo.GetPayrollAdjustmentByID(ctx, adjustmentID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.New("adjustment not found")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("pay_adj_delete-%s", adjustmentID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if err := s.ValidateAllowed(ctx, existing.CompanyID, existing.ApplicableMonth); err != nil {
		return err
	}

	beforeState, _ := json.Marshal(existing)

	if err := s.repo.DeletePayrollAdjustment(ctx, adjustmentID); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &existing.CompanyID, "payroll", "adjustment_deleted", "payroll_adjustment",
		&existing.AdjustmentID, "user", &actorID, beforeState, nil,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// Get — single-row read.
func (s *payrollAdjustmentService) Get(
	ctx context.Context,
	adjustmentID uuid.UUID,
) (*models.PayrollAdjustment, error) {
	return s.repo.GetPayrollAdjustmentByID(ctx, adjustmentID)
}

// List — filter carries LocationID; handler populates it.
func (s *payrollAdjustmentService) List(
	ctx context.Context,
	filter models.PayrollAdjustmentFilter,
) ([]*models.PayrollAdjustment, int64, error) {
	return s.repo.ListPayrollAdjustments(ctx, filter)
}

// GetEmployeeAdjustmentsForPeriod — location scope + read.
func (s *payrollAdjustmentService) GetEmployeeAdjustmentsForPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]*models.PayrollAdjustment, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	return s.repo.GetAdjustmentsForEmployee(ctx, companyID, userID, periodStart, periodEnd)
}
