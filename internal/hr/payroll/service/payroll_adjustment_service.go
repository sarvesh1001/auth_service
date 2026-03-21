package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
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
	repo   repository.PayrollRepository
	audit  *a.AuditService
	logger *zap.Logger
}

// NewPayrollAdjustmentService creates a new payroll adjustment service with audit support.
func NewPayrollAdjustmentService(
	repo repository.PayrollRepository,
	audit *a.AuditService,
	logger *zap.Logger,
) PayrollAdjustmentService {
	return &payrollAdjustmentService{
		repo:   repo,
		audit:  audit,
		logger: logger,
	}
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

	locked, err := s.repo.IsPayrollPeriodLockedRange(
		ctx,
		companyID,
		monthStart,
		monthEnd,
	)
	if err != nil {
		return err
	}
	if locked {
		return errors.New("adjustment not allowed: payroll period locked")
	}

	run, err := s.repo.GetPayrollRunByPeriod(
		ctx,
		companyID,
		monthStart,
		monthEnd,
	)
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

// Create adds a new payroll adjustment and audits the action.
func (s *payrollAdjustmentService) Create(
	ctx context.Context,
	input *models.CreatePayrollAdjustmentInput,
) (*models.PayrollAdjustment, error) {
	if input == nil {
		return nil, errors.New("nil input")
	}
	if input.Amount == 0 {
		return nil, errors.New("amount cannot be zero")
	}
	if err := s.ValidateAllowed(
		ctx,
		input.CompanyID,
		input.ApplicableMonth,
	); err != nil {
		return nil, err
	}

	// ✅ FIX: pass companyID to GetComponent
	component, err := s.repo.GetComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, err
	}
	if component == nil || !component.IsActive {
		return nil, errors.New("invalid or inactive component")
	}

	// Handle empty reason gracefully
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

	if err := s.repo.CreatePayrollAdjustment(ctx, adj); err != nil {
		return nil, err
	}

	// Audit successful creation (non‑blocking, errors only logged)
	afterState, _ := json.Marshal(adj)
	if err := s.audit.LogAction(
		ctx,
		nil,
		&adj.CompanyID,
		"payroll",
		"adjustment_created",
		"payroll_adjustment",
		&adj.AdjustmentID,
		"admin",
		adj.CreatedBy,
		nil,
		afterState,
		map[string]interface{}{
			"component_code":   adj.ComponentCode,
			"applicable_month": adj.ApplicableMonth,
		},
	); err != nil {
		s.logger.Error("Failed to audit adjustment creation",
			zap.String("adjustment_id", adj.AdjustmentID.String()),
			zap.Error(err))
	}

	return adj, nil
}

// BulkCreate creates multiple adjustments in a transaction.
func (s *payrollAdjustmentService) BulkCreate(
	ctx context.Context,
	inputs []*models.CreatePayrollAdjustmentInput,
) error {
	if len(inputs) == 0 {
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

	for _, input := range inputs {
		if input == nil {
			err = errors.New("nil input in bulk")
			return err
		}
		if input.Amount == 0 {
			err = errors.New("amount cannot be zero")
			return err
		}
		if err = s.ValidateAllowed(ctx, input.CompanyID, input.ApplicableMonth); err != nil {
			return err
		}
		// ✅ FIX: pass companyID to GetComponent
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
				adjustment_id,
				company_id,
				user_id,
				component_code,
				amount,
				adjustment_type,
				reason,
				applicable_month,
				created_at,
				created_by
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		`,
			adj.AdjustmentID,
			adj.CompanyID,
			adj.UserID,
			adj.ComponentCode,
			adj.Amount,
			adj.AdjustmentType,
			adj.Reason,
			adj.ApplicableMonth,
			adj.CreatedAt,
			adj.CreatedBy,
		)
		if err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}

	// Optional: add a summary audit entry for the bulk operation.
	// For now, we skip to keep the code simple.
	return nil
}

// Update modifies an existing adjustment and audits the change.
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
	if err := s.ValidateAllowed(
		ctx,
		existing.CompanyID,
		existing.ApplicableMonth,
	); err != nil {
		return nil, err
	}

	// Capture before state
	beforeState, _ := json.Marshal(existing)

	if input.Amount != nil {
		existing.Amount = *input.Amount
	}
	if input.Reason != nil {
		// If empty string is provided, we store nil to keep DB clean
		if *input.Reason == "" {
			existing.Reason = nil
		} else {
			existing.Reason = input.Reason
		}
	}

	if err := s.repo.UpdatePayrollAdjustment(ctx, existing); err != nil {
		return nil, err
	}

	// Audit successful update (non‑blocking)
	afterState, _ := json.Marshal(existing)
	if err := s.audit.LogAction(
		ctx,
		nil,
		&existing.CompanyID,
		"payroll",
		"adjustment_updated",
		"payroll_adjustment",
		&existing.AdjustmentID,
		"admin",
		&input.UpdatedBy,
		beforeState,
		afterState,
		nil,
	); err != nil {
		s.logger.Error("Failed to audit adjustment update",
			zap.String("adjustment_id", existing.AdjustmentID.String()),
			zap.Error(err))
	}

	return existing, nil
}

// Delete removes an adjustment and audits the deletion.
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
	if err := s.ValidateAllowed(
		ctx,
		existing.CompanyID,
		existing.ApplicableMonth,
	); err != nil {
		return err
	}

	// Capture before state
	beforeState, _ := json.Marshal(existing)

	if err := s.repo.DeletePayrollAdjustment(ctx, adjustmentID); err != nil {
		return err
	}

	// Audit successful deletion (non‑blocking)
	if err := s.audit.LogAction(
		ctx,
		nil,
		&existing.CompanyID,
		"payroll",
		"adjustment_deleted",
		"payroll_adjustment",
		&existing.AdjustmentID,
		"admin",
		&actorID,
		beforeState,
		nil,
		nil,
	); err != nil {
		s.logger.Error("Failed to audit adjustment deletion",
			zap.String("adjustment_id", existing.AdjustmentID.String()),
			zap.Error(err))
	}

	return nil
}

// Get retrieves a single adjustment by ID.
func (s *payrollAdjustmentService) Get(
	ctx context.Context,
	adjustmentID uuid.UUID,
) (*models.PayrollAdjustment, error) {
	return s.repo.GetPayrollAdjustmentByID(ctx, adjustmentID)
}

// List returns adjustments with pagination and filtering.
func (s *payrollAdjustmentService) List(
	ctx context.Context,
	filter models.PayrollAdjustmentFilter,
) ([]*models.PayrollAdjustment, int64, error) {
	return s.repo.ListPayrollAdjustments(ctx, filter)
}

// GetEmployeeAdjustmentsForPeriod retrieves adjustments for a specific employee in a date range.
func (s *payrollAdjustmentService) GetEmployeeAdjustmentsForPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]*models.PayrollAdjustment, error) {
	return s.repo.GetAdjustmentsForEmployee(
		ctx,
		companyID,
		userID,
		periodStart,
		periodEnd,
	)
}
