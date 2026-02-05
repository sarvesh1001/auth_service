package service

import (
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollRunService orchestrates payroll operations
type PayrollRunService interface {
	CreatePayrollRun(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, createdBy *uuid.UUID) (*models.PayrollRun, error)
	CalculatePayroll(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ApprovePayrollRun(ctx context.Context, runID uuid.UUID, approvedBy uuid.UUID) error
	PayPayrollRun(ctx context.Context, runID uuid.UUID, paidBy uuid.UUID) error
	GetPayrollRun(ctx context.Context, runID uuid.UUID) (*models.PayrollRun, error)
	ListPayrollRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error)
	DeletePayrollRun(ctx context.Context, runID uuid.UUID) error
	GetRunSummary(ctx context.Context, runID uuid.UUID) (*models.PayrollRunSummary, error)
	CreateSnapshot(ctx context.Context, runID uuid.UUID, snapshotType string, createdBy uuid.UUID) error
}

type payrollRunService struct {
	repo           repository.PayrollRepository
	calculationSvc PayrollCalculationService
	lockSvc        PayrollLockService
	auditService   *service.AuditService
	logger         *zap.Logger
}

func NewPayrollRunService(
	repo repository.PayrollRepository,
	calculationSvc PayrollCalculationService,
	lockSvc PayrollLockService,
	auditService *service.AuditService,
	logger *zap.Logger,
) PayrollRunService {
	return &payrollRunService{
		repo:           repo,
		calculationSvc: calculationSvc,
		lockSvc:        lockSvc,
		auditService:   auditService,
		logger:         logger,
	}
}

func (s *payrollRunService) CreatePayrollRun(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	createdBy *uuid.UUID,
) (*models.PayrollRun, error) {
	startTime := time.Now()

	// Validate period
	if periodStart.After(periodEnd) {
		return nil, fmt.Errorf("period_start cannot be after period_end")
	}

	// Check for overlapping runs
	existingRuns, _, err := s.repo.GetPayrollRuns(ctx, models.PayrollRunFilter{
		CompanyID:   companyID,
		PeriodStart: &periodStart,
		PeriodEnd:   &periodEnd,
		Status:      util.StringPtr(models.PayrollStatusDraft),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing runs: %w", err)
	}
	if len(existingRuns) > 0 {
		return nil, fmt.Errorf("draft payroll run already exists for this period")
	}

	// Create run
	run := &models.PayrollRun{
		PayrollRunID: uuid.New(),
		CompanyID:    companyID,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
		Status:       models.PayrollStatusDraft,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    createdBy,
	}

	if err := s.repo.CreatePayrollRun(ctx, run); err != nil {
		s.logger.Error("Failed to create payroll run",
			util.String("company_id", companyID.String()),
			util.String("period", fmt.Sprintf("%s to %s",
				periodStart.Format("2006-01-02"),
				periodEnd.Format("2006-01-02"))),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create payroll run: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.logAuditAction(ctx, &companyID, "payroll_run.create", run.PayrollRunID,
			"user", createdBy, nil, run, nil)
	}

	s.logger.Info("Payroll run created",
		util.String("run_id", run.PayrollRunID.String()),
		util.String("company_id", companyID.String()),
		util.String("status", run.Status),
		util.Duration("duration", time.Since(startTime)))

	return run, nil
}

func (s *payrollRunService) CalculatePayroll(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error {
	startTime := time.Now()

	// Get payroll run
	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return fmt.Errorf("payroll run not found")
	}

	// Validate status
	if run.Status != models.PayrollStatusDraft {
		return fmt.Errorf("payroll run must be in draft status, current: %s", run.Status)
	}

	// Lock attendance data for period
	if err := s.lockSvc.LockPeriod(ctx, run.CompanyID, run.PeriodStart, run.PeriodEnd); err != nil {
		return fmt.Errorf("failed to lock period: %w", err)
	}

	// Trigger calculation
	if err := s.calculationSvc.CalculateRun(ctx, run); err != nil {
		// Unlock on failure
		if unlockErr := s.lockSvc.UnlockPeriod(ctx, run.CompanyID, run.PeriodStart, run.PeriodEnd); unlockErr != nil {
			s.logger.Warn("Failed to unlock period after calculation error",
				util.String("run_id", runID.String()),
				util.ErrorField(unlockErr))
		}
		return fmt.Errorf("calculation failed: %w", err)
	}

	// Update status to calculated
	if err := s.repo.UpdatePayrollRunStatus(ctx, runID, models.PayrollStatusCalculated); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Create snapshot
	if err := s.CreateSnapshot(ctx, runID, "calculated", actorID); err != nil {
		s.logger.Warn("Failed to create snapshot after calculation",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
	}

	// Audit log
	if s.auditService != nil {
		s.logAuditAction(ctx, &run.CompanyID, "payroll_run.calculate", run.PayrollRunID,
			"user", &actorID, nil, run, nil)
	}

	s.logger.Info("Payroll run calculated",
		util.String("run_id", run.PayrollRunID.String()),
		util.String("company_id", run.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *payrollRunService) ApprovePayrollRun(ctx context.Context, runID uuid.UUID, approvedBy uuid.UUID) error {
	startTime := time.Now()

	// Get payroll run
	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return fmt.Errorf("payroll run not found")
	}

	// Validate status
	if run.Status != models.PayrollStatusCalculated {
		return fmt.Errorf("payroll run must be in calculated status, current: %s", run.Status)
	}

	// Update status to approved
	if err := s.repo.UpdatePayrollRunStatus(ctx, runID, models.PayrollStatusApproved); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Create snapshot
	if err := s.CreateSnapshot(ctx, runID, "approved", approvedBy); err != nil {
		s.logger.Warn("Failed to create snapshot after approval",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
	}

	// Audit log
	if s.auditService != nil {
		s.logAuditAction(ctx, &run.CompanyID, "payroll_run.approve", run.PayrollRunID,
			"user", &approvedBy, nil, run, nil)
	}

	s.logger.Info("Payroll run approved",
		util.String("run_id", run.PayrollRunID.String()),
		util.String("company_id", run.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *payrollRunService) PayPayrollRun(ctx context.Context, runID uuid.UUID, paidBy uuid.UUID) error {
	startTime := time.Now()

	// Get payroll run
	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return fmt.Errorf("payroll run not found")
	}

	// Validate status
	if run.Status != models.PayrollStatusApproved {
		return fmt.Errorf("payroll run must be in approved status, current: %s", run.Status)
	}

	// Update status to paid
	if err := s.repo.UpdatePayrollRunStatus(ctx, runID, models.PayrollStatusPaid); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Create snapshot
	if err := s.CreateSnapshot(ctx, runID, "paid", paidBy); err != nil {
		s.logger.Warn("Failed to create snapshot after payment",
			util.String("run_id", runID.String()),
			util.ErrorField(err))
	}

	// Audit log
	if s.auditService != nil {
		s.logAuditAction(ctx, &run.CompanyID, "payroll_run.pay", run.PayrollRunID,
			"user", &paidBy, nil, run, nil)
	}

	s.logger.Info("Payroll run paid",
		util.String("run_id", run.PayrollRunID.String()),
		util.String("company_id", run.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *payrollRunService) GetPayrollRun(ctx context.Context, runID uuid.UUID) (*models.PayrollRun, error) {
	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("failed to get payroll run: %w", err)
	}
	return run, nil
}

func (s *payrollRunService) ListPayrollRuns(
	ctx context.Context,
	filter models.PayrollRunFilter,
) ([]*models.PayrollRun, int64, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 || filter.PageSize > 100 {
		filter.PageSize = 50
	}

	runs, total, err := s.repo.GetPayrollRuns(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list payroll runs: %w", err)
	}
	return runs, total, nil
}
func (s *payrollRunService) DeletePayrollRun(ctx context.Context, runID uuid.UUID) error {
	startTime := time.Now()

	// Get payroll run
	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return fmt.Errorf("payroll run not found")
	}

	// Only draft runs can be deleted
	if run.Status != models.PayrollStatusDraft {
		return fmt.Errorf("can only delete draft payroll runs")
	}

	// ⚠️ IMPORTANT:
	// Draft runs NEVER lock attendance, so DO NOT unlock here.
	// Unlocking here could accidentally unlock another run’s lock.

	// Delete payroll run
	if err := s.repo.DeletePayrollRun(ctx, runID); err != nil {
		return fmt.Errorf("failed to delete payroll run: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		s.logAuditAction(
			ctx,
			&run.CompanyID,
			"payroll_run.delete",
			run.PayrollRunID,
			"system",
			nil,
			run,
			nil,
			nil,
		)
	}

	s.logger.Info("Payroll run deleted",
		util.String("run_id", run.PayrollRunID.String()),
		util.String("company_id", run.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

func (s *payrollRunService) GetRunSummary(ctx context.Context, runID uuid.UUID) (*models.PayrollRunSummary, error) {
	summary, err := s.repo.GetPayrollRunSummary(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("failed to get run summary: %w", err)
	}
	return summary, nil
}

func (s *payrollRunService) CreateSnapshot(
	ctx context.Context,
	runID uuid.UUID,
	snapshotType string,
	createdBy uuid.UUID,
) error {
	// Get payroll run details
	run, err := s.repo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return fmt.Errorf("payroll run not found")
	}

	// Get items and ledger for snapshot
	items, err := s.repo.GetPayrollItemsByRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to get payroll items: %w", err)
	}

	// Build snapshot data
	snapshotData := map[string]interface{}{
		"run":         run,
		"items":       items,
		"status":      run.Status,
		"total_items": len(items),
		"timestamp":   time.Now().UTC(),
	}

	// Convert to JSON
	data, err := json.Marshal(snapshotData)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot data: %w", err)
	}

	// Create snapshot
	snapshot := &models.PayrollSnapshot{
		SnapshotID:   uuid.New(),
		PayrollRunID: runID,
		CompanyID:    run.CompanyID,
		SnapshotType: snapshotType,
		SnapshotData: data,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    createdBy,
	}

	if err := s.repo.CreateSnapshot(ctx, snapshot); err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	return nil
}

func (s *payrollRunService) logAuditAction(
	ctx context.Context,
	companyID *uuid.UUID,
	action string,
	resourceID uuid.UUID,
	actorType string,
	actorID *uuid.UUID,
	beforeState, afterState interface{},
	metadata map[string]interface{},
) {
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var beforeJSON, afterJSON []byte
			var err error

			if beforeState != nil {
				beforeJSON, err = json.Marshal(beforeState)
				if err != nil {
					s.logger.Warn("Failed to marshal before state for audit",
						util.String("action", action),
						util.ErrorField(err))
				}
			}

			if afterState != nil {
				afterJSON, err = json.Marshal(afterState)
				if err != nil {
					s.logger.Warn("Failed to marshal after state for audit",
						util.String("action", action),
						util.ErrorField(err))
				}
			}

			s.auditService.LogAction(auditCtx,
				companyID,
				"payroll",
				action,
				"payroll_run",
				&resourceID,
				actorType,
				actorID,
				beforeJSON,
				afterJSON,
				metadata,
			)
		}()
	}
}
