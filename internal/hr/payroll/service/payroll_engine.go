package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrservice "auth-service/internal/hr/service"
	a "auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollEngineService defines the payroll engine operations.
type PayrollEngineService interface {
	// Run lifecycle
	InitializeRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ExecuteRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ApproveRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	MarkRunAsPaid(ctx context.Context, runID uuid.UUID, actorID uuid.UUID, paidAt time.Time) error
	CancelRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ProcessEmployee(ctx context.Context, runID, userID, actorID uuid.UUID, reflectLatestAdjustments bool, components map[string]*models.PayrollComponent, settings *models.CompanyPayrollSettings) error
	ReprocessEmployee(ctx context.Context, runID, userID, actorID uuid.UUID, reflectLatestAdjustments bool) error
	GetRunExecutionStatus(ctx context.Context, runID uuid.UUID) (*PayrollExecutionStatus, error)
	CreateRun(
		ctx context.Context,
		companyID uuid.UUID,
		periodStart time.Time,
		periodEnd time.Time,
		createdBy uuid.UUID,
	) (*models.PayrollRun, error)

	// Component Management
	CreateComponent(
		ctx context.Context,
		input *models.CreateComponentInput,
		actorID uuid.UUID,
	) (*models.PayrollComponent, error)

	UpdateComponent(
		ctx context.Context,
		input *models.UpdateComponentInput,
		actorID uuid.UUID,
	) (*models.PayrollComponent, error)

	DeactivateComponent(
		ctx context.Context,
		companyID uuid.UUID,
		componentCode string,
		actorID uuid.UUID,
	) error

	ListComponents(
		ctx context.Context,
		companyID uuid.UUID,
	) ([]*models.PayrollComponent, error)

	// NEW: Employee job completion tracking
	CountRemainingEmployeeJobs(ctx context.Context, runID uuid.UUID) (int, error)
	FinalizeRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
}

// PayrollExecutionStatus holds execution progress.
type PayrollExecutionStatus struct {
	RunID              uuid.UUID
	Status             string
	TotalEmployees     int
	ProcessedEmployees int
	FailedEmployees    int
	LastProcessedAt    *time.Time
}

// payrollEngineService implements PayrollEngineService.
type payrollEngineService struct {
	payrollRepo        repository.PayrollRepository
	jobRepo            repository.PayrollJobRepository
	compensationSvc    CompensationService
	statutoryEngine    StatutoryEngine
	attendanceBridge   hrservice.AttendancePayrollBridge
	audit              *a.AuditService
	attendanceRuleRepo repository.AttendanceRuleRepository
	employeeFineRepo   repository.EmployeeFineRepository
	arrearsRepo        repository.ArrearsRepository
	loanRepo           repository.LoanRepository
	componentRepo      repository.ComponentRepository
	settingsRepo       repository.CompanySettingsRepository
	logger             *zap.Logger
}

// NewPayrollEngineService creates a new payroll engine service.
func NewPayrollEngineService(
	payrollRepo repository.PayrollRepository,
	jobRepo repository.PayrollJobRepository,
	compensationSvc CompensationService,
	statutoryEngine StatutoryEngine,
	attendanceBridge hrservice.AttendancePayrollBridge,
	audit *a.AuditService,
	attendanceRuleRepo repository.AttendanceRuleRepository,
	employeeFineRepo repository.EmployeeFineRepository,
	arrearsRepo repository.ArrearsRepository,
	loanRepo repository.LoanRepository,
	componentRepo repository.ComponentRepository,
	settingsRepo repository.CompanySettingsRepository,
	logger *zap.Logger,
) PayrollEngineService {
	return &payrollEngineService{
		payrollRepo:        payrollRepo,
		jobRepo:            jobRepo,
		compensationSvc:    compensationSvc,
		statutoryEngine:    statutoryEngine,
		attendanceBridge:   attendanceBridge,
		audit:              audit,
		attendanceRuleRepo: attendanceRuleRepo,
		employeeFineRepo:   employeeFineRepo,
		arrearsRepo:        arrearsRepo,
		loanRepo:           loanRepo,
		componentRepo:      componentRepo,
		settingsRepo:       settingsRepo,
		logger:             logger,
	}
}

// ---------------------------------------------------------------------
// Run Lifecycle
// ---------------------------------------------------------------------

func (s *payrollEngineService) InitializeRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("payroll run not found")
	}

	if run.Status != "draft" && run.Status != "failed" {
		return fmt.Errorf("run cannot be initialized in state: %s", run.Status)
	}

	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, run.CompanyID, run.PeriodStart, run.PeriodEnd)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf("payroll period is locked")
	}

	employeeIDs, err := s.payrollRepo.GetEmployeeIDsForPayroll(ctx, run.CompanyID, run.PeriodStart, run.PeriodEnd)
	if err != nil {
		return err
	}

	ok, err := s.payrollRepo.TransitionRunToProcessing(ctx, runID, len(employeeIDs))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("run cannot transition to processing")
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "processing", actorID, nil)
	return nil
}

// ExecuteRun creates employee jobs and moves the run to "executing".
func (s *payrollEngineService) ExecuteRun(
	ctx context.Context,
	runID uuid.UUID,
	actorID uuid.UUID,
) error {

	s.logger.Info("ExecuteRun started",
		zap.String("run_id", runID.String()),
	)

	// ---------------------------------------------------------------------
	// 🔁 Unstick runs that are in 'executing' with no pending employee jobs
	// ---------------------------------------------------------------------
	runCheck, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to fetch run: %w", err)
	}
	if runCheck == nil {
		return fmt.Errorf("run not found")
	}

	if runCheck.Status == "executing" {
		incomplete, err := s.CountRemainingEmployeeJobs(ctx, runID)
		if err != nil {
			return fmt.Errorf("failed to count employee jobs: %w", err)
		}
		if incomplete == 0 {
			s.logger.Info("Run stuck in executing with no pending jobs – finalizing",
				zap.String("run_id", runID.String()))
			// Finalize the run (executing → calculated)
			if err := s.FinalizeRun(ctx, runID, actorID); err != nil {
				return fmt.Errorf("failed to finalize stuck run: %w", err)
			}
			// Run is now 'calculated' – the rest of ExecuteRun will handle it
		} else {
			return fmt.Errorf("run is currently executing with %d pending employee jobs", incomplete)
		}
	}

	// ---------------------------------------------------------------------
	// Original transaction – now the run is either draft, failed, or calculated
	// ---------------------------------------------------------------------
	tx, err := s.payrollRepo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// 1️⃣ Lock payroll run
	run, err := s.payrollRepo.GetPayrollRunForUpdateTx(ctx, tx, runID)
	if err != nil {
		return err
	}
	if run == nil {
		return fmt.Errorf("run not found")
	}

	// 2️⃣ Only allow execution from draft / calculated / failed
	if run.Status == "approved" || run.Status == "paid" {
		return fmt.Errorf("run cannot be executed in state: %s", run.Status)
	}

	// 3️⃣ If rerun from calculated – reset all data and then transition to processing
	if run.Status == "calculated" {
		// 🔥 Reset all existing data for this run to ensure fresh calculation
		if err := s.payrollRepo.ResetPayrollRunDataTx(ctx, tx, runID); err != nil {
			return fmt.Errorf("failed to reset run data before recalc: %w", err)
		}

		ok, err := s.payrollRepo.UpdatePayrollRunStatusIfCurrentTx(
			ctx,
			tx,
			runID,
			"calculated",
			"processing",
		)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("failed to transition run from calculated to processing")
		}
	}

	// 4️⃣ If retrying failed run – cleanup and then transition to processing
	if run.Status == "failed" {
		err = s.payrollRepo.CleanupFailedRunTx(ctx, tx, runID)
		if err != nil {
			return fmt.Errorf("failed to cleanup previous failed run: %w", err)
		}
		ok, err := s.payrollRepo.UpdatePayrollRunStatusIfCurrentTx(
			ctx,
			tx,
			runID,
			"failed",
			"processing",
		)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("failed to transition run from failed to processing")
		}
	}

	// 5️⃣ First run: draft → processing
	if run.Status == "draft" {
		ok, err := s.payrollRepo.UpdatePayrollRunStatusIfCurrentTx(
			ctx,
			tx,
			runID,
			"draft",
			"processing",
		)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("failed to transition run from draft to processing")
		}
	}

	// 6️⃣ Commit TX before heavy operations
	err = tx.Commit()
	if err != nil {
		return err
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "processing", actorID, nil)

	// 7️⃣ Fetch employees for payroll
	employeeIDs, err := s.payrollRepo.GetEmployeeIDsForPayroll(
		ctx,
		run.CompanyID,
		run.PeriodStart,
		run.PeriodEnd,
	)
	if err != nil {
		return err
	}

	s.logger.Info("Employees fetched for payroll run",
		zap.String("run_id", runID.String()),
		zap.Int("employee_count", len(employeeIDs)),
	)

	if len(employeeIDs) == 0 {
		_ = s.payrollRepo.UpdatePayrollRunStatusIfCurrent(
			ctx,
			runID,
			"processing",
			"failed",
		)
		return fmt.Errorf("no eligible employees found")
	}

	// 8️⃣ Create employee payroll jobs
	err = s.jobRepo.CreateEmployeeJobsForRun(ctx, runID, employeeIDs)
	if err != nil {
		return fmt.Errorf("failed creating employee jobs: %w", err)
	}

	s.logger.Info("Employee payroll jobs created",
		zap.String("run_id", runID.String()),
		zap.Int("employee_count", len(employeeIDs)),
	)

	// 9️⃣ Transition run → executing
	err = s.payrollRepo.UpdatePayrollRunStatusIfCurrent(
		ctx,
		runID,
		"processing",
		"executing",
	)
	if err != nil {
		return fmt.Errorf("failed to transition run to executing: %w", err)
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "executing", actorID, nil)

	s.logger.Info("Payroll run execution started",
		zap.String("run_id", runID.String()),
		zap.Int("employees", len(employeeIDs)),
	)

	return nil
}

// ApproveRun locks the payroll period and marks the run as approved.
func (s *payrollEngineService) ApproveRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("run not found")
	}
	if run.Status != "calculated" {
		return fmt.Errorf("run must be calculated before approval")
	}
	reason := "payroll approved"
	lock := &models.PayrollPeriodLock{
		LockID:      uuid.New(),
		CompanyID:   run.CompanyID,
		PeriodStart: run.PeriodStart,
		PeriodEnd:   run.PeriodEnd,
		LockedBy:    &actorID,
		LockedAt:    time.Now().UTC(),
		Reason:      &reason,
	}
	if err := s.payrollRepo.CreatePayrollPeriodLock(ctx, lock); err != nil {
		return err
	}
	if err := s.payrollRepo.UpdatePayrollRunStatus(ctx, runID, "approved"); err != nil {
		return err
	}
	s.auditRunStateChange(ctx, run.CompanyID, runID, "approved", actorID, nil)
	return nil
}

// MarkRunAsPaid sets the run status to "paid".
func (s *payrollEngineService) MarkRunAsPaid(ctx context.Context, runID uuid.UUID, actorID uuid.UUID, paidAt time.Time) error {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("run not found")
	}
	if run.Status != "approved" {
		return fmt.Errorf("run must be approved before payment")
	}
	if err := s.payrollRepo.UpdatePayrollRunStatus(ctx, runID, "paid"); err != nil {
		return err
	}
	s.auditRunStateChange(ctx, run.CompanyID, runID, "paid", actorID, map[string]interface{}{
		"paid_at": paidAt,
	})
	return nil
}

// CancelRun deletes a draft run.
func (s *payrollEngineService) CancelRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("run not found")
	}
	if run.Status != "draft" {
		return fmt.Errorf("only draft runs can be cancelled")
	}
	if err := s.payrollRepo.DeletePayrollRun(ctx, runID); err != nil {
		return err
	}
	s.auditRunStateChange(ctx, run.CompanyID, runID, "draft_deleted", actorID, nil)
	return nil
}

// ---------------------------------------------------------------------
// Employee Processing (split into two phases)
// ---------------------------------------------------------------------

// ProcessEmployee now coordinates the two-phase processing:
//
//	Phase 1: core payroll (earnings, fines, loans, adjustments) → payroll item + non‑statutory ledger
//	Phase 2: statutory deductions + their ledger entries
func (s *payrollEngineService) ProcessEmployee(
	ctx context.Context,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
	reflectLatestAdjustments bool,
	components map[string]*models.PayrollComponent,
	settings *models.CompanyPayrollSettings,
) (err error) {

	s.logger.Info("ProcessEmployee started",
		zap.String("run_id", runID.String()),
		zap.String("user_id", userID.String()),
	)

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Panic Protection
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic recovered in ProcessEmployee",
				zap.String("run_id", runID.String()),
				zap.String("user_id", userID.String()),
				zap.Any("panic", r),
			)
			err = fmt.Errorf("payroll processing panic recovered")
		}
	}()

	if components == nil {
		components = map[string]*models.PayrollComponent{}
	}
	if settings == nil {
		settings = &models.CompanyPayrollSettings{}
	}

	// Phase 1 – Core payroll (no statutory)
	itemID, earningsForStatutory, companyID, periodStart, periodEnd, err := s.processEmployeeCore(
		ctx, runID, userID, actorID,
		reflectLatestAdjustments, components, settings,
	)
	if err != nil {
		return err
	}

	// If itemID is nil, the payroll item already existed (duplicate). Skip statutory phase.
	if itemID == uuid.Nil {
		s.logger.Info("Payroll item already exists, skipping statutory phase",
			zap.String("run_id", runID.String()),
			zap.String("user_id", userID.String()),
		)
		return nil
	}

	// Phase 2 – Statutory (separate transaction)
	if err := s.processEmployeeStatutory(
		ctx, runID, userID, actorID, itemID, earningsForStatutory, companyID, periodStart, periodEnd,
	); err != nil {
		return err
	}

	// ✅ Update run progress (successful employee processed)
	if err := s.payrollRepo.UpdateRunProgress(ctx, runID, 1, 0); err != nil {
		// Log but don't fail the employee processing
		s.logger.Warn("failed to update payroll run progress",
			zap.String("run_id", runID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}

	// Best‑effort attendance lock (original behaviour)
	// Re‑fetch run to get CompanyID (could also use returned companyID)
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		s.logger.Warn("cannot fetch run for attendance lock", zap.Error(err))
	} else {
		if err = s.attendanceBridge.LockAttendanceForPayroll(
			ctx,
			run.CompanyID,
			userID,
			run.PeriodStart,
			run.PeriodEnd,
		); err != nil {
			if strings.Contains(err.Error(), "already payroll locked") {
				s.logger.Warn("attendance already locked, skipping",
					zap.String("run_id", runID.String()),
					zap.String("user_id", userID.String()),
				)
			} else {
				return err
			}
		}
	}

	return nil
}

// processEmployeeCore handles all non‑statutory calculations and commits them in a single transaction.
// Returns:
//   - payroll_item_id
//   - earnings slice (for statutory input)
//   - companyID, periodStart, periodEnd (to avoid extra query in Phase 2)
//   - error
func (s *payrollEngineService) processEmployeeCore(
	ctx context.Context,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
	reflectLatestAdjustments bool,
	components map[string]*models.PayrollComponent,
	settings *models.CompanyPayrollSettings,
) (uuid.UUID, []*models.PayrollLedgerItem, uuid.UUID, time.Time, time.Time, error) {

	tx, err := s.payrollRepo.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, nil, uuid.Nil, time.Time{}, time.Time{}, err
	}
	rollback := func(e error) (uuid.UUID, []*models.PayrollLedgerItem, uuid.UUID, time.Time, time.Time, error) {
		_ = tx.Rollback()
		return uuid.Nil, nil, uuid.Nil, time.Time{}, time.Time{}, e
	}

	// Lock Run
	run, err := s.payrollRepo.GetPayrollRunTx(ctx, tx, runID)
	if err != nil || run == nil {
		return rollback(fmt.Errorf("run not found"))
	}

	// Attendance Summary
	summary, err := s.attendanceBridge.GetPayrollAttendanceSummary(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
	)
	if err != nil {
		return rollback(err)
	}
	if summary == nil {
		s.logger.Warn("attendance summary missing, defaulting to full payable",
			zap.String("user_id", userID.String()),
			zap.String("run_id", runID.String()),
		)
		totalDays := daysBetween(run.PeriodStart, run.PeriodEnd)
		summary = &hrservice.PayrollAttendanceSummary{
			TotalDays:            totalDays,
			PayableDays:          totalDays,
			TotalOvertimeMinutes: 0,
			TotalLossMinutes:     0,
		}
	}

	// Salary Assignments
	assignments, err := s.compensationSvc.GetSalaryAssignmentsInRange(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
	)
	if err != nil {
		return rollback(err)
	}
	if len(assignments) == 0 {
		return rollback(fmt.Errorf("no active salary assignment for employee in period"))
	}

	totalPeriodDays := float64(daysBetween(run.PeriodStart, run.PeriodEnd))

	var allBaseEarnings []*models.PayrollLedgerItem
	var totalGrossBeforeRules float64

	for _, assign := range assignments {
		overlapStart := maxTime(assign.EffectiveFrom, run.PeriodStart)
		overlapEnd := minTimePtr(assign.EffectiveTo, run.PeriodEnd)

		if overlapEnd == nil || overlapEnd.Before(overlapStart) {
			continue
		}

		overlapDays := float64(daysBetween(overlapStart, *overlapEnd))

		fullEarnings, err := s.compensationSvc.ResolveEarnings(
			ctx,
			run.CompanyID,
			userID,
			run.PeriodStart,
			run.PeriodEnd,
			totalPeriodDays,
		)
		if err != nil {
			return rollback(err)
		}

		scaleFactor := overlapDays / totalPeriodDays

		for _, item := range fullEarnings {
			if item.ComponentType == models.ComponentTypeEarning {
				scaled := *item
				scaled.Amount *= scaleFactor
				allBaseEarnings = append(allBaseEarnings, &scaled)
				totalGrossBeforeRules += scaled.Amount
			}
		}
	}

	if len(allBaseEarnings) == 0 {
		return rollback(fmt.Errorf("no earnings resolved for employee – salary structure incomplete"))
	}

	// Attendance Rules
	expectedMinutesPerDay := 480
	attendanceItems, err := s.applyAttendanceRules(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		allBaseEarnings,
		summary,
		expectedMinutesPerDay,
		totalPeriodDays,
		components,
	)
	if err != nil {
		return rollback(err)
	}

	// Fines
	fineItems, err := s.applyEmployeeFines(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		run.PayrollRunID,
		components,
		settings.DefaultFineComponent,
	)
	if err != nil {
		return rollback(err)
	}

	// Arrears
	arrearsItems, err := s.applyArrears(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		run.PayrollRunID,
		components,
		settings.DefaultArrearsComponent,
	)
	if err != nil {
		return rollback(err)
	}

	// Loans
	s.logger.Info("Applying loan EMIs",
		zap.String("run_id", runID.String()),
		zap.String("user_id", userID.String()),
	)
	loanItems, err := s.applyLoanEMIs(
		ctx,
		tx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		run.PayrollRunID,
		components,
		settings.DefaultLoanComponent,
	)
	if err != nil {
		return rollback(err)
	}

	// Combine all non‑statutory items
	allItems := append([]*models.PayrollLedgerItem{}, allBaseEarnings...)
	allItems = append(allItems, attendanceItems...)
	allItems = append(allItems, fineItems...)
	allItems = append(allItems, arrearsItems...)
	allItems = append(allItems, loanItems...)

	// Adjustments
	adjustments, err := s.loadAdjustments(ctx, run, userID, reflectLatestAdjustments)
	if err != nil {
		return rollback(err)
	}
	for _, adj := range adjustments {
		componentType := models.ComponentTypeEarning
		if adj.AdjustmentType == models.AdjustmentTypeDeduction {
			componentType = models.ComponentTypeDeduction
		}
		allItems = append(allItems, &models.PayrollLedgerItem{
			ComponentCode: adj.ComponentCode,
			ComponentType: componentType,
			Amount:        adj.Amount,
		})
	}

	// Compute Totals (excluding statutory)
	var gross, deductions float64
	for _, item := range allItems {
		if item.ComponentType == models.ComponentTypeEarning {
			gross += item.Amount
		} else {
			deductions += item.Amount
		}
	}
	net := gross - deductions

	// Create Payroll Item
	item := &models.PayrollItem{
		PayrollItemID: uuid.New(),
		PayrollRunID:  runID,
		UserID:        userID,
		PayableDays:   float64(summary.PayableDays),
		UnpaidDays:    float64(summary.TotalDays - summary.PayableDays),
		GrossAmount:   gross,
		NetAmount:     net,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.payrollRepo.CreatePayrollItemTx(ctx, tx, item); err != nil {
		if repository.IsUniqueViolation(err) {
			s.logger.Warn("payroll item already exists, skipping",
				zap.String("run_id", runID.String()),
				zap.String("user_id", userID.String()),
			)
			_ = tx.Rollback()
			// Return zero values – Phase 2 must be skipped
			return uuid.Nil, nil, uuid.Nil, time.Time{}, time.Time{}, nil
		}
		return rollback(err)
	}

	// Insert ledger entries for all non‑statutory items
	var ledgerEntries []*models.PayrollLedger
	for _, li := range allItems {
		ledgerEntries = append(ledgerEntries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: item.PayrollItemID,
			ComponentCode: li.ComponentCode,
			Amount:        li.Amount,
			CreatedAt:     time.Now().UTC(),
		})
	}

	if err := s.payrollRepo.BulkCreateLedgerEntriesTx(ctx, tx, ledgerEntries); err != nil {
		return rollback(fmt.Errorf("failed to insert payroll ledger entries: %w", err))
	}

	s.logger.Info("Committing payroll item and ledger entries (core phase)",
		zap.String("run_id", runID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("ledger_entries", len(ledgerEntries)),
	)

	if err := tx.Commit(); err != nil {
		return uuid.Nil, nil, uuid.Nil, time.Time{}, time.Time{}, err
	}

	s.auditEmployeeProcessed(ctx, run.CompanyID, runID, userID, actorID, gross, net, "INR")

	// Return item ID, earnings slice, and run details for Phase 2
	return item.PayrollItemID, filterEarnings(allItems), run.CompanyID, run.PeriodStart, run.PeriodEnd, nil
}

// processEmployeeStatutory executes the statutory engine in its own transaction
// and inserts the resulting ledger entries.
func (s *payrollEngineService) processEmployeeStatutory(
	ctx context.Context,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
	payrollItemID uuid.UUID,
	earnings []*models.PayrollLedgerItem,
	companyID uuid.UUID,
	periodStart time.Time,
	periodEnd time.Time,
) error {

	// Start a new transaction for statutory ledger inserts
	tx, err := s.payrollRepo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Build statutory input (run details already passed)
	statInput := &StatutoryExecutionInput{
		PayrollRunID: runID,
		CompanyID:    companyID,
		UserID:       userID,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
		AsOf:         time.Now().UTC(),
		Earnings:     earnings,
		YTDContext:   nil, // TODO: load YTD if needed
		ActorID:      actorID,
		// TaxExemptAmount and TaxRegime can be loaded from employee declarations if needed
		TaxExemptAmount: 0,
		TaxRegime:       "",
	}

	// Execute statutory (non‑transactional)
	statResult, err := s.statutoryEngine.Execute(ctx, statInput)
	if err != nil {
		s.logger.Error("statutory execution failed",
			zap.String("run_id", runID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("statutory execution completed",
		zap.String("run_id", runID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("employee_deductions", len(statResult.EmployeeDeductions)),
		zap.Int("employer_contributions", len(statResult.EmployerContributions)),
	)

	// Insert statutory ledger entries (only employee deductions)
	var ledgerEntries []*models.PayrollLedger
	for _, li := range statResult.EmployeeDeductions {
		ledgerEntries = append(ledgerEntries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: payrollItemID,
			ComponentCode: li.ComponentCode,
			Amount:        li.Amount,
			CreatedAt:     time.Now().UTC(),
		})
	}

	if len(ledgerEntries) > 0 {
		if err := s.payrollRepo.BulkCreateLedgerEntriesTx(ctx, tx, ledgerEntries); err != nil {
			return fmt.Errorf("failed to insert statutory ledger entries: %w", err)
		}
	}

	// Commit the statutory ledger transaction
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true

	// ✅ Recalculate final net after statutory deductions
	if err := s.payrollRepo.RecalculatePayrollItemNet(ctx, payrollItemID); err != nil {
		s.logger.Warn("failed to recalculate payroll net after statutory",
			zap.String("item_id", payrollItemID.String()),
			zap.Error(err),
		)
	}

	s.logger.Info("Statutory phase committed",
		zap.String("run_id", runID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("statutory_entries", len(ledgerEntries)),
	)

	return nil
}

// filterEarnings returns only the earning items from a slice of ledger items.
func filterEarnings(items []*models.PayrollLedgerItem) []*models.PayrollLedgerItem {
	var out []*models.PayrollLedgerItem
	for _, i := range items {
		if i.ComponentType == models.ComponentTypeEarning {
			out = append(out, i)
		}
	}
	return out
}

// ---------------------------------------------------------------------
// Helper methods (unchanged from original)
// ---------------------------------------------------------------------

func (s *payrollEngineService) applyAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	baseEarnings []*models.PayrollLedgerItem,
	summary *hrservice.PayrollAttendanceSummary,
	expectedMinutesPerDay int,
	totalPeriodDays float64,
	components map[string]*models.PayrollComponent,
) ([]*models.PayrollLedgerItem, error) {
	rules, err := s.attendanceRuleRepo.GetActiveByCompany(ctx, companyID, periodEnd)
	if err != nil {
		s.logger.Info("No active attendance rules found. Skipping attendance adjustments.",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, nil
	}
	if len(rules) == 0 {
		return nil, nil
	}

	var grossBeforeRules float64
	for _, item := range baseEarnings {
		if item.ComponentType == models.ComponentTypeEarning {
			grossBeforeRules += item.Amount
		}
	}

	if totalPeriodDays == 0 {
		return nil, nil
	}
	dailyRate := grossBeforeRules / totalPeriodDays
	hourlyRate := 0.0
	if expectedMinutesPerDay > 0 {
		hourlyRate = dailyRate / (float64(expectedMinutesPerDay) / 60.0)
	}

	totalOvertimeMinutes := summary.TotalOvertimeMinutes
	totalLossMinutes := summary.TotalLossMinutes
	unpaidDays := float64(summary.TotalDays - summary.PayableDays)

	var items []*models.PayrollLedgerItem

	for _, rule := range rules {
		comp, ok := components[rule.ComponentCode]
		if !ok {
			return nil, fmt.Errorf("attendance rule %s references unknown component %s", rule.RuleID, rule.ComponentCode)
		}

		switch rule.RuleType {
		case models.RuleTypeOvertime:
			if totalOvertimeMinutes <= 0 {
				continue
			}
			overtimeHours := float64(totalOvertimeMinutes) / 60.0
			base := hourlyRate
			if rule.BasedOn != nil && *rule.BasedOn == models.BasedOnDaily {
				base = dailyRate
			}
			var amount float64
			switch rule.CalculationType {
			case models.CalculationTypePercentage:
				amount = base * overtimeHours * (rule.Value / 100.0)
			case models.CalculationTypeMultiplier:
				amount = base * overtimeHours * rule.Value
			case models.CalculationTypeFlat:
				amount = rule.Value * overtimeHours
			}
			if amount > 0 {
				items = append(items, &models.PayrollLedgerItem{
					ComponentCode: rule.ComponentCode,
					ComponentType: comp.ComponentType,
					Amount:        amount,
					IsTaxable:     comp.IsTaxable,
				})
			}

		case models.RuleTypeLate:
			if totalLossMinutes < rule.ThresholdMinutes {
				continue
			}
			base := dailyRate
			if rule.BasedOn != nil && *rule.BasedOn == models.BasedOnHourly {
				base = hourlyRate
			}
			var amount float64
			switch rule.CalculationType {
			case models.CalculationTypePercentage:
				amount = base * (rule.Value / 100.0)
			case models.CalculationTypeMultiplier:
				amount = base * rule.Value
			case models.CalculationTypeFlat:
				amount = rule.Value
			}
			if amount > 0 {
				items = append(items, &models.PayrollLedgerItem{
					ComponentCode: rule.ComponentCode,
					ComponentType: comp.ComponentType,
					Amount:        amount,
					IsTaxable:     comp.IsTaxable,
				})
			}

		case models.RuleTypeAbsent:
			if unpaidDays <= 0 {
				continue
			}
			base := dailyRate
			var amount float64
			switch rule.CalculationType {
			case models.CalculationTypeMultiplier:
				amount = base * rule.Value * unpaidDays
			case models.CalculationTypePercentage:
				amount = base * (rule.Value / 100.0) * unpaidDays
			case models.CalculationTypeFlat:
				amount = rule.Value * unpaidDays
			}
			if amount > 0 {
				items = append(items, &models.PayrollLedgerItem{
					ComponentCode: rule.ComponentCode,
					ComponentType: comp.ComponentType,
					Amount:        amount,
					IsTaxable:     comp.IsTaxable,
				})
			}
		}
	}
	return items, nil
}

func (s *payrollEngineService) applyEmployeeFines(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
	components map[string]*models.PayrollComponent,
	defaultFineComponent *string,
) ([]*models.PayrollLedgerItem, error) {
	fines, err := s.employeeFineRepo.LockUnprocessedForPayrollRun(
		ctx,
		companyID,
		periodStart,
		periodEnd,
		payrollRunID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to lock employee fines: %w", err)
	}

	var items []*models.PayrollLedgerItem
	for _, fine := range fines {
		if fine.UserID != userID {
			continue
		}
		code := fine.ComponentCode
		if code == "" && defaultFineComponent != nil {
			code = *defaultFineComponent
		}
		if code == "" {
			return nil, fmt.Errorf("fine %s has no component code and no company default", fine.FineID)
		}
		comp, ok := components[code]
		if !ok {
			return nil, fmt.Errorf("fine component %s not found in company components", code)
		}
		if comp.ComponentType != models.ComponentTypeDeduction {
			s.logger.Warn("fine component is not a deduction type, using anyway", zap.String("code", code))
		}
		items = append(items, &models.PayrollLedgerItem{
			ComponentCode: code,
			ComponentType: comp.ComponentType,
			Amount:        fine.FineAmount,
			IsTaxable:     comp.IsTaxable,
		})
	}
	return items, nil
}

func (s *payrollEngineService) applyArrears(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
	components map[string]*models.PayrollComponent,
	defaultArrearsComponent *string,
) ([]*models.PayrollLedgerItem, error) {
	arrearsList, err := s.arrearsRepo.GetUnprocessedForPayrollRun(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arrears: %w", err)
	}

	var items []*models.PayrollLedgerItem
	for _, ar := range arrearsList {
		if ar.UserID != userID {
			continue
		}
		code := ar.ComponentCode
		if code == "" && defaultArrearsComponent != nil {
			code = *defaultArrearsComponent
		}
		if code == "" {
			return nil, fmt.Errorf("arrears %s has no component code and no company default", ar.ArrearsID)
		}
		comp, ok := components[code]
		if !ok {
			return nil, fmt.Errorf("arrears component %s not found", code)
		}
		if comp.ComponentType != models.ComponentTypeEarning {
			s.logger.Warn("arrears component is not an earning type, using anyway", zap.String("code", code))
		}
		items = append(items, &models.PayrollLedgerItem{
			ComponentCode: code,
			ComponentType: comp.ComponentType,
			Amount:        ar.Amount,
			IsTaxable:     comp.IsTaxable,
		})

		if err := s.arrearsRepo.MarkAsProcessed(ctx, ar.ArrearsID, payrollRunID); err != nil {
			return nil, fmt.Errorf("failed to mark arrears as processed: %w", err)
		}
	}
	return items, nil
}

func (s *payrollEngineService) applyLoanEMIs(
	ctx context.Context,
	tx *sql.Tx,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
	components map[string]*models.PayrollComponent,
	defaultLoanComponent *string,
) ([]*models.PayrollLedgerItem, error) {

	details, err := s.loanRepo.GetPendingEMIsForEmployeeInPeriodWithDetails(
		ctx,
		companyID,
		userID,
		periodStart,
		periodEnd,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch loan EMIs with details: %w", err)
	}

	var items []*models.PayrollLedgerItem

	for _, detail := range details {
		code := detail.ComponentCode
		if code == "" && defaultLoanComponent != nil {
			code = *defaultLoanComponent
		}
		if code == "" {
			return nil, fmt.Errorf(
				"EMI %s has no component code and no company default",
				detail.Emi.EmiID,
			)
		}

		comp, ok := components[code]
		if !ok {
			return nil, fmt.Errorf("loan component %s not found", code)
		}
		if comp.ComponentType != models.ComponentTypeDeduction {
			s.logger.Warn("loan component is not deduction type", zap.String("code", code))
		}

		items = append(items, &models.PayrollLedgerItem{
			ComponentCode: code,
			ComponentType: comp.ComponentType,
			Amount:        detail.Emi.Amount,
			IsTaxable:     comp.IsTaxable,
		})

		s.logger.Info("Processing EMI payment",
			zap.String("run_id", payrollRunID.String()),
			zap.String("user_id", userID.String()),
			zap.String("emi_id", detail.Emi.EmiID.String()),
		)

		paidDate := time.Now().UTC()
		err := s.loanRepo.ProcessEMIPaymentTx(
			ctx,
			tx,
			detail.Emi.EmiID,
			detail.Emi.LoanID,
			paidDate,
			detail.Emi.Amount,
			0.0,
			&payrollRunID,
			"payroll",
		)
		if err != nil {
			return nil, fmt.Errorf("failed to process EMI payment: %w", err)
		}
	}
	return items, nil
}

func (s *payrollEngineService) loadAdjustments(
	ctx context.Context,
	run *models.PayrollRun,
	userID uuid.UUID,
	reflectLatest bool,
) ([]*models.PayrollAdjustment, error) {
	if reflectLatest {
		return s.payrollRepo.GetAdjustmentsForEmployee(
			ctx,
			run.CompanyID,
			userID,
			run.PeriodStart,
			run.PeriodEnd,
		)
	}
	snapshots, err := s.payrollRepo.GetSnapshotsByRun(ctx, run.PayrollRunID)
	if err != nil {
		return nil, err
	}
	for i := len(snapshots) - 1; i >= 0; i-- {
		snap := snapshots[i]
		if snap.SnapshotType != "employee_full_snapshot" {
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal(snap.SnapshotData, &data); err != nil {
			s.logger.Warn("Failed to unmarshal snapshot",
				zap.String("snapshot_id", snap.SnapshotID.String()),
				zap.Error(err))
			continue
		}
		uidStr, ok := data["user_id"].(string)
		if !ok || uidStr != userID.String() {
			continue
		}
		rawAdj, ok := data["adjustments"]
		if !ok {
			return []*models.PayrollAdjustment{}, nil
		}
		bytes, err := json.Marshal(rawAdj)
		if err != nil {
			return nil, fmt.Errorf("failed to re‑marshal adjustments: %w", err)
		}
		var adjustments []*models.PayrollAdjustment
		if err := json.Unmarshal(bytes, &adjustments); err != nil {
			return nil, fmt.Errorf("failed to unmarshal adjustments: %w", err)
		}
		return adjustments, nil
	}
	return []*models.PayrollAdjustment{}, nil
}

func (s *payrollEngineService) ReprocessEmployee(
	ctx context.Context,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
	reflectLatestAdjustments bool,
) error {
	tx, err := s.payrollRepo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	rollback := func(e error) error {
		_ = tx.Rollback()
		return e
	}

	run, err := s.payrollRepo.GetPayrollRunForUpdateTx(ctx, tx, runID)
	if err != nil || run == nil {
		return rollback(fmt.Errorf("run not found"))
	}

	if run.Status != "processing" && run.Status != "executing" {
		return rollback(fmt.Errorf("cannot reprocess in current state: %s", run.Status))
	}

	_, err = s.payrollRepo.SupersedePayrollItemTx(ctx, tx, runID, userID, actorID)
	if err != nil {
		return rollback(err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	components, err := s.componentRepo.GetComponentsByCompany(ctx, run.CompanyID)
	if err != nil {
		return fmt.Errorf("failed to load components for reprocess: %w", err)
	}
	settings, err := s.settingsRepo.GetPayrollSettings(ctx, run.CompanyID)
	if err != nil {
		s.logger.Warn("company payroll settings not found for reprocess, using defaults", zap.Error(err))
		settings = &models.CompanyPayrollSettings{CompanyID: run.CompanyID}
	}

	s.auditEmployeeReprocess(ctx, run.CompanyID, runID, userID, actorID)
	return s.ProcessEmployee(ctx, runID, userID, actorID, reflectLatestAdjustments, components, settings)
}

// ---------------------------------------------------------------------
// NEW: Count remaining employee jobs
// ---------------------------------------------------------------------

func (s *payrollEngineService) CountRemainingEmployeeJobs(ctx context.Context, runID uuid.UUID) (int, error) {
	return s.payrollRepo.CountIncompleteEmployeeJobs(ctx, runID)
}

// ---------------------------------------------------------------------
// NEW: Finalize run (move from executing to calculated)
// ---------------------------------------------------------------------

func (s *payrollEngineService) FinalizeRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("run not found")
	}

	err = s.payrollRepo.UpdatePayrollRunStatusIfCurrent(
		ctx,
		runID,
		"executing",
		"calculated",
	)
	if err != nil {
		return err
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "calculated", actorID, nil)
	s.logger.Info("Payroll run finalized (all employees processed)",
		zap.String("run_id", runID.String()),
	)

	return nil
}

// ---------------------------------------------------------------------
// Status & Helpers
// ---------------------------------------------------------------------

func (s *payrollEngineService) GetRunExecutionStatus(ctx context.Context, runID uuid.UUID) (*PayrollExecutionStatus, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return nil, fmt.Errorf("run not found")
	}
	total := 0
	if run.TotalEmployees != nil {
		total = *run.TotalEmployees
	}
	processed := 0
	if run.ProcessedCount != nil {
		processed = *run.ProcessedCount
	}
	failed := 0
	if run.FailedCount != nil {
		failed = *run.FailedCount
	}
	return &PayrollExecutionStatus{
		RunID:              run.PayrollRunID,
		Status:             run.Status,
		TotalEmployees:     total,
		ProcessedEmployees: processed,
		FailedEmployees:    failed,
		LastProcessedAt:    run.LastProcessedAt,
	}, nil
}

func (s *payrollEngineService) CreateRun(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart time.Time,
	periodEnd time.Time,
	createdBy uuid.UUID,
) (*models.PayrollRun, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("invalid company id")
	}
	if periodEnd.Before(periodStart) {
		return nil, fmt.Errorf("invalid period range")
	}
	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	if locked {
		return nil, fmt.Errorf("payroll period already locked")
	}
	existing, err := s.payrollRepo.GetPayrollRunByPeriod(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("payroll run already exists for this period")
	}
	run := &models.PayrollRun{
		PayrollRunID: uuid.New(),
		CompanyID:    companyID,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
		Status:       "draft",
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    &createdBy,
	}
	if err := s.payrollRepo.CreatePayrollRun(ctx, run); err != nil {
		return nil, err
	}
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"payroll_run_created",
		"payroll_run",
		&run.PayrollRunID,
		"admin",
		&createdBy,
		nil,
		nil,
		map[string]interface{}{
			"period_start": periodStart,
			"period_end":   periodEnd,
		},
	)
	return run, nil
}

// ---------------------------------------------------------------------
// Component Management
// ---------------------------------------------------------------------

func (s *payrollEngineService) CreateComponent(
	ctx context.Context,
	input *models.CreateComponentInput,
	actorID uuid.UUID,
) (*models.PayrollComponent, error) {
	if input.ComponentCode == "" {
		return nil, fmt.Errorf("component_code is required")
	}
	if input.IsSystem {
		return nil, fmt.Errorf("system components cannot be created via API")
	}

	component := &models.PayrollComponent{
		CompanyID:        input.CompanyID,
		ComponentCode:    input.ComponentCode,
		ComponentType:    input.ComponentType,
		Description:      input.Description,
		IsTaxable:        input.IsTaxable,
		IsSystem:         false,
		IsActive:         true,
		ContributionSide: input.ContributionSide,
	}

	err := s.payrollRepo.CreateComponent(ctx, component)
	if err != nil {
		return nil, err
	}

	_ = s.audit.LogAction(
		ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"component_created",
		"payroll_component",
		nil,
		"admin",
		&actorID,
		nil,
		nil,
		map[string]interface{}{
			"component_code": component.ComponentCode,
			"type":           component.ComponentType,
		},
	)

	return component, nil
}

func (s *payrollEngineService) UpdateComponent(
	ctx context.Context,
	input *models.UpdateComponentInput,
	actorID uuid.UUID,
) (*models.PayrollComponent, error) {
	component, err := s.componentRepo.GetComponent(
		ctx,
		input.CompanyID,
		input.ComponentCode,
	)
	if err != nil {
		return nil, err
	}
	if component == nil {
		return nil, fmt.Errorf("component not found")
	}
	if component.IsSystem {
		return nil, fmt.Errorf("system components cannot be modified")
	}

	component.Description = input.Description
	component.IsTaxable = input.IsTaxable
	component.IsActive = input.IsActive
	component.ContributionSide = input.ContributionSide

	err = s.payrollRepo.UpdateComponent(ctx, component)
	if err != nil {
		return nil, err
	}

	_ = s.audit.LogAction(
		ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"component_updated",
		"payroll_component",
		nil,
		"admin",
		&actorID,
		nil,
		nil,
		map[string]interface{}{
			"component_code": component.ComponentCode,
		},
	)

	return component, nil
}

func (s *payrollEngineService) DeactivateComponent(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
	actorID uuid.UUID,
) error {
	component, err := s.componentRepo.GetComponent(ctx, companyID, componentCode)
	if err != nil {
		return err
	}
	if component == nil {
		return fmt.Errorf("component not found")
	}
	if component.IsSystem {
		return fmt.Errorf("system components cannot be deactivated")
	}

	component.IsActive = false

	err = s.payrollRepo.UpdateComponent(ctx, component)
	if err != nil {
		return err
	}

	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"component_deactivated",
		"payroll_component",
		nil,
		"admin",
		&actorID,
		nil,
		nil,
		map[string]interface{}{
			"component_code": componentCode,
		},
	)

	return nil
}

func (s *payrollEngineService) ListComponents(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*models.PayrollComponent, error) {
	return s.payrollRepo.GetComponents(ctx, companyID, models.ComponentFilter{})
}

// ---------------------------------------------------------------------
// Audit Helpers
// ---------------------------------------------------------------------

func (s *payrollEngineService) auditRunStateChange(
	ctx context.Context,
	companyID uuid.UUID,
	runID uuid.UUID,
	newState string,
	actorID uuid.UUID,
	extra map[string]interface{},
) {
	metadata := map[string]interface{}{
		"run_id":    runID.String(),
		"new_state": newState,
	}
	for k, v := range extra {
		metadata[k] = v
	}
	if err := s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"run_state_changed",
		"payroll_run",
		&runID,
		"admin",
		&actorID,
		nil,
		nil,
		metadata,
	); err != nil {
		s.logger.Error("Failed to audit run state change",
			zap.String("run_id", runID.String()),
			zap.Error(err))
	}
}

func (s *payrollEngineService) auditEmployeeProcessed(
	ctx context.Context,
	companyID uuid.UUID,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
	gross, net float64,
	currency string,
) {
	metadata := map[string]interface{}{
		"run_id":   runID.String(),
		"user_id":  userID.String(),
		"gross":    gross,
		"net":      net,
		"currency": currency,
	}
	if err := s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"employee_processed",
		"payroll_item",
		nil,
		"admin",
		&actorID,
		nil,
		nil,
		metadata,
	); err != nil {
		s.logger.Error("Failed to audit employee processing",
			zap.String("run_id", runID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
	}
}

func (s *payrollEngineService) auditEmployeeReprocess(
	ctx context.Context,
	companyID uuid.UUID,
	runID uuid.UUID,
	userID uuid.UUID,
	actorID uuid.UUID,
) {
	metadata := map[string]interface{}{
		"run_id":  runID.String(),
		"user_id": userID.String(),
	}
	if err := s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"employee_reprocessed",
		"payroll_item",
		nil,
		"admin",
		&actorID,
		nil,
		nil,
		metadata,
	); err != nil {
		s.logger.Error("Failed to audit employee reprocess",
			zap.String("run_id", runID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
	}
}

// ---------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------

func daysBetween(start, end time.Time) int {
	return int(end.Sub(start).Hours()/24) + 1
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTimePtr(a *time.Time, b time.Time) *time.Time {
	if a == nil {
		return &b
	}
	if a.Before(b) {
		return a
	}
	return &b
}

func overlapEndTime(assignEnd, periodEnd *time.Time) time.Time {
	if assignEnd == nil {
		return *periodEnd
	}
	if periodEnd == nil {
		return *assignEnd
	}
	if assignEnd.Before(*periodEnd) {
		return *assignEnd
	}
	return *periodEnd
}
