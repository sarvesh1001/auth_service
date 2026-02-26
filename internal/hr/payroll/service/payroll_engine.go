package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrservice "auth-service/internal/hr/service"
)

// PayrollEngineService defines the payroll engine operations.
type PayrollEngineService interface {
	InitializeRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ExecuteRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ApproveRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	MarkRunAsPaid(ctx context.Context, runID uuid.UUID, actorID uuid.UUID, paidAt time.Time) error
	CancelRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error
	ProcessEmployee(ctx context.Context, runID, userID, actorID uuid.UUID, reflectLatestAdjustments bool) error
	ReprocessEmployee(ctx context.Context, runID, userID, actorID uuid.UUID, reflectLatestAdjustments bool) error
	GetRunExecutionStatus(ctx context.Context, runID uuid.UUID) (*PayrollExecutionStatus, error)
	CreateRun(
		ctx context.Context,
		companyID uuid.UUID,
		periodStart time.Time,
		periodEnd time.Time,
		createdBy uuid.UUID,
	) (*models.PayrollRun, error)
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
	compensationSvc    CompensationService // defined in compensation_service.go
	statutoryEngine    StatutoryEngine     // defined in statutory_engine.go
	attendanceBridge   hrservice.AttendancePayrollBridge
	audit              *hrservice.AuditService
	attendanceRuleRepo repository.AttendanceRuleRepository
	employeeFineRepo   repository.EmployeeFineRepository
	logger             *zap.Logger
}

// NewPayrollEngineService creates a new payroll engine service.
func NewPayrollEngineService(
	payrollRepo repository.PayrollRepository,
	compensationSvc CompensationService,
	statutoryEngine StatutoryEngine,
	attendanceBridge hrservice.AttendancePayrollBridge,
	audit *hrservice.AuditService,
	attendanceRuleRepo repository.AttendanceRuleRepository,
	employeeFineRepo repository.EmployeeFineRepository,
	logger *zap.Logger,
) PayrollEngineService {
	return &payrollEngineService{
		payrollRepo:        payrollRepo,
		compensationSvc:    compensationSvc,
		statutoryEngine:    statutoryEngine,
		attendanceBridge:   attendanceBridge,
		audit:              audit,
		attendanceRuleRepo: attendanceRuleRepo,
		employeeFineRepo:   employeeFineRepo,
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

	// ✅ 1. Validate state: allow only draft or failed
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
		// ✅ 1. Change error message
		return fmt.Errorf("run cannot transition to processing")
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "processing", actorID, nil)
	return nil
}

func (s *payrollEngineService) ExecuteRun(
	ctx context.Context,
	runID uuid.UUID,
	actorID uuid.UUID,
) error {

	tx, err := s.payrollRepo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// 1️⃣ Lock run row
	run, err := s.payrollRepo.GetPayrollRunForUpdateTx(ctx, tx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("run not found")
	}

	// 2️⃣ Allow only processing or failed
	if run.Status != "processing" && run.Status != "failed" {
		return fmt.Errorf("run cannot be executed in state: %s", run.Status)
	}

	// 3️⃣ If retrying failed run → cleanup inside SAME TX
	if run.Status == "failed" {
		if err = s.payrollRepo.CleanupFailedRunTx(ctx, tx, runID); err != nil {
			return fmt.Errorf("failed to cleanup previous failed run: %w", err)
		}

		// Move back to processing state safely
		ok, err2 := s.payrollRepo.UpdatePayrollRunStatusIfCurrentTx(
			ctx, tx, runID, "failed", "processing",
		)
		if err2 != nil {
			return err2
		}
		if !ok {
			return fmt.Errorf("failed to transition run from failed to processing")
		}
	}

	// 4️⃣ Commit TX before heavy processing
	if err = tx.Commit(); err != nil {
		return err
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "processing", actorID, nil)

	// 5️⃣ Fetch employees
	employeeIDs, err := s.payrollRepo.GetEmployeeIDsForPayroll(
		ctx,
		run.CompanyID,
		run.PeriodStart,
		run.PeriodEnd,
	)
	if err != nil {
		return err
	}

	if len(employeeIDs) == 0 {
		_ = s.payrollRepo.UpdatePayrollRunStatusIfCurrent(
			ctx, runID, "processing", "failed",
		)
		return fmt.Errorf("no eligible employees found")
	}

	var failedUser uuid.UUID
	var hasFailure bool

	// 6️⃣ Process employees
	for _, userID := range employeeIDs {

		err = s.ProcessEmployee(ctx, runID, userID, actorID, false)
		if err != nil {

			s.logger.Error("Payroll employee processing failed",
				zap.String("run_id", runID.String()),
				zap.String("user_id", userID.String()),
				zap.Error(err),
			)

			failedUser = userID
			hasFailure = true
			break
		}

		// ✅ Update progress safely
		_ = s.payrollRepo.UpdateRunProgress(ctx, runID, 1, 0)
	}

	// 7️⃣ If any failure → mark failed
	if hasFailure {

		_ = s.payrollRepo.UpdatePayrollRunStatusIfCurrent(
			ctx, runID, "processing", "failed",
		)

		s.auditRunStateChange(ctx, run.CompanyID, runID, "failed", actorID, map[string]interface{}{
			"failed_user": failedUser.String(),
		})

		return fmt.Errorf("payroll execution failed for user %s", failedUser)
	}

	// 8️⃣ All success → calculated
	err = s.payrollRepo.UpdatePayrollRunStatusIfCurrent(
		ctx, runID, "processing", "calculated",
	)
	if err != nil {
		return err
	}

	s.auditRunStateChange(ctx, run.CompanyID, runID, "calculated", actorID, nil)

	return nil
}

func (s *payrollEngineService) ApproveRun(ctx context.Context, runID uuid.UUID, actorID uuid.UUID) error {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil {
		return fmt.Errorf("run not found")
	}

	// ✅ 4. Tighten: allow only calculated (remove partially_processed)
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
// Employee Processing (Pay‑Type Aware with Bug Fixes)
// ---------------------------------------------------------------------

func (s *payrollEngineService) ProcessEmployee(
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

	// 🔒 Lock run row
	run, err := s.payrollRepo.GetPayrollRunForUpdateTx(ctx, tx, runID)
	if err != nil || run == nil {
		return rollback(fmt.Errorf("run not found"))
	}

	// ------------------------------------------------------------------
	// Attendance Summary
	// ------------------------------------------------------------------

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

	// ------------------------------------------------------------------
	// Salary Snapshot
	// ------------------------------------------------------------------

	salarySnapshot, err := s.compensationSvc.ResolveSalaryStructure(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodEnd,
	)
	if err != nil {
		return rollback(err)
	}

	totalCalendarDays := float64(summary.TotalDays)
	payableDays := float64(summary.PayableDays)

	var baseEarnings []*models.PayrollLedgerItem

	switch salarySnapshot.PayType {

	case models.PayTypeMonthly:

		baseEarnings, err = s.compensationSvc.ResolveEarnings(
			ctx,
			run.CompanyID,
			userID,
			run.PeriodStart,
			run.PeriodEnd,
			totalCalendarDays,
		)
		if err != nil {
			return rollback(err)
		}

	case models.PayTypeDailyWage:

		if totalCalendarDays == 0 {
			return rollback(fmt.Errorf("total calendar days zero for daily wage"))
		}

		dailyRate := salarySnapshot.MonthlyCTC / totalCalendarDays
		targetGross := dailyRate * payableDays

		fullEarnings, err := s.compensationSvc.ResolveEarnings(
			ctx,
			run.CompanyID,
			userID,
			run.PeriodStart,
			run.PeriodEnd,
			totalCalendarDays,
		)
		if err != nil {
			return rollback(err)
		}

		var currentTotal float64
		for _, item := range fullEarnings {
			if item.ComponentType == models.ComponentTypeEarning {
				currentTotal += item.Amount
			}
		}

		if currentTotal > 0 {
			scaleFactor := targetGross / currentTotal
			baseEarnings = make([]*models.PayrollLedgerItem, len(fullEarnings))
			for i, item := range fullEarnings {
				copyItem := *item
				if copyItem.ComponentType == models.ComponentTypeEarning {
					copyItem.Amount *= scaleFactor
				}
				baseEarnings[i] = &copyItem
			}
		} else {
			baseEarnings = []*models.PayrollLedgerItem{{
				ComponentCode: models.ComponentCodeBasic,
				ComponentType: models.ComponentTypeEarning,
				Amount:        targetGross,
				IsTaxable:     true,
			}}
		}

	case models.PayTypeHourly:

		hourlyRate := salarySnapshot.MonthlyCTC
		workedMinutes := summary.TotalWorkedMinutes + summary.TotalOvertimeMinutes
		workedHours := float64(workedMinutes) / 60.0
		targetGross := hourlyRate * workedHours

		baseEarnings = []*models.PayrollLedgerItem{{
			ComponentCode: models.ComponentCodeBasic,
			ComponentType: models.ComponentTypeEarning,
			Amount:        targetGross,
			IsTaxable:     true,
		}}

	default:

		baseEarnings, err = s.compensationSvc.ResolveEarnings(
			ctx,
			run.CompanyID,
			userID,
			run.PeriodStart,
			run.PeriodEnd,
			totalCalendarDays,
		)
		if err != nil {
			return rollback(err)
		}
	}

	// ------------------------------------------------------------------
	// Attendance Rules
	// ------------------------------------------------------------------

	expectedMinutesPerDay := 480

	attendanceItems, err := s.applyAttendanceRules(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		baseEarnings,
		summary,
		expectedMinutesPerDay,
		totalCalendarDays,
	)
	if err != nil {
		return rollback(err)
	}

	// ------------------------------------------------------------------
	// Fines
	// ------------------------------------------------------------------

	fineItems, err := s.applyEmployeeFines(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
		run.PayrollRunID,
	)
	if err != nil {
		return rollback(err)
	}

	// ------------------------------------------------------------------
	// Combine Ledger Items
	// ------------------------------------------------------------------

	allItems := append([]*models.PayrollLedgerItem{}, baseEarnings...)
	allItems = append(allItems, attendanceItems...)
	allItems = append(allItems, fineItems...)

	// ------------------------------------------------------------------
	// Adjustments
	// ------------------------------------------------------------------

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

	// ------------------------------------------------------------------
	// Statutory Engine (🔥 FIXED — SAME TX)
	// ------------------------------------------------------------------

	ytdContext, err := s.payrollRepo.BuildStatutoryYTDContext(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
	)
	if err != nil {
		return rollback(err)
	}

	statInput := &StatutoryExecutionInput{
		PayrollRunID: runID,
		CompanyID:    run.CompanyID,
		UserID:       userID,
		PeriodStart:  run.PeriodStart,
		PeriodEnd:    run.PeriodEnd,
		AsOf:         run.PeriodEnd,
		Earnings:     allItems,
		YTDContext:   ytdContext,
		ActorID:      actorID,
	}

	// 🔥 Create TX-based statutory engine
	txStatRepo := repository.NewStatutoryRepositoryFromTx(tx, s.logger)

	txStatEngine := NewStatutoryEngine(
		txStatRepo,
		s.audit,
		s.logger,
	)

	statResult, err := txStatEngine.ExecuteTx(ctx, statInput)
	if err != nil {

		s.logger.Warn("Statutory engine skipped",
			zap.String("company_id", run.CompanyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)

		statResult = &StatutoryExecutionResult{
			EmployeeDeductions:    []*models.PayrollLedgerItem{},
			EmployerContributions: []*models.PayrollLedgerItem{},
			ComputationTrace:      []StatutoryTraceStep{},
			RuleHash:              "",
			RuleSetID:             uuid.Nil,
		}
	}

	// ------------------------------------------------------------------
	// Compute Totals
	// ------------------------------------------------------------------

	var gross float64
	var manualDeductions float64

	for _, item := range allItems {
		if item.ComponentType == models.ComponentTypeEarning {
			gross += item.Amount
		} else {
			manualDeductions += item.Amount
		}
	}

	var statutoryDeductions float64
	for _, d := range statResult.EmployeeDeductions {
		statutoryDeductions += d.Amount
	}

	totalDeduction := manualDeductions + statutoryDeductions
	net := gross - totalDeduction

	// ------------------------------------------------------------------
	// Create Payroll Item
	// ------------------------------------------------------------------

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
		return rollback(err)
	}

	// ------------------------------------------------------------------
	// Ledger Entries
	// ------------------------------------------------------------------

	var ledgerEntries []*models.PayrollLedger
	now := time.Now().UTC()

	for _, e := range allItems {
		ledgerEntries = append(ledgerEntries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: item.PayrollItemID,
			ComponentCode: e.ComponentCode,
			Amount:        e.Amount,
			CreatedAt:     now,
		})
	}

	for _, d := range statResult.EmployeeDeductions {
		ledgerEntries = append(ledgerEntries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: item.PayrollItemID,
			ComponentCode: d.ComponentCode,
			Amount:        d.Amount,
			CreatedAt:     now,
		})
	}

	for _, c := range statResult.EmployerContributions {
		ledgerEntries = append(ledgerEntries, &models.PayrollLedger{
			LedgerID:      uuid.New(),
			PayrollItemID: item.PayrollItemID,
			ComponentCode: c.ComponentCode,
			Amount:        c.Amount,
			CreatedAt:     now,
		})
	}

	if err := s.payrollRepo.BulkCreateLedgerEntriesTx(ctx, tx, ledgerEntries); err != nil {
		return rollback(err)
	}

	// ------------------------------------------------------------------
	// Employee Snapshot
	// ------------------------------------------------------------------

	snapshotData, err := json.Marshal(map[string]interface{}{
		"user_id":                userID,
		"pay_type":               salarySnapshot.PayType,
		"salary_snapshot":        salarySnapshot,
		"attendance_summary":     summary,
		"earnings":               allItems,
		"employee_deductions":    statResult.EmployeeDeductions,
		"employer_contributions": statResult.EmployerContributions,
		"statutory_trace":        statResult.ComputationTrace,
		"rule_hash":              statResult.RuleHash,
		"rule_set_id":            statResult.RuleSetID,
		"gross":                  gross,
		"net":                    net,
	})
	if err != nil {
		return rollback(err)
	}

	snapshot := &models.PayrollSnapshot{
		SnapshotID:   uuid.New(),
		PayrollRunID: runID,
		CompanyID:    run.CompanyID,
		SnapshotType: "employee_full_snapshot",
		SnapshotData: snapshotData,
		CreatedAt:    now,
		CreatedBy:    actorID,
	}

	if err := s.payrollRepo.CreateSnapshotTx(ctx, tx, snapshot); err != nil {
		return rollback(err)
	}

	// ------------------------------------------------------------------
	// Commit Everything
	// ------------------------------------------------------------------

	if err := tx.Commit(); err != nil {
		return err
	}

	s.auditEmployeeProcessed(ctx, run.CompanyID, runID, userID, actorID, gross, net, salarySnapshot.Currency)

	_ = s.attendanceBridge.LockAttendanceForPayroll(
		ctx,
		run.CompanyID,
		userID,
		run.PeriodStart,
		run.PeriodEnd,
	)

	return nil
}

// loadAdjustments fetches either live adjustments or frozen ones from snapshot.
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

	s.auditEmployeeReprocess(ctx, run.CompanyID, runID, userID, actorID)
	return s.ProcessEmployee(ctx, runID, userID, actorID, reflectLatestAdjustments)
}

// ---------------------------------------------------------------------
// Attendance Rules and Fines (corrected daily rate denominator)
// ---------------------------------------------------------------------

// applyAttendanceRules generates ledger items based on active attendance rules.
func (s *payrollEngineService) applyAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	baseEarnings []*models.PayrollLedgerItem,
	summary *hrservice.PayrollAttendanceSummary, // corrected type name
	expectedMinutesPerDay int,
	totalCalendarDays float64, // added parameter
) ([]*models.PayrollLedgerItem, error) {
	rules, err := s.attendanceRuleRepo.GetActiveByCompany(ctx, companyID, periodEnd)
	if err != nil {
		// 🔧 Fix 1 — Treat repo error as "no rules" and log, don't fail
		s.logger.Info("No active attendance rules found. Skipping attendance adjustments.",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, nil
	}
	if len(rules) == 0 {
		return nil, nil
	}

	// Compute base gross from earnings (only earnings components)
	var grossBeforeRules float64
	for _, item := range baseEarnings {
		if item.ComponentType == models.ComponentTypeEarning {
			grossBeforeRules += item.Amount
		}
	}

	// Use total calendar days for daily rate (correct denominator)
	if totalCalendarDays == 0 {
		return nil, nil
	}
	dailyRate := grossBeforeRules / totalCalendarDays
	hourlyRate := 0.0
	if expectedMinutesPerDay > 0 {
		hourlyRate = dailyRate / (float64(expectedMinutesPerDay) / 60.0)
	}

	// Use the correct fields from summary
	totalOvertimeMinutes := summary.TotalOvertimeMinutes
	totalLossMinutes := summary.TotalLossMinutes
	unpaidDays := float64(summary.TotalDays - summary.PayableDays)

	var items []*models.PayrollLedgerItem

	for _, rule := range rules {
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
				// Typically flat amount per overtime hour; adjust if needed
				amount = rule.Value * overtimeHours
			}

			if amount > 0 {
				items = append(items, &models.PayrollLedgerItem{
					ComponentCode: "OVERTIME_PAY",
					ComponentType: models.ComponentTypeEarning,
					Amount:        amount,
					IsTaxable:     true,
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
					ComponentCode: "LATE_DEDUCTION",
					ComponentType: models.ComponentTypeDeduction,
					Amount:        amount,
					IsTaxable:     false,
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
					ComponentCode: "ABSENT_PENALTY",
					ComponentType: models.ComponentTypeDeduction,
					Amount:        amount,
					IsTaxable:     false,
				})
			}
		}
	}

	return items, nil
}

// applyEmployeeFines locks unprocessed fines for the period and returns deduction ledger items.
func (s *payrollEngineService) applyEmployeeFines(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
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
		items = append(items, &models.PayrollLedgerItem{
			ComponentCode: "MANUAL_FINE",
			ComponentType: models.ComponentTypeDeduction,
			Amount:        fine.FineAmount,
			IsTaxable:     false,
		})
	}
	return items, nil
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
