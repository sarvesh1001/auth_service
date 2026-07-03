package repository

import (
	"auth-service/internal/hr/payroll/models"
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type PayrollRepository interface {
	// ==============================
	// Payroll Run
	// ==============================
	CreatePayrollRun(ctx context.Context, run *models.PayrollRun) error
	GetPayrollRunByID(ctx context.Context, runID uuid.UUID) (*models.PayrollRun, error)
	GetPayrollRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error)
	UpdatePayrollRunStatus(ctx context.Context, runID uuid.UUID, status string) error
	DeletePayrollRun(ctx context.Context, runID uuid.UUID) error
	GetPayrollRunSummary(ctx context.Context, runID uuid.UUID) (*models.PayrollRunSummary, error)
	CleanupFailedRun(ctx context.Context, runID uuid.UUID) error

	// ==============================
	// Payroll Items (versioned)
	// ==============================
	CreatePayrollItem(ctx context.Context, item *models.PayrollItem) error
	GetPayrollItemByID(ctx context.Context, itemID uuid.UUID) (*models.PayrollItem, error)
	GetPayrollItemsByRun(ctx context.Context, runID uuid.UUID) ([]*models.PayrollItem, error)
	GetPayrollItemDetail(ctx context.Context, itemID uuid.UUID) (*models.PayrollItemDetail, error)
	BulkCreatePayrollItems(ctx context.Context, items []*models.PayrollItem) error
	SupersedePayrollItemTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID, userID uuid.UUID, actorID uuid.UUID) (int, error)

	// ==============================
	// Payroll Components – now company‑specific
	// ==============================
	CreateComponent(ctx context.Context, component *models.PayrollComponent) error
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)
	GetComponents(ctx context.Context, companyID uuid.UUID, filter models.ComponentFilter) ([]*models.PayrollComponent, error)
	UpdateComponent(ctx context.Context, component *models.PayrollComponent) error
	DeactivateComponent(ctx context.Context, companyID uuid.UUID, code string) error

	// ==============================
	// Payroll Ledger
	// ==============================
	CreateLedgerEntry(ctx context.Context, entry *models.PayrollLedger) error
	GetLedgerEntriesByItem(ctx context.Context, itemID uuid.UUID) ([]*models.PayrollLedger, error)
	GetLedgerSummaryByRun(ctx context.Context, runID uuid.UUID) ([]*models.LedgerSummary, error)
	BulkCreateLedgerEntries(ctx context.Context, entries []*models.PayrollLedger) error

	// ==============================
	// Snapshots
	// ==============================
	CreateSnapshot(ctx context.Context, snapshot *models.PayrollSnapshot) error
	GetSnapshot(ctx context.Context, snapshotID uuid.UUID) (*models.PayrollSnapshot, error)
	GetSnapshotsByRun(ctx context.Context, runID uuid.UUID) ([]*models.PayrollSnapshot, error)

	// ==============================
	// Payroll Lock
	// ==============================
	CreatePayrollPeriodLock(ctx context.Context, lock *models.PayrollPeriodLock) error
	DeletePayrollPeriodLock(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error
	IsPayrollPeriodLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error)
	IsPayrollPeriodLockedRange(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (bool, error)
	ListPayrollLocks(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.PayrollPeriodLock, error)

	// ==============================
	// Attendance & Employee
	// ==============================
	GetPayrollAttendanceDays(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, startDate, endDate time.Time) (float64, float64, error)
	GetEmployeeIDsForPayroll(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]uuid.UUID, error)

	// ==============================
	// Health
	// ==============================
	HealthCheck(ctx context.Context) error

	// ==============================
	// Transactional Helpers & Processing
	// ==============================
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)

	// Payroll run locking
	GetPayrollRunForUpdate(ctx context.Context, runID uuid.UUID) (*models.PayrollRun, error)
	GetPayrollRunForUpdateTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID) (*models.PayrollRun, error)
	UpdatePayrollRunStatusTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID, status string) error

	// Run state transitions
	TransitionRunToProcessing(ctx context.Context, runID uuid.UUID, totalEmployees int) (bool, error)
	TransitionRunToExecutingTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID) (bool, error)
	MarkRunProcessing(ctx context.Context, runID uuid.UUID, totalEmployees int) error
	UpdateRunProgress(ctx context.Context, runID uuid.UUID, processedInc, failedInc int) error

	// Payroll item existence checks (only active items)
	PayrollItemExists(ctx context.Context, runID uuid.UUID, userID uuid.UUID) (bool, error)
	PayrollItemExistsTx(ctx context.Context, tx *sql.Tx, runID uuid.UUID, userID uuid.UUID) (bool, error)

	// Item creation inside transaction (versioned)
	CreatePayrollItemTx(ctx context.Context, tx *sql.Tx, item *models.PayrollItem) error

	// Ledger bulk insert inside transaction
	BulkCreateLedgerEntriesTx(ctx context.Context, tx *sql.Tx, entries []*models.PayrollLedger) error

	// Snapshot inside transaction
	CreateSnapshotTx(ctx context.Context, tx *sql.Tx, snapshot *models.PayrollSnapshot) error

	// Adjustments
	GetAdjustmentsForEmployee(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]*models.PayrollAdjustment, error)
	CreatePayrollAdjustment(ctx context.Context, adjustment *models.PayrollAdjustment) error
	UpdatePayrollAdjustment(ctx context.Context, adjustment *models.PayrollAdjustment) error
	DeletePayrollAdjustment(ctx context.Context, adjustmentID uuid.UUID) error
	GetPayrollAdjustmentByID(ctx context.Context, adjustmentID uuid.UUID) (*models.PayrollAdjustment, error)
	ListPayrollAdjustments(ctx context.Context, filter models.PayrollAdjustmentFilter) ([]*models.PayrollAdjustment, int64, error)
	FinalizeAttendanceForPeriod(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) error

	// Statutory YTD context
	BuildStatutoryYTDContext(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, financialYearStart time.Time) (*models.StatutoryYTDContext, error)
	GetEmployeeIDsByRun(ctx context.Context, runID uuid.UUID) ([]uuid.UUID, error)

	// Payroll run by period
	GetPayrollRunByPeriod(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*models.PayrollRun, error)
	GetPayrollRunByPeriodTx(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, startDate, endDate time.Time) (*models.PayrollRun, error)

	// Lock deletion inside transaction
	DeletePayrollPeriodLockTx(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, periodStart, periodEnd time.Time) error

	// Employee history and YTD
	GetEmployeePayrollHistory(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, from, to time.Time) ([]*models.PayrollItemDetail, error)
	GetEmployeeYTDSummary(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, financialYearStart time.Time, asOf time.Time) (*models.EmployeeYTDSummary, error)

	// Trends and summaries
	GetPayrollTrend(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.PayrollTrendPoint, error)
	GetComponentTrend(ctx context.Context, companyID uuid.UUID, componentCode string, from, to time.Time) ([]*models.ComponentTrendPoint, error)
	GetRunStatutorySummary(ctx context.Context, runID uuid.UUID) ([]*models.StatutoryAggregate, error)
	GetPayableDaysInRange(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (float64, error)
	CleanupFailedRunTx(
		ctx context.Context,
		tx *sql.Tx,
		runID uuid.UUID,
	) error

	UpdatePayrollRunStatusIfCurrentTx(
		ctx context.Context,
		tx *sql.Tx,
		runID uuid.UUID,
		fromStatus string,
		toStatus string,
	) (bool, error)

	UpdatePayrollRunStatusIfCurrent(
		ctx context.Context,
		runID uuid.UUID,
		fromStatus string,
		toStatus string,
	) error
	CountIncompleteEmployeeJobs(ctx context.Context, runID uuid.UUID) (int, error)
	GetPayrollRunTx(
		ctx context.Context,
		tx *sql.Tx,
		runID uuid.UUID,
	) (*models.PayrollRun, error)
	RecalculatePayrollItemNet(ctx context.Context, itemID uuid.UUID) error
	GetPayrollRunExecutionStatus(
		ctx context.Context,
		runID uuid.UUID,
	) (*models.PayrollRun, error)
	ResetPayrollRunDataTx(
		ctx context.Context,
		tx *sql.Tx,
		runID uuid.UUID,
	) error
}
