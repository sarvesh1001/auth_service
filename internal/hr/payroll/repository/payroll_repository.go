package repository

import (
	"auth-service/internal/hr/payroll/models"
	"context"
	"time"

	"github.com/google/uuid"
)

type PayrollRepository interface {
	// Payroll Run
	CreatePayrollRun(ctx context.Context, run *models.PayrollRun) error
	GetPayrollRunByID(ctx context.Context, runID uuid.UUID) (*models.PayrollRun, error)
	GetPayrollRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error)
	UpdatePayrollRunStatus(ctx context.Context, runID uuid.UUID, status string) error
	DeletePayrollRun(ctx context.Context, runID uuid.UUID) error
	GetPayrollRunSummary(ctx context.Context, runID uuid.UUID) (*models.PayrollRunSummary, error)

	// Payroll Items
	CreatePayrollItem(ctx context.Context, item *models.PayrollItem) error
	GetPayrollItemByID(ctx context.Context, itemID uuid.UUID) (*models.PayrollItem, error)
	GetPayrollItemsByRun(ctx context.Context, runID uuid.UUID) ([]*models.PayrollItem, error)
	GetPayrollItemDetail(ctx context.Context, itemID uuid.UUID) (*models.PayrollItemDetail, error)
	DeletePayrollItem(ctx context.Context, itemID uuid.UUID) error
	BulkCreatePayrollItems(ctx context.Context, items []*models.PayrollItem) error

	// Payroll Components
	CreateComponent(ctx context.Context, component *models.PayrollComponent) error
	GetComponent(ctx context.Context, code string) (*models.PayrollComponent, error)
	GetComponents(ctx context.Context, filter models.ComponentFilter) ([]*models.PayrollComponent, error)
	UpdateComponent(ctx context.Context, component *models.PayrollComponent) error
	DeactivateComponent(ctx context.Context, code string) error

	// Payroll Ledger
	CreateLedgerEntry(ctx context.Context, entry *models.PayrollLedger) error
	GetLedgerEntriesByItem(ctx context.Context, itemID uuid.UUID) ([]*models.PayrollLedger, error)
	GetLedgerSummaryByRun(ctx context.Context, runID uuid.UUID) ([]*models.LedgerSummary, error)
	BulkCreateLedgerEntries(ctx context.Context, entries []*models.PayrollLedger) error

	// Tax Profiles
	CreateTaxProfile(ctx context.Context, profile *models.TaxProfile) error
	GetTaxProfile(ctx context.Context, profileID uuid.UUID) (*models.TaxProfile, error)
	GetTaxProfiles(ctx context.Context, filter models.TaxProfileFilter) ([]*models.TaxProfile, error)
	UpdateTaxProfile(ctx context.Context, profile *models.TaxProfile) error
	DeactivateTaxProfile(ctx context.Context, profileID uuid.UUID) error

	// Tax Rules
	CreateTaxRule(ctx context.Context, rule *models.TaxRule) error
	GetTaxRule(ctx context.Context, ruleID uuid.UUID) (*models.TaxRule, error)
	GetTaxRulesByProfile(ctx context.Context, profileID uuid.UUID) ([]*models.TaxRule, error)
	GetTaxRulesByComponent(ctx context.Context, companyID uuid.UUID, componentCode string) ([]*models.TaxRule, error)
	UpdateTaxRule(ctx context.Context, rule *models.TaxRule) error
	DeleteTaxRule(ctx context.Context, ruleID uuid.UUID) error

	// Snapshots
	CreateSnapshot(ctx context.Context, snapshot *models.PayrollSnapshot) error
	GetSnapshot(ctx context.Context, snapshotID uuid.UUID) (*models.PayrollSnapshot, error)
	GetSnapshotsByRun(ctx context.Context, runID uuid.UUID) ([]*models.PayrollSnapshot, error)

	// Health Check
	HealthCheck(ctx context.Context) error

	// Lock/Unlock for payroll processing
	LockPayrollPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error
	UnlockPayrollPeriod(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) error
	IsPeriodLocked(ctx context.Context, companyID uuid.UUID, date time.Time) (bool, error)
	GetEmployeeIDsForPayroll(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]uuid.UUID, error)
	IsPeriodLockedRange(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) (bool, error)
	// Get attendance days for payroll
	GetPayrollAttendanceDays(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, startDate, endDate time.Time) (float64, float64, error)
}
