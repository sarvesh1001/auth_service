package service

import (
	"context"
	"time"

	"auth-service/internal/hr/payroll/models"

	"github.com/google/uuid"
)

type PayrollQueryService interface {
	// Existing methods
	GetRunSummary(ctx context.Context, companyID, runID uuid.UUID) (*models.PayrollRunDashboard, error)
	ListRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error)
	GetRunLedgerSummary(ctx context.Context, companyID, runID uuid.UUID) ([]*models.LedgerSummary, error)
	GetRunExecutionStatus(ctx context.Context, companyID, runID uuid.UUID) (*models.PayrollExecutionStatus, error)
	GetEmployeePayrollDetail(ctx context.Context, companyID, payrollItemID uuid.UUID) (*models.PayrollItemDetail, error)
	ListEmployeesInRun(ctx context.Context, companyID, runID uuid.UUID) ([]*models.PayrollItem, error)
	GetEmployeePayrollHistory(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]*models.PayrollItemDetail, error)
	GetEmployeeYTD(ctx context.Context, companyID, userID uuid.UUID, financialYearStart time.Time) (*models.EmployeeYTDSummary, error)
	GetEmployeeStatutorySummary(ctx context.Context, companyID, userID uuid.UUID, financialYearStart time.Time) (*models.EmployeeStatutorySummary, error)
	GetRunStatutorySummary(ctx context.Context, companyID, runID uuid.UUID) ([]*models.StatutoryAggregate, error)
	GetCompanyPayrollTrend(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.PayrollTrendPoint, error)
	GetComponentBreakdownTrend(ctx context.Context, companyID uuid.UUID, componentCode string, from, to time.Time) ([]*models.ComponentTrendPoint, error)
	GetEmployeePayslip(ctx context.Context, companyID, payrollItemID uuid.UUID) (*models.Payslip, error)
	ExportRunToCSV(ctx context.Context, companyID, runID uuid.UUID) ([]byte, error)

	// New methods for missing features
	ExportBankFile(ctx context.Context, companyID, runID uuid.UUID, bankFormat string) ([]byte, error)
}
