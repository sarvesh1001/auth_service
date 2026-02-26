package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrservice "auth-service/internal/hr/service"
)

// ----------------------------------------------------------------------
// Input / Output Types (Enterprise Ready)
// ----------------------------------------------------------------------

type CreateEmployeeFineInput struct {
	CompanyID uuid.UUID
	UserID    uuid.UUID

	FineAmount float64
	Reason     string
	FineDate   time.Time

	Category  *string // optional future extensibility
	Reference *string // optional (attendance_id, incident_id)

	CreatedBy uuid.UUID
}

type UpdateEmployeeFineInput struct {
	FineID    uuid.UUID
	CompanyID uuid.UUID

	FineAmount *float64
	Reason     *string
	FineDate   *time.Time

	UpdatedBy uuid.UUID
}

type BulkCreateEmployeeFineInput struct {
	CompanyID uuid.UUID
	UserIDs   []uuid.UUID

	FineAmount float64
	Reason     string
	FineDate   time.Time

	CreatedBy uuid.UUID
}

type EmployeeFineSummary struct {
	UserID      uuid.UUID
	TotalFines  float64
	FineCount   int
	Processed   float64
	Unprocessed float64
}

type CompanyFineSummary struct {
	CompanyID   uuid.UUID
	TotalFines  float64
	TotalCount  int
	Processed   float64
	Unprocessed float64
}

// ----------------------------------------------------------------------
// Service Interface (as provided)
// ----------------------------------------------------------------------

type EmployeeFineService interface {
	// Create / Update / Delete
	CreateFine(ctx context.Context, input CreateEmployeeFineInput) (*models.EmployeeFine, error)
	UpdateFine(ctx context.Context, input UpdateEmployeeFineInput) (*models.EmployeeFine, error)
	DeleteFine(ctx context.Context, companyID, fineID, actorID uuid.UUID) error

	// Bulk Operations
	BulkCreateFines(ctx context.Context, input BulkCreateEmployeeFineInput) ([]*models.EmployeeFine, error)
	BulkDeleteUnprocessed(ctx context.Context, companyID uuid.UUID, fineIDs []uuid.UUID, actorID uuid.UUID) error

	// Processing / Payroll Integration
	MarkFineAsProcessed(ctx context.Context, fineID uuid.UUID, payrollRunID uuid.UUID) error
	LockFinesForPayrollRun(
		ctx context.Context,
		companyID uuid.UUID,
		periodStart, periodEnd time.Time,
		payrollRunID uuid.UUID,
	) ([]models.EmployeeFine, error)

	// Retrieval / Queries
	GetFineByID(ctx context.Context, companyID, fineID uuid.UUID) (*models.EmployeeFine, error)
	ListFines(ctx context.Context, filter models.EmployeeFineFilter) ([]models.EmployeeFine, int, error)
	GetEmployeeUnprocessedFines(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		periodStart, periodEnd time.Time,
	) ([]models.EmployeeFine, error)

	// Reporting / Aggregation
	GetFineSummaryByEmployee(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		periodStart, periodEnd time.Time,
	) (*EmployeeFineSummary, error)
	GetCompanyFineSummary(
		ctx context.Context,
		companyID uuid.UUID,
		periodStart, periodEnd time.Time,
	) (*CompanyFineSummary, error)
}

// ----------------------------------------------------------------------
// Service Implementation
// ----------------------------------------------------------------------

type employeeFineService struct {
	fineRepo    repository.EmployeeFineRepository
	payrollRepo repository.PayrollRepository // for period lock checks
	audit       *hrservice.AuditService
	logger      *zap.Logger
}

// NewEmployeeFineService creates a new instance of the service.
func NewEmployeeFineService(
	fineRepo repository.EmployeeFineRepository,
	payrollRepo repository.PayrollRepository,
	audit *hrservice.AuditService,
	logger *zap.Logger,
) EmployeeFineService {
	return &employeeFineService{
		fineRepo:    fineRepo,
		payrollRepo: payrollRepo,
		audit:       audit,
		logger:      logger,
	}
}

// ----------------------------------------------------------------------
// Create / Update / Delete
// ----------------------------------------------------------------------

func (s *employeeFineService) CreateFine(ctx context.Context, input CreateEmployeeFineInput) (*models.EmployeeFine, error) {
	// Validate that the fine date does not fall into a locked payroll period
	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, input.CompanyID, input.FineDate, input.FineDate)
	if err != nil {
		return nil, fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return nil, fmt.Errorf("cannot create fine in a locked payroll period")
	}

	fine := &models.EmployeeFine{
		FineID:      uuid.New(),
		CompanyID:   input.CompanyID,
		UserID:      input.UserID,
		FineAmount:  input.FineAmount,
		Reason:      input.Reason,
		FineDate:    input.FineDate,
		IsProcessed: false,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   input.CreatedBy,
	}

	if err := s.fineRepo.Create(ctx, fine); err != nil {
		return nil, err
	}

	// Audit log
	_ = s.audit.LogAction(ctx, &input.CompanyID, "payroll", "fine_created", "employee_fine",
		&fine.FineID, "admin", &input.CreatedBy, nil, nil, map[string]interface{}{
			"user_id":     input.UserID.String(),
			"fine_amount": input.FineAmount,
			"fine_date":   input.FineDate,
		})

	return fine, nil
}

func (s *employeeFineService) UpdateFine(ctx context.Context, input UpdateEmployeeFineInput) (*models.EmployeeFine, error) {
	// Fetch existing fine
	fine, err := s.fineRepo.GetByID(ctx, input.CompanyID, input.FineID)
	if err != nil {
		return nil, err
	}
	if fine == nil {
		return nil, fmt.Errorf("fine not found")
	}

	// Cannot update processed fine
	if fine.IsProcessed {
		return nil, fmt.Errorf("cannot update a processed fine")
	}

	// Check lock on the fine's date (or new date if provided)
	checkDate := fine.FineDate
	if input.FineDate != nil {
		checkDate = *input.FineDate
	}
	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, input.CompanyID, checkDate, checkDate)
	if err != nil {
		return nil, fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return nil, fmt.Errorf("cannot update fine in a locked payroll period")
	}

	// Apply updates
	if input.FineAmount != nil {
		fine.FineAmount = *input.FineAmount
	}
	if input.Reason != nil {
		fine.Reason = *input.Reason
	}
	if input.FineDate != nil {
		fine.FineDate = *input.FineDate
	}

	if err := s.fineRepo.Update(ctx, fine); err != nil {
		return nil, err
	}

	// Audit log
	_ = s.audit.LogAction(ctx, &input.CompanyID, "payroll", "fine_updated", "employee_fine",
		&fine.FineID, "admin", &input.UpdatedBy, nil, nil, map[string]interface{}{
			"user_id":     fine.UserID.String(),
			"fine_amount": fine.FineAmount,
			"fine_date":   fine.FineDate,
		})

	return fine, nil
}

func (s *employeeFineService) DeleteFine(ctx context.Context, companyID, fineID, actorID uuid.UUID) error {
	// Fetch fine to check lock and state
	fine, err := s.fineRepo.GetByID(ctx, companyID, fineID)
	if err != nil {
		return err
	}
	if fine == nil {
		return fmt.Errorf("fine not found")
	}
	if fine.IsProcessed {
		return fmt.Errorf("cannot delete processed fine")
	}

	// Check lock on the fine's date
	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, companyID, fine.FineDate, fine.FineDate)
	if err != nil {
		return fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return fmt.Errorf("cannot delete fine in a locked payroll period")
	}

	if err := s.fineRepo.DeleteIfUnprocessed(ctx, companyID, fineID); err != nil {
		return err
	}

	// Audit log
	_ = s.audit.LogAction(ctx, &companyID, "payroll", "fine_deleted", "employee_fine",
		&fineID, "admin", &actorID, nil, nil, map[string]interface{}{
			"user_id":     fine.UserID.String(),
			"fine_amount": fine.FineAmount,
			"fine_date":   fine.FineDate,
		})

	return nil
}

// ----------------------------------------------------------------------
// Bulk Operations
// ----------------------------------------------------------------------

func (s *employeeFineService) BulkCreateFines(ctx context.Context, input BulkCreateEmployeeFineInput) ([]*models.EmployeeFine, error) {
	// Validate that the fine date is not locked for any user? We assume all users share the same lock period.
	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, input.CompanyID, input.FineDate, input.FineDate)
	if err != nil {
		return nil, fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return nil, fmt.Errorf("cannot create fines in a locked payroll period")
	}

	var created []*models.EmployeeFine
	for _, userID := range input.UserIDs {
		fine := &models.EmployeeFine{
			FineID:      uuid.New(),
			CompanyID:   input.CompanyID,
			UserID:      userID,
			FineAmount:  input.FineAmount,
			Reason:      input.Reason,
			FineDate:    input.FineDate,
			IsProcessed: false,
			CreatedAt:   time.Now().UTC(),
			CreatedBy:   input.CreatedBy,
		}
		if err := s.fineRepo.Create(ctx, fine); err != nil {
			// Log error but continue? In production we might want a transaction.
			// For simplicity, we stop at first error.
			return nil, fmt.Errorf("failed to create fine for user %s: %w", userID, err)
		}
		created = append(created, fine)
	}

	// Audit log (bulk action)
	_ = s.audit.LogAction(ctx, &input.CompanyID, "payroll", "fines_bulk_created", "employee_fine",
		nil, "admin", &input.CreatedBy, nil, nil, map[string]interface{}{
			"user_count":  len(input.UserIDs),
			"fine_amount": input.FineAmount,
			"fine_date":   input.FineDate,
			"created_ids": createdIDs(created),
		})

	return created, nil
}

func (s *employeeFineService) BulkDeleteUnprocessed(ctx context.Context, companyID uuid.UUID, fineIDs []uuid.UUID, actorID uuid.UUID) error {
	// For each fine, check lock and delete. If any fail, we might want to rollback,
	// but without transaction we just return the first error.
	for _, fid := range fineIDs {
		fine, err := s.fineRepo.GetByID(ctx, companyID, fid)
		if err != nil {
			return err
		}
		if fine == nil {
			return fmt.Errorf("fine %s not found", fid)
		}
		if fine.IsProcessed {
			return fmt.Errorf("fine %s is already processed", fid)
		}
		locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, companyID, fine.FineDate, fine.FineDate)
		if err != nil {
			return fmt.Errorf("failed to check lock for fine %s: %w", fid, err)
		}
		if locked {
			return fmt.Errorf("fine %s lies in a locked payroll period", fid)
		}

		if err := s.fineRepo.DeleteIfUnprocessed(ctx, companyID, fid); err != nil {
			return err
		}
	}

	// Audit log
	_ = s.audit.LogAction(ctx, &companyID, "payroll", "fines_bulk_deleted", "employee_fine",
		nil, "admin", &actorID, nil, nil, map[string]interface{}{
			"fine_ids": fineIDs,
		})

	return nil
}

// ----------------------------------------------------------------------
// Processing / Payroll Integration
// ----------------------------------------------------------------------

func (s *employeeFineService) MarkFineAsProcessed(ctx context.Context, fineID uuid.UUID, payrollRunID uuid.UUID) error {
	// We trust that the caller has already validated the payroll run and lock.
	// The repository method checks is_processed = false.
	err := s.fineRepo.MarkAsProcessed(ctx, fineID, payrollRunID)
	if err != nil {
		return err
	}
	// Audit is done inside the repository? We'll add here.
	s.logger.Info("Fine marked as processed", zap.String("fine_id", fineID.String()), zap.String("payroll_run_id", payrollRunID.String()))
	return nil
}

func (s *employeeFineService) LockFinesForPayrollRun(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
) ([]models.EmployeeFine, error) {
	// This method updates and returns the locked fines.
	return s.fineRepo.LockUnprocessedForPayrollRun(ctx, companyID, periodStart, periodEnd, payrollRunID)
}

// ----------------------------------------------------------------------
// Retrieval / Queries
// ----------------------------------------------------------------------

func (s *employeeFineService) GetFineByID(ctx context.Context, companyID, fineID uuid.UUID) (*models.EmployeeFine, error) {
	return s.fineRepo.GetByID(ctx, companyID, fineID)
}

func (s *employeeFineService) ListFines(ctx context.Context, filter models.EmployeeFineFilter) ([]models.EmployeeFine, int, error) {
	return s.fineRepo.GetByFilter(ctx, filter)
}

func (s *employeeFineService) GetEmployeeUnprocessedFines(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]models.EmployeeFine, error) {
	return s.fineRepo.GetUnprocessedByUserAndPeriod(ctx, companyID, userID, periodStart, periodEnd)
}

// ----------------------------------------------------------------------
// Reporting / Aggregation
// ----------------------------------------------------------------------

func (s *employeeFineService) GetFineSummaryByEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
) (*EmployeeFineSummary, error) {
	// Get all fines for the employee in the period (both processed and unprocessed)
	filter := models.EmployeeFineFilter{
		CompanyID: companyID,
		UserID:    &userID,
		FromDate:  &periodStart,
		ToDate:    &periodEnd,
		Page:      1,
		PageSize:  10000, // large enough for summary; consider pagination if needed
	}
	fines, total, err := s.fineRepo.GetByFilter(ctx, filter)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return &EmployeeFineSummary{
			UserID:      userID,
			TotalFines:  0,
			FineCount:   0,
			Processed:   0,
			Unprocessed: 0,
		}, nil
	}

	var totalFines float64
	var processedTotal float64
	var unprocessedTotal float64
	var processedCount int
	var unprocessedCount int

	for _, f := range fines {
		totalFines += f.FineAmount
		if f.IsProcessed {
			processedTotal += f.FineAmount
			processedCount++
		} else {
			unprocessedTotal += f.FineAmount
			unprocessedCount++
		}
	}

	return &EmployeeFineSummary{
		UserID:      userID,
		TotalFines:  totalFines,
		FineCount:   processedCount + unprocessedCount,
		Processed:   processedTotal,
		Unprocessed: unprocessedTotal,
	}, nil
}

func (s *employeeFineService) GetCompanyFineSummary(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) (*CompanyFineSummary, error) {
	// Fetch all fines for the company in the period
	filter := models.EmployeeFineFilter{
		CompanyID: companyID,
		FromDate:  &periodStart,
		ToDate:    &periodEnd,
		Page:      1,
		PageSize:  10000,
	}
	fines, total, err := s.fineRepo.GetByFilter(ctx, filter)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return &CompanyFineSummary{
			CompanyID:   companyID,
			TotalFines:  0,
			TotalCount:  0,
			Processed:   0,
			Unprocessed: 0,
		}, nil
	}

	var totalFines float64
	var processedTotal float64
	var unprocessedTotal float64
	for _, f := range fines {
		totalFines += f.FineAmount
		if f.IsProcessed {
			processedTotal += f.FineAmount
		} else {
			unprocessedTotal += f.FineAmount
		}
	}

	return &CompanyFineSummary{
		CompanyID:   companyID,
		TotalFines:  totalFines,
		TotalCount:  total,
		Processed:   processedTotal,
		Unprocessed: unprocessedTotal,
	}, nil
}

// ----------------------------------------------------------------------
// Helper
// ----------------------------------------------------------------------

func createdIDs(fines []*models.EmployeeFine) []string {
	ids := make([]string, len(fines))
	for i, f := range fines {
		ids[i] = f.FineID.String()
	}
	return ids
}
