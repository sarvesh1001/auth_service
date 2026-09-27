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

// ----------------------------------------------------------------------
// Input / Output Types
// ----------------------------------------------------------------------

type CreateEmployeeFineInput struct {
	CompanyID     uuid.UUID
	UserID        uuid.UUID
	FineAmount    float64
	Reason        string
	FineDate      time.Time
	ComponentCode *string
	Category      *string
	Reference     *string
	CreatedBy     uuid.UUID
}

type UpdateEmployeeFineInput struct {
	FineID        uuid.UUID
	CompanyID     uuid.UUID
	FineAmount    *float64
	Reason        *string
	FineDate      *time.Time
	ComponentCode *string
	UpdatedBy     uuid.UUID
}

type BulkCreateEmployeeFineInput struct {
	CompanyID     uuid.UUID
	UserIDs       []uuid.UUID
	FineAmount    float64
	Reason        string
	FineDate      time.Time
	ComponentCode *string
	CreatedBy     uuid.UUID
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
// Service Interface
// ----------------------------------------------------------------------

type EmployeeFineService interface {
	CreateFine(ctx context.Context, input CreateEmployeeFineInput) (*models.EmployeeFine, error)
	UpdateFine(ctx context.Context, input UpdateEmployeeFineInput) (*models.EmployeeFine, error)
	DeleteFine(ctx context.Context, companyID, fineID, actorID uuid.UUID) error
	BulkCreateFines(ctx context.Context, input BulkCreateEmployeeFineInput) ([]*models.EmployeeFine, error)
	BulkDeleteUnprocessed(ctx context.Context, companyID uuid.UUID, fineIDs []uuid.UUID, actorID uuid.UUID) error
	MarkFineAsProcessed(ctx context.Context, fineID uuid.UUID, payrollRunID uuid.UUID) error
	LockFinesForPayrollRun(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, payrollRunID uuid.UUID) ([]models.EmployeeFine, error)
	GetFineByID(ctx context.Context, companyID, fineID uuid.UUID) (*models.EmployeeFine, error)
	ListFines(ctx context.Context, filter models.EmployeeFineFilter) ([]models.EmployeeFine, int, error)
	GetEmployeeUnprocessedFines(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, periodStart, periodEnd time.Time) ([]models.EmployeeFine, error)
	GetFineSummaryByEmployee(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, periodStart, periodEnd time.Time) (*EmployeeFineSummary, error)
	GetCompanyFineSummary(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) (*CompanyFineSummary, error)
}

// ----------------------------------------------------------------------
// Service Implementation
// ----------------------------------------------------------------------

type employeeFineService struct {
	fineRepo         repository.EmployeeFineRepository
	payrollRepo      repository.PayrollRepository
	componentRepo    repository.ComponentRepository
	settingsRepo     repository.CompanySettingsRepository
	employeeRepo     hrRepo.EmployeeRepository
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewEmployeeFineService(
	fineRepo repository.EmployeeFineRepository,
	payrollRepo repository.PayrollRepository,
	componentRepo repository.ComponentRepository,
	settingsRepo repository.CompanySettingsRepository,
	employeeRepo hrRepo.EmployeeRepository,
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
) EmployeeFineService {
	return &employeeFineService{
		fineRepo:         fineRepo,
		payrollRepo:      payrollRepo,
		componentRepo:    componentRepo,
		settingsRepo:     settingsRepo,
		employeeRepo:     employeeRepo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
	}
}

// ensureEmployeeInScope — same pattern as other payroll services.
func (s *employeeFineService) ensureEmployeeInScope(
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

// ----------------------------------------------------------------------
// Helper: resolve component.
//
// Returns the full component struct so the caller can set both ComponentID
// (the surrogate FK written to the DB) and ComponentCode (display / API).
// ----------------------------------------------------------------------

func (s *employeeFineService) resolveComponent(
	ctx context.Context,
	companyID uuid.UUID,
	inputCode *string,
) (*models.PayrollComponent, error) {
	var code string
	if inputCode != nil && *inputCode != "" {
		code = *inputCode
	} else {
		settings, err := s.settingsRepo.GetPayrollSettings(ctx, companyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get company payroll settings: %w", err)
		}
		if settings == nil || settings.DefaultFineComponentCode == nil || *settings.DefaultFineComponentCode == "" {
			return nil, errors.New("no component code provided and no default fine component configured for company")
		}
		code = *settings.DefaultFineComponentCode
	}
	comp, err := s.componentRepo.GetComponent(ctx, companyID, code)
	if err != nil {
		return nil, fmt.Errorf("failed to validate component %s: %w", code, err)
	}
	if comp == nil {
		return nil, fmt.Errorf("component %s not found or inactive", code)
	}
	if comp.ComponentType != models.ComponentTypeDeduction {
		return nil, fmt.Errorf("component %s is of type %s, but fine requires deduction type", code, comp.ComponentType)
	}
	return comp, nil
}

// ----------------------------------------------------------------------
// Create / Update / Delete
// ----------------------------------------------------------------------

func (s *employeeFineService) CreateFine(ctx context.Context, input CreateEmployeeFineInput) (*models.EmployeeFine, error) {
	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fine_create-%s-%s", input.CompanyID.String(), input.UserID.String())
	}
	var cached *models.EmployeeFine
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, input.CompanyID, input.FineDate, input.FineDate)
	if err != nil {
		return nil, fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return nil, fmt.Errorf("cannot create fine in a locked payroll period")
	}

	comp, err := s.resolveComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, err
	}

	fine := &models.EmployeeFine{
		FineID:        uuid.New(),
		CompanyID:     input.CompanyID,
		UserID:        input.UserID,
		ComponentID:   comp.ComponentID,
		ComponentCode: comp.ComponentCode,
		FineAmount:    input.FineAmount,
		Reason:        input.Reason,
		FineDate:      input.FineDate,
		IsProcessed:   false,
		CreatedAt:     time.Now().UTC(),
		CreatedBy:     input.CreatedBy,
	}

	beforeJSON, _ := json.Marshal(fine)
	if err := s.fineRepo.Create(ctx, fine); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(fine)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &input.CompanyID, "payroll", "fine_created", "employee_fine",
		&fine.FineID, "user", &input.CreatedBy, beforeJSON, afterJSON,
		map[string]interface{}{
			"ip":             ip,
			"user_id":        input.UserID.String(),
			"fine_amount":    input.FineAmount,
			"fine_date":      input.FineDate,
			"component_code": comp.ComponentCode,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, fine)
	return fine, nil
}

func (s *employeeFineService) UpdateFine(ctx context.Context, input UpdateEmployeeFineInput) (*models.EmployeeFine, error) {
	fine, err := s.fineRepo.GetByID(ctx, input.CompanyID, input.FineID)
	if err != nil {
		return nil, err
	}
	if fine == nil {
		return nil, fmt.Errorf("fine not found")
	}

	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, fine.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fine_update-%s", input.FineID.String())
	}
	var cached *models.EmployeeFine
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if fine.IsProcessed {
		return nil, fmt.Errorf("cannot update a processed fine")
	}

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

	beforeJSON, _ := json.Marshal(fine)

	if input.ComponentCode != nil && *input.ComponentCode != fine.ComponentCode {
		comp, err := s.resolveComponent(ctx, input.CompanyID, input.ComponentCode)
		if err != nil {
			return nil, err
		}
		fine.ComponentID = comp.ComponentID
		fine.ComponentCode = comp.ComponentCode
	}
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
	afterJSON, _ := json.Marshal(fine)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &input.CompanyID, "payroll", "fine_updated", "employee_fine",
		&fine.FineID, "user", &input.UpdatedBy, beforeJSON, afterJSON,
		map[string]interface{}{
			"ip":             ip,
			"user_id":        fine.UserID.String(),
			"fine_amount":    fine.FineAmount,
			"fine_date":      fine.FineDate,
			"component_code": fine.ComponentCode,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, fine)
	return fine, nil
}

func (s *employeeFineService) DeleteFine(ctx context.Context, companyID, fineID, actorID uuid.UUID) error {
	fine, err := s.fineRepo.GetByID(ctx, companyID, fineID)
	if err != nil {
		return err
	}
	if fine == nil {
		return fmt.Errorf("fine not found")
	}

	if err := s.ensureEmployeeInScope(ctx, companyID, fine.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fine_delete-%s", fineID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if fine.IsProcessed {
		return fmt.Errorf("cannot delete processed fine")
	}

	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, companyID, fine.FineDate, fine.FineDate)
	if err != nil {
		return fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return fmt.Errorf("cannot delete fine in a locked payroll period")
	}

	beforeJSON, _ := json.Marshal(fine)
	if err := s.fineRepo.DeleteIfUnprocessed(ctx, companyID, fineID); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "payroll", "fine_deleted", "employee_fine",
		&fineID, "user", &actorID, beforeJSON, []byte("{}"),
		map[string]interface{}{
			"ip":          ip,
			"user_id":     fine.UserID.String(),
			"fine_amount": fine.FineAmount,
			"fine_date":   fine.FineDate,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ----------------------------------------------------------------------
// Bulk Operations
// ----------------------------------------------------------------------

func (s *employeeFineService) BulkCreateFines(ctx context.Context, input BulkCreateEmployeeFineInput) ([]*models.EmployeeFine, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fines_bulk_create-%s-%s", input.CompanyID.String(), input.FineDate.Format("2006-01-02"))
	}
	var cached []*models.EmployeeFine
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	for _, userID := range input.UserIDs {
		if err := s.ensureEmployeeInScope(ctx, input.CompanyID, userID); err != nil {
			return nil, fmt.Errorf("user %s: %w", userID.String(), err)
		}
	}

	locked, err := s.payrollRepo.IsPayrollPeriodLockedRange(ctx, input.CompanyID, input.FineDate, input.FineDate)
	if err != nil {
		return nil, fmt.Errorf("failed to check payroll lock: %w", err)
	}
	if locked {
		return nil, fmt.Errorf("cannot create fines in a locked payroll period")
	}

	comp, err := s.resolveComponent(ctx, input.CompanyID, input.ComponentCode)
	if err != nil {
		return nil, err
	}

	var created []*models.EmployeeFine
	for _, userID := range input.UserIDs {
		fine := &models.EmployeeFine{
			FineID:        uuid.New(),
			CompanyID:     input.CompanyID,
			UserID:        userID,
			ComponentID:   comp.ComponentID,
			ComponentCode: comp.ComponentCode,
			FineAmount:    input.FineAmount,
			Reason:        input.Reason,
			FineDate:      input.FineDate,
			IsProcessed:   false,
			CreatedAt:     time.Now().UTC(),
			CreatedBy:     input.CreatedBy,
		}
		if err := s.fineRepo.Create(ctx, fine); err != nil {
			return nil, fmt.Errorf("failed to create fine for user %s: %w", userID, err)
		}
		created = append(created, fine)
	}

	afterJSON, _ := json.Marshal(created)
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &input.CompanyID, "payroll", "fines_bulk_created", "employee_fine",
		nil, "user", &input.CreatedBy, []byte("{}"), afterJSON,
		map[string]interface{}{
			"ip":             ip,
			"user_count":     len(input.UserIDs),
			"fine_amount":    input.FineAmount,
			"fine_date":      input.FineDate,
			"component_code": comp.ComponentCode,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, created)
	return created, nil
}

func (s *employeeFineService) BulkDeleteUnprocessed(ctx context.Context, companyID uuid.UUID, fineIDs []uuid.UUID, actorID uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fines_bulk_delete-%s", companyID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	var fines []*models.EmployeeFine
	for _, fid := range fineIDs {
		fine, err := s.fineRepo.GetByID(ctx, companyID, fid)
		if err != nil {
			return err
		}
		if fine == nil {
			return fmt.Errorf("fine %s not found", fid)
		}
		if err := s.ensureEmployeeInScope(ctx, companyID, fine.UserID); err != nil {
			return err
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
		fines = append(fines, fine)
	}

	beforeJSON, _ := json.Marshal(fines)

	for _, fid := range fineIDs {
		if err := s.fineRepo.DeleteIfUnprocessed(ctx, companyID, fid); err != nil {
			return err
		}
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "payroll", "fines_bulk_deleted", "employee_fine",
		nil, "user", &actorID, beforeJSON, []byte("{}"),
		map[string]interface{}{
			"ip":       ip,
			"fine_ids": fineIDs,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ----------------------------------------------------------------------
// Processing / Payroll Integration
// ----------------------------------------------------------------------

func (s *employeeFineService) MarkFineAsProcessed(ctx context.Context, fineID uuid.UUID, payrollRunID uuid.UUID) error {
	fine, err := s.fineRepo.GetByID(ctx, uuid.Nil, fineID)
	if err != nil {
		return err
	}
	if fine == nil {
		return fmt.Errorf("fine not found")
	}

	if err := s.ensureEmployeeInScope(ctx, fine.CompanyID, fine.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fine_mark_processed-%s", fineID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	beforeJSON, _ := json.Marshal(fine)
	if err := s.fineRepo.MarkAsProcessed(ctx, fineID, payrollRunID); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(fine)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &fine.CompanyID, "payroll", "fine_marked_processed", "employee_fine",
		&fineID, "system", nil, beforeJSON, afterJSON,
		map[string]interface{}{
			"ip":             ip,
			"payroll_run_id": payrollRunID.String(),
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// LockFinesForPayrollRun — system operation invoked by the payroll engine.
// Runs company-wide; passes nil so no location filter is applied.
func (s *employeeFineService) LockFinesForPayrollRun(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
) ([]models.EmployeeFine, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("fines_lock-%s", payrollRunID.String())
	}
	var cached []models.EmployeeFine
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	lockedFines, err := s.fineRepo.LockUnprocessedForPayrollRun(ctx, companyID, periodStart, periodEnd, payrollRunID, nil)
	if err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	afterJSON, _ := json.Marshal(lockedFines)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "payroll", "fines_locked_for_payroll", "employee_fine",
		nil, "system", nil, nil, afterJSON,
		map[string]interface{}{
			"ip":             ip,
			"payroll_run_id": payrollRunID.String(),
			"period_start":   periodStart,
			"period_end":     periodEnd,
			"count":          len(lockedFines),
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, lockedFines)
	return lockedFines, nil
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
	filter := models.EmployeeFineFilter{
		CompanyID: companyID,
		UserID:    &userID,
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
		return &EmployeeFineSummary{UserID: userID}, nil
	}
	var totalFines, processedTotal, unprocessedTotal float64
	var processedCount, unprocessedCount int
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
	filter := models.EmployeeFineFilter{
		CompanyID: companyID,
		FromDate:  &periodStart,
		ToDate:    &periodEnd,
		Page:      1,
		PageSize:  10000,
	}

	if locCtx, err := locationctx.FromContext(ctx); err == nil {
		if locCtx.Mode == locationctx.ScopeLocation {
			filter.LocationID = locCtx.LocationID
		}
	}

	fines, total, err := s.fineRepo.GetByFilter(ctx, filter)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return &CompanyFineSummary{CompanyID: companyID}, nil
	}
	var totalFines, processedTotal, unprocessedTotal float64
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
