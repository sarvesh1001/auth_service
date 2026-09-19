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

// TaxDeclarationService defines the interface for tax declaration operations.
type TaxDeclarationService interface {
	CreateDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode, description string, maxLimit *float64, createdBy uuid.UUID) (*models.TaxDeclarationType, error)
	UpdateDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode, description string, maxLimit *float64, isActive bool, updatedBy uuid.UUID) (*models.TaxDeclarationType, error)
	ListDeclarationTypes(ctx context.Context, companyID uuid.UUID) ([]models.TaxDeclarationType, error)
	GetDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode string) (*models.TaxDeclarationType, error)

	CreateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error)
	UpdateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error)
	VerifyDeclaration(ctx context.Context, declarationID uuid.UUID, verifiedBy uuid.UUID, status string) (*models.TaxDeclaration, error)
	ListDeclarationsByUser(ctx context.Context, companyID, userID uuid.UUID, financialYear string) ([]models.TaxDeclaration, error)

	// ListDeclarationsByFinancialYear — location filter applies when locationID != nil.
	ListDeclarationsByFinancialYear(
		ctx context.Context,
		companyID uuid.UUID,
		financialYear string,
		status *string,
		locationID *uuid.UUID,
	) ([]models.TaxDeclaration, error)

	GetTotalDeclaredAmount(ctx context.Context, companyID, userID uuid.UUID, financialYear string, onlyVerified bool) (float64, error)
}

type taxDeclarationService struct {
	repo             repository.TaxDeclarationRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewTaxDeclarationService(
	repo repository.TaxDeclarationRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
) TaxDeclarationService {
	return &taxDeclarationService{
		repo:             repo,
		employeeRepo:     employeeRepo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
	}
}

// ensureEmployeeInScope — same helper pattern.
func (s *taxDeclarationService) ensureEmployeeInScope(
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

// ------------------------------------------------------------------------------
// Declaration Type Management — company catalog, no location dimension
// ------------------------------------------------------------------------------

func (s *taxDeclarationService) CreateDeclarationType(
	ctx context.Context,
	companyID uuid.UUID,
	typeCode, description string,
	maxLimit *float64,
	createdBy uuid.UUID,
) (*models.TaxDeclarationType, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("tax_decl_type_create-%s-%s", companyID.String(), typeCode)
	}
	var cached *models.TaxDeclarationType
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if companyID == uuid.Nil || typeCode == "" || description == "" || createdBy == uuid.Nil {
		return nil, errors.New("invalid input: missing required fields")
	}

	existing, err := s.repo.GetDeclarationType(ctx, companyID, typeCode)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing type: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("declaration type %s already exists for this company", typeCode)
	}

	dt := &models.TaxDeclarationType{
		CompanyID:   companyID,
		TypeCode:    typeCode,
		Description: description,
		MaxLimit:    maxLimit,
		IsActive:    true,
	}

	beforeJSON, _ := json.Marshal(dt)
	if err := s.repo.CreateDeclarationType(ctx, dt); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(dt)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "payroll", "tax_declaration_type_created", "tax_declaration_type",
		nil, "admin", &createdBy, beforeJSON, afterJSON,
		map[string]interface{}{
			"type_code":   typeCode,
			"description": description,
			"max_limit":   maxLimit,
			"ip":          ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, dt)
	return dt, nil
}

func (s *taxDeclarationService) UpdateDeclarationType(
	ctx context.Context,
	companyID uuid.UUID,
	typeCode, description string,
	maxLimit *float64,
	isActive bool,
	updatedBy uuid.UUID,
) (*models.TaxDeclarationType, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("tax_decl_type_update-%s-%s", companyID.String(), typeCode)
	}
	var cached *models.TaxDeclarationType
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if companyID == uuid.Nil || typeCode == "" || updatedBy == uuid.Nil {
		return nil, errors.New("invalid input")
	}

	current, err := s.repo.GetDeclarationType(ctx, companyID, typeCode)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, fmt.Errorf("declaration type %s not found", typeCode)
	}

	beforeJSON, _ := json.Marshal(current)

	current.Description = description
	current.MaxLimit = maxLimit
	current.IsActive = isActive

	if err := s.repo.UpdateDeclarationType(ctx, current); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(current)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "payroll", "tax_declaration_type_updated", "tax_declaration_type",
		nil, "admin", &updatedBy, beforeJSON, afterJSON,
		map[string]interface{}{"type_code": typeCode, "ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, current)
	return current, nil
}

func (s *taxDeclarationService) ListDeclarationTypes(ctx context.Context, companyID uuid.UUID) ([]models.TaxDeclarationType, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company ID is required")
	}
	return s.repo.ListDeclarationTypes(ctx, companyID)
}

func (s *taxDeclarationService) GetDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode string) (*models.TaxDeclarationType, error) {
	if companyID == uuid.Nil || typeCode == "" {
		return nil, errors.New("company ID and type code are required")
	}
	return s.repo.GetDeclarationType(ctx, companyID, typeCode)
}

// ------------------------------------------------------------------------------
// Declaration Submission & Verification
// ------------------------------------------------------------------------------

func (s *taxDeclarationService) CreateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error) {
	if input == nil {
		return nil, errors.New("nil input")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("tax_decl_create-%s-%s-%s-%s",
			input.CompanyID.String(),
			input.UserID.String(),
			input.FinancialYear,
			input.DeclarationType,
		)
	}
	var cached *models.TaxDeclaration
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if err := s.validateDeclarationInput(ctx, input); err != nil {
		return nil, err
	}

	if input.Status == "" {
		input.Status = models.DeclarationStatusPending
	}
	if input.DeclarationID == uuid.Nil {
		input.DeclarationID = uuid.New()
	}
	now := time.Now().UTC()
	if input.SubmittedAt.IsZero() {
		input.SubmittedAt = now
	}
	if input.CreatedAt.IsZero() {
		input.CreatedAt = now
	}
	if input.UpdatedAt.IsZero() {
		input.UpdatedAt = now
	}

	if err := s.validateAmountAgainstLimit(ctx, input.CompanyID, input.DeclarationType, input.Amount); err != nil {
		return nil, err
	}

	beforeJSON, _ := json.Marshal(input)
	if err := s.repo.CreateDeclaration(ctx, input); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(input)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &input.CompanyID, "payroll", "tax_declaration_created", "tax_declaration",
		&input.DeclarationID, "employee", nil, beforeJSON, afterJSON,
		map[string]interface{}{
			"financial_year": input.FinancialYear,
			"type":           input.DeclarationType,
			"user_id":        input.UserID,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, input)
	return input, nil
}

func (s *taxDeclarationService) UpdateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error) {
	if input == nil || input.DeclarationID == uuid.Nil {
		return nil, errors.New("declaration ID required")
	}

	existing, err := s.repo.GetDeclarationByID(ctx, input.DeclarationID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("declaration not found")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("tax_decl_update-%s", input.DeclarationID.String())
	}
	var cached *models.TaxDeclaration
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if existing.Status != models.DeclarationStatusPending {
		return nil, fmt.Errorf("cannot update declaration with status %s", existing.Status)
	}

	beforeJSON, _ := json.Marshal(existing)

	existing.Amount = input.Amount
	existing.SupportingDocs = input.SupportingDocs
	existing.UpdatedAt = time.Now().UTC()
	if input.Status != "" && input.Status != existing.Status {
		if input.Status != models.DeclarationStatusPending {
			return nil, fmt.Errorf("cannot manually set status to %s; use VerifyDeclaration for verification", input.Status)
		}
		existing.Status = input.Status
	}

	if err := s.repo.UpdateDeclaration(ctx, existing); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(existing)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &existing.CompanyID, "payroll", "tax_declaration_updated", "tax_declaration",
		&existing.DeclarationID, "employee", nil, beforeJSON, afterJSON,
		map[string]interface{}{
			"financial_year": existing.FinancialYear,
			"type":           existing.DeclarationType,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, existing)
	return existing, nil
}

func (s *taxDeclarationService) VerifyDeclaration(ctx context.Context, declarationID uuid.UUID, verifiedBy uuid.UUID, status string) (*models.TaxDeclaration, error) {
	if declarationID == uuid.Nil || verifiedBy == uuid.Nil {
		return nil, errors.New("declaration ID and verifier required")
	}
	if status != models.DeclarationStatusVerified && status != models.DeclarationStatusRejected {
		return nil, fmt.Errorf("invalid verification status: %s", status)
	}

	existing, err := s.repo.GetDeclarationByID(ctx, declarationID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("declaration not found")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("tax_decl_verify-%s", declarationID.String())
	}
	var cached *models.TaxDeclaration
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if existing.Status != models.DeclarationStatusPending {
		return nil, fmt.Errorf("declaration already %s", existing.Status)
	}

	beforeJSON, _ := json.Marshal(existing)

	if err := s.repo.VerifyDeclaration(ctx, declarationID, verifiedBy, status); err != nil {
		return nil, err
	}

	updated, err := s.repo.GetDeclarationByID(ctx, declarationID)
	if err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(updated)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &existing.CompanyID, "payroll", "tax_declaration_verified", "tax_declaration",
		&declarationID, "admin", &verifiedBy, beforeJSON, afterJSON,
		map[string]interface{}{
			"status": status,
			"ip":     ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, updated)
	return updated, nil
}

// ListDeclarationsByUser — single-user read; validate target.
func (s *taxDeclarationService) ListDeclarationsByUser(ctx context.Context, companyID, userID uuid.UUID, financialYear string) ([]models.TaxDeclaration, error) {
	if companyID == uuid.Nil || userID == uuid.Nil || financialYear == "" {
		return nil, errors.New("company ID, user ID and financial year are required")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	return s.repo.ListDeclarationsByUser(ctx, companyID, userID, financialYear)
}

// ListDeclarationsByFinancialYear — set read; filter via locationID.
func (s *taxDeclarationService) ListDeclarationsByFinancialYear(
	ctx context.Context,
	companyID uuid.UUID,
	financialYear string,
	status *string,
	locationID *uuid.UUID,
) ([]models.TaxDeclaration, error) {
	if companyID == uuid.Nil || financialYear == "" {
		return nil, errors.New("company ID and financial year are required")
	}
	return s.repo.ListDeclarationsByFinancialYear(ctx, companyID, financialYear, status, locationID)
}

// ------------------------------------------------------------------------------
// Utility
// ------------------------------------------------------------------------------

func (s *taxDeclarationService) GetTotalDeclaredAmount(ctx context.Context, companyID, userID uuid.UUID, financialYear string, onlyVerified bool) (float64, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return 0, err
	}

	declarations, err := s.repo.ListDeclarationsByUser(ctx, companyID, userID, financialYear)
	if err != nil {
		return 0, err
	}
	var total float64
	for _, d := range declarations {
		if onlyVerified && d.Status != models.DeclarationStatusVerified {
			continue
		}
		total += d.Amount
	}
	return total, nil
}

// ------------------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------------------

func (s *taxDeclarationService) validateDeclarationInput(ctx context.Context, input *models.TaxDeclaration) error {
	if input.CompanyID == uuid.Nil {
		return errors.New("company ID is required")
	}
	if input.UserID == uuid.Nil {
		return errors.New("user ID is required")
	}
	if input.FinancialYear == "" {
		return errors.New("financial year is required")
	}
	if input.DeclarationType == "" {
		return errors.New("declaration type is required")
	}
	if input.Amount < 0 {
		return errors.New("amount cannot be negative")
	}

	dt, err := s.repo.GetDeclarationType(ctx, input.CompanyID, input.DeclarationType)
	if err != nil {
		return err
	}
	if dt == nil {
		return fmt.Errorf("declaration type %s does not exist", input.DeclarationType)
	}
	if !dt.IsActive {
		return fmt.Errorf("declaration type %s is inactive", input.DeclarationType)
	}
	return nil
}

func (s *taxDeclarationService) validateAmountAgainstLimit(ctx context.Context, companyID uuid.UUID, typeCode string, amount float64) error {
	dt, err := s.repo.GetDeclarationType(ctx, companyID, typeCode)
	if err != nil {
		return err
	}
	if dt == nil {
		return nil
	}
	if dt.MaxLimit != nil && amount > *dt.MaxLimit {
		return fmt.Errorf("amount %.2f exceeds maximum limit %.2f for type %s", amount, *dt.MaxLimit, typeCode)
	}
	return nil
}
