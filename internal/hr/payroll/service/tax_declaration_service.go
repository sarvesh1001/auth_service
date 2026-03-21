package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/infrastructure/audit"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TaxDeclarationService defines the interface for tax declaration operations.
type TaxDeclarationService interface {
	// Declaration type management (admin)
	CreateDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode, description string, maxLimit *float64, createdBy uuid.UUID) (*models.TaxDeclarationType, error)
	UpdateDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode, description string, maxLimit *float64, isActive bool, updatedBy uuid.UUID) (*models.TaxDeclarationType, error)
	ListDeclarationTypes(ctx context.Context, companyID uuid.UUID) ([]models.TaxDeclarationType, error)
	GetDeclarationType(ctx context.Context, companyID uuid.UUID, typeCode string) (*models.TaxDeclarationType, error)

	// Declaration submission and verification
	CreateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error)
	UpdateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error)
	VerifyDeclaration(ctx context.Context, declarationID uuid.UUID, verifiedBy uuid.UUID, status string) (*models.TaxDeclaration, error)
	ListDeclarationsByUser(ctx context.Context, companyID, userID uuid.UUID, financialYear string) ([]models.TaxDeclaration, error)
	ListDeclarationsByFinancialYear(ctx context.Context, companyID uuid.UUID, financialYear string, status *string) ([]models.TaxDeclaration, error)

	// Utility for payroll engine
	GetTotalDeclaredAmount(ctx context.Context, companyID, userID uuid.UUID, financialYear string, onlyVerified bool) (float64, error)
}

type taxDeclarationService struct {
	repo   repository.TaxDeclarationRepository
	audit  *a.AuditService
	logger *zap.Logger
}

// NewTaxDeclarationService creates a new tax declaration service.
func NewTaxDeclarationService(
	repo repository.TaxDeclarationRepository,
	audit *a.AuditService,
	logger *zap.Logger,
) TaxDeclarationService {
	return &taxDeclarationService{
		repo:   repo,
		audit:  audit,
		logger: logger.Named("tax_declaration_service"),
	}
}

//------------------------------------------------------------------------------
// Declaration Type Management
//------------------------------------------------------------------------------

func (s *taxDeclarationService) CreateDeclarationType(
	ctx context.Context,
	companyID uuid.UUID,
	typeCode, description string,
	maxLimit *float64,
	createdBy uuid.UUID,
) (*models.TaxDeclarationType, error) {

	if companyID == uuid.Nil || typeCode == "" || description == "" || createdBy == uuid.Nil {
		return nil, errors.New("invalid input: missing required fields")
	}

	// Check if already exists
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

	if err := s.repo.CreateDeclarationType(ctx, dt); err != nil {
		s.logger.Error("failed to create declaration type",
			util.String("company_id", companyID.String()),
			util.String("type_code", typeCode),
			util.ErrorField(err),
		)
		return nil, err
	}

	// Audit
	if err := s.audit.LogAction(ctx,
		nil,
		&companyID,
		"payroll",
		"tax_declaration_type_created",
		"tax_declaration_type",
		nil,
		"admin",
		&createdBy,
		nil,
		nil,
		map[string]interface{}{
			"type_code":   typeCode,
			"description": description,
			"max_limit":   maxLimit,
		},
	); err != nil {
		s.logger.Error("failed to audit tax declaration type creation", zap.Error(err))
	}

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

	if companyID == uuid.Nil || typeCode == "" || updatedBy == uuid.Nil {
		return nil, errors.New("invalid input")
	}

	// Fetch current to ensure existence and for audit
	current, err := s.repo.GetDeclarationType(ctx, companyID, typeCode)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, fmt.Errorf("declaration type %s not found", typeCode)
	}

	// Capture before state for audit
	before := *current

	// Update fields
	current.Description = description
	current.MaxLimit = maxLimit
	current.IsActive = isActive

	if err := s.repo.UpdateDeclarationType(ctx, current); err != nil {
		s.logger.Error("failed to update declaration type",
			util.String("company_id", companyID.String()),
			util.String("type_code", typeCode),
			util.ErrorField(err),
		)
		return nil, err
	}

	// Audit
	if err := s.audit.LogAction(ctx,
		nil,
		&companyID,
		"payroll",
		"tax_declaration_type_updated",
		"tax_declaration_type",
		nil,
		"admin",
		&updatedBy,
		util.MustMarshalJSON(before),
		util.MustMarshalJSON(current),
		map[string]interface{}{
			"type_code": typeCode,
		},
	); err != nil {
		s.logger.Error("failed to audit tax declaration type update", zap.Error(err))
	}

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

//------------------------------------------------------------------------------
// Declaration Submission & Verification
//------------------------------------------------------------------------------

func (s *taxDeclarationService) CreateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error) {
	if err := s.validateDeclarationInput(ctx, input); err != nil {
		return nil, err
	}

	// Set default status if not provided
	if input.Status == "" {
		input.Status = models.DeclarationStatusPending
	}
	// Generate ID if missing
	if input.DeclarationID == uuid.Nil {
		input.DeclarationID = uuid.New()
	}
	// Ensure timestamps
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

	// Optional: validate amount against max limit of declaration type
	if err := s.validateAmountAgainstLimit(ctx, input.CompanyID, input.DeclarationType, input.Amount); err != nil {
		return nil, err
	}

	if err := s.repo.CreateDeclaration(ctx, input); err != nil {
		s.logger.Error("failed to create tax declaration",
			util.String("company_id", input.CompanyID.String()),
			util.String("user_id", input.UserID.String()),
			util.String("type", input.DeclarationType),
			util.ErrorField(err),
		)
		return nil, err
	}

	// Audit
	if err := s.audit.LogAction(ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"tax_declaration_created",
		"tax_declaration",
		&input.DeclarationID,
		"employee",       // assuming employee submits
		input.VerifiedBy, // could be employee ID? We'll use a separate actor field? For now use VerifiedBy as actor (but that's HR). We'll set actor as "system" or maybe we need a separate CreatedBy field in input? The model has VerifiedBy and VerifiedAt but no CreatedBy. We'll use the VerifiedBy as actor if available, else fallback to nil. Better to have a dedicated CreatedBy field in input, but for now we'll pass nil and log as "system".
		nil,
		util.MustMarshalJSON(input),
		map[string]interface{}{
			"financial_year": input.FinancialYear,
			"type":           input.DeclarationType,
			"user_id":        input.UserID,
		},
	); err != nil {
		s.logger.Error("failed to audit tax declaration creation", zap.Error(err))
	}

	return input, nil
}

func (s *taxDeclarationService) UpdateDeclaration(ctx context.Context, input *models.TaxDeclaration) (*models.TaxDeclaration, error) {
	if input.DeclarationID == uuid.Nil {
		return nil, errors.New("declaration ID required")
	}

	// Fetch existing to check status and for audit
	existing, err := s.repo.GetDeclarationByID(ctx, input.DeclarationID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("declaration not found")
	}
	// Only allow updates if status is pending
	if existing.Status != models.DeclarationStatusPending {
		return nil, fmt.Errorf("cannot update declaration with status %s", existing.Status)
	}

	// Capture before state
	before := *existing

	// Update fields (only allowed fields)
	existing.Amount = input.Amount
	existing.SupportingDocs = input.SupportingDocs
	existing.UpdatedAt = time.Now().UTC()
	// Status may be changed only to pending? We'll allow setting status if provided, but restrict to pending maybe.
	if input.Status != "" && input.Status != existing.Status {
		if input.Status != models.DeclarationStatusPending {
			return nil, fmt.Errorf("cannot manually set status to %s; use VerifyDeclaration for verification", input.Status)
		}
		existing.Status = input.Status
	}

	if err := s.repo.UpdateDeclaration(ctx, existing); err != nil {
		s.logger.Error("failed to update tax declaration",
			util.String("declaration_id", input.DeclarationID.String()),
			util.ErrorField(err),
		)
		return nil, err
	}

	// Audit
	if err := s.audit.LogAction(ctx,
		nil,
		&existing.CompanyID,
		"payroll",
		"tax_declaration_updated",
		"tax_declaration",
		&existing.DeclarationID,
		"employee", // assuming employee updates
		nil,        // actor unknown
		util.MustMarshalJSON(before),
		util.MustMarshalJSON(existing),
		map[string]interface{}{
			"financial_year": existing.FinancialYear,
			"type":           existing.DeclarationType,
		},
	); err != nil {
		s.logger.Error("failed to audit tax declaration update", zap.Error(err))
	}

	return existing, nil
}

func (s *taxDeclarationService) VerifyDeclaration(ctx context.Context, declarationID uuid.UUID, verifiedBy uuid.UUID, status string) (*models.TaxDeclaration, error) {
	if declarationID == uuid.Nil || verifiedBy == uuid.Nil {
		return nil, errors.New("declaration ID and verifier required")
	}
	if status != models.DeclarationStatusVerified && status != models.DeclarationStatusRejected {
		return nil, fmt.Errorf("invalid verification status: %s", status)
	}

	// Fetch existing for audit
	existing, err := s.repo.GetDeclarationByID(ctx, declarationID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("declaration not found")
	}
	if existing.Status != models.DeclarationStatusPending {
		return nil, fmt.Errorf("declaration already %s", existing.Status)
	}

	// Capture before state
	before := *existing

	// Perform verification
	if err := s.repo.VerifyDeclaration(ctx, declarationID, verifiedBy, status); err != nil {
		s.logger.Error("failed to verify tax declaration",
			util.String("declaration_id", declarationID.String()),
			util.ErrorField(err),
		)
		return nil, err
	}

	// Fetch updated record
	updated, err := s.repo.GetDeclarationByID(ctx, declarationID)
	if err != nil {
		return nil, err
	}

	// Audit
	if err := s.audit.LogAction(ctx,
		nil,
		&existing.CompanyID,
		"payroll",
		"tax_declaration_verified",
		"tax_declaration",
		&declarationID,
		"admin",
		&verifiedBy,
		util.MustMarshalJSON(before),
		util.MustMarshalJSON(updated),
		map[string]interface{}{
			"status": status,
		},
	); err != nil {
		s.logger.Error("failed to audit tax declaration verification", zap.Error(err))
	}

	return updated, nil
}

func (s *taxDeclarationService) ListDeclarationsByUser(ctx context.Context, companyID, userID uuid.UUID, financialYear string) ([]models.TaxDeclaration, error) {
	if companyID == uuid.Nil || userID == uuid.Nil || financialYear == "" {
		return nil, errors.New("company ID, user ID and financial year are required")
	}
	return s.repo.ListDeclarationsByUser(ctx, companyID, userID, financialYear)
}

func (s *taxDeclarationService) ListDeclarationsByFinancialYear(ctx context.Context, companyID uuid.UUID, financialYear string, status *string) ([]models.TaxDeclaration, error) {
	if companyID == uuid.Nil || financialYear == "" {
		return nil, errors.New("company ID and financial year are required")
	}
	return s.repo.ListDeclarationsByFinancialYear(ctx, companyID, financialYear, status)
}

//------------------------------------------------------------------------------
// Utility for Payroll Engine
//------------------------------------------------------------------------------

func (s *taxDeclarationService) GetTotalDeclaredAmount(ctx context.Context, companyID, userID uuid.UUID, financialYear string, onlyVerified bool) (float64, error) {
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

//------------------------------------------------------------------------------
// Internal helpers
//------------------------------------------------------------------------------

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

	// Check that declaration type exists and is active
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
		return nil // shouldn't happen if called after existence check
	}
	if dt.MaxLimit != nil && amount > *dt.MaxLimit {
		return fmt.Errorf("amount %.2f exceeds maximum limit %.2f for type %s", amount, *dt.MaxLimit, typeCode)
	}
	return nil
}
