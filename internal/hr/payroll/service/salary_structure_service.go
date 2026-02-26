package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/hr/service" // audit service

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SalaryStructureService defines the interface for salary structure operations.
// All methods that access a salary structure now require a companyID to enforce
// multi‑tenant isolation.
type SalaryStructureService interface {
	// Structure lifecycle
	CreateStructure(ctx context.Context, input *models.CreateSalaryStructureInput) (*models.SalaryStructure, error)
	UpdateStructure(ctx context.Context, input *models.UpdateSalaryStructureInput) (*models.SalaryStructure, error)
	CloneStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, effectiveFrom time.Time, createdBy uuid.UUID) (*models.SalaryStructure, error)
	PublishStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, actorID uuid.UUID) error
	DeactivateStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, actorID uuid.UUID) error
	GetStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID) (*models.SalaryStructureDetail, error)
	ListStructures(ctx context.Context, filter models.SalaryStructureFilter) ([]*models.SalaryStructure, int64, error)

	// Component management
	AddComponent(ctx context.Context, input *models.AddSalaryStructureComponentInput, actorID uuid.UUID) error
	UpdateComponent(ctx context.Context, input *models.UpdateSalaryStructureComponentInput, actorID uuid.UUID) error
	RemoveComponent(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, componentCode string, actorID uuid.UUID) error
	ReorderComponents(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, componentCodes []string, actorID uuid.UUID) error
	GetStructureComponents(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID) ([]*models.SalaryStructureComponent, error)

	// Employee assignment (unchanged)
	AssignToEmployee(ctx context.Context, input *models.AssignSalaryStructureInput) error
	BulkAssignToEmployees(ctx context.Context, input *models.BulkAssignSalaryStructureInput) error
	ChangeEmployeeStructure(ctx context.Context, input *models.ChangeSalaryStructureInput) error
	EndEmployeeStructure(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, endDate time.Time, actorID uuid.UUID) error
	GetActiveStructureForEmployee(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.EmployeeSalaryStructure, error)
	GetEmployeeStructureHistory(ctx context.Context, companyID uuid.UUID, userID uuid.UUID) ([]*models.EmployeeSalaryStructure, error)

	// Validation & governance
	ValidateStructureMutationAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error
	ValidateAssignmentAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error
	CanDeactivateStructure(ctx context.Context, structureID uuid.UUID) (bool, error)

	// Snapshot
	BuildStructureSnapshot(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.SalaryStructureSnapshot, error)
}

type salaryStructureService struct {
	repo            repository.CompensationRepository
	lockService     PayrollLockService
	compensationSvc CompensationService
	audit           *a.AuditService
	logger          *zap.Logger
}

// NewSalaryStructureService creates a new service with audit support.
func NewSalaryStructureService(
	repo repository.CompensationRepository,
	lockService PayrollLockService,
	compensationSvc CompensationService,
	audit *a.AuditService,
	logger *zap.Logger,
) SalaryStructureService {
	return &salaryStructureService{
		repo:            repo,
		lockService:     lockService,
		compensationSvc: compensationSvc,
		audit:           audit,
		logger:          logger.Named("salary_structure_service"),
	}
}

// ---------------------------------------------------------------------
// STRUCTURE LIFECYCLE
// ---------------------------------------------------------------------

func (s *salaryStructureService) CreateStructure(
	ctx context.Context,
	input *models.CreateSalaryStructureInput,
) (*models.SalaryStructure, error) {
	if input.CompanyID == uuid.Nil {
		return nil, errors.New("invalid company id")
	}

	structure := &models.SalaryStructure{
		SalaryStructureID: uuid.New(),
		CompanyID:         input.CompanyID,
		StructureName:     input.StructureName,
		CurrencyCode:      input.CurrencyCode,
		IsActive:          false,
		CreatedBy:         &input.CreatedBy,
	}

	if err := s.repo.CreateSalaryStructure(ctx, structure); err != nil {
		return nil, err
	}

	afterState, _ := json.Marshal(structure)
	_ = s.audit.LogAction(
		ctx,
		&structure.CompanyID,
		"payroll",
		"salary_structure_created",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&input.CreatedBy,
		nil,
		afterState,
		map[string]interface{}{
			"structure_name": structure.StructureName,
			"currency_code":  structure.CurrencyCode,
		},
	)

	return structure, nil
}

func (s *salaryStructureService) UpdateStructure(
	ctx context.Context,
	input *models.UpdateSalaryStructureInput,
) (*models.SalaryStructure, error) {
	structure, err := s.repo.GetSalaryStructure(ctx, input.StructureID, input.CompanyID)
	if err != nil || structure == nil {
		return nil, fmt.Errorf("structure not found")
	}
	if structure.IsActive {
		return nil, fmt.Errorf("cannot update active structure")
	}

	beforeState, _ := json.Marshal(structure)

	structure.StructureName = input.StructureName
	structure.CurrencyCode = input.CurrencyCode
	structure.UpdatedBy = &input.UpdatedBy

	if err := s.repo.UpdateSalaryStructure(ctx, structure); err != nil {
		return nil, err
	}

	afterState, _ := json.Marshal(structure)
	_ = s.audit.LogAction(
		ctx,
		&structure.CompanyID,
		"payroll",
		"salary_structure_updated",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&input.UpdatedBy,
		beforeState,
		afterState,
		nil,
	)

	return structure, nil
}

// CloneStructure now requires companyID.
func (s *salaryStructureService) CloneStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	effectiveFrom time.Time,
	createdBy uuid.UUID,
) (*models.SalaryStructure, error) {
	orig, err := s.repo.GetSalaryStructure(ctx, structureID, companyID)
	if err != nil || orig == nil {
		return nil, fmt.Errorf("original structure not found")
	}

	newStructure := &models.SalaryStructure{
		SalaryStructureID: uuid.New(),
		CompanyID:         orig.CompanyID,
		StructureName:     orig.StructureName + " (Clone)",
		CurrencyCode:      orig.CurrencyCode,
		IsActive:          false,
		CreatedBy:         &createdBy,
	}

	if err := s.repo.CreateSalaryStructure(ctx, newStructure); err != nil {
		return nil, err
	}

	afterState, _ := json.Marshal(newStructure)
	_ = s.audit.LogAction(
		ctx,
		&newStructure.CompanyID,
		"payroll",
		"salary_structure_cloned",
		"salary_structure",
		&newStructure.SalaryStructureID,
		"admin",
		&createdBy,
		nil,
		afterState,
		map[string]interface{}{
			"source_structure_id": structureID.String(),
		},
	)

	return newStructure, nil
}

// PublishStructure now requires companyID.
func (s *salaryStructureService) PublishStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	actorID uuid.UUID,
) error {
	structure, err := s.repo.GetSalaryStructure(ctx, structureID, companyID)
	if err != nil || structure == nil {
		return fmt.Errorf("structure not found")
	}
	if structure.IsActive {
		return fmt.Errorf("already active")
	}

	beforeState, _ := json.Marshal(structure)

	structure.IsActive = true
	structure.UpdatedBy = &actorID

	if err := s.repo.UpdateSalaryStructure(ctx, structure); err != nil {
		return err
	}

	afterState, _ := json.Marshal(structure)
	_ = s.audit.LogAction(
		ctx,
		&structure.CompanyID,
		"payroll",
		"salary_structure_published",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&actorID,
		beforeState,
		afterState,
		nil,
	)

	return nil
}

// DeactivateStructure now requires companyID.
func (s *salaryStructureService) DeactivateStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	actorID uuid.UUID,
) error {
	inUse, err := s.repo.IsSalaryStructureInUse(ctx, structureID)
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("cannot deactivate structure assigned to employees")
	}

	structure, err := s.repo.GetSalaryStructure(ctx, structureID, companyID)
	if err != nil || structure == nil {
		return fmt.Errorf("structure not found")
	}

	beforeState, _ := json.Marshal(structure)

	if err := s.repo.DeactivateSalaryStructure(ctx, structureID, actorID); err != nil {
		return err
	}

	_ = s.audit.LogAction(
		ctx,
		&structure.CompanyID,
		"payroll",
		"salary_structure_deactivated",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&actorID,
		beforeState,
		nil,
		nil,
	)

	return nil
}

// GetStructure now requires companyID.
func (s *salaryStructureService) GetStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
) (*models.SalaryStructureDetail, error) {
	structure, err := s.repo.GetSalaryStructure(ctx, structureID, companyID)
	if err != nil || structure == nil {
		return nil, fmt.Errorf("structure not found")
	}

	comps, err := s.repo.GetStructureComponentsOrdered(ctx, structureID, companyID)
	if err != nil {
		return nil, err
	}

	return &models.SalaryStructureDetail{
		SalaryStructure: *structure,
		Components:      comps,
	}, nil
}

func (s *salaryStructureService) ListStructures(
	ctx context.Context,
	filter models.SalaryStructureFilter,
) ([]*models.SalaryStructure, int64, error) {
	list, err := s.repo.GetSalaryStructuresByCompany(ctx, filter.CompanyID, filter.IncludeInactive)
	if err != nil {
		return nil, 0, err
	}
	var result []*models.SalaryStructure
	for i := range list {
		result = append(result, &list[i])
	}
	return result, int64(len(result)), nil
}

// ---------------------------------------------------------------------
// COMPONENT MANAGEMENT
// ---------------------------------------------------------------------

func (s *salaryStructureService) AddComponent(
	ctx context.Context,
	input *models.AddSalaryStructureComponentInput,
	actorID uuid.UUID,
) error {
	component := &models.SalaryStructureComponent{
		MappingID:         uuid.New(),
		SalaryStructureID: input.StructureID,
		CompanyID:         input.CompanyID,
		ComponentCode:     input.ComponentCode,
		CalculationType:   input.CalculationType,
		Value:             input.Value,
		BasedOnComponent:  input.BasedOnComponent,
		SequenceOrder:     input.SequenceOrder,
	}

	if err := s.repo.AddStructureComponent(ctx, component); err != nil {
		return err
	}

	afterState, _ := json.Marshal(component)
	_ = s.audit.LogAction(
		ctx,
		&input.CompanyID,
		"payroll",
		"salary_structure_component_added",
		"salary_structure_component",
		&component.MappingID,
		"admin",
		&actorID,
		nil,
		afterState,
		map[string]interface{}{
			"structure_id":   input.StructureID.String(),
			"component_code": input.ComponentCode,
		},
	)

	return nil
}

func (s *salaryStructureService) UpdateComponent(
	ctx context.Context,
	input *models.UpdateSalaryStructureComponentInput,
	actorID uuid.UUID,
) error {
	component, err := s.repo.GetStructureComponentByID(ctx, input.MappingID)
	if err != nil || component == nil {
		return fmt.Errorf("component not found")
	}

	beforeState, _ := json.Marshal(component)

	component.Value = input.Value
	component.SequenceOrder = input.SequenceOrder

	if err := s.repo.UpdateStructureComponent(ctx, component); err != nil {
		return err
	}

	afterState, _ := json.Marshal(component)
	_ = s.audit.LogAction(
		ctx,
		&component.CompanyID,
		"payroll",
		"salary_structure_component_updated",
		"salary_structure_component",
		&component.MappingID,
		"admin",
		&actorID,
		beforeState,
		afterState,
		nil,
	)

	return nil
}

// RemoveComponent now requires companyID.
func (s *salaryStructureService) RemoveComponent(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	componentCode string,
	actorID uuid.UUID,
) error {
	comps, err := s.repo.GetStructureComponents(ctx, structureID, companyID)
	if err != nil {
		return err
	}
	var targetMappingID uuid.UUID
	for _, c := range comps {
		if c.ComponentCode == componentCode {
			targetMappingID = c.MappingID
			break
		}
	}
	if targetMappingID == uuid.Nil {
		return fmt.Errorf("component not found")
	}

	component, err := s.repo.GetStructureComponentByID(ctx, targetMappingID)
	if err != nil || component == nil {
		return fmt.Errorf("component not found")
	}

	beforeState, _ := json.Marshal(component)

	if err := s.repo.RemoveStructureComponent(ctx, targetMappingID); err != nil {
		return err
	}

	_ = s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"salary_structure_component_removed",
		"salary_structure_component",
		&targetMappingID,
		"admin",
		&actorID,
		beforeState,
		nil,
		map[string]interface{}{
			"structure_id":   structureID.String(),
			"component_code": componentCode,
		},
	)

	return nil
}

// ReorderComponents now requires companyID.
func (s *salaryStructureService) ReorderComponents(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	componentCodes []string,
	actorID uuid.UUID,
) error {
	comps, err := s.repo.GetStructureComponents(ctx, structureID, companyID)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return nil // nothing to reorder
	}

	orderMap := make(map[string]int)
	for i, code := range componentCodes {
		orderMap[code] = i + 1
	}

	beforeState, _ := json.Marshal(comps)

	for _, c := range comps {
		if newOrder, ok := orderMap[c.ComponentCode]; ok {
			c.SequenceOrder = newOrder
			if err := s.repo.UpdateStructureComponent(ctx, &c); err != nil {
				return err
			}
		}
	}

	afterState, _ := json.Marshal(comps)
	_ = s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"salary_structure_components_reordered",
		"salary_structure",
		&structureID,
		"admin",
		&actorID,
		beforeState,
		afterState,
		map[string]interface{}{
			"new_order": componentCodes,
		},
	)

	return nil
}

// GetStructureComponents now requires companyID.
func (s *salaryStructureService) GetStructureComponents(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
) ([]*models.SalaryStructureComponent, error) {
	comps, err := s.repo.GetStructureComponentsOrdered(ctx, structureID, companyID)
	if err != nil {
		return nil, err
	}
	var result []*models.SalaryStructureComponent
	for i := range comps {
		result = append(result, &comps[i])
	}
	return result, nil
}

// ---------------------------------------------------------------------
// EMPLOYEE ASSIGNMENT (unchanged)
// ---------------------------------------------------------------------

func (s *salaryStructureService) AssignToEmployee(
	ctx context.Context,
	input *models.AssignSalaryStructureInput,
) error {
	if err := s.ValidateAssignmentAllowed(ctx, input.CompanyID, input.EffectiveFrom); err != nil {
		return err
	}
	salary := &models.EmployeeSalary{
		EmployeeSalaryID:  uuid.New(),
		CompanyID:         input.CompanyID,
		UserID:            input.UserID,
		SalaryStructureID: input.StructureID,
		MonthlyCTC:        input.MonthlyCTC,
		EffectiveFrom:     input.EffectiveFrom,
		IsActive:          true,
		UpdatedBy:         &input.ActorID,
	}

	if err := s.repo.CreateEmployeeSalary(ctx, salary); err != nil {
		return err
	}

	afterState, _ := json.Marshal(salary)
	_ = s.audit.LogAction(
		ctx,
		&input.CompanyID,
		"payroll",
		"salary_structure_assigned",
		"employee_salary",
		&salary.EmployeeSalaryID,
		"admin",
		&input.ActorID,
		nil,
		afterState,
		map[string]interface{}{
			"user_id":      input.UserID.String(),
			"structure_id": input.StructureID.String(),
		},
	)

	return nil
}

func (s *salaryStructureService) BulkAssignToEmployees(
	ctx context.Context,
	input *models.BulkAssignSalaryStructureInput,
) error {
	for _, userID := range input.UserIDs {
		err := s.AssignToEmployee(ctx, &models.AssignSalaryStructureInput{
			CompanyID:     input.CompanyID,
			UserID:        userID,
			StructureID:   input.StructureID,
			MonthlyCTC:    input.MonthlyCTC,
			EffectiveFrom: input.EffectiveFrom,
			ActorID:       input.ActorID,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *salaryStructureService) ChangeEmployeeStructure(
	ctx context.Context,
	input *models.ChangeSalaryStructureInput,
) error {
	return s.AssignToEmployee(ctx, &models.AssignSalaryStructureInput{
		CompanyID:     input.CompanyID,
		UserID:        input.UserID,
		StructureID:   input.NewStructureID,
		MonthlyCTC:    input.MonthlyCTC,
		EffectiveFrom: input.EffectiveFrom,
		ActorID:       input.ActorID,
	})
}

func (s *salaryStructureService) EndEmployeeStructure(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	endDate time.Time,
	actorID uuid.UUID,
) error {
	active, err := s.repo.GetActiveEmployeeSalary(ctx, companyID, userID, endDate)
	if err != nil || active == nil {
		return fmt.Errorf("no active salary found")
	}

	beforeState, _ := json.Marshal(active)

	active.EffectiveTo = &endDate
	active.IsActive = false
	active.UpdatedBy = &actorID

	if err := s.repo.UpdateEmployeeSalary(ctx, active); err != nil {
		return err
	}

	afterState, _ := json.Marshal(active)
	_ = s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"salary_structure_ended",
		"employee_salary",
		&active.EmployeeSalaryID,
		"admin",
		&actorID,
		beforeState,
		afterState,
		map[string]interface{}{
			"user_id":      userID.String(),
			"structure_id": active.SalaryStructureID.String(),
		},
	)

	return nil
}

func (s *salaryStructureService) GetActiveStructureForEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.EmployeeSalaryStructure, error) {
	salary, err := s.repo.GetActiveEmployeeSalary(ctx, companyID, userID, asOf)
	if err != nil || salary == nil {
		return nil, err
	}
	return &models.EmployeeSalaryStructure{
		EmployeeSalary: *salary,
	}, nil
}

func (s *salaryStructureService) GetEmployeeStructureHistory(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) ([]*models.EmployeeSalaryStructure, error) {
	history, err := s.repo.GetEmployeeSalaryHistory(ctx, companyID, userID, 1, 1000)
	if err != nil {
		return nil, err
	}
	var result []*models.EmployeeSalaryStructure
	for i := range history {
		result = append(result, &models.EmployeeSalaryStructure{
			EmployeeSalary: history[i],
		})
	}
	return result, nil
}

// ---------------------------------------------------------------------
// VALIDATION & GOVERNANCE
// ---------------------------------------------------------------------

func (s *salaryStructureService) ValidateStructureMutationAllowed(
	ctx context.Context,
	companyID uuid.UUID,
	effectiveFrom time.Time,
) error {
	return s.lockService.ValidateMutationAllowed(ctx, companyID, effectiveFrom)
}

func (s *salaryStructureService) ValidateAssignmentAllowed(
	ctx context.Context,
	companyID uuid.UUID,
	effectiveFrom time.Time,
) error {
	return s.lockService.ValidateMutationAllowed(ctx, companyID, effectiveFrom)
}

func (s *salaryStructureService) CanDeactivateStructure(
	ctx context.Context,
	structureID uuid.UUID,
) (bool, error) {
	return s.repo.IsSalaryStructureInUse(ctx, structureID)
}

// ---------------------------------------------------------------------
// SNAPSHOT
// ---------------------------------------------------------------------

func (s *salaryStructureService) BuildStructureSnapshot(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.SalaryStructureSnapshot, error) {
	return s.compensationSvc.ResolveSalaryStructure(ctx, companyID, userID, asOf)
}
