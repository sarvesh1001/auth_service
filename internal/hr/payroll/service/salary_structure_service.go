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

// ---------------------------------------------------------------------
// ArrearsService interface – to be implemented elsewhere
// ---------------------------------------------------------------------
type ArrearsService interface {
	GenerateArrearsForSalaryChange(ctx context.Context, companyID, userID uuid.UUID, previousSalaryID, newSalaryID uuid.UUID, effectiveFrom time.Time) error
	GenerateArrearsForSalaryEnd(ctx context.Context, companyID, userID uuid.UUID, salaryID uuid.UUID, endDate time.Time) error
}

// ---------------------------------------------------------------------
// SalaryStructureService interface (unchanged)
// ---------------------------------------------------------------------
type SalaryStructureService interface {
	CreateStructure(ctx context.Context, input *models.CreateSalaryStructureInput) (*models.SalaryStructure, error)
	UpdateStructure(ctx context.Context, input *models.UpdateSalaryStructureInput) (*models.SalaryStructure, error)
	CloneStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, effectiveFrom time.Time, createdBy uuid.UUID) (*models.SalaryStructure, error)
	PublishStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, actorID uuid.UUID) error
	DeactivateStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, actorID uuid.UUID) error
	GetStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID) (*models.SalaryStructureDetail, error)
	ListStructures(ctx context.Context, filter models.SalaryStructureFilter) ([]*models.SalaryStructure, int64, error)

	AddComponent(ctx context.Context, input *models.AddSalaryStructureComponentInput, actorID uuid.UUID) error
	UpdateComponent(ctx context.Context, input *models.UpdateSalaryStructureComponentInput, actorID uuid.UUID) error
	RemoveComponent(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, componentCode string, actorID uuid.UUID) error
	ReorderComponents(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, componentCodes []string, actorID uuid.UUID) error
	GetStructureComponents(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID) ([]*models.SalaryStructureComponent, error)

	AssignToEmployee(ctx context.Context, input *models.AssignSalaryStructureInput) error
	BulkAssignToEmployees(ctx context.Context, input *models.BulkAssignSalaryStructureInput) error
	ChangeEmployeeStructure(ctx context.Context, input *models.ChangeSalaryStructureInput) error
	EndEmployeeStructure(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, endDate time.Time, actorID uuid.UUID) error
	GetActiveStructureForEmployee(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.EmployeeSalaryStructure, error)
	GetEmployeeStructureHistory(ctx context.Context, companyID uuid.UUID, userID uuid.UUID) ([]*models.EmployeeSalaryStructure, error)

	ValidateStructureMutationAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error
	ValidateAssignmentAllowed(ctx context.Context, companyID uuid.UUID, effectiveFrom time.Time) error
	CanDeactivateStructure(ctx context.Context, structureID uuid.UUID) (bool, error)

	BuildStructureSnapshot(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.SalaryStructureSnapshot, error)
}

type salaryStructureService struct {
	repo             repository.CompensationRepository
	lockService      PayrollLockService
	compensationSvc  CompensationService
	arrearsSvc       ArrearsService
	employeeRepo     hrRepo.EmployeeRepository // 👈 new — for location scope lookup
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewSalaryStructureService(
	repo repository.CompensationRepository,
	lockService PayrollLockService,
	compensationSvc CompensationService,
	arrearsSvc ArrearsService,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
) SalaryStructureService {
	return &salaryStructureService{
		repo:             repo,
		lockService:      lockService,
		compensationSvc:  compensationSvc,
		arrearsSvc:       arrearsSvc,
		employeeRepo:     employeeRepo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
	}
}

// ensureEmployeeInScope verifies the target employee is within the caller's
// current location scope.
//
//   - Self-action (actor == target) → always allowed
//   - No location context           → allowed (system / worker call)
//   - ScopeAll                      → allowed
//   - ScopeLocation                 → target.employment_location_id must match
func (s *salaryStructureService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	// Self-action shortcut
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}

	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		// No location context → system call, allow.
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

// ---------------------------------------------------------------------
// STRUCTURE LIFECYCLE (with idempotency & IP audit)
// ---------------------------------------------------------------------

func (s *salaryStructureService) CreateStructure(
	ctx context.Context,
	input *models.CreateSalaryStructureInput,
) (*models.SalaryStructure, error) {
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_struct_create-%s-%s", input.CompanyID.String(), input.StructureName)
	}
	var cached *models.SalaryStructure
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if input.CompanyID == uuid.Nil {
		return nil, errors.New("invalid company id")
	}

	existing, err := s.repo.GetSalaryStructuresByCompany(ctx, input.CompanyID, true)
	if err != nil {
		return nil, err
	}
	for _, st := range existing {
		if st.StructureName == input.StructureName {
			return nil, fmt.Errorf("salary structure '%s' already exists for this company", input.StructureName)
		}
	}

	structure := &models.SalaryStructure{
		SalaryStructureID: uuid.New(),
		CompanyID:         input.CompanyID,
		StructureName:     input.StructureName,
		CurrencyCode:      input.CurrencyCode,
		IsActive:          false,
		CreatedBy:         &input.CreatedBy,
	}

	beforeJSON, _ := json.Marshal(structure)
	if err := s.repo.CreateSalaryStructure(ctx, structure); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(structure)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&structure.CompanyID,
		"payroll",
		"salary_structure_created",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&input.CreatedBy,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"structure_name": structure.StructureName,
			"currency_code":  structure.CurrencyCode,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, structure)
	return structure, nil
}

func (s *salaryStructureService) UpdateStructure(
	ctx context.Context,
	input *models.UpdateSalaryStructureInput,
) (*models.SalaryStructure, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_struct_update-%s", input.StructureID.String())
	}
	var cached *models.SalaryStructure
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	structure, err := s.repo.GetSalaryStructure(ctx, input.StructureID, input.CompanyID)
	if err != nil || structure == nil {
		return nil, fmt.Errorf("structure not found")
	}
	if structure.IsActive {
		return nil, fmt.Errorf("cannot update active structure")
	}

	beforeJSON, _ := json.Marshal(structure)

	structure.StructureName = input.StructureName
	structure.CurrencyCode = input.CurrencyCode
	structure.UpdatedBy = &input.UpdatedBy

	if err := s.repo.UpdateSalaryStructure(ctx, structure); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(structure)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&structure.CompanyID,
		"payroll",
		"salary_structure_updated",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&input.UpdatedBy,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, structure)
	return structure, nil
}

func (s *salaryStructureService) CloneStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	effectiveFrom time.Time,
	createdBy uuid.UUID,
) (*models.SalaryStructure, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_struct_clone-%s", structureID.String())
	}
	var cached *models.SalaryStructure
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

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

	beforeJSON, _ := json.Marshal(newStructure)
	if err := s.repo.CreateSalaryStructure(ctx, newStructure); err != nil {
		return nil, err
	}
	afterJSON, _ := json.Marshal(newStructure)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&newStructure.CompanyID,
		"payroll",
		"salary_structure_cloned",
		"salary_structure",
		&newStructure.SalaryStructureID,
		"admin",
		&createdBy,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"source_structure_id": structureID.String(),
			"ip":                  ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, newStructure)
	return newStructure, nil
}

func (s *salaryStructureService) PublishStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_struct_publish-%s", structureID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	structure, err := s.repo.GetSalaryStructure(ctx, structureID, companyID)
	if err != nil || structure == nil {
		return fmt.Errorf("structure not found")
	}
	if structure.IsActive {
		return fmt.Errorf("already active")
	}

	comps, err := s.repo.GetStructureComponents(ctx, structureID, companyID)
	if err != nil {
		return fmt.Errorf("failed to check structure components: %w", err)
	}
	if len(comps) == 0 {
		return fmt.Errorf("cannot publish structure without components")
	}

	beforeJSON, _ := json.Marshal(structure)

	structure.IsActive = true
	structure.UpdatedBy = &actorID
	structure.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateSalaryStructure(ctx, structure); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(structure)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&structure.CompanyID,
		"payroll",
		"salary_structure_published",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) DeactivateStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_struct_deactivate-%s", structureID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

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

	beforeJSON, _ := json.Marshal(structure)

	if err := s.repo.DeactivateSalaryStructure(ctx, structureID, actorID); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(structure)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&structure.CompanyID,
		"payroll",
		"salary_structure_deactivated",
		"salary_structure",
		&structure.SalaryStructureID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ---------------------------------------------------------------------
// READ METHODS (no idempotency, but we add IP to audit if needed)
// ---------------------------------------------------------------------

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
// COMPONENT MANAGEMENT (with idempotency)
// ---------------------------------------------------------------------

func (s *salaryStructureService) AddComponent(
	ctx context.Context,
	input *models.AddSalaryStructureComponentInput,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_comp_add-%s-%s", input.StructureID.String(), input.ComponentCode)
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

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

	beforeJSON, _ := json.Marshal(component)
	if err := s.repo.AddStructureComponent(ctx, component); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(component)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"salary_structure_component_added",
		"salary_structure_component",
		&component.MappingID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"structure_id":   input.StructureID.String(),
			"component_code": input.ComponentCode,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) UpdateComponent(
	ctx context.Context,
	input *models.UpdateSalaryStructureComponentInput,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_comp_update-%s", input.MappingID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	component, err := s.repo.GetStructureComponentByID(ctx, input.MappingID)
	if err != nil || component == nil {
		return fmt.Errorf("component not found")
	}

	beforeJSON, _ := json.Marshal(component)

	component.Value = input.Value
	component.SequenceOrder = input.SequenceOrder

	if err := s.repo.UpdateStructureComponent(ctx, component); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(component)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&component.CompanyID,
		"payroll",
		"salary_structure_component_updated",
		"salary_structure_component",
		&component.MappingID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) RemoveComponent(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	componentCode string,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_comp_remove-%s-%s", structureID.String(), componentCode)
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

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

	beforeJSON, _ := json.Marshal(component)

	if err := s.repo.RemoveStructureComponent(ctx, targetMappingID); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"salary_structure_component_removed",
		"salary_structure_component",
		&targetMappingID,
		"admin",
		&actorID,
		beforeJSON,
		nil,
		map[string]interface{}{
			"structure_id":   structureID.String(),
			"component_code": componentCode,
			"ip":             ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) ReorderComponents(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	componentCodes []string,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_comp_reorder-%s", structureID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	comps, err := s.repo.GetStructureComponents(ctx, structureID, companyID)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return nil
	}

	orderMap := make(map[string]int)
	for i, code := range componentCodes {
		orderMap[code] = i + 1
	}

	beforeJSON, _ := json.Marshal(comps)

	for _, c := range comps {
		if newOrder, ok := orderMap[c.ComponentCode]; ok {
			c.SequenceOrder = newOrder
			if err := s.repo.UpdateStructureComponent(ctx, &c); err != nil {
				return err
			}
		}
	}

	afterJSON, _ := json.Marshal(comps)
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"salary_structure_components_reordered",
		"salary_structure",
		&structureID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"new_order": componentCodes,
			"ip":        ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

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
// EMPLOYEE ASSIGNMENT (with idempotency + location scope)
// ---------------------------------------------------------------------

func (s *salaryStructureService) AssignToEmployee(
	ctx context.Context,
	input *models.AssignSalaryStructureInput,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_assign-%s-%s", input.UserID.String(), input.EffectiveFrom.Format("2006-01-02"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
		return err
	}

	if err := s.ValidateAssignmentAllowed(ctx, input.CompanyID, input.EffectiveFrom); err != nil {
		return err
	}

	overlap, err := s.repo.HasOverlappingSalaryAssignment(
		ctx,
		input.CompanyID,
		input.UserID,
		input.EffectiveFrom,
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	if overlap {
		return fmt.Errorf("employee already has an active salary overlapping this effective date; please end the current one first")
	}

	salary := &models.EmployeeSalary{
		EmployeeSalaryID:  uuid.New(),
		CompanyID:         input.CompanyID,
		UserID:            input.UserID,
		SalaryStructureID: input.StructureID,
		MonthlyCTC:        input.MonthlyCTC,
		PayType:           input.PayType,
		EffectiveFrom:     input.EffectiveFrom,
		IsActive:          true,
		UpdatedBy:         &input.ActorID,
	}

	beforeJSON, _ := json.Marshal(salary)
	if err := s.repo.CreateEmployeeSalary(ctx, salary); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(salary)

	// Arrears generation (best effort)
	today := time.Now().Truncate(24 * time.Hour)
	if input.EffectiveFrom.Before(today) {
		prev, _ := s.repo.GetActiveEmployeeSalary(ctx, input.CompanyID, input.UserID, input.EffectiveFrom.Add(-time.Nanosecond))
		if prev != nil {
			_ = s.arrearsSvc.GenerateArrearsForSalaryChange(
				ctx,
				input.CompanyID,
				input.UserID,
				prev.EmployeeSalaryID,
				salary.EmployeeSalaryID,
				input.EffectiveFrom,
			)
		}
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&input.CompanyID,
		"payroll",
		"salary_structure_assigned",
		"employee_salary",
		&salary.EmployeeSalaryID,
		"admin",
		&input.ActorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"user_id":      input.UserID.String(),
			"structure_id": input.StructureID.String(),
			"ip":           ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) BulkAssignToEmployees(
	ctx context.Context,
	input *models.BulkAssignSalaryStructureInput,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_bulk_assign-%s", input.StructureID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// 👇 Location scope check for every target user (fail fast before any write)
	for _, userID := range input.UserIDs {
		if err := s.ensureEmployeeInScope(ctx, input.CompanyID, userID); err != nil {
			return fmt.Errorf("user %s: %w", userID.String(), err)
		}
	}

	for _, userID := range input.UserIDs {
		err := s.AssignToEmployee(ctx, &models.AssignSalaryStructureInput{
			CompanyID:     input.CompanyID,
			UserID:        userID,
			StructureID:   input.StructureID,
			MonthlyCTC:    input.MonthlyCTC,
			PayType:       input.PayType,
			EffectiveFrom: input.EffectiveFrom,
			ActorID:       input.ActorID,
		})
		if err != nil {
			return err
		}
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) ChangeEmployeeStructure(
	ctx context.Context,
	input *models.ChangeSalaryStructureInput,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_change-%s-%s", input.UserID.String(), input.EffectiveFrom.Format("2006-01-02"))
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, input.CompanyID, input.UserID); err != nil {
		return err
	}

	if err := s.ValidateAssignmentAllowed(ctx, input.CompanyID, input.EffectiveFrom); err != nil {
		return err
	}

	endDate := input.EffectiveFrom.AddDate(0, 0, -1)
	_ = s.EndEmployeeStructure(ctx, input.CompanyID, input.UserID, endDate, input.ActorID)

	if err := s.AssignToEmployee(ctx, &models.AssignSalaryStructureInput{
		CompanyID:     input.CompanyID,
		UserID:        input.UserID,
		StructureID:   input.NewStructureID,
		MonthlyCTC:    input.MonthlyCTC,
		PayType:       input.PayType,
		EffectiveFrom: input.EffectiveFrom,
		ActorID:       input.ActorID,
	}); err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *salaryStructureService) EndEmployeeStructure(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	endDate time.Time,
	actorID uuid.UUID,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("salary_end-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return err
	}

	active, err := s.repo.GetActiveEmployeeSalary(ctx, companyID, userID, endDate)
	if err != nil || active == nil {
		return fmt.Errorf("no active salary found on %s", endDate.Format("2006-01-02"))
	}

	beforeJSON, _ := json.Marshal(active)

	active.EffectiveTo = &endDate
	active.IsActive = false
	active.UpdatedBy = &actorID

	if err := s.repo.UpdateEmployeeSalary(ctx, active); err != nil {
		return err
	}
	afterJSON, _ := json.Marshal(active)

	today := time.Now().Truncate(24 * time.Hour)
	if endDate.Before(today) {
		_ = s.arrearsSvc.GenerateArrearsForSalaryEnd(
			ctx,
			companyID,
			userID,
			active.EmployeeSalaryID,
			endDate,
		)
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"salary_structure_ended",
		"employee_salary",
		&active.EmployeeSalaryID,
		"admin",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"user_id":      userID.String(),
			"structure_id": active.SalaryStructureID.String(),
			"end_date":     endDate,
			"ip":           ip,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ---------------------------------------------------------------------
// QUERY METHODS (with location scope where target is an employee)
// ---------------------------------------------------------------------

func (s *salaryStructureService) GetActiveStructureForEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.EmployeeSalaryStructure, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

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
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

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
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	return s.compensationSvc.ResolveSalaryStructure(ctx, companyID, userID, asOf)
}
