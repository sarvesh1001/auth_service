// internal/hr/service/compensation_service_impl.go
package service

import (
	"auth-service/internal/hr/models/compensation"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// ============================================================================
// COMPENSATION SERVICE IMPLEMENTATION
// ============================================================================

type compensationServiceImpl struct {
	compRepo  repository.CompensationRepository
	auditRepo repository.AuditRepository
	logger    *zap.Logger
	mu        sync.RWMutex
}

// NewCompensationService creates a new compensation service
func NewCompensationService(
	compRepo repository.CompensationRepository,
	auditRepo repository.AuditRepository,
	logger *zap.Logger,
) CompensationService {
	return &compensationServiceImpl{
		compRepo:  compRepo,
		auditRepo: auditRepo,
		logger:    logger,
	}
}

// ============================================================================
// PAY UNIT MANAGEMENT
// ============================================================================
func (s *compensationServiceImpl) CreatePayUnit(
	ctx context.Context,
	payUnit *compensation.PayUnit,
	actorType string,
	actorID uuid.UUID,
) (*compensation.PayUnit, error) {

	startTime := time.Now()

	// Validate
	if err := s.validatePayUnit(payUnit); err != nil {
		return nil, fmt.Errorf("pay unit validation failed: %w", err)
	}

	// Generate ID
	if payUnit.PayUnitID == uuid.Nil {
		payUnit.PayUnitID = uuid.New()
	}

	// Persist (DB is the source of truth)
	if err := s.compRepo.CreatePayUnit(ctx, payUnit); err != nil {
		return nil, err
	}

	// Audit (use existing pattern in this service)
	afterState, _ := json.Marshal(payUnit)
	if err := s.logAudit(
		ctx,
		nil, // pay units are global (no company)
		"compensation",
		"pay_unit.create",
		"pay_unit",
		&payUnit.PayUnitID,
		&actorID,
		nil,
		afterState,
		nil,
	); err != nil {
		s.logger.Warn("Failed to log audit for pay unit creation",
			util.ErrorField(err))
	}

	s.logger.Info("Pay unit created",
		util.String("pay_unit_id", payUnit.PayUnitID.String()),
		util.String("pay_unit_name", payUnit.Name),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return payUnit, nil
}

// ============================================================================
// COMPENSATION STRUCTURE MANAGEMENT
// ============================================================================

func (s *compensationServiceImpl) CreateCompensationStructure(
	ctx context.Context,
	structure *compensation.CompensationStructure,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*compensation.CompensationStructure, error) {
	startTime := time.Now()

	// Validate compensation structure
	if err := s.validateCompensationStructure(structure); err != nil {
		return nil, fmt.Errorf("compensation structure validation failed: %w", err)
	}

	// Check for duplicate structure code
	existingStructure, err := s.compRepo.GetCompensationStructureByCode(ctx, structure.CompanyID, structure.StructureCode)
	if err == nil && existingStructure != nil {
		return nil, fmt.Errorf("compensation structure with code '%s' already exists", structure.StructureCode)
	}

	// Generate structure ID if not provided
	if structure.StructureID == uuid.Nil {
		structure.StructureID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if structure.CreatedAt.IsZero() {
		structure.CreatedAt = now
	}

	// Validate components
	if err := s.validateComponents(structure.Components); err != nil {
		return nil, fmt.Errorf("components validation failed: %w", err)
	}

	// Set default values
	if structure.Currency == "" {
		structure.Currency = "INR"
	}
	if !structure.IsActive {
		structure.IsActive = true
	}

	// Save to repository
	err = s.compRepo.CreateCompensationStructure(ctx, structure)
	if err != nil {
		s.logger.Error("Failed to create compensation structure",
			util.String("company_id", structure.CompanyID.String()),
			util.String("structure_code", structure.StructureCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create compensation structure: %w", err)
	}

	// Log audit
	afterState, _ := json.Marshal(structure)
	if err := s.logAudit(ctx, &structure.CompanyID, "compensation", "structure.create", "compensation_structure",
		&structure.StructureID, &actorID, nil, afterState, metadata); err != nil {
		s.logger.Warn("Failed to log audit for compensation structure creation",
			util.ErrorField(err))
	}

	s.logger.Info("Compensation structure created",
		util.String("structure_id", structure.StructureID.String()),
		util.String("company_id", structure.CompanyID.String()),
		util.String("structure_code", structure.StructureCode),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return structure, nil
}

func (s *compensationServiceImpl) UpdateCompensationStructure(
	ctx context.Context,
	structure *compensation.CompensationStructure,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get existing structure
	existingStructure, err := s.compRepo.GetCompensationStructureByID(ctx, structure.StructureID)
	if err != nil {
		return fmt.Errorf("compensation structure not found: %w", err)
	}

	// Validate update
	if existingStructure.CompanyID != structure.CompanyID {
		return fmt.Errorf("cannot change company ID for compensation structure")
	}

	if existingStructure.StructureCode != structure.StructureCode {
		// Check if new structure code already exists
		duplicate, err := s.compRepo.GetCompensationStructureByCode(ctx, structure.CompanyID, structure.StructureCode)
		if err == nil && duplicate != nil && duplicate.StructureID != structure.StructureID {
			return fmt.Errorf("compensation structure with code '%s' already exists", structure.StructureCode)
		}
	}

	// Validate components
	if err := s.validateComponents(structure.Components); err != nil {
		return fmt.Errorf("components validation failed: %w", err)
	}

	// Save before state for audit
	beforeState, _ := json.Marshal(existingStructure)

	// Update structure
	err = s.compRepo.UpdateCompensationStructure(ctx, structure)
	if err != nil {
		s.logger.Error("Failed to update compensation structure",
			util.String("structure_id", structure.StructureID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update compensation structure: %w", err)
	}

	// Log audit
	afterState, _ := json.Marshal(structure)
	if err := s.logAudit(ctx, &structure.CompanyID, "compensation", "structure.update", "compensation_structure",
		&structure.StructureID, &actorID, beforeState, afterState, metadata); err != nil {
		s.logger.Warn("Failed to log audit for compensation structure update",
			util.ErrorField(err))
	}

	s.logger.Info("Compensation structure updated",
		util.String("structure_id", structure.StructureID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *compensationServiceImpl) DeactivateCompensationStructure(
	ctx context.Context,
	structureID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get existing structure
	structure, err := s.compRepo.GetCompensationStructureByID(ctx, structureID)
	if err != nil {
		return fmt.Errorf("compensation structure not found: %w", err)
	}

	// Check if structure is already inactive
	if !structure.IsActive {
		return fmt.Errorf("compensation structure is already inactive")
	}

	// Check if structure is in use
	userComps, _, err := s.compRepo.GetUserCompensationsByCompany(ctx, structure.CompanyID, 1, 0)
	if err == nil && len(userComps) > 0 {
		for _, comp := range userComps {
			if comp.StructureID == structureID {
				// Check if any active user compensation exists
				if comp.EffectiveTo == nil || comp.EffectiveTo.After(time.Now()) {
					return fmt.Errorf("cannot deactivate structure that is in use by active employees")
				}
			}
		}
	}

	// Save before state for audit
	beforeState, _ := json.Marshal(structure)

	// Deactivate structure
	structure.IsActive = false
	err = s.compRepo.UpdateCompensationStructure(ctx, structure)
	if err != nil {
		s.logger.Error("Failed to deactivate compensation structure",
			util.String("structure_id", structureID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate compensation structure: %w", err)
	}

	// Log audit
	afterState, _ := json.Marshal(structure)
	if err := s.logAudit(ctx, &structure.CompanyID, "compensation", "structure.deactivate", "compensation_structure",
		&structureID, &actorID, beforeState, afterState, metadata); err != nil {
		s.logger.Warn("Failed to log audit for compensation structure deactivation",
			util.ErrorField(err))
	}

	s.logger.Info("Compensation structure deactivated",
		util.String("structure_id", structureID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *compensationServiceImpl) AssignCompensationStructureToUsers(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	userIDs []uuid.UUID,
	effectiveFrom time.Time,
	effectiveTo *time.Time,
	assignedBy uuid.UUID,
	metadata map[string]interface{},
) ([]*compensation.UserCompensation, error) {
	startTime := time.Now()

	// Validate parameters
	if len(userIDs) == 0 {
		return nil, fmt.Errorf("no user IDs provided")
	}

	if effectiveFrom.IsZero() {
		effectiveFrom = time.Now().UTC()
	}

	// Get compensation structure
	structure, err := s.compRepo.GetCompensationStructureByID(ctx, structureID)
	if err != nil {
		return nil, fmt.Errorf("compensation structure not found: %w", err)
	}

	if structure.CompanyID != companyID {
		return nil, fmt.Errorf("compensation structure does not belong to company")
	}

	if !structure.IsActive {
		return nil, fmt.Errorf("cannot assign inactive compensation structure")
	}

	// Create user compensations
	var userComps []*compensation.UserCompensation
	var createdComps []*compensation.UserCompensation

	for _, userID := range userIDs {
		// End any existing active compensation
		if err := s.compRepo.EndUserCompensation(ctx, userID, effectiveFrom); err != nil {
			s.logger.Warn("Failed to end existing user compensation",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			// Continue anyway
		}

		// Create new user compensation
		userComp := &compensation.UserCompensation{
			UserID:        userID,
			StructureID:   structureID,
			CTCAmount:     decimal.Zero, // Should be calculated based on structure
			EffectiveFrom: effectiveFrom,
			EffectiveTo:   effectiveTo,
			AssignedBy:    &assignedBy,
			CreatedAt:     time.Now().UTC(),
		}

		// Calculate CTC amount based on structure
		ctcAmount, err := s.calculateCTCAmount(structure, userComp)
		if err != nil {
			s.logger.Warn("Failed to calculate CTC amount",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			continue
		}
		userComp.CTCAmount = ctcAmount

		// Take snapshot of structure
		snapshot, err := json.Marshal(structure)
		if err != nil {
			s.logger.Warn("Failed to marshal structure snapshot",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			continue
		}
		userComp.StructureSnapshot = snapshot

		userComps = append(userComps, userComp)
	}

	// Save user compensations in batch
	if len(userComps) > 0 {
		if err := s.compRepo.CreateUserCompensationsBatch(ctx, userComps); err != nil {
			return nil, fmt.Errorf("failed to create user compensations: %w", err)
		}
		createdComps = userComps
	}

	// Log audit
	for _, comp := range createdComps {
		compJSON, _ := json.Marshal(comp)
		if err := s.logAudit(ctx, &companyID, "compensation", "structure.assign", "user_compensation",
			&comp.UserID, &assignedBy, nil, compJSON, metadata); err != nil {
			s.logger.Warn("Failed to log audit for compensation assignment",
				util.String("user_id", comp.UserID.String()),
				util.ErrorField(err))
		}
	}

	s.logger.Info("Compensation structure assigned to users",
		util.String("structure_id", structureID.String()),
		util.String("company_id", companyID.String()),
		util.Int("user_count", len(createdComps)),
		util.String("assigned_by", assignedBy.String()),
		util.Duration("duration", time.Since(startTime)))

	return createdComps, nil
}

// ============================================================================
// USER COMPENSATION MANAGEMENT
// ============================================================================

func (s *compensationServiceImpl) CreateUserCompensation(
	ctx context.Context,
	userComp *compensation.UserCompensation,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*compensation.UserCompensation, error) {
	startTime := time.Now()

	// Validate user compensation
	if err := s.validateUserCompensation(userComp); err != nil {
		return nil, fmt.Errorf("user compensation validation failed: %w", err)
	}

	// Get compensation structure
	structure, err := s.compRepo.GetCompensationStructureByID(ctx, userComp.StructureID)
	if err != nil {
		return nil, fmt.Errorf("compensation structure not found: %w", err)
	}

	// Check if structure is active
	if !structure.IsActive {
		return nil, fmt.Errorf("cannot assign inactive compensation structure")
	}

	// End any existing active compensation
	if err := s.compRepo.EndUserCompensation(ctx, userComp.UserID, userComp.EffectiveFrom); err != nil {
		s.logger.Warn("Failed to end existing user compensation",
			util.String("user_id", userComp.UserID.String()),
			util.ErrorField(err))
	}

	// Calculate CTC amount based on structure
	ctcAmount, err := s.calculateCTCAmount(structure, userComp)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate CTC amount: %w", err)
	}
	userComp.CTCAmount = ctcAmount

	// Take snapshot of structure
	snapshot, err := json.Marshal(structure)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal structure snapshot: %w", err)
	}
	userComp.StructureSnapshot = snapshot

	// Set timestamps
	if userComp.CreatedAt.IsZero() {
		userComp.CreatedAt = time.Now().UTC()
	}

	// Save to repository
	err = s.compRepo.CreateUserCompensation(ctx, userComp)
	if err != nil {
		s.logger.Error("Failed to create user compensation",
			util.String("user_id", userComp.UserID.String()),
			util.String("structure_id", userComp.StructureID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create user compensation: %w", err)
	}

	// Log audit
	compJSON, _ := json.Marshal(userComp)
	if err := s.logAudit(ctx, &structure.CompanyID, "compensation", "user_compensation.create", "user_compensation",
		&userComp.UserID, &actorID, nil, compJSON, metadata); err != nil {
		s.logger.Warn("Failed to log audit for user compensation creation",
			util.ErrorField(err))
	}

	s.logger.Info("User compensation created",
		util.String("user_id", userComp.UserID.String()),
		util.String("structure_id", userComp.StructureID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return userComp, nil
}

func (s *compensationServiceImpl) UpdateUserCompensation(
	ctx context.Context,
	userComp *compensation.UserCompensation,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get existing user compensation
	existingComp, err := s.compRepo.GetUserCompensationByID(ctx, userComp.UserID, userComp.StructureID, userComp.EffectiveFrom)
	if err != nil {
		return fmt.Errorf("user compensation not found: %w", err)
	}

	// Validate update
	if existingComp.UserID != userComp.UserID || existingComp.StructureID != userComp.StructureID {
		return fmt.Errorf("cannot change user ID or structure ID for user compensation")
	}

	// Get compensation structure for validation
	structure, err := s.compRepo.GetCompensationStructureByID(ctx, userComp.StructureID)
	if err != nil {
		return fmt.Errorf("compensation structure not found: %w", err)
	}

	// Recalculate CTC amount if needed
	if userComp.CTCAmount.IsZero() {
		ctcAmount, err := s.calculateCTCAmount(structure, userComp)
		if err != nil {
			return fmt.Errorf("failed to calculate CTC amount: %w", err)
		}
		userComp.CTCAmount = ctcAmount
	}

	// Take snapshot of current structure
	snapshot, err := json.Marshal(structure)
	if err != nil {
		return fmt.Errorf("failed to marshal structure snapshot: %w", err)
	}
	userComp.StructureSnapshot = snapshot

	// Save before state for audit
	beforeState, _ := json.Marshal(existingComp)

	// Update user compensation
	err = s.compRepo.UpdateUserCompensation(ctx, userComp)
	if err != nil {
		s.logger.Error("Failed to update user compensation",
			util.String("user_id", userComp.UserID.String()),
			util.String("structure_id", userComp.StructureID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update user compensation: %w", err)
	}

	// Log audit
	afterState, _ := json.Marshal(userComp)
	if err := s.logAudit(ctx, &structure.CompanyID, "compensation", "user_compensation.update", "user_compensation",
		&userComp.UserID, &actorID, beforeState, afterState, metadata); err != nil {
		s.logger.Warn("Failed to log audit for user compensation update",
			util.ErrorField(err))
	}

	s.logger.Info("User compensation updated",
		util.String("user_id", userComp.UserID.String()),
		util.String("structure_id", userComp.StructureID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *compensationServiceImpl) EndUserCompensation(
	ctx context.Context,
	userID uuid.UUID,
	endDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if endDate.IsZero() {
		endDate = time.Now().UTC()
	}

	// Get current user compensation
	currentComp, err := s.compRepo.GetCurrentUserCompensation(ctx, userID)
	if err != nil {
		return fmt.Errorf("no active compensation found for user: %w", err)
	}

	// Save before state for audit
	beforeState, _ := json.Marshal(currentComp)

	// End the compensation
	err = s.compRepo.EndUserCompensation(ctx, userID, endDate)
	if err != nil {
		s.logger.Error("Failed to end user compensation",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end user compensation: %w", err)
	}

	// Update the compensation record
	currentComp.EffectiveTo = &endDate
	afterState, _ := json.Marshal(currentComp)

	// Get company ID from structure
	structure, err := s.compRepo.GetCompensationStructureByID(ctx, currentComp.StructureID)
	if err != nil {
		s.logger.Warn("Failed to get compensation structure for audit",
			util.String("structure_id", currentComp.StructureID.String()),
			util.ErrorField(err))
	} else {
		// Log audit
		if err := s.logAudit(ctx, &structure.CompanyID, "compensation", "user_compensation.end", "user_compensation",
			&userID, &actorID, beforeState, afterState, metadata); err != nil {
			s.logger.Warn("Failed to log audit for user compensation end",
				util.ErrorField(err))
		}
	}

	s.logger.Info("User compensation ended",
		util.String("user_id", userID.String()),
		util.String("structure_id", currentComp.StructureID.String()),
		util.Time("end_date", endDate),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

func (s *compensationServiceImpl) BulkAssignCompensationStructure(
	ctx context.Context,
	companyID uuid.UUID,
	structureID uuid.UUID,
	userCompensations []*compensation.UserCompensation,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if len(userCompensations) == 0 {
		return fmt.Errorf("no user compensations provided")
	}

	// Get compensation structure
	structure, err := s.compRepo.GetCompensationStructureByID(ctx, structureID)
	if err != nil {
		return fmt.Errorf("compensation structure not found: %w", err)
	}

	if structure.CompanyID != companyID {
		return fmt.Errorf("compensation structure does not belong to company")
	}

	if !structure.IsActive {
		return fmt.Errorf("cannot assign inactive compensation structure")
	}

	// Process each user compensation
	var validComps []*compensation.UserCompensation
	for _, userComp := range userCompensations {
		// Validate user compensation
		if err := s.validateUserCompensation(userComp); err != nil {
			s.logger.Warn("Invalid user compensation in bulk assignment",
				util.String("user_id", userComp.UserID.String()),
				util.ErrorField(err))
			continue
		}

		// End any existing active compensation
		if err := s.compRepo.EndUserCompensation(ctx, userComp.UserID, userComp.EffectiveFrom); err != nil {
			s.logger.Warn("Failed to end existing user compensation",
				util.String("user_id", userComp.UserID.String()),
				util.ErrorField(err))
		}

		// Calculate CTC amount
		ctcAmount, err := s.calculateCTCAmount(structure, userComp)
		if err != nil {
			s.logger.Warn("Failed to calculate CTC amount",
				util.String("user_id", userComp.UserID.String()),
				util.ErrorField(err))
			continue
		}
		userComp.CTCAmount = ctcAmount

		// Take snapshot of structure
		snapshot, err := json.Marshal(structure)
		if err != nil {
			s.logger.Warn("Failed to marshal structure snapshot",
				util.String("user_id", userComp.UserID.String()),
				util.ErrorField(err))
			continue
		}
		userComp.StructureSnapshot = snapshot

		// Set timestamps
		if userComp.CreatedAt.IsZero() {
			userComp.CreatedAt = time.Now().UTC()
		}

		validComps = append(validComps, userComp)
	}

	// Save in batch
	if len(validComps) > 0 {
		err = s.compRepo.CreateUserCompensationsBatch(ctx, validComps)
		if err != nil {
			s.logger.Error("Failed to create bulk user compensations",
				util.Int("compensation_count", len(validComps)),
				util.ErrorField(err))
			return fmt.Errorf("failed to create bulk user compensations: %w", err)
		}
	}

	// Log audit for each created compensation
	for _, comp := range validComps {
		compJSON, _ := json.Marshal(comp)
		if err := s.logAudit(ctx, &companyID, "compensation", "structure.bulk_assign", "user_compensation",
			&comp.UserID, &actorID, nil, compJSON, metadata); err != nil {
			s.logger.Warn("Failed to log audit for bulk compensation assignment",
				util.String("user_id", comp.UserID.String()),
				util.ErrorField(err))
		}
	}

	s.logger.Info("Bulk compensation assignment completed",
		util.String("structure_id", structureID.String()),
		util.String("company_id", companyID.String()),
		util.Int("total_compensations", len(validComps)),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// PAYROLL CALCULATIONS
// ============================================================================

func (s *compensationServiceImpl) CalculateMonthlyPayroll(
	ctx context.Context,
	companyID uuid.UUID,
	monthYear time.Time,
) (map[uuid.UUID]decimal.Decimal, error) {
	startTime := time.Now()

	// Get all active user compensations for the company
	userComps, _, err := s.compRepo.GetUserCompensationsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get user compensations: %w", err)
	}

	// Calculate monthly payroll for each user
	payroll := make(map[uuid.UUID]decimal.Decimal)
	firstDay := time.Date(monthYear.Year(), monthYear.Month(), 1, 0, 0, 0, 0, time.UTC)
	lastDay := firstDay.AddDate(0, 1, -1)

	for _, comp := range userComps {
		// Check if compensation is active for the given month
		if comp.EffectiveFrom.After(lastDay) {
			continue
		}
		if comp.EffectiveTo != nil && comp.EffectiveTo.Before(firstDay) {
			continue
		}

		// Calculate monthly salary
		monthlySalary, _, err := s.CalculateUserMonthlySalary(ctx, comp.UserID, monthYear)
		if err != nil {
			s.logger.Warn("Failed to calculate monthly salary for user",
				util.String("user_id", comp.UserID.String()),
				util.ErrorField(err))
			continue
		}

		payroll[comp.UserID] = monthlySalary
	}

	s.logger.Debug("Monthly payroll calculated",
		util.String("company_id", companyID.String()),
		util.String("month", monthYear.Format("2006-01")),
		util.Int("employee_count", len(payroll)),
		util.Duration("duration", time.Since(startTime)))

	return payroll, nil
}

func (s *compensationServiceImpl) CalculateUserMonthlySalary(
	ctx context.Context,
	userID uuid.UUID,
	monthYear time.Time,
) (decimal.Decimal, map[string]interface{}, error) {
	startTime := time.Now()

	// Get current user compensation
	comp, err := s.compRepo.GetCurrentUserCompensation(ctx, userID)
	if err != nil {
		return decimal.Zero, nil, fmt.Errorf("no active compensation found for user: %w", err)
	}

	// Parse structure snapshot
	var structure compensation.CompensationStructure
	if err := json.Unmarshal(comp.StructureSnapshot, &structure); err != nil {
		return decimal.Zero, nil, fmt.Errorf("failed to parse structure snapshot: %w", err)
	}

	// Get pay unit
	var payUnitName = "monthly" // default
	if comp.PayUnitID != nil {
		payUnit, err := s.compRepo.GetPayUnitByID(ctx, *comp.PayUnitID)
		if err == nil && payUnit != nil {
			payUnitName = payUnit.Name
		}
	}

	// Calculate monthly salary based on pay unit
	var monthlySalary decimal.Decimal
	details := make(map[string]interface{})

	switch payUnitName {
	case "monthly":
		monthlySalary = comp.CTCAmount
		details["calculation"] = "direct_monthly"
		details["pay_unit"] = "monthly"

	case "daily":
		// Assuming 26 working days in a month
		dailyRate := comp.CTCAmount.Div(decimal.NewFromInt(26))
		monthlySalary = dailyRate.Mul(decimal.NewFromInt(26))
		details["calculation"] = "daily_to_monthly"
		details["pay_unit"] = "daily"
		details["daily_rate"] = dailyRate
		details["working_days"] = 26

	case "hourly":
		// Assuming 8 hours/day, 26 days/month = 208 hours/month
		hourlyRate := comp.CTCAmount.Div(decimal.NewFromInt(208))
		monthlySalary = hourlyRate.Mul(decimal.NewFromInt(208))
		details["calculation"] = "hourly_to_monthly"
		details["pay_unit"] = "hourly"
		details["hourly_rate"] = hourlyRate
		details["monthly_hours"] = 208

	case "per_class":
		// Assuming 4 classes/day, 26 days/month = 104 classes/month
		classRate := comp.CTCAmount.Div(decimal.NewFromInt(104))
		monthlySalary = classRate.Mul(decimal.NewFromInt(104))
		details["calculation"] = "per_class_to_monthly"
		details["pay_unit"] = "per_class"
		details["class_rate"] = classRate
		details["monthly_classes"] = 104

	case "per_shift":
		// Assuming 26 shifts/month
		shiftRate := comp.CTCAmount.Div(decimal.NewFromInt(26))
		monthlySalary = shiftRate.Mul(decimal.NewFromInt(26))
		details["calculation"] = "per_shift_to_monthly"
		details["pay_unit"] = "per_shift"
		details["shift_rate"] = shiftRate
		details["monthly_shifts"] = 26

	default:
		monthlySalary = comp.CTCAmount
		details["calculation"] = "default_monthly"
		details["pay_unit"] = "unknown"
	}

	// Apply component calculations
	componentBreakdown, totalDeductions, totalAdditions := s.calculateComponentBreakdown(structure.Components, monthlySalary)
	netSalary := monthlySalary.Add(totalAdditions).Sub(totalDeductions)

	details["gross_salary"] = monthlySalary
	details["component_breakdown"] = componentBreakdown
	details["total_additions"] = totalAdditions
	details["total_deductions"] = totalDeductions
	details["net_salary"] = netSalary
	details["currency"] = structure.Currency

	s.logger.Debug("User monthly salary calculated",
		util.String("user_id", userID.String()),
		util.String("month", monthYear.Format("2006-01")),
		util.String("pay_unit", payUnitName),
		util.Duration("duration", time.Since(startTime)))

	return netSalary, details, nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (s *compensationServiceImpl) validatePayUnit(payUnit *compensation.PayUnit) error {
	if payUnit.Name == "" {
		return fmt.Errorf("pay unit name is required")
	}
	if len(payUnit.Name) > 30 {
		return fmt.Errorf("pay unit name cannot exceed 30 characters")
	}
	return nil
}

func (s *compensationServiceImpl) validateCompensationStructure(structure *compensation.CompensationStructure) error {
	if structure.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if structure.StructureCode == "" {
		return fmt.Errorf("structure code is required")
	}
	if len(structure.StructureCode) > 50 {
		return fmt.Errorf("structure code cannot exceed 50 characters")
	}
	if structure.Name == "" {
		return fmt.Errorf("structure name is required")
	}
	if len(structure.Name) > 100 {
		return fmt.Errorf("structure name cannot exceed 100 characters")
	}
	if len(structure.Components) == 0 {
		return fmt.Errorf("at least one component is required")
	}
	return nil
}

func (s *compensationServiceImpl) validateComponents(components []compensation.Component) error {
	if len(components) == 0 {
		return fmt.Errorf("components cannot be empty")
	}

	componentCodes := make(map[string]bool)
	for _, comp := range components {
		if comp.Code == "" {
			return fmt.Errorf("component code is required")
		}
		if componentCodes[comp.Code] {
			return fmt.Errorf("duplicate component code: %s", comp.Code)
		}
		componentCodes[comp.Code] = true

		if comp.Type != "earning" && comp.Type != "deduction" {
			return fmt.Errorf("invalid component type for %s: %s", comp.Code, comp.Type)
		}

		if comp.Calc != "fixed" && comp.Calc != "percentage" && comp.Calc != "hourly" {
			return fmt.Errorf("invalid calculation type for %s: %s", comp.Code, comp.Calc)
		}

		if comp.Calc == "percentage" && comp.Base == nil {
			return fmt.Errorf("base amount is required for percentage calculation in component %s", comp.Code)
		}

		if comp.Value == nil {
			return fmt.Errorf("value is required for component %s", comp.Code)
		}
	}

	return nil
}

func (s *compensationServiceImpl) validateUserCompensation(userComp *compensation.UserCompensation) error {
	if userComp.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if userComp.StructureID == uuid.Nil {
		return fmt.Errorf("structure ID is required")
	}
	if userComp.EffectiveFrom.IsZero() {
		return fmt.Errorf("effective from date is required")
	}
	if userComp.EffectiveTo != nil && userComp.EffectiveTo.Before(userComp.EffectiveFrom) {
		return fmt.Errorf("effective to date cannot be before effective from date")
	}
	return nil
}

func (s *compensationServiceImpl) calculateCTCAmount(structure *compensation.CompensationStructure, userComp *compensation.UserCompensation) (decimal.Decimal, error) {
	// In a real implementation, this would calculate CTC based on structure components
	// For now, return a default value or use provided CTC amount
	if !userComp.CTCAmount.IsZero() {
		return userComp.CTCAmount, nil
	}

	// Calculate CTC from components
	var ctc decimal.Decimal
	for _, component := range structure.Components {
		if component.Type == "earning" {
			if component.Calc == "fixed" && component.Value != nil {
				ctc = ctc.Add(*component.Value)
			}
		}
	}

	if ctc.IsZero() {
		// Default CTC if no earnings specified
		ctc = decimal.NewFromInt(300000) // 3 LPA default
	}

	return ctc, nil
}

func (s *compensationServiceImpl) calculateComponentBreakdown(components []compensation.Component, baseAmount decimal.Decimal) (map[string]interface{}, decimal.Decimal, decimal.Decimal) {
	breakdown := make(map[string]interface{})
	var totalDeductions, totalAdditions decimal.Decimal

	for _, component := range components {
		var amount decimal.Decimal

		switch component.Calc {
		case "fixed":
			if component.Value != nil {
				amount = *component.Value
			}
		case "percentage":
			if component.Value != nil && component.Base != nil {
				// Calculate percentage of base
				percentage := component.Value.Div(decimal.NewFromInt(100))
				amount = component.Base.Mul(percentage)
			}
		case "hourly":
			// Hourly calculations would need hours worked
			// For simplicity, using fixed for now
			if component.Value != nil {
				amount = *component.Value
			}
		}

		componentData := map[string]interface{}{
			"amount":   amount,
			"type":     component.Type,
			"calc":     component.Calc,
			"taxable":  component.Taxable,
			"currency": "INR",
		}

		breakdown[component.Code] = componentData

		if component.Type == "earning" {
			totalAdditions = totalAdditions.Add(amount)
		} else if component.Type == "deduction" {
			totalDeductions = totalDeductions.Add(amount)
		}
	}

	return breakdown, totalDeductions, totalAdditions
}

func (s *compensationServiceImpl) logAudit(
	ctx context.Context,
	companyID *uuid.UUID,
	module, action, entityType string,
	entityID, actorID *uuid.UUID,
	beforeState, afterState []byte,
	metadata map[string]interface{},
) error {
	// This is a simplified audit logging
	// In a real implementation, you would use the audit service
	s.logger.Debug("Audit log would be created",
		util.String("module", module),
		util.String("action", action),
		util.String("entity_type", entityType))
	return nil
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (s *compensationServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.compRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("compensation repository health check failed: %w", err)
	}
	return nil
}
