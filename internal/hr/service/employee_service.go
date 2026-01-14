package service

import (
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// EMPLOYEE SERVICE (WRITE OPERATIONS)
// ============================================================================

// EmployeeService handles employee write operations with audit logging
type EmployeeService struct {
	employeeRepo      repository.EmployeeRepository
	auditService      *AuditService
	documentStorage   DocumentStorage
	logger            *zap.Logger
	maxDocumentSizeMB int
}

// EmployeeServiceConfig contains service configuration
type EmployeeServiceConfig struct {
	MaxDocumentSizeMB int
	DocumentStorage   DocumentStorage
}

func NewEmployeeService(
	employeeRepo repository.EmployeeRepository,
	auditService *AuditService,
	config EmployeeServiceConfig,
	logger *zap.Logger,
) *EmployeeService {

	if auditService == nil {
		panic("auditService is required for EmployeeService")
	}
	if config.DocumentStorage == nil {
		panic("documentStorage is required for EmployeeService")
	}

	if config.MaxDocumentSizeMB <= 0 {
		config.MaxDocumentSizeMB = 50
	}

	return &EmployeeService{
		employeeRepo:      employeeRepo,
		auditService:      auditService,
		documentStorage:   config.DocumentStorage,
		logger:            logger,
		maxDocumentSizeMB: config.MaxDocumentSizeMB,
	}
}

// CreateEmployeeProfile creates a new employee profile
func (s *EmployeeService) CreateEmployeeProfile(
	ctx context.Context,
	profile *employee.EmployeeProfile,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeProfile, error) {
	startTime := time.Now()

	// Generate profile ID if not provided
	if profile.EmployeeProfileID == uuid.Nil {
		profile.EmployeeProfileID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}

	// Validate required fields
	if profile.UserID == uuid.Nil {
		return nil, fmt.Errorf("user_id is required")
	}
	if profile.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}

	// Create profile in repository
	beforeState := []byte("{}") // Empty before state for creation

	err := s.employeeRepo.CreateEmployeeProfile(ctx, profile)
	if err != nil {
		s.logger.Error("Failed to create employee profile",
			util.String("user_id", profile.UserID.String()),
			util.String("company_id", profile.CompanyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create employee profile: %w", err)
	}

	// Prepare after state for audit
	afterState, _ := util.ToJSON(profile)

	// Log audit entry
	auditErr := s.auditService.LogAction(
		ctx,
		&profile.CompanyID,
		"hr",
		"employee.profile.create",
		"employee_profile",
		&profile.EmployeeProfileID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)

	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for profile creation",
			util.String("profile_id", profile.EmployeeProfileID.String()),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Employee profile created",
		util.String("profile_id", profile.EmployeeProfileID.String()),
		util.String("user_id", profile.UserID.String()),
		util.String("company_id", profile.CompanyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return profile, nil
}

// UpdateEmployeeProfile updates an existing employee profile
func (s *EmployeeService) UpdateEmployeeProfile(
	ctx context.Context,
	profileID uuid.UUID,
	updates map[string]interface{},
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeProfile, error) {
	startTime := time.Now()

	// Get existing profile for audit
	existingProfile, err := s.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing profile: %w", err)
	}

	beforeState, _ := util.ToJSON(existingProfile)

	// Apply updates
	updatedProfile := *existingProfile
	updatedProfile.UpdatedAt = time.Now().UTC()

	// Update fields (simplified - in reality, you'd have validation for each field)
	for key, value := range updates {
		switch key {
		case "date_of_birth":
			if dob, ok := value.(time.Time); ok {
				updatedProfile.DateOfBirth = &dob
			}
		case "gender":
			if gender, ok := value.(string); ok {
				updatedProfile.Gender = &gender
			}
		case "marital_status":
			if status, ok := value.(string); ok {
				updatedProfile.MaritalStatus = &status
			}
		case "nationality":
			if nationality, ok := value.(string); ok {
				updatedProfile.Nationality = &nationality
			}
		case "employment_type":
			if empType, ok := value.(string); ok {
				updatedProfile.EmploymentType = &empType
			}
		case "employment_status":
			if status, ok := value.(string); ok {
				updatedProfile.EmploymentStatus = &status
			}
		case "job_title":
			if title, ok := value.(string); ok {
				updatedProfile.JobTitle = &title
			}
		case "grade":
			if grade, ok := value.(string); ok {
				updatedProfile.Grade = &grade
			}
		}
	}

	// Save updated profile
	err = s.employeeRepo.UpdateEmployeeProfile(ctx, &updatedProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to update employee profile: %w", err)
	}

	// Log audit
	afterState, _ := util.ToJSON(&updatedProfile)

	auditErr := s.auditService.LogAction(
		ctx,
		&updatedProfile.CompanyID,
		"hr",
		"employee.profile.update",
		"employee_profile",
		&profileID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)

	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for profile update",
			util.String("profile_id", profileID.String()),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Employee profile updated",
		util.String("profile_id", profileID.String()),
		util.String("user_id", updatedProfile.UserID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return &updatedProfile, nil
}

// DeleteEmployeeProfile deletes an employee profile
func (s *EmployeeService) DeleteEmployeeProfile(
	ctx context.Context,
	profileID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get profile for audit
	profile, err := s.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return fmt.Errorf("failed to get profile for deletion: %w", err)
	}

	beforeState, _ := util.ToJSON(profile)

	// Delete the profile
	err = s.employeeRepo.DeleteEmployeeProfile(ctx, profileID)
	if err != nil {
		return fmt.Errorf("failed to delete employee profile: %w", err)
	}

	// Log audit
	auditErr := s.auditService.LogAction(
		ctx,
		&profile.CompanyID,
		"hr",
		"employee.profile.delete",
		"employee_profile",
		&profileID,
		actorType,
		&actorID,
		beforeState,
		[]byte("{}"), // Empty after state for deletion
		metadata,
	)

	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for profile deletion",
			util.String("profile_id", profileID.String()),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Employee profile deleted",
		util.String("profile_id", profileID.String()),
		util.String("user_id", profile.UserID.String()),
		util.String("company_id", profile.CompanyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *EmployeeService) UploadEmployeeDocument(
	ctx context.Context,
	file multipart.File,
	header *multipart.FileHeader,
	companyID, userID uuid.UUID,
	documentType, documentName string,
	isConfidential bool,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeDocument, error) {
	startTime := time.Now()

	// 🔒 1. ENFORCE MAX FILE SIZE (cheap check first)
	if header.Size > int64(s.maxDocumentSizeMB)*1024*1024 {
		return nil, fmt.Errorf(
			"file size %d exceeds max allowed size %d MB",
			header.Size,
			s.maxDocumentSizeMB,
		)
	}

	// 🔒 2. VALIDATE USER EXISTS
	userExists, err := s.employeeRepo.UserExists(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user existence: %w", err)
	}
	if !userExists {
		return nil, fmt.Errorf("user does not exist")
	}

	// 🔒 3. VALIDATE USER IS EMPLOYEE OF COMPANY
	isEmployee, err := s.employeeRepo.IsUserEmployeeOfCompany(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate employee ownership: %w", err)
	}
	if !isEmployee {
		return nil, fmt.Errorf("user is not an employee of this company")
	}

	// 📤 4. UPLOAD TO DOCUMENT STORAGE (only after validations)
	uploadResult, err := s.documentStorage.UploadDocument(ctx, file, header, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to upload document: %w", err)
	}

	// 🧾 5. CREATE DOCUMENT RECORD
	document := &employee.EmployeeDocument{
		DocumentID:        uuid.New(),
		UserID:            userID,
		CompanyID:         companyID,
		DocumentType:      &documentType,
		DocumentName:      &documentName,
		DocumentObjectKey: uploadResult.ObjectKey,
		MimeType:          &uploadResult.MimeType,
		IsConfidential:    isConfidential,
		UploadedBy:        &actorID,
		UploadedAt:        &uploadResult.UploadedAt,
	}

	// 💾 6. SAVE TO DATABASE
	err = s.employeeRepo.CreateEmployeeDocument(ctx, document)
	if err != nil {
		// 🧹 CLEANUP UPLOADED FILE IF DB WRITE FAILS
		_ = s.documentStorage.DeleteDocument(ctx, uploadResult.ObjectKey)
		return nil, fmt.Errorf("failed to save document record: %w", err)
	}

	// 🧠 7. AUDIT LOG (non-blocking)
	afterState, _ := util.ToJSON(document)

	auditErr := s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"employee.document.upload",
		"employee_document",
		&document.DocumentID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterState,
		metadata,
	)
	if auditErr != nil {
		s.logger.Warn(
			"Failed to log audit entry for document upload",
			util.String("document_id", document.DocumentID.String()),
			util.ErrorField(auditErr),
		)
	}

	// 📊 8. LOG SUCCESS
	s.logger.Info(
		"Employee document uploaded",
		util.String("document_id", document.DocumentID.String()),
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.String("document_type", documentType),
		util.Bool("confidential", isConfidential),
		util.Int64("file_size", uploadResult.FileSize),
		util.Duration("duration", time.Since(startTime)),
	)

	return document, nil
}

func (s *EmployeeService) DeleteEmployeeDocument(
	ctx context.Context,
	documentID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get document for audit
	document, err := s.employeeRepo.GetEmployeeDocumentByID(ctx, documentID)
	if err != nil {
		return fmt.Errorf("failed to get document for deletion: %w", err)
	}

	beforeState, _ := util.ToJSON(document)

	// ✅ DELETE DB RECORD FIRST (SOURCE OF TRUTH)
	err = s.employeeRepo.DeleteEmployeeDocument(ctx, documentID)
	if err != nil {
		return fmt.Errorf("failed to delete document record: %w", err)
	}

	// ✅ DELETE STORAGE FILE (BEST-EFFORT)
	if err := s.documentStorage.DeleteDocument(ctx, document.DocumentObjectKey); err != nil {
		s.logger.Warn("Failed to delete document file after DB deletion",
			util.String("document_id", documentID.String()),
			util.ErrorField(err))
	}

	// Audit log
	auditErr := s.auditService.LogAction(
		ctx,
		&document.CompanyID,
		"hr",
		"employee.document.delete",
		"employee_document",
		&documentID,
		actorType,
		&actorID,
		beforeState,
		[]byte("{}"),
		metadata,
	)

	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for document deletion",
			util.String("document_id", documentID.String()),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Employee document deleted",
		util.String("document_id", documentID.String()),
		util.String("user_id", document.UserID.String()),
		util.String("company_id", document.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// CreateDepartmentAssignment assigns an employee to a department
func (s *EmployeeService) CreateDepartmentAssignment(
	ctx context.Context,
	userID, companyID, departmentID uuid.UUID,
	changeReason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeDepartmentHistory, error) {

	startTime := time.Now()
	now := time.Now().UTC()

	// ---------------------------------------------------------------------
	// 1. Check current active department
	// ---------------------------------------------------------------------
	activeAssignment, err := s.employeeRepo.GetActiveDepartmentAssignment(ctx, userID)
	if err == nil {
		// Active assignment exists
		if activeAssignment.DepartmentID == departmentID {
			// ❌ SAME department → reject
			return nil, fmt.Errorf("employee is already assigned to this department")
		}

		// ✅ Different department → end previous assignment
		err = s.employeeRepo.EndDepartmentAssignment(ctx, userID, now.Add(-time.Second))
		if err != nil {
			return nil, fmt.Errorf("failed to end previous department assignment: %w", err)
		}
	}

	// ---------------------------------------------------------------------
	// 2. Create new department assignment
	// ---------------------------------------------------------------------
	history := &employee.EmployeeDepartmentHistory{
		ID:           uuid.New(),
		UserID:       userID,
		CompanyID:    companyID,
		DepartmentID: departmentID,
		StartDate:    now,
		EndDate:      nil,
		ChangeReason: &changeReason,
		CreatedAt:    now,
	}

	err = s.employeeRepo.CreateDepartmentHistory(ctx, history)
	if err != nil {
		return nil, fmt.Errorf("failed to create department assignment: %w", err)
	}

	// ---------------------------------------------------------------------
	// 3. Audit log
	// ---------------------------------------------------------------------
	afterState, _ := util.ToJSON(history)

	auditErr := s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"employee.department.assign",
		"employee_department_history",
		&history.ID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterState,
		metadata,
	)

	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for department assignment",
			util.String("history_id", history.ID.String()),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Department assignment created",
		util.String("history_id", history.ID.String()),
		util.String("user_id", userID.String()),
		util.String("department_id", departmentID.String()),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return history, nil
}

// CreateEmployeeExit records employee termination/exit
func (s *EmployeeService) CreateEmployeeExit(
	ctx context.Context,
	userID, companyID uuid.UUID,
	exitDate time.Time,
	exitReason string,
	eligibleForRehire bool,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeExit, error) {

	// Prevent duplicate active exits
	existing, _ := s.employeeRepo.GetEmployeeExitByUserID(ctx, userID, companyID)
	if existing != nil && existing.ExitState == "scheduled" {
		return nil, fmt.Errorf("employee exit already scheduled")
	}

	exit := &employee.EmployeeExit{
		ExitID:            uuid.New(),
		UserID:            userID,
		CompanyID:         companyID,
		ExitDate:          &exitDate,
		ExitReason:        &exitReason,
		EligibleForRehire: &eligibleForRehire,
		ExitState:         "scheduled",
		CreatedAt:         time.Now().UTC(),
	}

	if err := s.employeeRepo.CreateEmployeeExit(ctx, exit); err != nil {
		return nil, err
	}

	afterState, _ := util.ToJSON(exit)

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"employee.exit.schedule",
		"employee_exit",
		&exit.ExitID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterState,
		metadata,
	)

	return exit, nil
}

// CreatePosition creates a new position
func (s *EmployeeService) CreatePosition(
	ctx context.Context,
	position *employee.Position,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.Position, error) {
	startTime := time.Now()

	if position.PositionID == uuid.Nil {
		position.PositionID = uuid.New()
	}

	now := time.Now().UTC()
	if position.CreatedAt.IsZero() {
		position.CreatedAt = now
	}
	if position.UpdatedAt.IsZero() {
		position.UpdatedAt = now
	}

	err := s.employeeRepo.CreatePosition(ctx, position)
	if err != nil {
		return nil, fmt.Errorf("failed to create position: %w", err)
	}

	// Log audit
	afterState, _ := util.ToJSON(position)

	auditErr := s.auditService.LogAction(
		ctx,
		&position.CompanyID,
		"hr",
		"position.create",
		"position",
		&position.PositionID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterState,
		metadata,
	)

	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for position creation",
			util.String("position_id", position.PositionID.String()),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Position created",
		util.String("position_id", position.PositionID.String()),
		util.String("company_id", position.CompanyID.String()),
		util.String("department_id", position.DepartmentID.String()),
		util.String("title", *position.Title),
		util.Bool("is_open", position.IsOpen),
		util.Duration("duration", time.Since(startTime)))

	return position, nil
}

// HealthCheck performs service health check
func (s *EmployeeService) HealthCheck(ctx context.Context) error {
	if err := s.employeeRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("employee repository health check failed: %w", err)
	}

	if s.documentStorage != nil {
		if err := s.documentStorage.HealthCheck(ctx); err != nil {
			return fmt.Errorf("document storage health check failed: %w", err)
		}
	}

	return nil
}

// TODO: replace with typed repository errors (errors.Is(err, repository.ErrNotFound))

// Helper function to check if error is "not found"
func isNotFoundError(err error) bool {
	return err != nil && (err.Error() == "employee profile not found" ||
		err.Error() == "no active department assignment found for user")
}

// GetEmployeeProfileByID returns an employee profile by profile ID
func (s *EmployeeService) GetEmployeeProfileByID(
	ctx context.Context,
	profileID uuid.UUID,
) (*employee.EmployeeProfile, error) {

	if profileID == uuid.Nil {
		return nil, fmt.Errorf("employee profile id is required")
	}

	profile, err := s.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (s *EmployeeService) EnforceScheduledEmployeeExits(
	ctx context.Context,
	effectiveDate time.Time,
	actorID uuid.UUID,
) (int, error) {

	count, err := s.employeeRepo.EnforceScheduledEmployeeExits(
		ctx,
		effectiveDate,
		actorID,
	)
	if err != nil {
		return 0, err
	}

	s.logger.Info("Employee exits enforced",
		util.Int("count", count),
		util.Time("effective_date", effectiveDate),
	)

	return count, nil
}

func (s *EmployeeService) RehireEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {

	if err := s.employeeRepo.RehireEmployee(ctx, companyID, userID); err != nil {
		return err
	}

	_ = s.auditService.LogAction(
		ctx,
		&companyID,
		"hr",
		"employee.rehire",
		"employee_exit",
		nil,
		actorType,
		&actorID,
		nil,
		nil,
		metadata,
	)

	return nil
}
