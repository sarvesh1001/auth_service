// internal/hr/service/employee_service.go
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/devicefp"
	"auth-service/internal/encryption"
	leaveRepo "auth-service/internal/hr/leave/repository"
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

// ============================================================================
// ERROR VARIABLES
// ============================================================================

var ErrEmployeeOutsideScope = errors.New("employee belongs to a different location than your current scope")
var ErrEmployeeHasNoLocation = errors.New("target employee has no employment location assigned")

// ============================================================================
// EMPLOYEE SERVICE
// ============================================================================

type EmployeeService struct {
	employeeRepo      repository.EmployeeRepository
	auditService      *audit.AuditService
	idempotencyStore  idempotency.Store
	documentStorage   DocumentStorage
	encryptionMgr     *encryption.EncryptionManager
	maxDocumentSizeMB int

	// 👇 ADD
	pgClient     *client.PostgresClient
	resolverJobs leaveRepo.ResolverJobRepository
}

type EmployeeServiceConfig struct {
	MaxDocumentSizeMB int
	DocumentStorage   DocumentStorage
	EncryptionMgr     *encryption.EncryptionManager
}

func NewEmployeeService(
	employeeRepo repository.EmployeeRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	config EmployeeServiceConfig,
	pgClient *client.PostgresClient, // 👈 ADD
	resolverJobs leaveRepo.ResolverJobRepository, // 👈 ADD
) *EmployeeService {
	if auditService == nil {
		panic("auditService is required for EmployeeService")
	}
	if idempotencyStore == nil {
		panic("idempotencyStore is required for EmployeeService")
	}
	if config.DocumentStorage == nil {
		panic("documentStorage is required for EmployeeService")
	}
	if config.EncryptionMgr == nil {
		panic("encryptionMgr is required for EmployeeService")
	}
	if pgClient == nil {
		panic("pgClient is required for EmployeeService")
	}
	if resolverJobs == nil {
		panic("resolverJobs is required for EmployeeService")
	}
	if config.MaxDocumentSizeMB <= 0 {
		config.MaxDocumentSizeMB = 50
	}

	return &EmployeeService{
		employeeRepo:      employeeRepo,
		auditService:      auditService,
		idempotencyStore:  idempotencyStore,
		documentStorage:   config.DocumentStorage,
		encryptionMgr:     config.EncryptionMgr,
		maxDocumentSizeMB: config.MaxDocumentSizeMB,
		pgClient:          pgClient,
		resolverJobs:      resolverJobs,
	}
}

// ============================================================================
// ROW-LEVEL AUTHORIZATION HELPER
// ============================================================================

func (s *EmployeeService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, userID uuid.UUID,
) error {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("location context missing: %w", err)
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, userID)
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

// ============================================================================
// PII ENCRYPTION HELPERS
// ============================================================================

func (s *EmployeeService) encryptStringField(
	ctx context.Context,
	plaintext *string,
	purpose string,
	outCT *[]byte,
	outDEK **string,
	outKey **uuid.UUID,
) error {
	if plaintext == nil || *plaintext == "" {
		return nil
	}
	enc, err := s.encryptionMgr.EncryptField(ctx, *plaintext, purpose)
	if err != nil {
		return fmt.Errorf("encrypt %s: %w", purpose, err)
	}
	keyID, err := uuid.Parse(enc.KeyID)
	if err != nil {
		return fmt.Errorf("parse %s key id: %w", purpose, err)
	}
	*outCT = []byte(enc.EncryptedValue)
	dek := enc.EncryptedDEK
	*outDEK = &dek
	*outKey = &keyID
	return nil
}

func (s *EmployeeService) encryptTimeField(
	ctx context.Context,
	t *time.Time,
	purpose string,
	outCT *[]byte,
	outDEK **string,
	outKey **uuid.UUID,
) error {
	if t == nil {
		return nil
	}
	str := t.UTC().Format(time.RFC3339)
	return s.encryptStringField(ctx, &str, purpose, outCT, outDEK, outKey)
}

func (s *EmployeeService) encryptPIIFields(ctx context.Context, p *employee.EmployeeProfile) error {
	if err := s.encryptStringField(ctx, p.Email, "employee.email",
		&p.EmailEncrypted, &p.EmailEncryptedDEK, &p.EmailKeyID); err != nil {
		return err
	}
	if p.Email != nil && *p.Email != "" {
		h := devicefp.Hash(*p.Email)
		p.EmailHash = &h
	}

	if err := s.encryptStringField(ctx, p.TaxID, "employee.tax_id",
		&p.TaxIDEncrypted, &p.TaxIDEncryptedDEK, &p.TaxIDKeyID); err != nil {
		return err
	}
	if err := s.encryptStringField(ctx, p.SocialSecurityID, "employee.ssn",
		&p.SocialSecurityIDEncrypted, &p.SocialSecurityIDEncryptedDEK, &p.SocialSecurityIDKeyID); err != nil {
		return err
	}
	if err := s.encryptTimeField(ctx, p.DateOfBirth, "employee.dob",
		&p.DateOfBirthEncrypted, &p.DateOfBirthEncryptedDEK, &p.DateOfBirthKeyID); err != nil {
		return err
	}
	if err := s.encryptStringField(ctx, p.Nationality, "employee.nationality",
		&p.NationalityEncrypted, &p.NationalityEncryptedDEK, &p.NationalityKeyID); err != nil {
		return err
	}
	if err := s.encryptStringField(ctx, p.MaritalStatus, "employee.marital_status",
		&p.MaritalStatusEncrypted, &p.MaritalStatusEncryptedDEK, &p.MaritalStatusKeyID); err != nil {
		return err
	}
	return nil
}

func (s *EmployeeService) decryptPIIFields(ctx context.Context, p *employee.EmployeeProfile) {
	if len(p.EmailEncrypted) > 0 && p.EmailEncryptedDEK != nil && p.EmailKeyID != nil {
		if plain, err := s.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.EmailEncrypted),
			EncryptedDEK:   *p.EmailEncryptedDEK,
			KeyID:          p.EmailKeyID.String(),
		}); err == nil {
			p.Email = &plain
		}
	}
	if len(p.TaxIDEncrypted) > 0 && p.TaxIDEncryptedDEK != nil && p.TaxIDKeyID != nil {
		if plain, err := s.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.TaxIDEncrypted),
			EncryptedDEK:   *p.TaxIDEncryptedDEK,
			KeyID:          p.TaxIDKeyID.String(),
		}); err == nil {
			p.TaxID = &plain
		}
	}
	if len(p.SocialSecurityIDEncrypted) > 0 && p.SocialSecurityIDEncryptedDEK != nil && p.SocialSecurityIDKeyID != nil {
		if plain, err := s.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.SocialSecurityIDEncrypted),
			EncryptedDEK:   *p.SocialSecurityIDEncryptedDEK,
			KeyID:          p.SocialSecurityIDKeyID.String(),
		}); err == nil {
			p.SocialSecurityID = &plain
		}
	}
	if len(p.DateOfBirthEncrypted) > 0 && p.DateOfBirthEncryptedDEK != nil && p.DateOfBirthKeyID != nil {
		if plain, err := s.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.DateOfBirthEncrypted),
			EncryptedDEK:   *p.DateOfBirthEncryptedDEK,
			KeyID:          p.DateOfBirthKeyID.String(),
		}); err == nil {
			if t, perr := time.Parse(time.RFC3339, plain); perr == nil {
				p.DateOfBirth = &t
			}
		}
	}
	if len(p.NationalityEncrypted) > 0 && p.NationalityEncryptedDEK != nil && p.NationalityKeyID != nil {
		if plain, err := s.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.NationalityEncrypted),
			EncryptedDEK:   *p.NationalityEncryptedDEK,
			KeyID:          p.NationalityKeyID.String(),
		}); err == nil {
			p.Nationality = &plain
		}
	}
	if len(p.MaritalStatusEncrypted) > 0 && p.MaritalStatusEncryptedDEK != nil && p.MaritalStatusKeyID != nil {
		if plain, err := s.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.MaritalStatusEncrypted),
			EncryptedDEK:   *p.MaritalStatusEncryptedDEK,
			KeyID:          p.MaritalStatusKeyID.String(),
		}); err == nil {
			p.MaritalStatus = &plain
		}
	}
}

// ============================================================================
// EMPLOYEE PROFILE WRITES
// ============================================================================

func (s *EmployeeService) CreateEmployeeProfile(
	ctx context.Context,
	profile *employee.EmployeeProfile,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeProfile, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_emp_profile-%s", uuid.New().String())
	}
	var cached *employee.EmployeeProfile
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if profile.EmployeeProfileID == uuid.Nil {
		profile.EmployeeProfileID = uuid.New()
	}
	now := time.Now().UTC()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}

	if profile.UserID == uuid.Nil {
		return nil, fmt.Errorf("user_id is required")
	}
	if profile.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}

	// 🔐 Encrypt PII before persisting.
	if err := s.encryptPIIFields(ctx, profile); err != nil {
		return nil, err
	}

	beforeJSON, _ := json.Marshal(profile)

	if err := s.employeeRepo.CreateEmployeeProfile(ctx, profile); err != nil {
		return nil, fmt.Errorf("failed to create employee profile: %w", err)
	}

	afterJSON, _ := json.Marshal(profile)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":         ip,
		"profile_id": profile.EmployeeProfileID.String(),
		"user_id":    profile.UserID.String(),
		"company_id": profile.CompanyID.String(),
	})
	_ = s.auditService.LogAction(
		ctx, nil, &profile.CompanyID, "hr",
		"employee.profile.create", "employee_profile", &profile.EmployeeProfileID,
		actorType, &actorID, beforeJSON, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, profile)

	s.decryptPIIFields(ctx, profile)
	return profile, nil
}

func (s *EmployeeService) CreateEmployeeProfileInTx(
	ctx context.Context,
	tx *sql.Tx,
	profile *employee.EmployeeProfile,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile is required")
	}
	if profile.EmployeeProfileID == uuid.Nil {
		profile.EmployeeProfileID = uuid.New()
	}
	now := time.Now().UTC()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}
	if profile.UserID == uuid.Nil {
		return nil, fmt.Errorf("user_id is required")
	}
	if profile.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}

	if err := s.encryptPIIFields(ctx, profile); err != nil {
		return nil, err
	}

	if err := s.employeeRepo.CreateEmployeeProfileTx(ctx, tx, profile); err != nil {
		return nil, fmt.Errorf("failed to create employee profile (tx): %w", err)
	}

	out := *profile
	s.decryptPIIFields(ctx, &out)
	return &out, nil
}

func (s *EmployeeService) UpdateEmployeeProfile(
	ctx context.Context,
	profileID uuid.UUID,
	updates map[string]interface{},
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeProfile, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_emp_profile-%s", profileID.String())
	}
	var cached *employee.EmployeeProfile
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	existingProfile, err := s.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing profile: %w", err)
	}

	if err := s.ensureEmployeeInScope(ctx, existingProfile.CompanyID, existingProfile.UserID); err != nil {
		return nil, err
	}

	s.decryptPIIFields(ctx, existingProfile)

	beforeJSON, _ := json.Marshal(existingProfile)

	updatedProfile := *existingProfile
	updatedProfile.UpdatedAt = time.Now().UTC()

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
		case "cost_center":
			if cc, ok := value.(string); ok {
				updatedProfile.CostCenter = &cc
			}
		case "cost_center_id":
			if ccID, ok := value.(uuid.UUID); ok {
				updatedProfile.CostCenterID = &ccID
			}
		case "tax_id":
			if taxID, ok := value.(string); ok {
				updatedProfile.TaxID = &taxID
			}
		case "social_security_id":
			if ssn, ok := value.(string); ok {
				updatedProfile.SocialSecurityID = &ssn
			}
		case "email":
			if email, ok := value.(string); ok {
				updatedProfile.Email = &email
			}
		}
	}

	if err := s.encryptPIIFields(ctx, &updatedProfile); err != nil {
		return nil, err
	}

	if err := s.employeeRepo.UpdateEmployeeProfile(ctx, &updatedProfile); err != nil {
		return nil, fmt.Errorf("failed to update employee profile: %w", err)
	}

	afterJSON, _ := json.Marshal(&updatedProfile)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":         ip,
		"profile_id": profileID.String(),
		"updates":    updates,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &updatedProfile.CompanyID, "hr",
		"employee.profile.update", "employee_profile", &profileID,
		actorType, &actorID, beforeJSON, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, &updatedProfile)

	out := updatedProfile
	s.decryptPIIFields(ctx, &out)
	return &out, nil
}

func (s *EmployeeService) DeleteEmployeeProfile(
	ctx context.Context,
	profileID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("delete_emp_profile-%s", profileID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	profile, err := s.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return fmt.Errorf("failed to get profile for deletion: %w", err)
	}

	if err := s.ensureEmployeeInScope(ctx, profile.CompanyID, profile.UserID); err != nil {
		return err
	}

	s.decryptPIIFields(ctx, profile)
	beforeJSON, _ := json.Marshal(profile)

	if err := s.employeeRepo.DeleteEmployeeProfile(ctx, profileID); err != nil {
		return fmt.Errorf("failed to delete employee profile: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":         ip,
		"profile_id": profileID.String(),
		"user_id":    profile.UserID.String(),
	})
	_ = s.auditService.LogAction(
		ctx, nil, &profile.CompanyID, "hr",
		"employee.profile.delete", "employee_profile", &profileID,
		actorType, &actorID, beforeJSON, []byte("{}"), auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ============================================================================
// EMPLOYEE DOCUMENT WRITES
// ============================================================================

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
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("upload_doc-%s", uuid.New().String())
	}
	var cached *employee.EmployeeDocument
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	if header.Size > int64(s.maxDocumentSizeMB)*1024*1024 {
		return nil, fmt.Errorf("file size %d exceeds max allowed size %d MB", header.Size, s.maxDocumentSizeMB)
	}

	userExists, err := s.employeeRepo.UserExists(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate user existence: %w", err)
	}
	if !userExists {
		return nil, fmt.Errorf("user does not exist")
	}

	isEmployee, err := s.employeeRepo.IsUserEmployeeOfCompany(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate employee ownership: %w", err)
	}
	if !isEmployee {
		return nil, fmt.Errorf("user is not an employee of this company")
	}

	uploadResult, err := s.documentStorage.UploadDocument(ctx, file, header, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to upload document: %w", err)
	}

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

	if err := s.employeeRepo.CreateEmployeeDocument(ctx, document); err != nil {
		_ = s.documentStorage.DeleteDocument(ctx, uploadResult.ObjectKey)
		return nil, fmt.Errorf("failed to save document record: %w", err)
	}

	afterJSON, _ := json.Marshal(document)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":           ip,
		"document_id":  document.DocumentID.String(),
		"user_id":      userID.String(),
		"company_id":   companyID.String(),
		"file_size":    uploadResult.FileSize,
		"mime_type":    uploadResult.MimeType,
		"confidential": isConfidential,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.document.upload", "employee_document", &document.DocumentID,
		actorType, &actorID, []byte("{}"), afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, document)
	return document, nil
}

func (s *EmployeeService) DeleteEmployeeDocument(
	ctx context.Context,
	documentID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("delete_doc-%s", documentID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	document, err := s.employeeRepo.GetEmployeeDocumentByID(ctx, documentID)
	if err != nil {
		return fmt.Errorf("failed to get document for deletion: %w", err)
	}

	if err := s.ensureEmployeeInScope(ctx, document.CompanyID, document.UserID); err != nil {
		return err
	}

	beforeJSON, _ := json.Marshal(document)

	if err := s.employeeRepo.DeleteEmployeeDocument(ctx, documentID); err != nil {
		return fmt.Errorf("failed to delete document record: %w", err)
	}

	_ = s.documentStorage.DeleteDocument(ctx, document.DocumentObjectKey)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":          ip,
		"document_id": documentID.String(),
		"user_id":     document.UserID.String(),
		"company_id":  document.CompanyID.String(),
	})
	_ = s.auditService.LogAction(
		ctx, nil, &document.CompanyID, "hr",
		"employee.document.delete", "employee_document", &documentID,
		actorType, &actorID, beforeJSON, []byte("{}"), auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ============================================================================
// DEPARTMENT ASSIGNMENT
// ============================================================================

func (s *EmployeeService) CreateDepartmentAssignment(
	ctx context.Context,
	userID, companyID, departmentID uuid.UUID,
	changeReason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeDepartmentHistory, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("dept_assign-%s-%s", userID.String(), departmentID.String())
	}
	var cached *employee.EmployeeDepartmentHistory
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	activeAssignment, err := s.employeeRepo.GetActiveDepartmentAssignment(ctx, userID)
	if err == nil {
		if activeAssignment.DepartmentID == departmentID {
			return nil, fmt.Errorf("employee is already assigned to this department")
		}
		if err := s.employeeRepo.EndDepartmentAssignment(ctx, userID, now.Add(-time.Second)); err != nil {
			return nil, fmt.Errorf("failed to end previous department assignment: %w", err)
		}
	}

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

	if err := s.employeeRepo.CreateDepartmentHistory(ctx, history); err != nil {
		return nil, fmt.Errorf("failed to create department assignment: %w", err)
	}

	afterJSON, _ := json.Marshal(history)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":            ip,
		"history_id":    history.ID.String(),
		"user_id":       userID.String(),
		"department_id": departmentID.String(),
		"company_id":    companyID.String(),
		"change_reason": changeReason,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.department.assign", "employee_department_history", &history.ID,
		actorType, &actorID, []byte("{}"), afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, history)
	return history, nil
}

// ============================================================================
// EMPLOYEE EXIT
// ============================================================================

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
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("exit-%s", userID.String())
	}
	var cached *employee.EmployeeExit
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

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

	afterJSON, _ := json.Marshal(exit)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":         ip,
		"exit_id":    exit.ExitID.String(),
		"user_id":    userID.String(),
		"company_id": companyID.String(),
		"exit_date":  exitDate,
		"reason":     exitReason,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.exit.schedule", "employee_exit", &exit.ExitID,
		actorType, &actorID, []byte("{}"), afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, exit)
	return exit, nil
}

// ============================================================================
// POSITION WRITES
// ============================================================================

// ============================================================================
// POSITION WRITES
// ============================================================================

func (s *EmployeeService) CreatePosition(
	ctx context.Context,
	position *employee.Position,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.Position, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_pos-%s", uuid.New().String())
	}
	var cached *employee.Position
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

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

	if err := s.employeeRepo.CreatePosition(ctx, position); err != nil {
		return nil, fmt.Errorf("failed to create position: %w", err)
	}

	afterJSON, _ := json.Marshal(position)
	ip, _ := ctx.Value("ip_address").(string)

	// Audit metadata now carries the new schema fields (job_id + location_id)
	// and the seat's title override rather than the old `Title`.
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":             ip,
		"position_id":    position.PositionID.String(),
		"company_id":     position.CompanyID.String(),
		"department_id":  position.DepartmentID.String(),
		"job_id":         position.JobID.String(),
		"location_id":    position.LocationID,
		"title_override": position.TitleOverride,
		"work_center":    position.WorkCenterCode,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &position.CompanyID, "hr",
		"position.create", "position", &position.PositionID,
		actorType, &actorID, []byte("{}"), afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, position)
	return position, nil
}

// ============================================================================
// REHIRE
// ============================================================================

func (s *EmployeeService) RehireEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("rehire-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return err
	}

	if err := s.employeeRepo.RehireEmployee(ctx, companyID, userID); err != nil {
		return err
	}

	// 👇 Enqueue resolver job.
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.resolverJobs.EnqueueUserResolution(ctx, tx, companyID, userID, "rehire")
	}); err != nil {
		return fmt.Errorf("enqueue resolver job: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":         ip,
		"user_id":    userID.String(),
		"company_id": companyID.String(),
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.rehire", "employee_exit", nil,
		actorType, &actorID, nil, nil, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ============================================================================
// SYSTEM OPERATIONS
// ============================================================================

func (s *EmployeeService) EnforceScheduledEmployeeExits(
	ctx context.Context,
	effectiveDate time.Time,
	actorID uuid.UUID,
) (int, error) {
	// 1. Snapshot the pairs that are about to flip to 'effective'.
	pairs, err := s.employeeRepo.GetDueScheduledExits(ctx, effectiveDate)
	if err != nil {
		return 0, fmt.Errorf("list due scheduled exits: %w", err)
	}

	// 2. Run the enforcement function (unchanged).
	count, err := s.employeeRepo.EnforceScheduledEmployeeExits(ctx, effectiveDate, actorID)
	if err != nil {
		return 0, err
	}

	// 3. Enqueue end_entitlements for each (company, user) that just exited.
	logger := zap.L()
	for _, p := range pairs {
		if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
			return s.resolverJobs.EnqueueEndEntitlements(ctx, tx, p.CompanyID, p.UserID, "scheduled exit")
		}); err != nil {
			logger.Warn("enqueue end_entitlements failed",
				zap.String("company_id", p.CompanyID.String()),
				zap.String("user_id", p.UserID.String()),
				zap.Error(err),
			)
		}
	}
	return count, nil
}

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
	s.decryptPIIFields(ctx, profile)
	return profile, nil
}

// ============================================================================
// HELPERS
// ============================================================================

func mergeMetadata(base, extra map[string]interface{}) map[string]interface{} {
	if base == nil {
		base = make(map[string]interface{})
	}
	for k, v := range extra {
		base[k] = v
	}
	return base
}

func (s *EmployeeService) UpdateEmployeeProfileInTx(
	ctx context.Context,
	tx *sql.Tx,
	profile *employee.EmployeeProfile,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*employee.EmployeeProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile is required")
	}
	if profile.EmployeeProfileID == uuid.Nil {
		return nil, fmt.Errorf("employee_profile_id is required")
	}
	if profile.UserID == uuid.Nil {
		return nil, fmt.Errorf("user_id is required")
	}
	if profile.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company_id is required")
	}

	profile.UpdatedAt = time.Now().UTC()

	if err := s.encryptPIIFields(ctx, profile); err != nil {
		return nil, err
	}

	if err := s.employeeRepo.UpdateEmployeeProfileTx(ctx, tx, profile); err != nil {
		return nil, fmt.Errorf("failed to update employee profile (tx): %w", err)
	}

	out := *profile
	s.decryptPIIFields(ctx, &out)
	return &out, nil
}
