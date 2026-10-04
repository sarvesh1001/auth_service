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

// Lifecycle-specific errors
var (
	ErrProbationAlreadyOpen = errors.New("employee already has an open probation")
	ErrNoticeAlreadyActive  = errors.New("employee already has an active notice")
	ErrOnHoldAlreadyActive  = errors.New("employee is already on hold")
)

// ============================================================================
// EMPLOYEE SERVICE
// ============================================================================

type EmployeeService struct {
	employeeRepo      repository.EmployeeRepository
	scheduledJobs     repository.ScheduledJobRepository
	reminderSvc       *ReminderService
	auditService      *audit.AuditService
	idempotencyStore  idempotency.Store
	documentStorage   DocumentStorage
	encryptionMgr     *encryption.EncryptionManager
	maxDocumentSizeMB int

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
	scheduledJobs repository.ScheduledJobRepository,
	reminderSvc *ReminderService,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	config EmployeeServiceConfig,
	pgClient *client.PostgresClient,
	resolverJobs leaveRepo.ResolverJobRepository,
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
	if scheduledJobs == nil {
		panic("scheduledJobs is required for EmployeeService")
	}
	if reminderSvc == nil {
		panic("reminderSvc is required for EmployeeService")
	}
	if config.MaxDocumentSizeMB <= 0 {
		config.MaxDocumentSizeMB = 50
	}

	return &EmployeeService{
		employeeRepo:      employeeRepo,
		scheduledJobs:     scheduledJobs,
		reminderSvc:       reminderSvc,
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

	// Auto-open a probation row if the hire carries a probation window.
	// Non-fatal: we never fail the hire for this.
	if profile.ProbationEndDate != nil {
		if _, err := s.StartProbation(ctx,
			profile.CompanyID,
			profile.UserID,
			profile.CreatedAt,
			*profile.ProbationEndDate,
			100,
		); err != nil {
			zap.L().Warn("auto StartProbation failed on hire",
				zap.String("company_id", profile.CompanyID.String()),
				zap.String("user_id", profile.UserID.String()),
				zap.Error(err),
			)
		}
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

	// NOTE: StartProbation is NOT called here. It uses the non-tx repo and
	// would deadlock against the caller's tx. The caller (CompanyService.AddMember)
	// must call StartProbation AFTER the tx commits.

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
		// NOTE: "employment_status" deliberately NOT handled here.
		// Status only changes through the lifecycle methods
		// (StartProbation / ConfirmProbation / FailProbation /
		//  StartNotice / CancelNotice / StartOnHold / EndOnHold),
		// which keep the probation/notice/on_hold tables in sync.
		// Allowing it here would let a caller bypass the whole flow.
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
	// NOTE: idempotency key is per-CALL, not per-user. Using userID would
	// cache the exit forever and return a stale (possibly cancelled) exit
	// when the same employee starts a new notice later. The DB unique index
	// uq_employee_exit_active + the "already scheduled" check below enforce
	// the one-scheduled-exit-per-user invariant.
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("exit-%s", uuid.New().String())
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

	// Enqueue resolver job.
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

// EnforceScheduledEmployeeExits runs the nightly transition:
//
//  1. Flip employee_exit.exit_state 'scheduled' → 'effective' for exits
//     whose exit_date <= effectiveDate.
//  2. Cascade: deactivate company_employees, set employment_status =
//     'terminated', close the linked notice row (via DB trigger).
//  3. For each affected (company, user):
//     - enqueue leave end_entitlements resolver job
//     - cancel any pending reminder/expiry jobs
//     - close any open reminders (probation / notice / on-hold)
//
// The whole thing is idempotent — rerunning it on the same date is a no-op
// once the exit is 'effective'.
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

	// 3. Per-employee cleanup: leave resolver enqueue, pending job cancellation,
	//    and open reminder closure.
	logger := zap.L()
	for _, p := range pairs {
		// 3a. Enqueue leave end-entitlements resolver job.
		if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
			return s.resolverJobs.EnqueueEndEntitlements(ctx, tx, p.CompanyID, p.UserID, "scheduled exit")
		}); err != nil {
			logger.Warn("enqueue end_entitlements failed",
				zap.String("company_id", p.CompanyID.String()),
				zap.String("user_id", p.UserID.String()),
				zap.Error(err),
			)
		}

		// 3b. Cancel any pending lifecycle jobs. They are meaningless now —
		//     the employee is terminated. Leaving them queued would cause
		//     the worker to fire "notice ends in 3 days" for a person who
		//     is already gone.
		uid := p.UserID
		if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
			for _, jt := range []string{
				employee.JobProbationReminder,
				employee.JobProbationEndReached,
				employee.JobNoticeReminder,
				employee.JobOnHoldReminder,
				employee.JobOnHoldExpiry,
			} {
				if err := s.scheduledJobs.CancelJobs(ctx, tx, p.CompanyID, &uid, jt); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			logger.Warn("cancel pending lifecycle jobs failed",
				zap.String("company_id", p.CompanyID.String()),
				zap.String("user_id", p.UserID.String()),
				zap.Error(err),
			)
		}

		// 3c. Close any open reminders. They stay in history (status='actioned')
		//     but drop out of the HR unread badge. HR no longer needs to
		//     "act" on a probation that will never be confirmed.
		s.reminderSvc.MarkActioned(ctx, p.CompanyID, p.UserID, ReminderTypePrefixProbation)
		s.reminderSvc.MarkActioned(ctx, p.CompanyID, p.UserID, ReminderTypePrefixNotice)
		s.reminderSvc.MarkActioned(ctx, p.CompanyID, p.UserID, ReminderTypePrefixOnHold)
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
// EMPLOYEE LIFECYCLE — PROBATION / NOTICE / ON-HOLD
// ============================================================================

// setEmploymentStatus is the ONLY place that should write employment_status
// outside of the lifecycle methods. It talks to the repo directly (no
// service-level idempotency cache) so consecutive transitions don't collide.
func (s *EmployeeService) setEmploymentStatus(
	ctx context.Context, companyID, userID uuid.UUID, status string,
) error {
	prof, err := s.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return fmt.Errorf("setEmploymentStatus: fetch profile: %w", err)
	}
	prev := ""
	if prof.EmploymentStatus != nil {
		prev = *prof.EmploymentStatus
	}
	if prev == status {
		return nil
	}
	prof.EmploymentStatus = &status
	prof.UpdatedAt = time.Now().UTC()
	return s.employeeRepo.UpdateEmployeeProfile(ctx, prof)
}

// ---- PROBATION ----

func (s *EmployeeService) StartProbation(
	ctx context.Context,
	companyID, userID uuid.UUID,
	start, end time.Time,
	payPct float64,
) (*employee.EmployeeProbation, error) {
	if !end.After(start) {
		return nil, fmt.Errorf("probation end must be after start")
	}
	if payPct <= 0 {
		payPct = 100
	}
	if _, err := s.employeeRepo.GetActiveProbation(ctx, companyID, userID); err == nil {
		return nil, ErrProbationAlreadyOpen
	}

	p := &employee.EmployeeProbation{
		ProbationID:   uuid.New(),
		CompanyID:     companyID,
		UserID:        userID,
		StartDate:     start,
		EndDate:       end,
		PayPercentage: payPct,
		Status:        "pending",
	}
	if err := s.employeeRepo.CreateProbation(ctx, p); err != nil {
		return nil, err
	}
	if err := s.setEmploymentStatus(ctx, companyID, userID, "probation"); err != nil {
		return nil, err
	}
	s.enqueueProbationReminders(ctx, companyID, userID, p.ProbationID, end)
	return p, nil
}

func (s *EmployeeService) ConfirmProbation(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID, note string,
) (*employee.EmployeeProbation, error) {
	p, err := s.employeeRepo.GetActiveProbation(ctx, companyID, userID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	p.Status = "confirmed"
	p.ConfirmedAt = &now
	p.ConfirmedBy = &actorID
	if note != "" {
		p.OutcomeReason = &note
	}
	if err := s.employeeRepo.UpdateProbationStatus(ctx, p); err != nil {
		return nil, err
	}
	if err := s.setEmploymentStatus(ctx, companyID, userID, "active"); err != nil {
		return nil, err
	}
	s.cancelJobs(ctx, companyID, userID, employee.JobProbationReminder)
	s.cancelJobs(ctx, companyID, userID, employee.JobProbationEndReached)

	// Close out every open probation reminder about this employee so they
	// drop out of the HR unread feed.
	s.reminderSvc.MarkActioned(ctx, companyID, userID, ReminderTypePrefixProbation)

	afterJSON, _ := json.Marshal(p)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.probation.confirm", "employee_probation", &p.ProbationID,
		"user", &actorID, []byte("{}"), afterJSON,
		map[string]interface{}{
			"probation_id": p.ProbationID.String(),
			"user_id":      userID.String(),
			"company_id":   companyID.String(),
			"note":         note,
		},
	)
	return p, nil
}

func (s *EmployeeService) FailProbation(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID,
	reason string, terminationDate time.Time,
) error {
	p, err := s.employeeRepo.GetActiveProbation(ctx, companyID, userID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	p.Status = "failed"
	p.ConfirmedAt = &now
	p.ConfirmedBy = &actorID
	p.OutcomeReason = &reason
	if err := s.employeeRepo.UpdateProbationStatus(ctx, p); err != nil {
		return err
	}

	// No notice period — straight to a scheduled exit.
	if _, err := s.CreateEmployeeExit(ctx, userID, companyID, terminationDate,
		"probation_failed", false, "user", actorID, nil); err != nil {
		return err
	}

	s.cancelJobs(ctx, companyID, userID, employee.JobProbationReminder)
	s.cancelJobs(ctx, companyID, userID, employee.JobProbationEndReached)

	// Close out every open probation reminder — the decision has been made.
	s.reminderSvc.MarkActioned(ctx, companyID, userID, ReminderTypePrefixProbation)

	afterJSON, _ := json.Marshal(p)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.probation.fail", "employee_probation", &p.ProbationID,
		"user", &actorID, []byte("{}"), afterJSON,
		map[string]interface{}{
			"probation_id":     p.ProbationID.String(),
			"user_id":          userID.String(),
			"company_id":       companyID.String(),
			"reason":           reason,
			"termination_date": terminationDate,
		},
	)
	return nil
}

func (s *EmployeeService) ExtendProbation(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID,
	newEnd time.Time, reason string,
) (*employee.EmployeeProbation, error) {
	p, err := s.employeeRepo.GetActiveProbation(ctx, companyID, userID)
	if err != nil {
		return nil, err
	}
	if p.ExtensionCount >= 2 {
		return nil, fmt.Errorf("probation can only be extended twice")
	}
	if !newEnd.After(p.EndDate) {
		return nil, fmt.Errorf("new end must be after current end")
	}
	p.ExtensionCount++
	p.EndDate = newEnd
	p.Status = "extended"
	if reason != "" {
		p.OutcomeReason = &reason
	}
	if err := s.employeeRepo.UpdateProbationStatus(ctx, p); err != nil {
		return nil, err
	}
	s.cancelJobs(ctx, companyID, userID, employee.JobProbationReminder)
	s.cancelJobs(ctx, companyID, userID, employee.JobProbationEndReached)
	s.enqueueProbationReminders(ctx, companyID, userID, p.ProbationID, newEnd)

	// NOTE: we intentionally do NOT MarkActioned here. The probation is
	// still open, just with a new end date. Old reminders expire naturally
	// via ExpiresIn; new ones are scheduled with the new end date.

	afterJSON, _ := json.Marshal(p)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.probation.extend", "employee_probation", &p.ProbationID,
		"user", &actorID, []byte("{}"), afterJSON,
		map[string]interface{}{
			"probation_id":    p.ProbationID.String(),
			"user_id":         userID.String(),
			"company_id":      companyID.String(),
			"new_end":         newEnd,
			"extension_count": p.ExtensionCount,
		},
	)
	return p, nil
}

// ---- NOTICE ----

func (s *EmployeeService) StartNotice(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID,
	endDate time.Time,
	reason, initiatedBy string,
	served bool, payPct float64,
) (*employee.EmployeeNotice, error) {
	if initiatedBy != "employee" && initiatedBy != "employer" {
		return nil, fmt.Errorf("initiated_by must be employee or employer")
	}
	if served && !endDate.After(time.Now()) {
		return nil, fmt.Errorf("notice end must be in the future")
	}
	if payPct <= 0 {
		payPct = 100
	}
	if _, err := s.employeeRepo.GetActiveNotice(ctx, companyID, userID); err == nil {
		return nil, ErrNoticeAlreadyActive
	}

	// Status guard: an employee must be 'active' to start notice. Probation
	// must be resolved first (confirm or fail) — otherwise open probation
	// reminders linger forever and the transition is ambiguous.
	prof, err := s.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}
	if prof.EmploymentStatus == nil {
		return nil, fmt.Errorf("employee has no employment status set")
	}
	switch *prof.EmploymentStatus {
	case "active":
		// ok
	case "probation":
		return nil, fmt.Errorf("employee is on probation — confirm or fail probation first")
	case "notice":
		return nil, ErrNoticeAlreadyActive
	case "on_hold":
		return nil, fmt.Errorf("employee is on hold — end the hold first")
	case "terminated":
		return nil, fmt.Errorf("employee is already terminated")
	default:
		return nil, fmt.Errorf("cannot start notice from status %q", *prof.EmploymentStatus)
	}

	// 1. schedule the exit first so we can link notice → exit
	exit, err := s.CreateEmployeeExit(ctx, userID, companyID, endDate,
		reason, initiatedBy == "employee", "user", actorID, nil)
	if err != nil {
		return nil, fmt.Errorf("schedule exit: %w", err)
	}

	// 2. create the notice row, linked to the exit
	reasonCopy := reason
	n := &employee.EmployeeNotice{
		NoticeID:      uuid.New(),
		CompanyID:     companyID,
		UserID:        userID,
		StartDate:     time.Now().UTC().Truncate(24 * time.Hour),
		EndDate:       endDate,
		Reason:        &reasonCopy,
		InitiatedBy:   initiatedBy,
		Served:        served,
		PayPercentage: payPct,
		Status:        "active",
		ExitID:        &exit.ExitID,
		CreatedBy:     &actorID,
	}
	if err := s.employeeRepo.CreateNotice(ctx, n); err != nil {
		return nil, fmt.Errorf("create notice: %w", err)
	}
	if err := s.employeeRepo.AttachNoticeToExit(ctx, n.NoticeID, exit.ExitID); err != nil {
		return nil, fmt.Errorf("attach notice to exit: %w", err)
	}

	// 3. flip the profile status
	if err := s.setEmploymentStatus(ctx, companyID, userID, "notice"); err != nil {
		return nil, err
	}

	// 3a. Close any open probation reminders in the HR feed. With the
	//     status guard above, this is only reachable from 'active', so
	//     there shouldn't be open probation reminders — but the call is
	//     cheap insurance against races.
	s.reminderSvc.MarkActioned(ctx, companyID, userID, ReminderTypePrefixProbation)

	// 4. schedule T-3 and T-1 reminders before the notice ends
	s.enqueueNoticeReminders(ctx, companyID, userID, n.NoticeID, endDate)

	// 5. compute day counters for the response
	s.populateNoticeCounts(n)

	// 6. audit
	afterJSON, _ := json.Marshal(n)
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.notice.start", "employee_notice", &n.NoticeID,
		"user", &actorID, []byte("{}"), afterJSON,
		map[string]interface{}{
			"ip":         ip,
			"notice_id":  n.NoticeID.String(),
			"user_id":    userID.String(),
			"company_id": companyID.String(),
			"end_date":   endDate,
			"initiated":  initiatedBy,
			"served":     served,
		},
	)
	return n, nil
}

func (s *EmployeeService) CancelNotice(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID, reason string,
) error {
	n, err := s.employeeRepo.GetActiveNotice(ctx, companyID, userID)
	if err != nil {
		return err
	}
	if err := s.employeeRepo.UpdateNoticeStatus(ctx, n.NoticeID, "cancelled"); err != nil {
		return err
	}
	if n.ExitID != nil {
		if err := s.employeeRepo.CancelEmployeeExit(ctx, *n.ExitID); err != nil {
			return err
		}
	}
	if err := s.setEmploymentStatus(ctx, companyID, userID, "active"); err != nil {
		return err
	}

	// Cancel any queued notice reminders.
	s.cancelJobs(ctx, companyID, userID, employee.JobNoticeReminder)

	// Close out open notice reminders in the HR feed.
	s.reminderSvc.MarkActioned(ctx, companyID, userID, ReminderTypePrefixNotice)

	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.notice.cancel", "employee_notice", &n.NoticeID,
		"user", &actorID, nil, nil,
		map[string]interface{}{
			"notice_id":  n.NoticeID.String(),
			"user_id":    userID.String(),
			"company_id": companyID.String(),
			"reason":     reason,
		},
	)
	return nil
}

// ---- ON HOLD ----

func (s *EmployeeService) StartOnHold(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID,
	start time.Time, end *time.Time,
	reason string, payPct float64,
) (*employee.EmployeeOnHold, error) {
	if reason == "" {
		return nil, fmt.Errorf("reason is required")
	}
	if payPct <= 0 {
		payPct = 100
	}
	if _, err := s.employeeRepo.GetActiveOnHold(ctx, companyID, userID); err == nil {
		return nil, ErrOnHoldAlreadyActive
	}

	prof, err := s.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, err
	}
	prev := "active"
	if prof.EmploymentStatus != nil {
		prev = *prof.EmploymentStatus
	}

	// Status guard: on-hold is only meaningful for a fully active employee.
	// Probation must be resolved, notice must be cancelled first, and a
	// terminated employee obviously can't be put on hold.
	switch prev {
	case "active":
		// ok
	case "probation":
		return nil, fmt.Errorf("cannot place a probationary employee on hold — confirm or fail probation first")
	case "notice":
		return nil, fmt.Errorf("cannot place an employee on notice on hold — cancel or complete the notice first")
	case "on_hold":
		return nil, ErrOnHoldAlreadyActive
	case "terminated":
		return nil, fmt.Errorf("cannot place a terminated employee on hold")
	default:
		return nil, fmt.Errorf("cannot place %s employee on hold", prev)
	}

	h := &employee.EmployeeOnHold{
		OnHoldID:       uuid.New(),
		CompanyID:      companyID,
		UserID:         userID,
		StartDate:      start,
		EndDate:        end,
		Reason:         reason,
		PreviousStatus: prev,
		PayPercentage:  payPct,
		Status:         "active",
		CreatedBy:      &actorID,
	}
	if err := s.employeeRepo.CreateOnHold(ctx, h); err != nil {
		return nil, err
	}
	if err := s.setEmploymentStatus(ctx, companyID, userID, "on_hold"); err != nil {
		return nil, err
	}
	if end != nil {
		s.enqueueOnHoldExpiry(ctx, companyID, userID, *end)
		s.enqueueOnHoldReminders(ctx, companyID, userID, h.OnHoldID, *end)
	}

	afterJSON, _ := json.Marshal(h)
	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.on_hold.start", "employee_on_hold", &h.OnHoldID,
		"user", &actorID, []byte("{}"), afterJSON,
		map[string]interface{}{
			"ip":         ip,
			"on_hold_id": h.OnHoldID.String(),
			"user_id":    userID.String(),
			"company_id": companyID.String(),
			"reason":     reason,
			"prev":       prev,
		},
	)
	return h, nil
}

func (s *EmployeeService) EndOnHold(
	ctx context.Context,
	companyID, userID, actorID uuid.UUID,
) error {
	h, err := s.employeeRepo.GetActiveOnHold(ctx, companyID, userID)
	if err != nil {
		return err
	}
	if err := s.employeeRepo.EndOnHoldRow(ctx, h.OnHoldID, actorID); err != nil {
		return err
	}
	if err := s.setEmploymentStatus(ctx, companyID, userID, h.PreviousStatus); err != nil {
		return err
	}
	s.cancelJobs(ctx, companyID, userID, employee.JobOnHoldExpiry)
	s.cancelJobs(ctx, companyID, userID, employee.JobOnHoldReminder)

	// Close out open on-hold reminders in the HR feed.
	s.reminderSvc.MarkActioned(ctx, companyID, userID, ReminderTypePrefixOnHold)

	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.on_hold.end", "employee_on_hold", &h.OnHoldID,
		"user", &actorID, nil, nil,
		map[string]interface{}{
			"on_hold_id": h.OnHoldID.String(),
			"user_id":    userID.String(),
			"company_id": companyID.String(),
		},
	)
	return nil
}

// ---- enqueue / cancel helpers ----
//
// All enqueue helpers go through the ScheduledJobRepository via
// pgClient.WithTx so the job row commits atomically with the enqueue.
// Failures are logged, never propagated — a full queue table must not
// fail the HR transition.

func (s *EmployeeService) enqueueProbationReminders(
	ctx context.Context, companyID, userID, probationID uuid.UUID, end time.Time,
) {
	now := time.Now()
	offsets := []time.Duration{-14 * 24 * time.Hour, -7 * 24 * time.Hour, -3 * 24 * time.Hour}

	err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		for _, off := range offsets {
			runAt := end.Add(off)
			if runAt.Before(now) {
				continue
			}
			if err := s.scheduledJobs.EnqueueProbationReminder(
				ctx, tx, companyID, userID, runAt, probationID, end,
			); err != nil {
				return err
			}
		}
		return s.scheduledJobs.EnqueueProbationEndReached(
			ctx, tx, companyID, userID, end.Add(24*time.Hour), probationID,
		)
	})
	if err != nil {
		zap.L().Warn("enqueue probation reminders failed",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

func (s *EmployeeService) enqueueNoticeReminders(
	ctx context.Context, companyID, userID, noticeID uuid.UUID, end time.Time,
) {
	now := time.Now()
	offsets := []time.Duration{-3 * 24 * time.Hour, -1 * 24 * time.Hour}

	err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		for _, off := range offsets {
			runAt := end.Add(off)
			if runAt.Before(now) {
				continue
			}
			if err := s.scheduledJobs.EnqueueNoticeReminder(
				ctx, tx, companyID, userID, runAt, noticeID, end,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		zap.L().Warn("enqueue notice reminders failed",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

func (s *EmployeeService) enqueueOnHoldExpiry(
	ctx context.Context, companyID, userID uuid.UUID, end time.Time,
) {
	err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.scheduledJobs.EnqueueOnHoldExpiry(ctx, tx, companyID, userID, end)
	})
	if err != nil {
		zap.L().Warn("enqueue on-hold expiry failed",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

func (s *EmployeeService) enqueueOnHoldReminders(
	ctx context.Context, companyID, userID, onHoldID uuid.UUID, end time.Time,
) {
	now := time.Now()
	offsets := []time.Duration{-3 * 24 * time.Hour, -1 * 24 * time.Hour}

	err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		for _, off := range offsets {
			runAt := end.Add(off)
			if runAt.Before(now) {
				continue
			}
			if err := s.scheduledJobs.EnqueueOnHoldReminder(
				ctx, tx, companyID, userID, runAt, onHoldID, end,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		zap.L().Warn("enqueue on-hold reminders failed",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

func (s *EmployeeService) cancelJobs(
	ctx context.Context, companyID, userID uuid.UUID, jobType string,
) {
	uid := userID
	err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.scheduledJobs.CancelJobs(ctx, tx, companyID, &uid, jobType)
	})
	if err != nil {
		zap.L().Warn("cancel scheduled jobs failed",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.String("job_type", jobType),
			zap.Error(err),
		)
	}
}

func (s *EmployeeService) populateNoticeCounts(n *employee.EmployeeNotice) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	n.DaysTotal = int(n.EndDate.Sub(n.StartDate).Hours()/24) + 1
	served := int(today.Sub(n.StartDate).Hours()/24) + 1
	if served < 0 {
		served = 0
	}
	if served > n.DaysTotal {
		served = n.DaysTotal
	}
	n.DaysServed = served
	n.DaysRemaining = n.DaysTotal - served
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

// ============================================================================
// REACTIVATE (inverse of exit enforcement)
// ============================================================================

// ReactivateEmployee restores a terminated or resigned employee to active.
//
// Flow:
//  1. Row-level authorization check (ensureEmployeeInScope).
//  2. Status guard — only 'terminated' or 'resigned' can be reactivated.
//     An employee on notice / probation / on-hold must go through their
//     own lifecycle path first (cancel notice, confirm probation, end hold).
//  3. Repo call — flips employee_profiles.employment_status to 'active',
//     re-enables company_employees.is_active, marks the latest effective
//     exit as 'rehired'. All three happen in one tx inside the repo.
//  4. Leave resolver enqueue — so entitlements get rebuilt for the new
//     employment window. Non-fatal on failure (worker will retry).
//  5. Audit log.
//
// Idempotent: calling on an already-active employee returns nil.
func (s *EmployeeService) ReactivateEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	logger := zap.L().With(
		zap.String("component", "employee_service"),
		zap.String("op", "reactivate_employee"),
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
	)
	logger.Info("reactivate — entry")

	if companyID == uuid.Nil || userID == uuid.Nil {
		return fmt.Errorf("company_id and user_id are required")
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("reactivate-%s-%s", companyID.String(), userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("reactivate — short-circuited by idempotency",
			zap.String("idemp_key", idempKey))
		return nil
	}

	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		logger.Warn("reactivate — out of scope", zap.Error(err))
		return err
	}

	// Status guard — read current status.
	prof, err := s.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		logger.Error("reactivate — load profile failed", zap.Error(err))
		return fmt.Errorf("load profile: %w", err)
	}
	var prevStatus string
	if prof.EmploymentStatus != nil {
		prevStatus = *prof.EmploymentStatus
	}
	logger.Info("reactivate — current status",
		zap.String("employment_status", prevStatus))

	switch prevStatus {
	case "active":
		logger.Info("reactivate — already active, treating as success")
		_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
		return nil
	case "terminated", "resigned":
		// ok — proceed
	case "probation":
		return fmt.Errorf("cannot reactivate a probationary employee — confirm or fail probation first")
	case "notice":
		return fmt.Errorf("cannot reactivate an employee on notice — cancel the notice first")
	case "on_hold":
		return fmt.Errorf("cannot reactivate an employee on hold — end the hold first")
	default:
		return fmt.Errorf("cannot reactivate employee with status %q", prevStatus)
	}

	// Repo call — profile + roster + exit in one tx.
	if err := s.employeeRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
		logger.Error("reactivate — repo failed", zap.Error(err))
		return err
	}
	logger.Info("reactivate — repo committed")

	// Enqueue leave resolver so entitlements get rebuilt. Non-fatal.
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.resolverJobs.EnqueueUserResolution(
			ctx, tx, companyID, userID, "reactivate",
		)
	}); err != nil {
		logger.Warn("reactivate — enqueue resolver job failed", zap.Error(err))
		// continue — the resolver job will be re-enqueued by the next
		// policy edit or manual re-resolve. Not fatal to the reactivate.
	}

	// Audit
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMetadata(metadata, map[string]interface{}{
		"ip":              ip,
		"user_id":         userID.String(),
		"company_id":      companyID.String(),
		"previous_status": prevStatus,
		"new_status":      "active",
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.reactivate", "employee_profile", &userID,
		actorType, &actorID, nil, nil, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	logger.Info("reactivate — done")
	return nil
}
