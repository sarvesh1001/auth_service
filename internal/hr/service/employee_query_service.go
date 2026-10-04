// internal/hr/service/employee_query_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/encryption"
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
)

// ============================================================================
// EMPLOYEE QUERY SERVICE
// ============================================================================

type EmployeeQueryService struct {
	employeeRepo    repository.EmployeeRepository
	documentStorage DocumentStorage
	auditService    *audit.AuditService
	encryptionMgr   *encryption.EncryptionManager
	logger          *zap.Logger
}

func NewEmployeeQueryService(
	employeeRepo repository.EmployeeRepository,
	documentStorage DocumentStorage,
	auditService *audit.AuditService,
	encryptionMgr *encryption.EncryptionManager,
) *EmployeeQueryService {
	if documentStorage == nil {
		panic("documentStorage is required for EmployeeQueryService")
	}
	if auditService == nil {
		panic("auditService is required for EmployeeQueryService")
	}
	if encryptionMgr == nil {
		panic("encryptionMgr is required for EmployeeQueryService")
	}
	return &EmployeeQueryService{
		employeeRepo:    employeeRepo,
		documentStorage: documentStorage,
		auditService:    auditService,
		encryptionMgr:   encryptionMgr,
		logger:          zap.L(),
	}
}

// ensureEmployeeInScope mirrors the write-side helper.
func (qs *EmployeeQueryService) ensureEmployeeInScope(
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
	empLoc, err := qs.employeeRepo.GetEmploymentLocationID(ctx, companyID, userID)
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

func locationScopeLabel(locationID *uuid.UUID) string {
	if locationID == nil {
		return "ALL"
	}
	return locationID.String()
}

// ============================================================================
// PII DECRYPTION HELPER (single-profile variant)
// ============================================================================

// decryptProfile populates the ephemeral plaintext PII fields on the profile
// by decrypting the *_encrypted siblings.
//
// The plaintext PII columns have been dropped from employee_profiles — the
// repository no longer returns them. The plaintext fields on the in-memory
// struct exist only as carriers for the response payload and audit snapshot.
//
// Decryption failures are swallowed so a KMS blip never takes down a read
// path; callers observe the field as nil in that case.
func (qs *EmployeeQueryService) decryptProfile(ctx context.Context, p *employee.EmployeeProfile) {
	if p == nil {
		return
	}

	if len(p.EmailEncrypted) > 0 && p.EmailEncryptedDEK != nil && p.EmailKeyID != nil {
		if plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.EmailEncrypted),
			EncryptedDEK:   *p.EmailEncryptedDEK,
			KeyID:          p.EmailKeyID.String(),
		}); err == nil {
			p.Email = &plain
		}
	}
	if len(p.TaxIDEncrypted) > 0 && p.TaxIDEncryptedDEK != nil && p.TaxIDKeyID != nil {
		if plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.TaxIDEncrypted),
			EncryptedDEK:   *p.TaxIDEncryptedDEK,
			KeyID:          p.TaxIDKeyID.String(),
		}); err == nil {
			p.TaxID = &plain
		}
	}
	if len(p.SocialSecurityIDEncrypted) > 0 && p.SocialSecurityIDEncryptedDEK != nil && p.SocialSecurityIDKeyID != nil {
		if plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.SocialSecurityIDEncrypted),
			EncryptedDEK:   *p.SocialSecurityIDEncryptedDEK,
			KeyID:          p.SocialSecurityIDKeyID.String(),
		}); err == nil {
			p.SocialSecurityID = &plain
		}
	}
	if len(p.DateOfBirthEncrypted) > 0 && p.DateOfBirthEncryptedDEK != nil && p.DateOfBirthKeyID != nil {
		if plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
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
		if plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.NationalityEncrypted),
			EncryptedDEK:   *p.NationalityEncryptedDEK,
			KeyID:          p.NationalityKeyID.String(),
		}); err == nil {
			p.Nationality = &plain
		}
	}
	if len(p.MaritalStatusEncrypted) > 0 && p.MaritalStatusEncryptedDEK != nil && p.MaritalStatusKeyID != nil {
		if plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(p.MaritalStatusEncrypted),
			EncryptedDEK:   *p.MaritalStatusEncryptedDEK,
			KeyID:          p.MaritalStatusKeyID.String(),
		}); err == nil {
			p.MaritalStatus = &plain
		}
	}
}

// decryptProfiles is a convenience loop for list/search responses.
func (qs *EmployeeQueryService) decryptProfiles(ctx context.Context, profiles []*employee.EmployeeProfile) {
	for _, p := range profiles {
		qs.decryptProfile(ctx, p)
	}
}

// ============================================================================
// EMPLOYEE PROFILE READS
// ============================================================================

func (qs *EmployeeQueryService) GetEmployeeProfile(
	ctx context.Context,
	profileID uuid.UUID,
) (*employee.EmployeeProfile, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	profile, err := qs.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee profile: %w", err)
	}

	// Row-level authorization
	if err := qs.ensureEmployeeInScope(ctx, profile.CompanyID, profile.UserID); err != nil {
		return nil, err
	}

	// 🔓 Decrypt PII before returning / auditing.
	qs.decryptProfile(ctx, profile)

	afterJSON, _ := json.Marshal(profile)
	_ = qs.auditService.LogAction(
		ctx, nil, &profile.CompanyID, "hr",
		"employee.profile.read", "employee_profile", &profileID,
		"system", nil, nil, afterJSON,
		map[string]interface{}{
			"ip":          ip,
			"profile_id":  profileID.String(),
			"user_id":     profile.UserID.String(),
			"company_id":  profile.CompanyID.String(),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return profile, nil
}

func (qs *EmployeeQueryService) GetEmployeeProfileByUserID(
	ctx context.Context,
	userID, companyID uuid.UUID,
) (*employee.EmployeeProfile, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	profile, err := qs.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee profile by user ID: %w", err)
	}

	qs.decryptProfile(ctx, profile)

	afterJSON, _ := json.Marshal(profile)
	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr",
		"employee.profile.read_by_user", "employee_profile", &profile.EmployeeProfileID,
		"system", nil, nil, afterJSON,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return profile, nil
}

// ============================================================================
// LIST / SEARCH / STATS
// ============================================================================

func (qs *EmployeeQueryService) ListEmployeeProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	page, pageSize int,
) ([]*employee.EmployeeProfile, int, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	profiles, totalCount, err := qs.employeeRepo.ListEmployeeProfilesByCompany(
		ctx, companyID, locationID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list employee profiles: %w", err)
	}

	qs.decryptProfiles(ctx, profiles)

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.profile.list",
		"employee_profile", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":             ip,
			"company_id":     companyID.String(),
			"location_scope": locationScopeLabel(locationID),
			"page":           page,
			"page_size":      pageSize,
			"total_count":    totalCount,
			"return_count":   len(profiles),
			"duration_ms":    time.Since(startTime).Milliseconds(),
		},
	)
	return profiles, totalCount, nil
}

func (qs *EmployeeQueryService) SearchEmployeeProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*employee.EmployeeProfile, int, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	profiles, totalCount, err := qs.employeeRepo.SearchEmployeeProfiles(
		ctx, companyID, locationID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search employee profiles: %w", err)
	}

	qs.decryptProfiles(ctx, profiles)

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.profile.search",
		"employee_profile", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":             ip,
			"company_id":     companyID.String(),
			"location_scope": locationScopeLabel(locationID),
			"filters":        filters,
			"page":           page,
			"page_size":      pageSize,
			"total_count":    totalCount,
			"return_count":   len(profiles),
			"duration_ms":    time.Since(startTime).Milliseconds(),
		},
	)
	return profiles, totalCount, nil
}

func (qs *EmployeeQueryService) GetEmployeeStats(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
) (map[string]interface{}, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	stats, err := qs.employeeRepo.GetEmployeeStatsByCompany(ctx, companyID, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee stats: %w", err)
	}
	if locationID == nil {
		deptCounts, err := qs.employeeRepo.GetEmployeeCountByDepartment(ctx, companyID)
		if err == nil {
			stats["department_distribution"] = deptCounts
		}
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.stats.read",
		"employee_stats", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":             ip,
			"company_id":     companyID.String(),
			"location_scope": locationScopeLabel(locationID),
			"duration_ms":    time.Since(startTime).Milliseconds(),
		},
	)
	return stats, nil
}

func (qs *EmployeeQueryService) GetActiveEmployeesByDateRange(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	startDate, endDate time.Time,
) ([]*employee.EmployeeProfile, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	profiles, err := qs.employeeRepo.GetActiveEmployeesByDateRange(
		ctx, companyID, locationID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees by date range: %w", err)
	}

	qs.decryptProfiles(ctx, profiles)

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.active_by_date_range",
		"employee_profile", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":             ip,
			"company_id":     companyID.String(),
			"location_scope": locationScopeLabel(locationID),
			"start_date":     startDate,
			"end_date":       endDate,
			"count":          len(profiles),
			"duration_ms":    time.Since(startTime).Milliseconds(),
		},
	)
	return profiles, nil
}

// ============================================================================
// DOCUMENT READS
// ============================================================================

func (qs *EmployeeQueryService) GetEmployeeDocuments(
	ctx context.Context,
	userID, companyID uuid.UUID,
) ([]*employee.EmployeeDocument, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	documents, err := qs.employeeRepo.GetEmployeeDocumentsByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee documents: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.document.list",
		"employee_document", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"count":       len(documents),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return documents, nil
}

func (qs *EmployeeQueryService) GetConfidentialDocuments(
	ctx context.Context,
	userID, companyID uuid.UUID,
) ([]*employee.EmployeeDocument, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	documents, err := qs.employeeRepo.GetConfidentialDocumentsByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get confidential documents: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.document.list_confidential",
		"employee_document", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"count":       len(documents),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return documents, nil
}

func (qs *EmployeeQueryService) DownloadEmployeeDocument(
	ctx context.Context,
	documentID uuid.UUID,
) (io.ReadCloser, int64, string, *employee.EmployeeDocument, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	document, err := qs.employeeRepo.GetEmployeeDocumentByID(ctx, documentID)
	if err != nil {
		return nil, 0, "", nil, fmt.Errorf("failed to get document record: %w", err)
	}

	if err := qs.ensureEmployeeInScope(ctx, document.CompanyID, document.UserID); err != nil {
		return nil, 0, "", nil, err
	}

	reader, size, mimeType, err := qs.documentStorage.DownloadDocument(ctx, document.DocumentObjectKey)
	if err != nil {
		return nil, 0, "", nil, fmt.Errorf("failed to download document: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &document.CompanyID, "hr", "employee.document.download",
		"employee_document", &documentID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"document_id": documentID.String(),
			"user_id":     document.UserID.String(),
			"company_id":  document.CompanyID.String(),
			"file_size":   size,
			"mime_type":   mimeType,
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return reader, size, mimeType, document, nil
}

func (qs *EmployeeQueryService) GenerateDocumentURL(
	ctx context.Context,
	documentID uuid.UUID,
	expiry time.Duration,
) (string, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	document, err := qs.employeeRepo.GetEmployeeDocumentByID(ctx, documentID)
	if err != nil {
		return "", fmt.Errorf("failed to get document record: %w", err)
	}

	if err := qs.ensureEmployeeInScope(ctx, document.CompanyID, document.UserID); err != nil {
		return "", err
	}

	url, err := qs.documentStorage.GenerateSignedURL(ctx, document.DocumentObjectKey, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate document URL: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &document.CompanyID, "hr", "employee.document.generate_url",
		"employee_document", &documentID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"document_id": documentID.String(),
			"user_id":     document.UserID.String(),
			"expiry_sec":  int(expiry.Seconds()),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return url, nil
}

// ============================================================================
// HISTORY / EXIT / ROLE READS
// ============================================================================

func (qs *EmployeeQueryService) GetDepartmentHistory(
	ctx context.Context,
	userID, companyID uuid.UUID,
) ([]*employee.EmployeeDepartmentHistory, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	history, err := qs.employeeRepo.GetDepartmentHistoryByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department history: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.department.history_read",
		"employee_department_history", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"count":       len(history),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return history, nil
}

func (qs *EmployeeQueryService) GetEmployeeExit(
	ctx context.Context,
	userID, companyID uuid.UUID,
) (*employee.EmployeeExit, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	exit, err := qs.employeeRepo.GetEmployeeExitByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee exit record: %w", err)
	}

	afterJSON, _ := json.Marshal(exit)
	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.exit.read",
		"employee_exit", &exit.ExitID, "system", nil, nil, afterJSON,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return exit, nil
}

func (qs *EmployeeQueryService) GetPositionsByDepartment(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
) ([]*employee.Position, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	positions, err := qs.employeeRepo.GetPositionsByDepartment(ctx, companyID, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by department: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "position.list_by_department",
		"position", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":            ip,
			"company_id":    companyID.String(),
			"department_id": departmentID.String(),
			"count":         len(positions),
			"duration_ms":   time.Since(startTime).Milliseconds(),
		},
	)
	return positions, nil
}

func (qs *EmployeeQueryService) GetOpenPositions(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*employee.Position, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	positions, err := qs.employeeRepo.GetOpenPositions(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get open positions: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "position.list_open",
		"position", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"company_id":  companyID.String(),
			"count":       len(positions),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return positions, nil
}

func (qs *EmployeeQueryService) GetRoleHistory(
	ctx context.Context,
	companyID, userID uuid.UUID,
) ([]*employee.EmployeeRoleHistory, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	history, err := qs.employeeRepo.GetRoleHistoryByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role history: %w", err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.role.history_read",
		"employee_role_history", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"count":       len(history),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return history, nil
}

// ============================================================================
// EXPORT
// ============================================================================

func (qs *EmployeeQueryService) ExportEmployeeData(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	format string,
) ([]byte, string, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	profiles, _, err := qs.employeeRepo.ListEmployeeProfilesByCompany(
		ctx, companyID, locationID, 10000, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get employee data for export: %w", err)
	}

	// Decrypt before serialising for export.
	qs.decryptProfiles(ctx, profiles)

	var data []byte
	var contentType string

	switch format {
	case "json":
		data, err = json.Marshal(profiles)
		contentType = "application/json"
	case "csv":
		data, err = qs.convertToCSV(profiles)
		contentType = "text/csv"
	default:
		return nil, "", fmt.Errorf("unsupported export format: %s", format)
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert data to %s: %w", format, err)
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.data.export",
		"employee_profile", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":             ip,
			"company_id":     companyID.String(),
			"location_scope": locationScopeLabel(locationID),
			"format":         format,
			"count":          len(profiles),
			"data_size":      len(data),
			"duration_ms":    time.Since(startTime).Milliseconds(),
		},
	)
	return data, contentType, nil
}

// ============================================================================
// HEALTH CHECK + HELPERS
// ============================================================================

func (qs *EmployeeQueryService) HealthCheck(ctx context.Context) error {
	if err := qs.employeeRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("employee repository health check failed: %w", err)
	}
	if err := qs.documentStorage.HealthCheck(ctx); err != nil {
		return fmt.Errorf("document storage health check failed: %w", err)
	}
	return nil
}

func (qs *EmployeeQueryService) convertToCSV(profiles []*employee.EmployeeProfile) ([]byte, error) {
	csvData := "Employee Profile ID,User ID,Email,Employment Type,Employment Status,Job Title,Department,Join Date\n"
	for _, profile := range profiles {
		row := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			profile.EmployeeProfileID,
			profile.UserID,
			safeString(profile.Email),
			safeString(profile.EmploymentType),
			safeString(profile.EmploymentStatus),
			safeString(profile.JobTitle),
			"",
			profile.CreatedAt.Format("2006-01-02"),
		)
		csvData += row
	}
	return []byte(csvData), nil
}

func safeString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

// ============================================================================
// DECRYPTED EMPLOYEE DETAILS (wire DTO)
// ============================================================================
//
// DecryptedEmployeeDetails is the fully-decrypted read projection returned to
// the handler. Every PII field here is PLAINTEXT.
//
// JSON tags are load-bearing: the mobile client keys off snake_case.
//
// NOTE: nullable fields intentionally DO NOT carry `omitempty` — the client
// needs to distinguish "backend returned null" from "backend never sent the
// key". Every field the UI renders is always present in the JSON, even when
// its value is null.
type DecryptedEmployeeDetails struct {
	// Identity (users)
	UserID    uuid.UUID `json:"user_id"`
	CompanyID uuid.UUID `json:"company_id"`
	Username  string    `json:"username"`
	FullName  *string   `json:"full_name"`

	// Decrypted contact
	PhoneNumber *string `json:"phone_number"`
	Email       *string `json:"email"`

	// Roster (company_employees + joined names)
	EmployeeID          string     `json:"employee_id"`
	RoleID              uuid.UUID  `json:"role_id"`
	RoleName            string     `json:"role_name"`
	PositionID          *uuid.UUID `json:"position_id"`
	PositionTitle       *string    `json:"position_title"`
	DepartmentID        *uuid.UUID `json:"department_id"`
	DepartmentName      *string    `json:"department_name"`
	PrimaryLocationID   *uuid.UUID `json:"primary_location_id"`
	PrimaryLocationName *string    `json:"primary_location_name"`
	LocationAccessScope string     `json:"location_access_scope"`
	ReportsTo           *uuid.UUID `json:"reports_to"`
	HireDate            time.Time  `json:"hire_date"`
	IsActive            bool       `json:"is_active"`

	// Profile — non-PII
	EmployeeProfileID *uuid.UUID `json:"employee_profile_id"`
	Gender            *string    `json:"gender"`
	EmploymentType    *string    `json:"employment_type"`
	EmploymentStatus  *string    `json:"employment_status"`
	JobTitle          *string    `json:"job_title"`
	Grade             *string    `json:"grade"`

	// Cost center (FK + resolved name/code from accounting.cost_centers)
	CostCenterID   *uuid.UUID `json:"cost_center_id"`
	CostCenter     *string    `json:"cost_center"`
	CostCenterName *string    `json:"cost_center_name"`
	CostCenterCode *string    `json:"cost_center_code"`

	// Probation / confirmation
	ProbationEndDate *time.Time `json:"probation_end_date"`
	ConfirmationDate *time.Time `json:"confirmation_date"`

	// Profile — decrypted PII
	DateOfBirth      *time.Time `json:"date_of_birth"`
	Nationality      *string    `json:"nationality"`
	MaritalStatus    *string    `json:"marital_status"`
	TaxID            *string    `json:"tax_id"`
	SocialSecurityID *string    `json:"social_security_id"`

	// Timestamps
	ProfileCreatedAt *time.Time `json:"profile_created_at"`
	ProfileUpdatedAt *time.Time `json:"profile_updated_at"`
	UserCreatedAt    time.Time  `json:"user_created_at"`
	UserLastLogin    *time.Time `json:"user_last_login"`
}

// ============================================================================
// LOCATION SCOPE RESOLUTION
// ============================================================================

// resolveLocationScopeIDs returns the locationIDs slice the repository methods
// expect, derived from the caller's location context.
//
// Contract (mirrors ensureEmployeeInScope):
//   - ScopeAll      → nil          (no filter; see the whole company)
//   - otherwise     → [LocationID] (single-location filter)
//
// If you later add a SELECTED mode with multiple granted locations, extend the
// switch here — the repository already accepts a []uuid.UUID.
func (qs *EmployeeQueryService) resolveLocationScopeIDs(
	ctx context.Context,
	companyID uuid.UUID,
) ([]uuid.UUID, error) {
	logger := qs.logger
	if logger == nil {
		logger = zap.L()
	}

	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		logger.Error("resolveLocationScopeIDs: location context missing",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("location context missing: %w", err)
	}

	logger.Info("resolveLocationScopeIDs",
		zap.String("company_id", companyID.String()),
		zap.String("mode", string(locCtx.Mode)),
		zap.Any("location_id", locCtx.LocationID),
	)

	switch locCtx.Mode {
	case locationctx.ScopeAll:
		logger.Info("resolveLocationScopeIDs: returning nil (ScopeAll)",
			zap.String("company_id", companyID.String()),
		)
		return nil, nil
	default:
		if locCtx.LocationID == nil {
			logger.Warn("resolveLocationScopeIDs: non-ALL mode but LocationID is nil",
				zap.String("company_id", companyID.String()),
				zap.String("mode", string(locCtx.Mode)),
			)
			return nil, ErrEmployeeHasNoLocation
		}
		ids := []uuid.UUID{*locCtx.LocationID}
		logger.Info("resolveLocationScopeIDs: returning single location",
			zap.String("company_id", companyID.String()),
			zap.String("location_id", locCtx.LocationID.String()),
		)
		return ids, nil
	}
}

// ============================================================================
// SEARCH + HYDRATE (free-text search with PII decryption)
// ============================================================================

// SearchEmployees runs the Instagram-style employee search for a company,
// scoped to whatever locations the caller is allowed to see.
//
// Returns ONLY the matching user IDs. Callers that need the full record then
// call GetEmployeeDetailsByIDs with the same company + scope.
//
// Modes (decided by the SQL function based on query length):
//   - query == ""      → recommendation feed
//   - 1-2 chars        → prefix match (username / full_name)
//   - 3+ chars         → trigram + full-text
func (qs *EmployeeQueryService) SearchEmployees(
	ctx context.Context,
	companyID uuid.UUID,
	query string,
	page, pageSize int,
) ([]uuid.UUID, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	logger := qs.logger
	if logger == nil {
		logger = zap.L()
	}

	logger.Info("service.SearchEmployees entry",
		zap.String("company_id", companyID.String()),
		zap.String("query_raw", query),
		zap.Int("query_len_raw", len(query)),
		zap.Int("page_in", page),
		zap.Int("page_size_in", pageSize),
		zap.String("ip", ip),
	)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 30
	}
	offset := (page - 1) * pageSize

	locationIDs, err := qs.resolveLocationScopeIDs(ctx, companyID)
	if err != nil {
		logger.Error("service.SearchEmployees: resolveLocationScopeIDs failed",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	logger.Info("service.SearchEmployees calling repo.SearchEmployeeIDs",
		zap.String("company_id", companyID.String()),
		zap.String("query", query),
		zap.Int("location_ids_count", len(locationIDs)),
		zap.Int("limit", pageSize),
		zap.Int("offset", offset),
	)

	ids, err := qs.employeeRepo.SearchEmployeeIDs(ctx, companyID, query, locationIDs, pageSize, offset)
	if err != nil {
		logger.Error("service.SearchEmployees: repo.SearchEmployeeIDs failed",
			zap.String("company_id", companyID.String()),
			zap.String("query", query),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to search employees: %w", err)
	}

	logger.Info("service.SearchEmployees success",
		zap.String("company_id", companyID.String()),
		zap.String("query", query),
		zap.Int("result_count", len(ids)),
		zap.Duration("duration", time.Since(startTime)),
	)

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.search_ids",
		"employee", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":           ip,
			"company_id":   companyID.String(),
			"query":        query,
			"location_ids": locationIDs,
			"page":         page,
			"page_size":    pageSize,
			"return_count": len(ids),
			"duration_ms":  time.Since(startTime).Milliseconds(),
		},
	)
	return ids, nil
}

// GetEmployeeDetailsByIDs hydrates a batch of user IDs with the full employee
// record and decrypts every PII field before returning.
//
// Decryption failures are swallowed per-field: a KMS blip degrades a single
// field to nil rather than failing the whole request. The audit log records
// the (attempted) batch, not per-field outcomes.
func (qs *EmployeeQueryService) GetEmployeeDetailsByIDs(
	ctx context.Context,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
) ([]*DecryptedEmployeeDetails, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	logger := qs.logger
	if logger == nil {
		logger = zap.L()
	}

	logger.Info("service.GetEmployeeDetailsByIDs entry",
		zap.String("company_id", companyID.String()),
		zap.Int("user_ids_count", len(userIDs)),
		zap.String("ip", ip),
	)

	if len(userIDs) == 0 {
		logger.Info("service.GetEmployeeDetailsByIDs: empty userIDs → short-circuit")
		return []*DecryptedEmployeeDetails{}, nil
	}

	locationIDs, err := qs.resolveLocationScopeIDs(ctx, companyID)
	if err != nil {
		logger.Error("service.GetEmployeeDetailsByIDs: resolveLocationScopeIDs failed",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	logger.Info("service.GetEmployeeDetailsByIDs calling repo.GetEmployeeFullDetailsByIDs",
		zap.String("company_id", companyID.String()),
		zap.Int("user_ids_count", len(userIDs)),
		zap.Int("location_ids_count", len(locationIDs)),
	)

	raw, err := qs.employeeRepo.GetEmployeeFullDetailsByIDs(ctx, companyID, userIDs, locationIDs)
	if err != nil {
		logger.Error("service.GetEmployeeDetailsByIDs: repo failed",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get employee details: %w", err)
	}

	logger.Info("service.GetEmployeeDetailsByIDs: repo returned",
		zap.String("company_id", companyID.String()),
		zap.Int("raw_rows", len(raw)),
	)

	out := make([]*DecryptedEmployeeDetails, 0, len(raw))
	for _, d := range raw {
		out = append(out, qs.decryptFullDetails(ctx, d))
	}

	// Final DTO dump — one log line per row with every nullable field.
	for _, dto := range out {
		if dto == nil {
			continue
		}
		logger.Info("service.GetEmployeeDetailsByIDs: final DTO",
			zap.String("user_id", dto.UserID.String()),
			zap.String("username", dto.Username),
			zap.Any("full_name", dto.FullName),
			zap.Any("phone_number", dto.PhoneNumber),
			zap.Any("email", dto.Email),
			zap.Any("date_of_birth", dto.DateOfBirth),
			zap.Any("nationality", dto.Nationality),
			zap.Any("marital_status", dto.MaritalStatus),
			zap.Any("tax_id", dto.TaxID),
			zap.Any("social_security_id", dto.SocialSecurityID),
			zap.Any("gender", dto.Gender),
			zap.Any("employment_type", dto.EmploymentType),
			zap.Any("employment_status", dto.EmploymentStatus),
			zap.Any("grade", dto.Grade),
			zap.Any("cost_center_id", dto.CostCenterID),
			zap.Any("cost_center", dto.CostCenter),
			zap.Any("cost_center_name", dto.CostCenterName),
			zap.Any("cost_center_code", dto.CostCenterCode),
			zap.Any("probation_end_date", dto.ProbationEndDate),
			zap.Any("confirmation_date", dto.ConfirmationDate),
			zap.Any("user_last_login", dto.UserLastLogin),
		)
	}

	logger.Info("service.GetEmployeeDetailsByIDs success",
		zap.String("company_id", companyID.String()),
		zap.Int("requested", len(userIDs)),
		zap.Int("returned", len(out)),
		zap.Duration("duration", time.Since(startTime)),
	)

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.full_details.read",
		"employee", nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":            ip,
			"company_id":    companyID.String(),
			"requested_ids": len(userIDs),
			"returned_ids":  len(out),
			"location_ids":  locationIDs,
			"duration_ms":   time.Since(startTime).Milliseconds(),
		},
	)
	return out, nil
}

// ============================================================================
// FULL-DETAILS DECRYPTION HELPER
// ============================================================================

// decryptFullDetails projects an EmployeeFullDetailsExt (encrypted blobs) into
// a DecryptedEmployeeDetails (plaintext PII). Non-PII fields — including the
// Ext-only CostCenterID/CostCenterName/CostCenterCode and the probation/
// confirmation dates — are copied verbatim.
//
// Unlike decryptProfile, PhoneKeyID here is a non-pointer uuid.UUID on the
// model — we test it against uuid.Nil instead of nil.
//
// Every field decrypt attempt is logged: "decrypted" (with length + preview),
// "no_ciphertext" (empty column — no data to decrypt), or "decrypt_error" /
// "parse_error" (something failed). This makes the "why is email empty?"
// question answerable from logs alone.
func (qs *EmployeeQueryService) decryptFullDetails(
	ctx context.Context,
	d *employee.EmployeeFullDetailsExt,
) *DecryptedEmployeeDetails {
	if d == nil {
		return nil
	}

	out := &DecryptedEmployeeDetails{
		// Identity
		UserID:    d.UserID,
		CompanyID: d.CompanyID,
		Username:  d.Username,
		FullName:  d.FullName,

		// Roster
		EmployeeID:          d.EmployeeID,
		RoleID:              d.RoleID,
		RoleName:            d.RoleName,
		PositionID:          d.PositionID,
		PositionTitle:       d.PositionTitle,
		DepartmentID:        d.DepartmentID,
		DepartmentName:      d.DepartmentName,
		PrimaryLocationID:   d.PrimaryLocationID,
		PrimaryLocationName: d.PrimaryLocationName,
		LocationAccessScope: d.LocationAccessScope,
		ReportsTo:           d.ReportsTo,
		HireDate:            d.HireDate,
		IsActive:            d.IsActive,

		// Profile — non-PII (promoted from embedded EmployeeFullDetails)
		EmployeeProfileID: d.EmployeeProfileID,
		Gender:            d.Gender,
		EmploymentType:    d.EmploymentType,
		EmploymentStatus:  d.EmploymentStatus,
		JobTitle:          d.JobTitle,
		Grade:             d.Grade,

		// Cost center (Ext-only fields)
		CostCenterID:   d.CostCenterID,
		CostCenter:     d.CostCenter,
		CostCenterName: d.CostCenterName,
		CostCenterCode: d.CostCenterCode,

		// Probation / confirmation (Ext-only fields)
		ProbationEndDate: d.ProbationEndDate,
		ConfirmationDate: d.ConfirmationDate,

		// Timestamps (promoted from embedded EmployeeFullDetails)
		ProfileCreatedAt: d.ProfileCreatedAt,
		ProfileUpdatedAt: d.ProfileUpdatedAt,
		UserCreatedAt:    d.UserCreatedAt,
		UserLastLogin:    d.UserLastLogin,
	}

	logger := qs.logger
	if logger == nil {
		logger = zap.L()
	}

	// logDecrypt is the per-field logging wrapper. Redacts high-sensitivity
	// fields (tax_id, social_security_id) to first+last char.
	logDecrypt := func(field, stage string, plainLen int, preview string, err error) {
		if err != nil {
			logger.Warn("decryptFullDetails: field failed",
				zap.String("field", field),
				zap.String("stage", stage),
				zap.String("user_id", d.UserID.String()),
				zap.Error(err),
			)
			return
		}
		if stage == "no_ciphertext" {
			logger.Info("decryptFullDetails: field skipped",
				zap.String("field", field),
				zap.String("stage", stage),
				zap.String("user_id", d.UserID.String()),
				zap.String("reason", "empty encrypted column"),
			)
			return
		}
		logger.Info("decryptFullDetails: field ok",
			zap.String("field", field),
			zap.String("stage", stage),
			zap.String("user_id", d.UserID.String()),
			zap.Int("plain_len", plainLen),
			zap.String("plain_preview", preview),
		)
	}

	redact := func(field, plain string) string {
		switch field {
		case "tax_id", "social_security_id":
			if len(plain) > 2 {
				return plain[:1] + "***" + plain[len(plain)-1:]
			}
		}
		return plain
	}

	// ---- Phone ----
	if len(d.PhoneEncrypted) > 0 && d.PhoneEncryptedDEK != "" && d.PhoneKeyID != uuid.Nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.PhoneEncrypted),
			EncryptedDEK:   d.PhoneEncryptedDEK,
			KeyID:          d.PhoneKeyID.String(),
		})
		if err == nil {
			out.PhoneNumber = &plain
			logDecrypt("phone_number", "decrypted", len(plain), plain, nil)
		} else {
			logDecrypt("phone_number", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("phone_number", "no_ciphertext", 0, "", nil)
	}

	// ---- Email ----
	if len(d.EmailEncrypted) > 0 && d.EmailEncryptedDEK != nil && d.EmailKeyID != nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.EmailEncrypted),
			EncryptedDEK:   *d.EmailEncryptedDEK,
			KeyID:          d.EmailKeyID.String(),
		})
		if err == nil {
			out.Email = &plain
			logDecrypt("email", "decrypted", len(plain), plain, nil)
		} else {
			logDecrypt("email", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("email", "no_ciphertext", 0, "", nil)
	}

	// ---- Tax ID ----
	if len(d.TaxIDEncrypted) > 0 && d.TaxIDEncryptedDEK != nil && d.TaxIDKeyID != nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.TaxIDEncrypted),
			EncryptedDEK:   *d.TaxIDEncryptedDEK,
			KeyID:          d.TaxIDKeyID.String(),
		})
		if err == nil {
			out.TaxID = &plain
			logDecrypt("tax_id", "decrypted", len(plain), redact("tax_id", plain), nil)
		} else {
			logDecrypt("tax_id", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("tax_id", "no_ciphertext", 0, "", nil)
	}

	// ---- Social Security ID ----
	if len(d.SocialSecurityIDEncrypted) > 0 &&
		d.SocialSecurityIDEncryptedDEK != nil &&
		d.SocialSecurityIDKeyID != nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.SocialSecurityIDEncrypted),
			EncryptedDEK:   *d.SocialSecurityIDEncryptedDEK,
			KeyID:          d.SocialSecurityIDKeyID.String(),
		})
		if err == nil {
			out.SocialSecurityID = &plain
			logDecrypt("social_security_id", "decrypted", len(plain), redact("social_security_id", plain), nil)
		} else {
			logDecrypt("social_security_id", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("social_security_id", "no_ciphertext", 0, "", nil)
	}

	// ---- Date of Birth (stored as RFC3339) ----
	if len(d.DateOfBirthEncrypted) > 0 && d.DateOfBirthEncryptedDEK != nil && d.DateOfBirthKeyID != nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.DateOfBirthEncrypted),
			EncryptedDEK:   *d.DateOfBirthEncryptedDEK,
			KeyID:          d.DateOfBirthKeyID.String(),
		})
		if err == nil {
			if t, perr := time.Parse(time.RFC3339, plain); perr == nil {
				out.DateOfBirth = &t
				logDecrypt("date_of_birth", "decrypted", len(plain), plain, nil)
			} else {
				logDecrypt("date_of_birth", "parse_error", len(plain), plain, perr)
			}
		} else {
			logDecrypt("date_of_birth", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("date_of_birth", "no_ciphertext", 0, "", nil)
	}

	// ---- Nationality ----
	if len(d.NationalityEncrypted) > 0 && d.NationalityEncryptedDEK != nil && d.NationalityKeyID != nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.NationalityEncrypted),
			EncryptedDEK:   *d.NationalityEncryptedDEK,
			KeyID:          d.NationalityKeyID.String(),
		})
		if err == nil {
			out.Nationality = &plain
			logDecrypt("nationality", "decrypted", len(plain), plain, nil)
		} else {
			logDecrypt("nationality", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("nationality", "no_ciphertext", 0, "", nil)
	}

	// ---- Marital Status ----
	if len(d.MaritalStatusEncrypted) > 0 && d.MaritalStatusEncryptedDEK != nil && d.MaritalStatusKeyID != nil {
		plain, err := qs.encryptionMgr.DecryptField(ctx, &encryption.EncryptedData{
			EncryptedValue: string(d.MaritalStatusEncrypted),
			EncryptedDEK:   *d.MaritalStatusEncryptedDEK,
			KeyID:          d.MaritalStatusKeyID.String(),
		})
		if err == nil {
			out.MaritalStatus = &plain
			logDecrypt("marital_status", "decrypted", len(plain), plain, nil)
		} else {
			logDecrypt("marital_status", "decrypt_error", 0, "", err)
		}
	} else {
		logDecrypt("marital_status", "no_ciphertext", 0, "", nil)
	}

	// ---- Summary ----
	logger.Info("decryptFullDetails: complete",
		zap.String("user_id", d.UserID.String()),
		zap.Bool("has_email", out.Email != nil),
		zap.Bool("has_dob", out.DateOfBirth != nil),
		zap.Bool("has_tax_id", out.TaxID != nil),
		zap.Bool("has_ssn", out.SocialSecurityID != nil),
		zap.Bool("has_nationality", out.Nationality != nil),
		zap.Bool("has_marital_status", out.MaritalStatus != nil),
		zap.Bool("has_cost_center_id", out.CostCenterID != nil),
		zap.Bool("has_cost_center_name", out.CostCenterName != nil),
		zap.Bool("has_cost_center_code", out.CostCenterCode != nil),
		zap.Bool("has_probation_end", out.ProbationEndDate != nil),
		zap.Bool("has_confirmation", out.ConfirmationDate != nil),
	)

	return out
}

// ============================================================================
// STATUS NOW — merged lifecycle view for a single employee
// ============================================================================

// EmployeeStatusNow is the read model backing GET .../status-now.
//
// employment_status is the cached rollup from employee_profiles.
// The three sub-objects expose the *detail* rows from the lifecycle tables,
// each present only while its phase is active:
//
//   - Probation is non-nil while employee_probation.status IN ('pending','extended')
//   - Notice    is non-nil while employee_notice.status = 'active'
//   - OnHold    is non-nil while employee_on_hold.status = 'active'
//   - Exit      is non-nil for any employee_exit row (scheduled/effective/cancelled/rehired)
//
// Day counters on Notice are computed here so the client never has to do
// date math (timezones, half-days, etc.).
type EmployeeStatusNow struct {
	UserID           uuid.UUID                   `json:"user_id"`
	CompanyID        uuid.UUID                   `json:"company_id"`
	EmploymentStatus string                      `json:"employment_status"`
	Probation        *employee.EmployeeProbation `json:"probation,omitempty"`
	Notice           *employee.EmployeeNotice    `json:"notice,omitempty"`
	OnHold           *employee.EmployeeOnHold    `json:"on_hold,omitempty"`
	Exit             *employee.EmployeeExit      `json:"exit,omitempty"`
}

// GetStatusNow returns the merged lifecycle state for one employee.
//
// Every sub-fetch is best-effort: a missing row is simply omitted from the
// response. Only the profile fetch is treated as required (an employee
// without a profile row is a real error, not "no lifecycle in progress").
func (qs *EmployeeQueryService) GetStatusNow(
	ctx context.Context,
	companyID, userID uuid.UUID,
) (*EmployeeStatusNow, error) {
	startTime := time.Now()
	ip, _ := ctx.Value("ip_address").(string)

	if err := qs.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	out := &EmployeeStatusNow{
		UserID:    userID,
		CompanyID: companyID,
	}

	// ---- Required: the profile row ----
	prof, err := qs.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	if prof.EmploymentStatus != nil {
		out.EmploymentStatus = *prof.EmploymentStatus
	}

	// ---- Optional: the lifecycle sub-rows ----
	if p, err := qs.employeeRepo.GetActiveProbation(ctx, companyID, userID); err == nil {
		out.Probation = p
	}
	if n, err := qs.employeeRepo.GetActiveNotice(ctx, companyID, userID); err == nil {
		qs.populateNoticeCounts(n)
		out.Notice = n
	}
	if h, err := qs.employeeRepo.GetActiveOnHold(ctx, companyID, userID); err == nil {
		out.OnHold = h
	}
	if e, err := qs.employeeRepo.GetEmployeeExitByUserID(ctx, userID, companyID); err == nil {
		out.Exit = e
	}

	_ = qs.auditService.LogAction(
		ctx, nil, &companyID, "hr", "employee.status.read",
		"employee", &userID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"company_id":  companyID.String(),
			"status":      out.EmploymentStatus,
			"has_prob":    out.Probation != nil,
			"has_notice":  out.Notice != nil,
			"has_on_hold": out.OnHold != nil,
			"has_exit":    out.Exit != nil,
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)
	return out, nil
}

// populateNoticeCounts fills the computed day counters on a notice row.
// Kept local to the query service so read paths don't have to reach into the
// write-side service just to render a response.
func (qs *EmployeeQueryService) populateNoticeCounts(n *employee.EmployeeNotice) {
	if n == nil {
		return
	}
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

// SearchEmployeesWithStatus is the status-aware sibling of SearchEmployees.
//
// status semantics:
//
//	""        -> no filter (same as SearchEmployees)
//	"all"     -> no filter
//	"active"  -> employment_status = 'active'
//	"probation" | "notice" | "on_hold" | "terminated" | "resigned" -> exact match
//
// Location scope flows through resolveLocationScopeIDs, same as the base
// method — mode=ALL → nil, mode=LOCATION → single location, mode=SELECTED
// → caller's selected set.
//
// Returns (rows, total, err). Total is computed by the count function so
// the HTTP layer can populate pagination meta even when the LIMIT trims
// the page.
// SearchEmployeesWithStatus is the status-aware sibling of SearchEmployees.
//
// status semantics:
//
//	""        -> no filter (same as SearchEmployees)
//	"all"     -> no filter
//	"active" | "probation" | "notice" | "on_hold" | "terminated" | "resigned"
//	          -> exact match against employee_profiles.employment_status
//
// Location scope flows through resolveLocationScopeIDs, same as the base
// method — mode=ALL → nil, mode=LOCATION → single location, mode=SELECTED
// → caller's selected set.
//
// Returns (rows, total, err). Total is computed by the count function so
// the HTTP layer can populate pagination meta even when LIMIT trims the
// page.
func (s *EmployeeQueryService) SearchEmployeesWithStatus(
	ctx context.Context,
	companyID uuid.UUID,
	query string,
	status string,
	page, pageSize int,
	idsOnly bool,
) ([]*employee.EmployeeFullDetailsExt, int, error) {
	logger := zap.L().With(
		zap.String("component", "employee_query_service"),
		zap.String("op", "search_employees_with_status"),
		zap.String("company_id", companyID.String()),
		zap.String("query", query),
		zap.String("status", status),
		zap.Int("page", page),
		zap.Int("page_size", pageSize),
		zap.Bool("ids_only", idsOnly),
	)
	logger.Info("SearchEmployeesWithStatus entry")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 30
	}
	offset := (page - 1) * pageSize

	locationIDs, err := s.resolveLocationScopeIDs(ctx, companyID)
	if err != nil {
		logger.Error("resolveLocationScopeIDs failed", zap.Error(err))
		return nil, 0, err
	}
	logger.Info("resolved location scope", zap.Int("location_ids_count", len(locationIDs)))

	total, err := s.employeeRepo.CountEmployeeIDsByStatus(
		ctx, companyID, query, locationIDs, status,
	)
	if err != nil {
		logger.Error("CountEmployeeIDsByStatus failed", zap.Error(err))
		return nil, 0, fmt.Errorf("count employees: %w", err)
	}
	logger.Info("count done", zap.Int("total", total))

	if total == 0 {
		return []*employee.EmployeeFullDetailsExt{}, 0, nil
	}

	ids, err := s.employeeRepo.SearchEmployeeIDsByStatus(
		ctx, companyID, query, locationIDs, status, pageSize, offset,
	)
	if err != nil {
		logger.Error("SearchEmployeeIDsByStatus failed", zap.Error(err))
		return nil, 0, fmt.Errorf("search employees: %w", err)
	}
	logger.Info("id search done", zap.Int("ids_count", len(ids)))

	if len(ids) == 0 {
		return []*employee.EmployeeFullDetailsExt{}, total, nil
	}

	// Hydrate unconditionally. The previous ids-only stub optimization
	// tried to construct EmployeeFullDetailsExt via struct literal, but
	// CompanyID/UserID are *promoted* fields (embedded CompanyEmployee),
	// and Go doesn't permit setting promoted fields in a composite literal.
	// Hydration is cheap and the response shape stays consistent, so just
	// always hydrate.
	//
	// If idsOnly becomes a real performance need, do the light path in the
	// repo (a dedicated SearchEmployeeIDs-lite query) rather than
	// reconstructing the DTO in the service.
	_ = idsOnly

	rows, err := s.employeeRepo.GetEmployeeFullDetailsByIDs(
		ctx, companyID, ids, locationIDs,
	)
	if err != nil {
		logger.Error("GetEmployeeFullDetailsByIDs failed", zap.Error(err))
		return nil, 0, fmt.Errorf("hydrate employees: %w", err)
	}
	logger.Info("hydration done",
		zap.Int("requested", len(ids)),
		zap.Int("returned", len(rows)))

	return rows, total, nil
}

// GetTerminatedEmployees returns terminated (and resigned) employees for
// a company, scoped to the caller's location context.
//
// This is a thin convenience wrapper over SearchEmployeesWithStatus so the
// UI's "Terminated" filter can be served without a caller-side status
// string. Prefer SearchEmployeesWithStatus for a generic list endpoint.
func (s *EmployeeQueryService) GetTerminatedEmployees(
	ctx context.Context,
	companyID uuid.UUID,
	query string,
	page, pageSize int,
) ([]*employee.EmployeeFullDetailsExt, int, error) {
	// The two "gone" statuses. If your schema only uses 'terminated',
	// drop the 'resigned' call or union them at the SQL layer.
	//
	// NOTE: search_company_employee_ids_by_status matches ONE status value
	// per call. If you need both terminated + resigned in one response,
	// either:
	//   - call twice and merge (loses pagination accuracy), or
	//   - extend the SQL function to accept text[] for status, or
	//   - pick one canonical status for 'left the company'.
	//
	// For now we assume the app uses 'terminated' exclusively.
	return s.SearchEmployeesWithStatus(
		ctx, companyID, query, "terminated", page, pageSize, false,
	)
}

// DecryptFullDetailsExt is the exported wrapper around decryptFullDetails.
// The HTTP handler lives in a different package and needs to post-process
// the rows returned by SearchEmployeesWithStatus / GetTerminatedEmployees
// without duplicating the decryption loop.
func (qs *EmployeeQueryService) DecryptFullDetailsExt(
	ctx context.Context,
	d *employee.EmployeeFullDetailsExt,
) *DecryptedEmployeeDetails {
	return qs.decryptFullDetails(ctx, d)
}
