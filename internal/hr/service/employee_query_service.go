// internal/hr/service/employee_query_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

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
// PII DECRYPTION HELPER
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
