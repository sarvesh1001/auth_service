package service

import (
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// EMPLOYEE QUERY SERVICE (READ OPERATIONS)
// ============================================================================

// EmployeeQueryService handles employee read operations
type EmployeeQueryService struct {
	employeeRepo    repository.EmployeeRepository
	documentStorage DocumentStorage
	logger          *zap.Logger
}

func NewEmployeeQueryService(
	employeeRepo repository.EmployeeRepository,
	documentStorage DocumentStorage,
	logger *zap.Logger,
) *EmployeeQueryService {

	if documentStorage == nil {
		panic("documentStorage is required for EmployeeQueryService")
	}

	return &EmployeeQueryService{
		employeeRepo:    employeeRepo,
		documentStorage: documentStorage,
		logger:          logger,
	}
}

// GetEmployeeProfile retrieves an employee profile by ID
func (qs *EmployeeQueryService) GetEmployeeProfile(
	ctx context.Context,
	profileID uuid.UUID,
) (*employee.EmployeeProfile, error) {
	startTime := time.Now()

	profile, err := qs.employeeRepo.GetEmployeeProfileByID(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee profile: %w", err)
	}

	qs.logger.Debug("Employee profile retrieved",
		util.String("profile_id", profileID.String()),
		util.Duration("duration", time.Since(startTime)))

	return profile, nil
}

// GetEmployeeProfileByUserID retrieves employee profile by user ID
func (qs *EmployeeQueryService) GetEmployeeProfileByUserID(
	ctx context.Context,
	userID, companyID uuid.UUID,
) (*employee.EmployeeProfile, error) {
	startTime := time.Now()

	profile, err := qs.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee profile by user ID: %w", err)
	}

	qs.logger.Debug("Employee profile retrieved by user ID",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return profile, nil
}

// ListEmployeeProfiles lists employee profiles with pagination
func (qs *EmployeeQueryService) ListEmployeeProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	page, pageSize int,
) ([]*employee.EmployeeProfile, int, error) {
	startTime := time.Now()

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	profiles, totalCount, err := qs.employeeRepo.ListEmployeeProfilesByCompany(
		ctx, companyID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list employee profiles: %w", err)
	}

	qs.logger.Debug("Employee profiles listed",
		util.String("company_id", companyID.String()),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(profiles)),
		util.Duration("duration", time.Since(startTime)))

	return profiles, totalCount, nil
}

// SearchEmployeeProfiles searches employee profiles with filters
func (qs *EmployeeQueryService) SearchEmployeeProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*employee.EmployeeProfile, int, error) {
	startTime := time.Now()

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	profiles, totalCount, err := qs.employeeRepo.SearchEmployeeProfiles(
		ctx, companyID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search employee profiles: %w", err)
	}

	qs.logger.Debug("Employee profiles searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(profiles)),
		util.Duration("duration", time.Since(startTime)))

	return profiles, totalCount, nil
}

// GetEmployeeDocuments retrieves documents for an employee
func (qs *EmployeeQueryService) GetEmployeeDocuments(
	ctx context.Context,
	userID, companyID uuid.UUID,
) ([]*employee.EmployeeDocument, error) {
	startTime := time.Now()

	documents, err := qs.employeeRepo.GetEmployeeDocumentsByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee documents: %w", err)
	}

	qs.logger.Debug("Employee documents retrieved",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.Int("document_count", len(documents)),
		util.Duration("duration", time.Since(startTime)))

	return documents, nil
}

// GetConfidentialDocuments retrieves confidential documents for an employee
func (qs *EmployeeQueryService) GetConfidentialDocuments(
	ctx context.Context,
	userID, companyID uuid.UUID,
) ([]*employee.EmployeeDocument, error) {
	startTime := time.Now()

	documents, err := qs.employeeRepo.GetConfidentialDocumentsByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get confidential documents: %w", err)
	}

	qs.logger.Debug("Confidential documents retrieved",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.Int("document_count", len(documents)),
		util.Duration("duration", time.Since(startTime)))

	return documents, nil
}

// DownloadEmployeeDocument downloads a document file
func (qs *EmployeeQueryService) DownloadEmployeeDocument(
	ctx context.Context,
	documentID uuid.UUID,
) (io.ReadCloser, int64, string, *employee.EmployeeDocument, error) {
	startTime := time.Now()

	// Get document record
	document, err := qs.employeeRepo.GetEmployeeDocumentByID(ctx, documentID)
	if err != nil {
		return nil, 0, "", nil, fmt.Errorf("failed to get document record: %w", err)
	}

	// Download from storage
	reader, size, mimeType, err := qs.documentStorage.DownloadDocument(
		ctx, document.DocumentObjectKey)
	if err != nil {
		return nil, 0, "", nil, fmt.Errorf("failed to download document: %w", err)
	}

	qs.logger.Debug("Employee document downloaded",
		util.String("document_id", documentID.String()),
		util.String("user_id", document.UserID.String()),
		util.Int64("file_size", size),
		util.Duration("duration", time.Since(startTime)))

	return reader, size, mimeType, document, nil
}

// GenerateDocumentURL generates a temporary URL for document access
func (qs *EmployeeQueryService) GenerateDocumentURL(
	ctx context.Context,
	documentID uuid.UUID,
	expiry time.Duration,
) (string, error) {
	startTime := time.Now()

	// Get document record
	document, err := qs.employeeRepo.GetEmployeeDocumentByID(ctx, documentID)
	if err != nil {
		return "", fmt.Errorf("failed to get document record: %w", err)
	}

	// Generate signed URL
	url, err := qs.documentStorage.GenerateSignedURL(ctx, document.DocumentObjectKey, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate document URL: %w", err)
	}

	qs.logger.Debug("Document URL generated",
		util.String("document_id", documentID.String()),
		util.String("user_id", document.UserID.String()),
		util.Duration("expiry", expiry),
		util.Duration("duration", time.Since(startTime)))

	return url, nil
}

// GetDepartmentHistory retrieves department history for an employee
func (qs *EmployeeQueryService) GetDepartmentHistory(
	ctx context.Context,
	userID, companyID uuid.UUID,
) ([]*employee.EmployeeDepartmentHistory, error) {
	startTime := time.Now()

	history, err := qs.employeeRepo.GetDepartmentHistoryByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department history: %w", err)
	}

	qs.logger.Debug("Department history retrieved",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.Int("history_count", len(history)),
		util.Duration("duration", time.Since(startTime)))

	return history, nil
}

// GetEmployeeExit retrieves employee exit record
func (qs *EmployeeQueryService) GetEmployeeExit(
	ctx context.Context,
	userID, companyID uuid.UUID,
) (*employee.EmployeeExit, error) {
	startTime := time.Now()

	exit, err := qs.employeeRepo.GetEmployeeExitByUserID(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee exit record: %w", err)
	}

	qs.logger.Debug("Employee exit record retrieved",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return exit, nil
}

// GetPositionsByDepartment retrieves positions in a department
func (qs *EmployeeQueryService) GetPositionsByDepartment(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
) ([]*employee.Position, error) {
	startTime := time.Now()

	positions, err := qs.employeeRepo.GetPositionsByDepartment(ctx, companyID, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by department: %w", err)
	}

	qs.logger.Debug("Positions retrieved by department",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()),
		util.Int("position_count", len(positions)),
		util.Duration("duration", time.Since(startTime)))

	return positions, nil
}

// GetOpenPositions retrieves open positions in a company
func (qs *EmployeeQueryService) GetOpenPositions(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*employee.Position, error) {
	startTime := time.Now()

	positions, err := qs.employeeRepo.GetOpenPositions(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get open positions: %w", err)
	}

	qs.logger.Debug("Open positions retrieved",
		util.String("company_id", companyID.String()),
		util.Int("open_position_count", len(positions)),
		util.Duration("duration", time.Since(startTime)))

	return positions, nil
}

// GetRoleHistory retrieves role history for an employee
func (qs *EmployeeQueryService) GetRoleHistory(
	ctx context.Context,
	userID uuid.UUID,
) ([]*employee.EmployeeRoleHistory, error) {
	startTime := time.Now()

	history, err := qs.employeeRepo.GetRoleHistoryByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role history: %w", err)
	}

	qs.logger.Debug("Role history retrieved",
		util.String("user_id", userID.String()),
		util.Int("history_count", len(history)),
		util.Duration("duration", time.Since(startTime)))

	return history, nil
}

// GetEmployeeStats provides statistics about employees
func (qs *EmployeeQueryService) GetEmployeeStats(
	ctx context.Context,
	companyID uuid.UUID,
) (map[string]interface{}, error) {
	startTime := time.Now()

	stats, err := qs.employeeRepo.GetEmployeeStatsByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee stats: %w", err)
	}

	// Get employee count by department
	deptCounts, err := qs.employeeRepo.GetEmployeeCountByDepartment(ctx, companyID)
	if err == nil {
		stats["department_distribution"] = deptCounts
	}

	qs.logger.Debug("Employee statistics retrieved",
		util.String("company_id", companyID.String()),
		util.Int("stat_count", len(stats)),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

// GetActiveEmployeesByDateRange gets employees hired in a date range
func (qs *EmployeeQueryService) GetActiveEmployeesByDateRange(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]*employee.EmployeeProfile, error) {
	startTime := time.Now()

	profiles, err := qs.employeeRepo.GetActiveEmployeesByDateRange(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees by date range: %w", err)
	}

	qs.logger.Debug("Active employees retrieved by date range",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("employee_count", len(profiles)),
		util.Duration("duration", time.Since(startTime)))

	return profiles, nil
}

// ExportEmployeeData exports employee data for reporting
func (qs *EmployeeQueryService) ExportEmployeeData(
	ctx context.Context,
	companyID uuid.UUID,
	format string,
) ([]byte, string, error) {
	startTime := time.Now()

	// Get all employee profiles for the company
	profiles, _, err := qs.employeeRepo.ListEmployeeProfilesByCompany(ctx, companyID, 10000, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get employee data for export: %w", err)
	}

	var data []byte
	var contentType string

	switch format {
	case "json":
		data, err = util.ToJSON(profiles)
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

	qs.logger.Info("Employee data exported",
		util.String("company_id", companyID.String()),
		util.String("format", format),
		util.Int("employee_count", len(profiles)),
		util.Int("data_size", len(data)),
		util.Duration("duration", time.Since(startTime)))

	return data, contentType, nil
}

func (qs *EmployeeQueryService) HealthCheck(ctx context.Context) error {
	if err := qs.employeeRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("employee repository health check failed: %w", err)
	}
	if err := qs.documentStorage.HealthCheck(ctx); err != nil {
		return fmt.Errorf("document storage health check failed: %w", err)
	}
	return nil
}

// convertToCSV converts employee profiles to CSV format
func (qs *EmployeeQueryService) convertToCSV(profiles []*employee.EmployeeProfile) ([]byte, error) {
	// Use proper CSV writing for production (here using simple string building for clarity)
	// Headers: Employee ID, User ID, Email, Name, Employment Type, Employment Status, Job Title, Department, Join Date
	csvData := "Employee Profile ID,User ID,Email,Employment Type,Employment Status,Job Title,Department,Join Date\n"

	for _, profile := range profiles {
		// Note: You would need to get user name and department from other services
		// This is a simplified example; in real code you'd enrich the data.
		row := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			profile.EmployeeProfileID,
			profile.UserID,
			safeString(profile.Email), // <-- Email added here
			safeString(profile.EmploymentType),
			safeString(profile.EmploymentStatus),
			safeString(profile.JobTitle),
			"", // Department would need to be fetched (e.g., from employee_department_history)
			profile.CreatedAt.Format("2006-01-02"),
		)
		csvData += row
	}

	return []byte(csvData), nil
}

// Helper function for safe string conversion
func safeString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}
