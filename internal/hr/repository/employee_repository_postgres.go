package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"
)

// EmployeeRepositoryImpl handles PostgreSQL HR employee operations
type EmployeeRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

// NewEmployeeRepository creates a new PostgreSQL employee repository
func NewEmployeeRepository(postgresClient *client.PostgresClient, logger *zap.Logger) EmployeeRepository {
	repo := &EmployeeRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ============================================================================
// EMPLOYEE PROFILE METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error {
	startTime := time.Now()

	// First, get the position title from the positions table using position_id from company_employees
	var jobTitle *string
	queryGetTitle := `
		SELECT p.title 
		FROM company_employees ce
		LEFT JOIN positions p ON ce.position_id = p.position_id
		WHERE ce.user_id = $1 AND ce.company_id = $2
		LIMIT 1`

	err := r.client.QueryRow(ctx, queryGetTitle, profile.UserID, profile.CompanyID).Scan(&jobTitle)
	if err != nil && err != pgx.ErrNoRows {
		r.logger.Error("Failed to get position title",
			util.String("user_id", profile.UserID.String()),
			util.String("company_id", profile.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to get position title: %w", err)
	}

	// Use the fetched job title (could be NULL if no position assigned)
	profile.JobTitle = jobTitle

	query := `
		INSERT INTO employee_profiles (
			employee_profile_id, user_id, company_id, date_of_birth, gender, 
			marital_status, nationality, employment_type, employment_status, 
			probation_end_date, confirmation_date, job_title, grade, cost_center, 
			tax_id, social_security_id, email, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`

	_, err = r.client.Exec(ctx, query,
		profile.EmployeeProfileID,
		profile.UserID,
		profile.CompanyID,
		profile.DateOfBirth,
		profile.Gender,
		profile.MaritalStatus,
		profile.Nationality,
		profile.EmploymentType,
		profile.EmploymentStatus,
		profile.ProbationEndDate,
		profile.ConfirmationDate,
		jobTitle, // Use the fetched title
		profile.Grade,
		profile.CostCenter,
		profile.TaxID,
		profile.SocialSecurityID,
		profile.Email,
		profile.CreatedAt,
		profile.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create employee profile",
			util.String("user_id", profile.UserID.String()),
			util.String("company_id", profile.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create employee profile: %w", err)
	}

	r.logger.Debug("Employee profile created",
		util.String("profile_id", profile.EmployeeProfileID.String()),
		util.String("user_id", profile.UserID.String()),
		util.String("job_title", util.SafeString(jobTitle)),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *EmployeeRepositoryImpl) GetEmployeeProfileByID(ctx context.Context, profileID uuid.UUID) (*employee.EmployeeProfile, error) {
	stmt, ok := r.getStmt("get_employee_profile_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_employee_profile_by_id")
	}

	rows, err := stmt.QueryContext(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee profile by ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeProfile(rows)
	}

	return nil, fmt.Errorf("employee profile not found: %s", profileID)
}

func (r *EmployeeRepositoryImpl) GetEmployeeProfileByUserID(ctx context.Context, userID, companyID uuid.UUID) (*employee.EmployeeProfile, error) {
	stmt, ok := r.getStmt("get_employee_profile_by_user_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_employee_profile_by_user_id")
	}

	rows, err := stmt.QueryContext(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee profile by user ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeProfile(rows)
	}

	return nil, fmt.Errorf("employee profile not found for user: %s", userID)
}

func (r *EmployeeRepositoryImpl) UpdateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error {
	now := time.Now().UTC()
	profile.UpdatedAt = now

	query := `
		UPDATE employee_profiles SET
			date_of_birth = $1, gender = $2, marital_status = $3, 
			nationality = $4, employment_type = $5, employment_status = $6, 
			probation_end_date = $7, confirmation_date = $8, job_title = $9, 
			grade = $10, cost_center = $11, tax_id = $12, 
			social_security_id = $13, email = $14, updated_at = $15
		WHERE employee_profile_id = $16`

	result, err := r.client.Exec(ctx, query,
		profile.DateOfBirth,
		profile.Gender,
		profile.MaritalStatus,
		profile.Nationality,
		profile.EmploymentType,
		profile.EmploymentStatus,
		profile.ProbationEndDate,
		profile.ConfirmationDate,
		profile.JobTitle,
		profile.Grade,
		profile.CostCenter,
		profile.TaxID,
		profile.SocialSecurityID,
		profile.Email,
		profile.UpdatedAt,
		profile.EmployeeProfileID,
	)

	if err != nil {
		return fmt.Errorf("failed to update employee profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee profile not found: %s", profile.EmployeeProfileID)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) DeleteEmployeeProfile(ctx context.Context, profileID uuid.UUID) error {
	query := `DELETE FROM employee_profiles WHERE employee_profile_id = $1`
	result, err := r.client.Exec(ctx, query, profileID)
	if err != nil {
		return fmt.Errorf("failed to delete employee profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee profile not found: %s", profileID)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) ListEmployeeProfilesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*employee.EmployeeProfile, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Get total count
	var totalCount int
	countQuery := `SELECT COUNT(*) FROM employee_profiles WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count employee profiles: %w", err)
	}

	// Get profiles - using raw query since parameters vary
	query := `
		SELECT 
			employee_profile_id, user_id, company_id, date_of_birth, gender, 
			marital_status, nationality, employment_type, employment_status, 
			probation_end_date, confirmation_date, job_title, grade, cost_center, 
			tax_id, social_security_id, email, created_at, updated_at
		FROM employee_profiles 
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list employee profiles: %w", err)
	}
	defer rows.Close()

	profiles := make([]*employee.EmployeeProfile, 0, limit)
	for rows.Next() {
		profile, err := r.scanEmployeeProfile(rows)
		if err != nil {
			r.logger.Warn("Failed to scan employee profile", util.ErrorField(err))
			continue
		}
		profiles = append(profiles, profile)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee profiles: %w", err)
	}

	return profiles, totalCount, nil
}

func (r *EmployeeRepositoryImpl) SearchEmployeeProfiles(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*employee.EmployeeProfile, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramCount := 2

	for field, value := range filters {
		switch field {
		case "employment_type":
			conditions = append(conditions, fmt.Sprintf("employment_type = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "employment_status":
			conditions = append(conditions, fmt.Sprintf("employment_status = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "department_id":
			// Join with department history to filter by department
			conditions = append(conditions, fmt.Sprintf(
				"user_id IN (SELECT user_id FROM employee_department_history WHERE department_id = $%d AND end_date IS NULL)",
				paramCount))
			params = append(params, value)
			paramCount++
		case "job_title":
			conditions = append(conditions, fmt.Sprintf("job_title ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "gender":
			conditions = append(conditions, fmt.Sprintf("gender = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "hire_date_from":
			conditions = append(conditions, fmt.Sprintf("created_at >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "email":
			conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM employee_profiles %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	// Search query - dynamic query, not suitable for prepared statement
	searchQuery := fmt.Sprintf(`
		SELECT 
			employee_profile_id, user_id, company_id, date_of_birth, gender, 
			marital_status, nationality, employment_type, employment_status, 
			probation_end_date, confirmation_date, job_title, grade, cost_center, 
			tax_id, social_security_id, email, created_at, updated_at
		FROM employee_profiles %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCount, paramCount+1)

	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search employee profiles: %w", err)
	}
	defer rows.Close()

	profiles := make([]*employee.EmployeeProfile, 0, limit)
	for rows.Next() {
		profile, err := r.scanEmployeeProfile(rows)
		if err != nil {
			r.logger.Warn("Failed to scan employee profile", util.ErrorField(err))
			continue
		}
		profiles = append(profiles, profile)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return profiles, totalCount, nil
}

// ============================================================================
// EMPLOYEE DEPARTMENT HISTORY METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateDepartmentHistory(ctx context.Context, history *employee.EmployeeDepartmentHistory) error {
	query := `
		INSERT INTO employee_department_history (
			id, user_id, company_id, department_id, start_date, end_date, 
			change_reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.client.Exec(ctx, query,
		history.ID,
		history.UserID,
		history.CompanyID,
		history.DepartmentID,
		history.StartDate,
		history.EndDate,
		history.ChangeReason,
		history.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create department history: %w", err)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) GetDepartmentHistoryByID(ctx context.Context, id uuid.UUID) (*employee.EmployeeDepartmentHistory, error) {
	query := `
		SELECT id, user_id, company_id, department_id, start_date, end_date, 
		       change_reason, created_at
		FROM employee_department_history 
		WHERE id = $1`

	rows, err := r.client.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get department history: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanDepartmentHistory(rows)
	}

	return nil, fmt.Errorf("department history not found: %s", id)
}

func (r *EmployeeRepositoryImpl) GetDepartmentHistoryByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDepartmentHistory, error) {
	stmt, ok := r.getStmt("get_department_history_by_user_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_department_history_by_user_id")
	}

	rows, err := stmt.QueryContext(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department history by user ID: %w", err)
	}
	defer rows.Close()

	histories := make([]*employee.EmployeeDepartmentHistory, 0)
	for rows.Next() {
		history, err := r.scanDepartmentHistory(rows)
		if err != nil {
			r.logger.Warn("Failed to scan department history", util.ErrorField(err))
			continue
		}
		histories = append(histories, history)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department histories: %w", err)
	}

	return histories, nil
}

func (r *EmployeeRepositoryImpl) UpdateDepartmentHistory(ctx context.Context, history *employee.EmployeeDepartmentHistory) error {
	query := `
		UPDATE employee_department_history SET
			department_id = $1, start_date = $2, end_date = $3, 
			change_reason = $4
		WHERE id = $5`

	result, err := r.client.Exec(ctx, query,
		history.DepartmentID,
		history.StartDate,
		history.EndDate,
		history.ChangeReason,
		history.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update department history: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("department history not found: %s", history.ID)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) EndDepartmentAssignment(ctx context.Context, userID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE employee_department_history 
		SET end_date = $1
		WHERE user_id = $2 AND end_date IS NULL`

	result, err := r.client.Exec(ctx, query, endDate, userID)
	if err != nil {
		return fmt.Errorf("failed to end department assignment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("no active department assignment found for user: %s", userID)
	}

	return nil
}

// ============================================================================
// EMPLOYEE DOCUMENT METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateEmployeeDocument(ctx context.Context, doc *employee.EmployeeDocument) error {
	query := `
		INSERT INTO employee_documents (
			document_id, user_id, company_id, document_type, document_name, 
			document_object_key, mime_type, is_confidential, uploaded_by, uploaded_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.client.Exec(ctx, query,
		doc.DocumentID,
		doc.UserID,
		doc.CompanyID,
		doc.DocumentType,
		doc.DocumentName,
		doc.DocumentObjectKey,
		doc.MimeType,
		doc.IsConfidential,
		doc.UploadedBy,
		doc.UploadedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create employee document: %w", err)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) GetEmployeeDocumentByID(ctx context.Context, documentID uuid.UUID) (*employee.EmployeeDocument, error) {
	query := `
		SELECT document_id, user_id, company_id, document_type, document_name, 
		       document_object_key, mime_type, is_confidential, uploaded_by, uploaded_at
		FROM employee_documents 
		WHERE document_id = $1`

	rows, err := r.client.Query(ctx, query, documentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee document: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeDocument(rows)
	}

	return nil, fmt.Errorf("employee document not found: %s", documentID)
}

func (r *EmployeeRepositoryImpl) GetEmployeeDocumentsByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDocument, error) {
	stmt, ok := r.getStmt("get_employee_documents_by_user_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_employee_documents_by_user_id")
	}

	rows, err := stmt.QueryContext(ctx, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee documents: %w", err)
	}
	defer rows.Close()

	documents := make([]*employee.EmployeeDocument, 0)
	for rows.Next() {
		doc, err := r.scanEmployeeDocument(rows)
		if err != nil {
			r.logger.Warn("Failed to scan employee document", util.ErrorField(err))
			continue
		}
		documents = append(documents, doc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee documents: %w", err)
	}

	return documents, nil
}

func (r *EmployeeRepositoryImpl) GetConfidentialDocumentsByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDocument, error) {
	query := `
		SELECT document_id, user_id, company_id, document_type, document_name, 
		       document_object_key, mime_type, is_confidential, uploaded_by, uploaded_at
		FROM employee_documents 
		WHERE user_id = $1 AND company_id = $2 AND is_confidential = true
		ORDER BY uploaded_at DESC`

	rows, err := r.client.Query(ctx, query, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get confidential documents: %w", err)
	}
	defer rows.Close()

	documents := make([]*employee.EmployeeDocument, 0)
	for rows.Next() {
		doc, err := r.scanEmployeeDocument(rows)
		if err != nil {
			r.logger.Warn("Failed to scan confidential document", util.ErrorField(err))
			continue
		}
		documents = append(documents, doc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating confidential documents: %w", err)
	}

	return documents, nil
}

func (r *EmployeeRepositoryImpl) UpdateEmployeeDocument(ctx context.Context, doc *employee.EmployeeDocument) error {
	query := `
		UPDATE employee_documents SET
			document_type = $1, document_name = $2, is_confidential = $3
		WHERE document_id = $4`

	result, err := r.client.Exec(ctx, query,
		doc.DocumentType,
		doc.DocumentName,
		doc.IsConfidential,
		doc.DocumentID,
	)

	if err != nil {
		return fmt.Errorf("failed to update employee document: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee document not found: %s", doc.DocumentID)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) DeleteEmployeeDocument(ctx context.Context, documentID uuid.UUID) error {
	query := `DELETE FROM employee_documents WHERE document_id = $1`
	result, err := r.client.Exec(ctx, query, documentID)
	if err != nil {
		return fmt.Errorf("failed to delete employee document: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee document not found: %s", documentID)
	}

	return nil
}

// ============================================================================
// EMPLOYEE EXIT METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateEmployeeExit(ctx context.Context, exit *employee.EmployeeExit) error {
	query := `
	INSERT INTO employee_exit (
		exit_id,
		user_id,
		company_id,
		exit_date,
		exit_reason,
		eligible_for_rehire,
		exit_state,
		created_at
	)
	VALUES ($1, $2, $3, $4, $5, $6, 'scheduled', $7)
	`

	_, err := r.client.Exec(ctx, query,
		exit.ExitID,
		exit.UserID,
		exit.CompanyID,
		exit.ExitDate,
		exit.ExitReason,
		exit.EligibleForRehire,
		exit.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create employee exit: %w", err)
	}
	return nil
}

func (r *EmployeeRepositoryImpl) GetEmployeeExitByID(
	ctx context.Context,
	exitID uuid.UUID,
) (*employee.EmployeeExit, error) {

	query := `
		SELECT
			exit_id,
			user_id,
			company_id,
			exit_date,
			exit_reason,
			eligible_for_rehire,
			exit_state,
			enforced_at,
			enforced_by,
			created_at
		FROM employee_exit
		WHERE exit_id = $1
	`

	rows, err := r.client.Query(ctx, query, exitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee exit record: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeExit(rows)
	}

	return nil, fmt.Errorf("employee exit record not found: %s", exitID)
}

func (r *EmployeeRepositoryImpl) GetEmployeeExitByUserID(
	ctx context.Context,
	userID, companyID uuid.UUID,
) (*employee.EmployeeExit, error) {

	query := `
		SELECT
			exit_id,
			user_id,
			company_id,
			exit_date,
			exit_reason,
			eligible_for_rehire,
			exit_state,
			enforced_at,
			enforced_by,
			created_at
		FROM employee_exit
		WHERE user_id = $1 AND company_id = $2
	`

	rows, err := r.client.Query(ctx, query, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee exit record by user ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeExit(rows)
	}

	return nil, fmt.Errorf("employee exit record not found for user: %s", userID)
}

func (r *EmployeeRepositoryImpl) UpdateEmployeeExit(ctx context.Context, exit *employee.EmployeeExit) error {
	query := `
		UPDATE employee_exit SET
			exit_date = $1, exit_reason = $2, eligible_for_rehire = $3
		WHERE exit_id = $4`

	result, err := r.client.Exec(ctx, query,
		exit.ExitDate,
		exit.ExitReason,
		exit.EligibleForRehire,
		exit.ExitID,
	)

	if err != nil {
		return fmt.Errorf("failed to update employee exit record: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee exit record not found: %s", exit.ExitID)
	}

	return nil
}

// ============================================================================
// POSITION METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreatePosition(ctx context.Context, position *employee.Position) error {
	query := `
		INSERT INTO positions (
			position_id, company_id, department_id, title, is_open, 
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.client.Exec(ctx, query,
		position.PositionID,
		position.CompanyID,
		position.DepartmentID,
		position.Title,
		position.IsOpen,
		position.CreatedAt,
		position.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create position: %w", err)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) GetPositionByID(ctx context.Context, positionID uuid.UUID) (*employee.Position, error) {
	stmt, ok := r.getStmt("get_position_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_position_by_id")
	}

	rows, err := stmt.QueryContext(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanPosition(rows)
	}

	return nil, fmt.Errorf("position not found: %s", positionID)
}

func (r *EmployeeRepositoryImpl) GetPositionsByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*employee.Position, error) {
	query := `
		SELECT position_id, company_id, department_id, title, is_open, 
		       created_at, updated_at
		FROM positions 
		WHERE company_id = $1 AND department_id = $2
		ORDER BY created_at DESC`

	rows, err := r.client.Query(ctx, query, companyID, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by department: %w", err)
	}
	defer rows.Close()

	positions := make([]*employee.Position, 0)
	for rows.Next() {
		position, err := r.scanPosition(rows)
		if err != nil {
			r.logger.Warn("Failed to scan position", util.ErrorField(err))
			continue
		}
		positions = append(positions, position)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating positions: %w", err)
	}

	return positions, nil
}

func (r *EmployeeRepositoryImpl) GetOpenPositions(ctx context.Context, companyID uuid.UUID) ([]*employee.Position, error) {
	stmt, ok := r.getStmt("get_open_positions")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_open_positions")
	}

	rows, err := stmt.QueryContext(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get open positions: %w", err)
	}
	defer rows.Close()

	positions := make([]*employee.Position, 0)
	for rows.Next() {
		position, err := r.scanPosition(rows)
		if err != nil {
			r.logger.Warn("Failed to scan open position", util.ErrorField(err))
			continue
		}
		positions = append(positions, position)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating open positions: %w", err)
	}

	return positions, nil
}

func (r *EmployeeRepositoryImpl) UpdatePosition(ctx context.Context, position *employee.Position) error {
	now := time.Now().UTC()
	position.UpdatedAt = now

	query := `
		UPDATE positions SET
			title = $1, is_open = $2, updated_at = $3
		WHERE position_id = $4`

	result, err := r.client.Exec(ctx, query,
		position.Title,
		position.IsOpen,
		position.UpdatedAt,
		position.PositionID,
	)

	if err != nil {
		return fmt.Errorf("failed to update position: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("position not found: %s", position.PositionID)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) DeletePosition(ctx context.Context, positionID uuid.UUID) error {
	query := `DELETE FROM positions WHERE position_id = $1`
	result, err := r.client.Exec(ctx, query, positionID)
	if err != nil {
		return fmt.Errorf("failed to delete position: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("position not found: %s", positionID)
	}

	return nil
}

// ============================================================================
// EMPLOYEE ROLE HISTORY METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateRoleHistory(ctx context.Context, history *employee.EmployeeRoleHistory) error {
	query := `
		INSERT INTO employee_role_history (
			id, user_id, role_id, start_date, end_date, reason
		) VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.client.Exec(ctx, query,
		history.ID,
		history.UserID,
		history.RoleID,
		history.StartDate,
		history.EndDate,
		history.Reason,
	)

	if err != nil {
		return fmt.Errorf("failed to create role history: %w", err)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) GetRoleHistoryByID(ctx context.Context, id uuid.UUID) (*employee.EmployeeRoleHistory, error) {
	query := `
		SELECT id, user_id, role_id, start_date, end_date, reason
		FROM employee_role_history 
		WHERE id = $1`

	rows, err := r.client.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get role history: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanRoleHistory(rows)
	}

	return nil, fmt.Errorf("role history not found: %s", id)
}

func (r *EmployeeRepositoryImpl) GetRoleHistoryByUserID(ctx context.Context, userID uuid.UUID) ([]*employee.EmployeeRoleHistory, error) {
	query := `
		SELECT id, user_id, role_id, start_date, end_date, reason
		FROM employee_role_history 
		WHERE user_id = $1
		ORDER BY start_date DESC`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role history by user ID: %w", err)
	}
	defer rows.Close()

	histories := make([]*employee.EmployeeRoleHistory, 0)
	for rows.Next() {
		history, err := r.scanRoleHistory(rows)
		if err != nil {
			r.logger.Warn("Failed to scan role history", util.ErrorField(err))
			continue
		}
		histories = append(histories, history)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role histories: %w", err)
	}

	return histories, nil
}

func (r *EmployeeRepositoryImpl) UpdateRoleHistory(ctx context.Context, history *employee.EmployeeRoleHistory) error {
	query := `
		UPDATE employee_role_history SET
			role_id = $1, start_date = $2, end_date = $3, reason = $4
		WHERE id = $5`

	result, err := r.client.Exec(ctx, query,
		history.RoleID,
		history.StartDate,
		history.EndDate,
		history.Reason,
		history.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update role history: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("role history not found: %s", history.ID)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) EndRoleAssignment(ctx context.Context, userID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE employee_role_history 
		SET end_date = $1
		WHERE user_id = $2 AND end_date IS NULL`

	result, err := r.client.Exec(ctx, query, endDate, userID)
	if err != nil {
		return fmt.Errorf("failed to end role assignment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("no active role assignment found for user: %s", userID)
	}

	return nil
}

// ============================================================================
// BATCH OPERATIONS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateEmployeeProfilesBatch(ctx context.Context, profiles []*employee.EmployeeProfile) error {
	if len(profiles) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO employee_profiles (
			employee_profile_id, user_id, company_id, date_of_birth, gender, 
			marital_status, nationality, employment_type, employment_status, 
			probation_end_date, confirmation_date, job_title, grade, cost_center, 
			tax_id, social_security_id, email, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, profile := range profiles {
		_, err := stmt.ExecContext(ctx,
			profile.EmployeeProfileID,
			profile.UserID,
			profile.CompanyID,
			profile.DateOfBirth,
			profile.Gender,
			profile.MaritalStatus,
			profile.Nationality,
			profile.EmploymentType,
			profile.EmploymentStatus,
			profile.ProbationEndDate,
			profile.ConfirmationDate,
			profile.JobTitle,
			profile.Grade,
			profile.CostCenter,
			profile.TaxID,
			profile.SocialSecurityID,
			profile.Email,
			profile.CreatedAt,
			profile.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert employee profile %s: %w", profile.EmployeeProfileID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info("Batch employee profiles creation completed",
		util.Int("profiles_created", len(profiles)))
	return nil
}

func (r *EmployeeRepositoryImpl) CreateDepartmentHistoryBatch(ctx context.Context, histories []*employee.EmployeeDepartmentHistory) error {
	if len(histories) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO employee_department_history (
			id, user_id, company_id, department_id, start_date, end_date, 
			change_reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, history := range histories {
		_, err := stmt.ExecContext(ctx,
			history.ID,
			history.UserID,
			history.CompanyID,
			history.DepartmentID,
			history.StartDate,
			history.EndDate,
			history.ChangeReason,
			history.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert department history %s: %w", history.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

func (r *EmployeeRepositoryImpl) CreateEmployeeDocumentsBatch(ctx context.Context, documents []*employee.EmployeeDocument) error {
	if len(documents) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO employee_documents (
			document_id, user_id, company_id, document_type, document_name, 
			document_object_key, mime_type, is_confidential, uploaded_by, uploaded_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, doc := range documents {
		_, err := stmt.ExecContext(ctx,
			doc.DocumentID,
			doc.UserID,
			doc.CompanyID,
			doc.DocumentType,
			doc.DocumentName,
			doc.DocumentObjectKey,
			doc.MimeType,
			doc.IsConfidential,
			doc.UploadedBy,
			doc.UploadedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert employee document %s: %w", doc.DocumentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

// ============================================================================
// SEARCH AND ANALYTICS METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) GetEmployeeStatsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total employees
	var totalEmployees int
	err := r.client.QueryRow(ctx,
		"SELECT COUNT(*) FROM employee_profiles WHERE company_id = $1",
		companyID).Scan(&totalEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get total employees: %w", err)
	}
	stats["total_employees"] = totalEmployees

	// Active employees
	var activeEmployees int
	err = r.client.QueryRow(ctx,
		"SELECT COUNT(*) FROM employee_profiles WHERE company_id = $1 AND employment_status = 'active'",
		companyID).Scan(&activeEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees: %w", err)
	}
	stats["active_employees"] = activeEmployees

	// Employees by employment type
	query := `
		SELECT employment_type, COUNT(*) as count
		FROM employee_profiles 
		WHERE company_id = $1 
		GROUP BY employment_type`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employees by employment type: %w", err)
	}
	defer rows.Close()

	employmentTypeStats := make(map[string]int)
	for rows.Next() {
		var empType string
		var count int
		if err := rows.Scan(&empType, &count); err != nil {
			continue
		}
		employmentTypeStats[empType] = count
	}
	stats["employment_type_stats"] = employmentTypeStats

	// Gender distribution
	genderQuery := `
		SELECT gender, COUNT(*) as count
		FROM employee_profiles 
		WHERE company_id = $1 AND gender IS NOT NULL
		GROUP BY gender`

	genderRows, err := r.client.Query(ctx, genderQuery, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gender distribution: %w", err)
	}
	defer genderRows.Close()

	genderStats := make(map[string]int)
	for genderRows.Next() {
		var gender string
		var count int
		if err := genderRows.Scan(&gender, &count); err != nil {
			continue
		}
		genderStats[gender] = count
	}
	stats["gender_stats"] = genderStats

	return stats, nil
}

func (r *EmployeeRepositoryImpl) GetEmployeeCountByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]int, error) {
	query := `
		SELECT d.department_id, COUNT(DISTINCT edh.user_id) as employee_count
		FROM departments d
		LEFT JOIN employee_department_history edh ON d.department_id = edh.department_id 
			AND edh.end_date IS NULL
		WHERE d.company_id = $1
		GROUP BY d.department_id`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee count by department: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]int)
	for rows.Next() {
		var departmentID uuid.UUID
		var count int
		if err := rows.Scan(&departmentID, &count); err != nil {
			continue
		}
		result[departmentID] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department counts: %w", err)
	}

	return result, nil
}

func (r *EmployeeRepositoryImpl) GetActiveEmployeesByDateRange(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*employee.EmployeeProfile, error) {
	query := `
		SELECT 
			ep.employee_profile_id, ep.user_id, ep.company_id, ep.date_of_birth, ep.gender, 
			ep.marital_status, ep.nationality, ep.employment_type, ep.employment_status, 
			ep.probation_end_date, ep.confirmation_date, ep.job_title, ep.grade, ep.cost_center, 
			ep.tax_id, ep.social_security_id, ep.email, ep.created_at, ep.updated_at
		FROM employee_profiles ep
		WHERE ep.company_id = $1 
			AND ep.employment_status = 'active'
			AND ep.created_at BETWEEN $2 AND $3
		ORDER BY ep.created_at DESC`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees by date range: %w", err)
	}
	defer rows.Close()

	profiles := make([]*employee.EmployeeProfile, 0)
	for rows.Next() {
		profile, err := r.scanEmployeeProfile(rows)
		if err != nil {
			r.logger.Warn("Failed to scan employee profile", util.ErrorField(err))
			continue
		}
		profiles = append(profiles, profile)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating employee profiles: %w", err)
	}

	return profiles, nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) scanEmployeeProfile(rows *sql.Rows) (*employee.EmployeeProfile, error) {
	var profile employee.EmployeeProfile
	var dateOfBirth, probationEndDate, confirmationDate sql.NullTime
	var gender, maritalStatus, nationality, employmentType, employmentStatus,
		jobTitle, grade, costCenter, taxID, socialSecurityID, email sql.NullString

	err := rows.Scan(
		&profile.EmployeeProfileID,
		&profile.UserID,
		&profile.CompanyID,
		&dateOfBirth,
		&gender,
		&maritalStatus,
		&nationality,
		&employmentType,
		&employmentStatus,
		&probationEndDate,
		&confirmationDate,
		&jobTitle,
		&grade,
		&costCenter,
		&taxID,
		&socialSecurityID,
		&email,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if dateOfBirth.Valid {
		profile.DateOfBirth = &dateOfBirth.Time
	}
	if gender.Valid {
		profile.Gender = &gender.String
	}
	if maritalStatus.Valid {
		profile.MaritalStatus = &maritalStatus.String
	}
	if nationality.Valid {
		profile.Nationality = &nationality.String
	}
	if employmentType.Valid {
		profile.EmploymentType = &employmentType.String
	}
	if employmentStatus.Valid {
		profile.EmploymentStatus = &employmentStatus.String
	}
	if probationEndDate.Valid {
		profile.ProbationEndDate = &probationEndDate.Time
	}
	if confirmationDate.Valid {
		profile.ConfirmationDate = &confirmationDate.Time
	}
	if jobTitle.Valid {
		profile.JobTitle = &jobTitle.String
	}
	if grade.Valid {
		profile.Grade = &grade.String
	}
	if costCenter.Valid {
		profile.CostCenter = &costCenter.String
	}
	if taxID.Valid {
		profile.TaxID = &taxID.String
	}
	if socialSecurityID.Valid {
		profile.SocialSecurityID = &socialSecurityID.String
	}
	if email.Valid {
		profile.Email = &email.String
	}

	return &profile, nil
}

func (r *EmployeeRepositoryImpl) scanDepartmentHistory(rows *sql.Rows) (*employee.EmployeeDepartmentHistory, error) {
	var history employee.EmployeeDepartmentHistory
	var endDate sql.NullTime
	var changeReason sql.NullString

	err := rows.Scan(
		&history.ID,
		&history.UserID,
		&history.CompanyID,
		&history.DepartmentID,
		&history.StartDate,
		&endDate,
		&changeReason,
		&history.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if endDate.Valid {
		history.EndDate = &endDate.Time
	}
	if changeReason.Valid {
		history.ChangeReason = &changeReason.String
	}

	return &history, nil
}

func (r *EmployeeRepositoryImpl) scanEmployeeDocument(rows *sql.Rows) (*employee.EmployeeDocument, error) {
	var doc employee.EmployeeDocument
	var documentType, documentName, mimeType sql.NullString
	var uploadedBy sql.NullString // Scan as string first
	var uploadedAt sql.NullTime

	err := rows.Scan(
		&doc.DocumentID,
		&doc.UserID,
		&doc.CompanyID,
		&documentType,
		&documentName,
		&doc.DocumentObjectKey,
		&mimeType,
		&doc.IsConfidential,
		&uploadedBy, // Changed to string
		&uploadedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if documentType.Valid {
		doc.DocumentType = &documentType.String
	}
	if documentName.Valid {
		doc.DocumentName = &documentName.String
	}
	if mimeType.Valid {
		doc.MimeType = &mimeType.String
	}
	if uploadedBy.Valid && uploadedBy.String != "" {
		// Parse the UUID string to *uuid.UUID
		parsedUUID, err := uuid.Parse(uploadedBy.String)
		if err != nil {
			r.logger.Warn("Failed to parse uploaded_by UUID",
				util.String("uploaded_by", uploadedBy.String),
				util.ErrorField(err))
			doc.UploadedBy = nil
		} else {
			doc.UploadedBy = &parsedUUID
		}
	} else {
		doc.UploadedBy = nil
	}
	if uploadedAt.Valid {
		doc.UploadedAt = &uploadedAt.Time
	}

	return &doc, nil
}

func (r *EmployeeRepositoryImpl) scanEmployeeExit(rows *sql.Rows) (*employee.EmployeeExit, error) {
	var exit employee.EmployeeExit

	var exitDate sql.NullTime
	var exitReason sql.NullString
	var eligibleForRehire sql.NullBool
	var exitState string
	var enforcedAt sql.NullTime
	var enforcedBy sql.NullString

	err := rows.Scan(
		&exit.ExitID,
		&exit.UserID,
		&exit.CompanyID,
		&exitDate,
		&exitReason,
		&eligibleForRehire,
		&exitState,
		&enforcedAt,
		&enforcedBy,
		&exit.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Nullable mappings
	if exitDate.Valid {
		exit.ExitDate = &exitDate.Time
	}
	if exitReason.Valid {
		exit.ExitReason = &exitReason.String
	}
	if eligibleForRehire.Valid {
		exit.EligibleForRehire = &eligibleForRehire.Bool
	}
	if enforcedAt.Valid {
		exit.EnforcedAt = &enforcedAt.Time
	}
	if enforcedBy.Valid && enforcedBy.String != "" {
		if id, err := uuid.Parse(enforcedBy.String); err == nil {
			exit.EnforcedBy = &id
		}
	}

	exit.ExitState = exitState

	return &exit, nil
}

func (r *EmployeeRepositoryImpl) scanPosition(rows *sql.Rows) (*employee.Position, error) {
	var position employee.Position
	var title sql.NullString

	err := rows.Scan(
		&position.PositionID,
		&position.CompanyID,
		&position.DepartmentID,
		&title,
		&position.IsOpen,
		&position.CreatedAt,
		&position.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if title.Valid {
		position.Title = &title.String
	}

	return &position, nil
}

func (r *EmployeeRepositoryImpl) scanRoleHistory(rows *sql.Rows) (*employee.EmployeeRoleHistory, error) {
	var history employee.EmployeeRoleHistory
	var startDate, endDate sql.NullTime
	var reason sql.NullString

	err := rows.Scan(
		&history.ID,
		&history.UserID,
		&history.RoleID,
		&startDate,
		&endDate,
		&reason,
	)

	if err != nil {
		return nil, err
	}

	if startDate.Valid {
		history.StartDate = &startDate.Time
	}
	if endDate.Valid {
		history.EndDate = &endDate.Time
	}
	if reason.Valid {
		history.Reason = &reason.String
	}

	return &history, nil
}

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

func (r *EmployeeRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_employee_profile_by_id": `
			SELECT employee_profile_id, user_id, company_id, date_of_birth, gender, 
			       marital_status, nationality, employment_type, employment_status, 
			       probation_end_date, confirmation_date, job_title, grade, cost_center, 
			       tax_id, social_security_id, email, created_at, updated_at
			FROM employee_profiles WHERE employee_profile_id = $1`,

		"get_employee_profile_by_user_id": `
			SELECT employee_profile_id, user_id, company_id, date_of_birth, gender, 
			       marital_status, nationality, employment_type, employment_status, 
			       probation_end_date, confirmation_date, job_title, grade, cost_center, 
			       tax_id, social_security_id, email, created_at, updated_at
			FROM employee_profiles WHERE user_id = $1 AND company_id = $2`,

		"get_department_history_by_user_id": `
			SELECT id, user_id, company_id, department_id, start_date, end_date, 
			       change_reason, created_at
			FROM employee_department_history 
			WHERE user_id = $1 AND company_id = $2
			ORDER BY start_date DESC`,

		"get_employee_documents_by_user_id": `
			SELECT document_id, user_id, company_id, document_type, document_name, 
			       document_object_key, mime_type, is_confidential, uploaded_by, uploaded_at
			FROM employee_documents 
			WHERE user_id = $1 AND company_id = $2 AND is_confidential = false
			ORDER BY uploaded_at DESC`,

		"get_position_by_id": `
			SELECT position_id, company_id, department_id, title, is_open, 
			       created_at, updated_at
			FROM positions WHERE position_id = $1`,

		"get_open_positions": `
			SELECT position_id, company_id, department_id, title, is_open, 
			       created_at, updated_at
			FROM positions WHERE company_id = $1 AND is_open = true
			ORDER BY created_at DESC`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}

		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("HR employee prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *EmployeeRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (r *EmployeeRepositoryImpl) HealthCheck(ctx context.Context) error {
	// Simple query to check database connectivity
	query := `SELECT 1 FROM employee_profiles LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("HR employee repository health check failed: %w", err)
	}
	return nil
}

func (r *EmployeeRepositoryImpl) UserExists(
	ctx context.Context,
	userID uuid.UUID,
) (bool, error) {
	var exists bool

	query := `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE user_id = $1
		)
	`

	err := r.client.QueryRow(ctx, query, userID).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *EmployeeRepositoryImpl) IsUserEmployeeOfCompany(
	ctx context.Context,
	userID, companyID uuid.UUID,
) (bool, error) {
	var exists bool

	query := `
		SELECT EXISTS (
			SELECT 1
			FROM company_employees
			WHERE user_id = $1
			  AND company_id = $2
			  AND is_active = true
		)
	`

	err := r.client.QueryRow(ctx, query, userID, companyID).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *EmployeeRepositoryImpl) GetActiveDepartmentAssignment(
	ctx context.Context,
	userID uuid.UUID,
) (*employee.EmployeeDepartmentHistory, error) {

	query := `
		SELECT 
			id,
			user_id,
			company_id,
			department_id,
			start_date,
			end_date,
			change_reason,
			created_at
		FROM employee_department_history
		WHERE user_id = $1
		  AND end_date IS NULL
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, userID)

	var history employee.EmployeeDepartmentHistory
	err := row.Scan(
		&history.ID,
		&history.UserID,
		&history.CompanyID,
		&history.DepartmentID,
		&history.StartDate,
		&history.EndDate,
		&history.ChangeReason,
		&history.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no active department assignment found")
		}
		return nil, fmt.Errorf("failed to get active department assignment: %w", err)
	}

	return &history, nil
}

func (r *EmployeeRepositoryImpl) EnforceScheduledEmployeeExits(
	ctx context.Context,
	effectiveDate time.Time,
	enforcedBy uuid.UUID,
) (int, error) {

	query := `SELECT enforce_scheduled_employee_exits($1, $2)`
	var count int

	err := r.client.QueryRow(ctx, query, effectiveDate, enforcedBy).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (r *EmployeeRepositoryImpl) RehireEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		UPDATE employee_exit
		SET exit_state = 'rehired'
		WHERE company_id = $1
		  AND user_id = $2
		  AND exit_state = 'effective'
	`, companyID, userID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE company_employees
		SET is_active = true
		WHERE company_id = $1
		  AND user_id = $2
	`, companyID, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}
