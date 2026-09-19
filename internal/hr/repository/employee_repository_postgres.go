package repository

import (
	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/models/employee"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
)

// NOTE ON LOCATION SCOPING
//
// The `locationID *uuid.UUID` parameter accepted by the methods below is a
// strict equality filter against company_employees.primary_location_id.
//
// Whether a caller should pass a non-nil locationID at all is a policy
// decision that belongs in the SERVICE layer, based on the requesting user's
// location_access_scope:
//
//   - scope = 'ALL'      -> pass nil (no location filter; see whole company)
//   - scope = 'PRIMARY'  -> pass the requester's primary_location_id
//   - scope = 'SELECTED' -> caller must invoke once per selected location
//                           (this repository API only accepts one UUID)
//
// The repository does NOT read company_employees.location_access_scope. That
// column describes the scope of the *row's* employee when they act as a
// requester; it is not a filter dimension for listing other employees.
//
// NOTE ON ENCRYPTION
//
// This repository persists encrypted PII columns as opaque values and does
// NOT call the encryption manager. Encryption / decryption / hashing live in
// the SERVICE layer, mirroring the UserRepository + UserService split.
//
// All PII is persisted EXCLUSIVELY in the *_encrypted siblings. The plaintext
// PII columns (email, tax_id, social_security_id, date_of_birth, nationality,
// marital_status) have been dropped from the schema. `gender` remains
// plaintext because it is not part of the encryption scheme.

// EmployeeRepositoryImpl handles PostgreSQL HR employee operations
type EmployeeRepositoryImpl struct {
	client    *client.PostgresClient
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

// NewEmployeeRepository creates a new PostgreSQL employee repository
func NewEmployeeRepository(postgresClient *client.PostgresClient) EmployeeRepository {
	repo := &EmployeeRepositoryImpl{
		client:    postgresClient,
		stmtCache: make(map[string]*sql.Stmt),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// employeeProfileColumns is the canonical SELECT list for employee_profiles.
// Every query that feeds scanEmployeeProfile must use this exact column order.
// All PII is read from the *_encrypted siblings; the plaintext PII columns
// have been dropped. `gender` stays plaintext.
const employeeProfileColumns = `
	ep.employee_profile_id, ep.user_id, ep.company_id,
	ep.gender,
	ep.employment_type, ep.employment_status,
	ep.probation_end_date, ep.confirmation_date,
	ep.job_title, ep.grade, ep.cost_center, ep.cost_center_id,
	ep.email_hash, ep.email_encrypted, ep.email_encrypted_dek, ep.email_key_id,
	ep.tax_id_encrypted, ep.tax_id_encrypted_dek, ep.tax_id_key_id,
	ep.social_security_id_encrypted, ep.social_security_id_encrypted_dek, ep.social_security_id_key_id,
	ep.date_of_birth_encrypted, ep.date_of_birth_encrypted_dek, ep.date_of_birth_key_id,
	ep.nationality_encrypted, ep.nationality_encrypted_dek, ep.nationality_key_id,
	ep.marital_status_encrypted, ep.marital_status_encrypted_dek, ep.marital_status_key_id,
	ep.created_at, ep.updated_at`

// ============================================================================
// EMPLOYEE PROFILE METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error {
	// Fetch position title (kept for compatibility with prior behavior).
	var jobTitle *string
	queryGetTitle := `
		SELECT p.title
		FROM company_employees ce
		LEFT JOIN positions p ON ce.position_id = p.position_id
		WHERE ce.user_id = $1 AND ce.company_id = $2
		LIMIT 1`

	err := r.client.QueryRow(ctx, queryGetTitle, profile.UserID, profile.CompanyID).Scan(&jobTitle)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("failed to get position title: %w", err)
	}
	profile.JobTitle = jobTitle

	// Plaintext PII columns have been dropped. Only the encrypted siblings
	// are written; gender stays plaintext.
	query := `
		INSERT INTO employee_profiles (
			employee_profile_id, user_id, company_id,
			gender,
			employment_type, employment_status,
			probation_end_date, confirmation_date,
			job_title, grade, cost_center, cost_center_id,
			email_hash, email_encrypted, email_encrypted_dek, email_key_id,
			tax_id_encrypted, tax_id_encrypted_dek, tax_id_key_id,
			social_security_id_encrypted, social_security_id_encrypted_dek, social_security_id_key_id,
			date_of_birth_encrypted, date_of_birth_encrypted_dek, date_of_birth_key_id,
			nationality_encrypted, nationality_encrypted_dek, nationality_key_id,
			marital_status_encrypted, marital_status_encrypted_dek, marital_status_key_id,
			created_at, updated_at
		) VALUES (
			$1,$2,$3,
			$4,
			$5,$6,
			$7,$8,
			$9,$10,$11,$12,
			$13,$14,$15,$16,
			$17,$18,$19,
			$20,$21,$22,
			$23,$24,$25,
			$26,$27,$28,
			$29,$30,$31,
			$32,$33
		)`

	_, err = r.client.Exec(ctx, query,
		profile.EmployeeProfileID, profile.UserID, profile.CompanyID,
		profile.Gender,
		profile.EmploymentType, profile.EmploymentStatus,
		profile.ProbationEndDate, profile.ConfirmationDate,
		jobTitle, profile.Grade, profile.CostCenter, profile.CostCenterID,
		profile.EmailHash, profile.EmailEncrypted, profile.EmailEncryptedDEK, profile.EmailKeyID,
		profile.TaxIDEncrypted, profile.TaxIDEncryptedDEK, profile.TaxIDKeyID,
		profile.SocialSecurityIDEncrypted, profile.SocialSecurityIDEncryptedDEK, profile.SocialSecurityIDKeyID,
		profile.DateOfBirthEncrypted, profile.DateOfBirthEncryptedDEK, profile.DateOfBirthKeyID,
		profile.NationalityEncrypted, profile.NationalityEncryptedDEK, profile.NationalityKeyID,
		profile.MaritalStatusEncrypted, profile.MaritalStatusEncryptedDEK, profile.MaritalStatusKeyID,
		profile.CreatedAt, profile.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create employee profile: %w", err)
	}
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
	return nil, hrErrors.ErrEmployeeProfileNotFound
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
	return nil, hrErrors.ErrEmployeeProfileNotFound
}

func (r *EmployeeRepositoryImpl) UpdateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error {
	now := time.Now().UTC()
	profile.UpdatedAt = now

	query := `
		UPDATE employee_profiles SET
			gender = $1,
			employment_type = $2, employment_status = $3,
			probation_end_date = $4, confirmation_date = $5,
			job_title = $6, grade = $7, cost_center = $8, cost_center_id = $9,
			email_hash = $10,
			email_encrypted = $11, email_encrypted_dek = $12, email_key_id = $13,
			tax_id_encrypted = $14, tax_id_encrypted_dek = $15, tax_id_key_id = $16,
			social_security_id_encrypted = $17, social_security_id_encrypted_dek = $18, social_security_id_key_id = $19,
			date_of_birth_encrypted = $20, date_of_birth_encrypted_dek = $21, date_of_birth_key_id = $22,
			nationality_encrypted = $23, nationality_encrypted_dek = $24, nationality_key_id = $25,
			marital_status_encrypted = $26, marital_status_encrypted_dek = $27, marital_status_key_id = $28,
			updated_at = $29
		WHERE employee_profile_id = $30`

	result, err := r.client.Exec(ctx, query,
		profile.Gender,
		profile.EmploymentType, profile.EmploymentStatus,
		profile.ProbationEndDate, profile.ConfirmationDate,
		profile.JobTitle, profile.Grade, profile.CostCenter, profile.CostCenterID,
		profile.EmailHash,
		profile.EmailEncrypted, profile.EmailEncryptedDEK, profile.EmailKeyID,
		profile.TaxIDEncrypted, profile.TaxIDEncryptedDEK, profile.TaxIDKeyID,
		profile.SocialSecurityIDEncrypted, profile.SocialSecurityIDEncryptedDEK, profile.SocialSecurityIDKeyID,
		profile.DateOfBirthEncrypted, profile.DateOfBirthEncryptedDEK, profile.DateOfBirthKeyID,
		profile.NationalityEncrypted, profile.NationalityEncryptedDEK, profile.NationalityKeyID,
		profile.MaritalStatusEncrypted, profile.MaritalStatusEncryptedDEK, profile.MaritalStatusKeyID,
		profile.UpdatedAt,
		profile.EmployeeProfileID,
	)
	if err != nil {
		return fmt.Errorf("failed to update employee profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeProfileNotFound
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
		return hrErrors.ErrEmployeeProfileNotFound
	}
	return nil
}

func (r *EmployeeRepositoryImpl) ListEmployeeProfilesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	limit, offset int,
) ([]*employee.EmployeeProfile, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `
		SELECT COUNT(*)
		FROM employee_profiles ep
		INNER JOIN company_employees ce
			ON ce.user_id = ep.user_id
		   AND ce.company_id = ep.company_id
		WHERE ep.company_id = $1
		  AND ($2::uuid IS NULL OR ce.primary_location_id = $2)`
	err := r.client.QueryRow(ctx, countQuery, companyID, locationID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count employee profiles: %w", err)
	}

	query := `
		SELECT ` + employeeProfileColumns + `
		FROM employee_profiles ep
		INNER JOIN company_employees ce
			ON ce.user_id = ep.user_id
		   AND ce.company_id = ep.company_id
		WHERE ep.company_id = $1
		  AND ($2::uuid IS NULL OR ce.primary_location_id = $2)
		ORDER BY ep.created_at DESC
		LIMIT $3 OFFSET $4`

	rows, err := r.client.Query(ctx, query, companyID, locationID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list employee profiles: %w", err)
	}
	defer rows.Close()

	profiles := make([]*employee.EmployeeProfile, 0, limit)
	for rows.Next() {
		profile, err := r.scanEmployeeProfile(rows)
		if err != nil {
			continue
		}
		profiles = append(profiles, profile)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating employee profiles: %w", err)
	}
	return profiles, totalCount, nil
}

func (r *EmployeeRepositoryImpl) SearchEmployeeProfiles(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	filters map[string]interface{},
	limit, offset int,
) ([]*employee.EmployeeProfile, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"ep.company_id = $1"}
	params := []interface{}{companyID}
	paramCount := 2

	if locationID != nil {
		conditions = append(conditions, fmt.Sprintf(
			"ep.user_id IN (SELECT user_id FROM company_employees WHERE company_id = $1 AND primary_location_id = $%d)",
			paramCount))
		params = append(params, *locationID)
		paramCount++
	}

	for field, value := range filters {
		switch field {
		case "employment_type":
			conditions = append(conditions, fmt.Sprintf("ep.employment_type = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "employment_status":
			conditions = append(conditions, fmt.Sprintf("ep.employment_status = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "department_id":
			conditions = append(conditions, fmt.Sprintf(
				"ep.user_id IN (SELECT user_id FROM employee_department_history WHERE department_id = $%d AND end_date IS NULL)",
				paramCount))
			params = append(params, value)
			paramCount++
		case "job_title":
			conditions = append(conditions, fmt.Sprintf("ep.job_title ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "gender":
			conditions = append(conditions, fmt.Sprintf("ep.gender = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "hire_date_from":
			conditions = append(conditions, fmt.Sprintf("ep.created_at >= $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "email_hash":
			// Service hashes the plaintext search term and passes the digest.
			conditions = append(conditions, fmt.Sprintf("ep.email_hash = $%d", paramCount))
			params = append(params, value)
			paramCount++
		}
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM employee_profiles ep %s", whereClause)
	var totalCount int
	if err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	searchQuery := fmt.Sprintf(`
		SELECT `+employeeProfileColumns+`
		FROM employee_profiles ep
		%s
		ORDER BY ep.created_at DESC
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
		history.ID, history.UserID, history.CompanyID, history.DepartmentID,
		history.StartDate, history.EndDate, history.ChangeReason, history.CreatedAt)
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
	return nil, hrErrors.ErrDepartmentHistoryNotFound
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
		history.DepartmentID, history.StartDate, history.EndDate,
		history.ChangeReason, history.ID)
	if err != nil {
		return fmt.Errorf("failed to update department history: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrDepartmentHistoryNotFound
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
		return hrErrors.ErrNoActiveDepartmentAssignment
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
		doc.DocumentID, doc.UserID, doc.CompanyID, doc.DocumentType, doc.DocumentName,
		doc.DocumentObjectKey, doc.MimeType, doc.IsConfidential, doc.UploadedBy, doc.UploadedAt)
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
	return nil, hrErrors.ErrEmployeeDocumentNotFound
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
		doc.DocumentType, doc.DocumentName, doc.IsConfidential, doc.DocumentID)
	if err != nil {
		return fmt.Errorf("failed to update employee document: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeDocumentNotFound
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
		return hrErrors.ErrEmployeeDocumentNotFound
	}
	return nil
}

// ============================================================================
// EMPLOYEE EXIT METHODS
// ============================================================================

func (r *EmployeeRepositoryImpl) CreateEmployeeExit(ctx context.Context, exit *employee.EmployeeExit) error {
	query := `
	INSERT INTO employee_exit (
		exit_id, user_id, company_id, exit_date, exit_reason,
		eligible_for_rehire, exit_state, created_at
	)
	VALUES ($1, $2, $3, $4, $5, $6, 'scheduled', $7)
	`

	_, err := r.client.Exec(ctx, query,
		exit.ExitID, exit.UserID, exit.CompanyID, exit.ExitDate,
		exit.ExitReason, exit.EligibleForRehire, exit.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create employee exit: %w", err)
	}
	return nil
}

func (r *EmployeeRepositoryImpl) GetEmployeeExitByID(ctx context.Context, exitID uuid.UUID) (*employee.EmployeeExit, error) {
	query := `
		SELECT exit_id, user_id, company_id, exit_date, exit_reason,
		       eligible_for_rehire, exit_state, enforced_at, enforced_by, created_at
		FROM employee_exit
		WHERE exit_id = $1`

	rows, err := r.client.Query(ctx, query, exitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee exit record: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeExit(rows)
	}
	return nil, hrErrors.ErrEmployeeExitNotFound
}

func (r *EmployeeRepositoryImpl) GetEmployeeExitByUserID(ctx context.Context, userID, companyID uuid.UUID) (*employee.EmployeeExit, error) {
	query := `
		SELECT exit_id, user_id, company_id, exit_date, exit_reason,
		       eligible_for_rehire, exit_state, enforced_at, enforced_by, created_at
		FROM employee_exit
		WHERE user_id = $1 AND company_id = $2`

	rows, err := r.client.Query(ctx, query, userID, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee exit record by user ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanEmployeeExit(rows)
	}
	return nil, hrErrors.ErrEmployeeExitNotFound
}

func (r *EmployeeRepositoryImpl) UpdateEmployeeExit(ctx context.Context, exit *employee.EmployeeExit) error {
	query := `
		UPDATE employee_exit SET
			exit_date = $1, exit_reason = $2, eligible_for_rehire = $3
		WHERE exit_id = $4`

	result, err := r.client.Exec(ctx, query,
		exit.ExitDate, exit.ExitReason, exit.EligibleForRehire, exit.ExitID)
	if err != nil {
		return fmt.Errorf("failed to update employee exit record: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeExitNotFound
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
			created_at, updated_at, work_center_code
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.client.Exec(ctx, query,
		position.PositionID, position.CompanyID, position.DepartmentID,
		position.Title, position.IsOpen, position.CreatedAt,
		position.UpdatedAt, position.WorkCenterCode)
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
	return nil, hrErrors.ErrPositionNotFound
}

func (r *EmployeeRepositoryImpl) GetPositionsByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*employee.Position, error) {
	query := `
		SELECT position_id, company_id, department_id, title, is_open,
		       created_at, updated_at, work_center_code
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
			title = $1, is_open = $2, updated_at = $3, work_center_code = $4
		WHERE position_id = $5`

	result, err := r.client.Exec(ctx, query,
		position.Title, position.IsOpen, position.UpdatedAt,
		position.WorkCenterCode, position.PositionID)
	if err != nil {
		return fmt.Errorf("failed to update position: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrPositionNotFound
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
		return hrErrors.ErrPositionNotFound
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
		history.ID, history.UserID, history.RoleID,
		history.StartDate, history.EndDate, history.Reason)
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
	return nil, hrErrors.ErrRoleHistoryNotFound
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
		history.RoleID, history.StartDate, history.EndDate, history.Reason, history.ID)
	if err != nil {
		return fmt.Errorf("failed to update role history: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrRoleHistoryNotFound
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
		return hrErrors.ErrRoleHistoryNotFound
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

	// Plaintext PII columns have been dropped. Only encrypted siblings and
	// non-PII (gender, employment_*, cost_center*) are written.
	query := `
		INSERT INTO employee_profiles (
			employee_profile_id, user_id, company_id,
			gender,
			employment_type, employment_status,
			probation_end_date, confirmation_date,
			job_title, grade, cost_center, cost_center_id,
			email_hash, email_encrypted, email_encrypted_dek, email_key_id,
			tax_id_encrypted, tax_id_encrypted_dek, tax_id_key_id,
			social_security_id_encrypted, social_security_id_encrypted_dek, social_security_id_key_id,
			date_of_birth_encrypted, date_of_birth_encrypted_dek, date_of_birth_key_id,
			nationality_encrypted, nationality_encrypted_dek, nationality_key_id,
			marital_status_encrypted, marital_status_encrypted_dek, marital_status_key_id,
			created_at, updated_at
		) VALUES (
			$1,$2,$3, $4,
			$5,$6, $7,$8,
			$9,$10,$11,$12,
			$13,$14,$15,$16,
			$17,$18,$19, $20,$21,$22,
			$23,$24,$25, $26,$27,$28,
			$29,$30,$31, $32,$33)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, profile := range profiles {
		_, err := stmt.ExecContext(ctx,
			profile.EmployeeProfileID, profile.UserID, profile.CompanyID,
			profile.Gender,
			profile.EmploymentType, profile.EmploymentStatus,
			profile.ProbationEndDate, profile.ConfirmationDate,
			profile.JobTitle, profile.Grade, profile.CostCenter, profile.CostCenterID,
			profile.EmailHash, profile.EmailEncrypted, profile.EmailEncryptedDEK, profile.EmailKeyID,
			profile.TaxIDEncrypted, profile.TaxIDEncryptedDEK, profile.TaxIDKeyID,
			profile.SocialSecurityIDEncrypted, profile.SocialSecurityIDEncryptedDEK, profile.SocialSecurityIDKeyID,
			profile.DateOfBirthEncrypted, profile.DateOfBirthEncryptedDEK, profile.DateOfBirthKeyID,
			profile.NationalityEncrypted, profile.NationalityEncryptedDEK, profile.NationalityKeyID,
			profile.MaritalStatusEncrypted, profile.MaritalStatusEncryptedDEK, profile.MaritalStatusKeyID,
			profile.CreatedAt, profile.UpdatedAt)
		if err != nil {
			return fmt.Errorf("failed to insert employee profile %s: %w", profile.EmployeeProfileID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}
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
			history.ID, history.UserID, history.CompanyID, history.DepartmentID,
			history.StartDate, history.EndDate, history.ChangeReason, history.CreatedAt)
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
			doc.DocumentID, doc.UserID, doc.CompanyID, doc.DocumentType,
			doc.DocumentName, doc.DocumentObjectKey, doc.MimeType,
			doc.IsConfidential, doc.UploadedBy, doc.UploadedAt)
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

func (r *EmployeeRepositoryImpl) GetEmployeeStatsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	const baseFrom = `
		FROM employee_profiles ep
		INNER JOIN company_employees ce
			ON ce.user_id = ep.user_id
		   AND ce.company_id = ep.company_id
		WHERE ep.company_id = $1
		  AND ($2::uuid IS NULL OR ce.primary_location_id = $2)`

	var totalEmployees int
	err := r.client.QueryRow(ctx,
		"SELECT COUNT(*) "+baseFrom, companyID, locationID).Scan(&totalEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get total employees: %w", err)
	}
	stats["total_employees"] = totalEmployees

	var activeEmployees int
	err = r.client.QueryRow(ctx,
		"SELECT COUNT(*) "+baseFrom+" AND ep.employment_status = 'active'",
		companyID, locationID).Scan(&activeEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees: %w", err)
	}
	stats["active_employees"] = activeEmployees

	rows, err := r.client.Query(ctx,
		"SELECT ep.employment_type, COUNT(*) "+baseFrom+" GROUP BY ep.employment_type",
		companyID, locationID)
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

	genderRows, err := r.client.Query(ctx,
		"SELECT ep.gender, COUNT(*) "+baseFrom+" AND ep.gender IS NOT NULL GROUP BY ep.gender",
		companyID, locationID)
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

func (r *EmployeeRepositoryImpl) GetActiveEmployeesByDateRange(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	startDate, endDate time.Time,
) ([]*employee.EmployeeProfile, error) {
	query := `
		SELECT ` + employeeProfileColumns + `
		FROM employee_profiles ep
		INNER JOIN company_employees ce
			ON ce.user_id = ep.user_id
		   AND ce.company_id = ep.company_id
		WHERE ep.company_id = $1
		  AND ($2::uuid IS NULL OR ce.primary_location_id = $2)
		  AND ep.employment_status = 'active'
		  AND ep.created_at BETWEEN $3 AND $4
		ORDER BY ep.created_at DESC`

	rows, err := r.client.Query(ctx, query, companyID, locationID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees by date range: %w", err)
	}
	defer rows.Close()

	profiles := make([]*employee.EmployeeProfile, 0)
	for rows.Next() {
		profile, err := r.scanEmployeeProfile(rows)
		if err != nil {
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
// HELPER METHODS — SCANNERS
// ============================================================================

func (r *EmployeeRepositoryImpl) scanEmployeeProfile(rows *sql.Rows) (*employee.EmployeeProfile, error) {
	var profile employee.EmployeeProfile

	// Non-PII / plaintext columns that still exist.
	var probationEndDate, confirmationDate sql.NullTime
	var gender, employmentType, employmentStatus,
		jobTitle, grade, costCenter sql.NullString
	var costCenterID uuid.NullUUID

	// Encrypted siblings — opaque to this layer.
	var (
		emailHash sql.NullString
		emailCT   []byte
		emailDEK  sql.NullString
		emailKey  uuid.NullUUID

		taxCT  []byte
		taxDEK sql.NullString
		taxKey uuid.NullUUID

		ssnCT  []byte
		ssnDEK sql.NullString
		ssnKey uuid.NullUUID

		dobCT  []byte
		dobDEK sql.NullString
		dobKey uuid.NullUUID

		natCT  []byte
		natDEK sql.NullString
		natKey uuid.NullUUID

		marCT  []byte
		marDEK sql.NullString
		marKey uuid.NullUUID
	)

	err := rows.Scan(
		&profile.EmployeeProfileID, &profile.UserID, &profile.CompanyID,
		&gender,
		&employmentType, &employmentStatus,
		&probationEndDate, &confirmationDate,
		&jobTitle, &grade, &costCenter, &costCenterID,
		&emailHash, &emailCT, &emailDEK, &emailKey,
		&taxCT, &taxDEK, &taxKey,
		&ssnCT, &ssnDEK, &ssnKey,
		&dobCT, &dobDEK, &dobKey,
		&natCT, &natDEK, &natKey,
		&marCT, &marDEK, &marKey,
		&profile.CreatedAt, &profile.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Non-PII / plaintext assignments. PII plaintext is populated later by
	// the service layer after decrypting the *Encrypted siblings.
	if gender.Valid {
		profile.Gender = &gender.String
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
	if costCenterID.Valid {
		profile.CostCenterID = &costCenterID.UUID
	}

	// Encrypted siblings — opaque to this layer.
	if emailHash.Valid {
		profile.EmailHash = &emailHash.String
	}
	if len(emailCT) > 0 {
		profile.EmailEncrypted = emailCT
	}
	if emailDEK.Valid {
		profile.EmailEncryptedDEK = &emailDEK.String
	}
	if emailKey.Valid {
		id := emailKey.UUID
		profile.EmailKeyID = &id
	}

	if len(taxCT) > 0 {
		profile.TaxIDEncrypted = taxCT
	}
	if taxDEK.Valid {
		profile.TaxIDEncryptedDEK = &taxDEK.String
	}
	if taxKey.Valid {
		id := taxKey.UUID
		profile.TaxIDKeyID = &id
	}

	if len(ssnCT) > 0 {
		profile.SocialSecurityIDEncrypted = ssnCT
	}
	if ssnDEK.Valid {
		profile.SocialSecurityIDEncryptedDEK = &ssnDEK.String
	}
	if ssnKey.Valid {
		id := ssnKey.UUID
		profile.SocialSecurityIDKeyID = &id
	}

	if len(dobCT) > 0 {
		profile.DateOfBirthEncrypted = dobCT
	}
	if dobDEK.Valid {
		profile.DateOfBirthEncryptedDEK = &dobDEK.String
	}
	if dobKey.Valid {
		id := dobKey.UUID
		profile.DateOfBirthKeyID = &id
	}

	if len(natCT) > 0 {
		profile.NationalityEncrypted = natCT
	}
	if natDEK.Valid {
		profile.NationalityEncryptedDEK = &natDEK.String
	}
	if natKey.Valid {
		id := natKey.UUID
		profile.NationalityKeyID = &id
	}

	if len(marCT) > 0 {
		profile.MaritalStatusEncrypted = marCT
	}
	if marDEK.Valid {
		profile.MaritalStatusEncryptedDEK = &marDEK.String
	}
	if marKey.Valid {
		id := marKey.UUID
		profile.MaritalStatusKeyID = &id
	}

	return &profile, nil
}

func (r *EmployeeRepositoryImpl) scanDepartmentHistory(rows *sql.Rows) (*employee.EmployeeDepartmentHistory, error) {
	var history employee.EmployeeDepartmentHistory
	var endDate sql.NullTime
	var changeReason sql.NullString

	err := rows.Scan(
		&history.ID, &history.UserID, &history.CompanyID,
		&history.DepartmentID, &history.StartDate, &endDate,
		&changeReason, &history.CreatedAt)
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
	var uploadedBy sql.NullString
	var uploadedAt sql.NullTime

	err := rows.Scan(
		&doc.DocumentID, &doc.UserID, &doc.CompanyID,
		&documentType, &documentName, &doc.DocumentObjectKey,
		&mimeType, &doc.IsConfidential, &uploadedBy, &uploadedAt)
	if err != nil {
		return nil, err
	}

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
		if parsedUUID, err := uuid.Parse(uploadedBy.String); err == nil {
			doc.UploadedBy = &parsedUUID
		}
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
		&exit.ExitID, &exit.UserID, &exit.CompanyID,
		&exitDate, &exitReason, &eligibleForRehire,
		&exitState, &enforcedAt, &enforcedBy, &exit.CreatedAt)
	if err != nil {
		return nil, err
	}

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
	var workCenterCode sql.NullString

	err := rows.Scan(
		&position.PositionID, &position.CompanyID, &position.DepartmentID,
		&title, &position.IsOpen, &position.CreatedAt,
		&position.UpdatedAt, &workCenterCode)
	if err != nil {
		return nil, err
	}
	if title.Valid {
		position.Title = &title.String
	}
	if workCenterCode.Valid {
		position.WorkCenterCode = &workCenterCode.String
	}
	return &position, nil
}

func (r *EmployeeRepositoryImpl) scanRoleHistory(rows *sql.Rows) (*employee.EmployeeRoleHistory, error) {
	var history employee.EmployeeRoleHistory
	var startDate, endDate sql.NullTime
	var reason sql.NullString

	err := rows.Scan(
		&history.ID, &history.UserID, &history.RoleID,
		&startDate, &endDate, &reason)
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
			SELECT ` + employeeProfileColumns + `
			FROM employee_profiles ep
			WHERE ep.employee_profile_id = $1`,

		"get_employee_profile_by_user_id": `
			SELECT ` + employeeProfileColumns + `
			FROM employee_profiles ep
			WHERE ep.user_id = $1 AND ep.company_id = $2`,

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
			       created_at, updated_at, work_center_code
			FROM positions WHERE position_id = $1`,

		"get_open_positions": `
			SELECT position_id, company_id, department_id, title, is_open,
			       created_at, updated_at, work_center_code
			FROM positions WHERE company_id = $1 AND is_open = true
			ORDER BY created_at DESC`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			continue
		}
		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}
}

func (r *EmployeeRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

// ============================================================================
// HEALTH CHECK + SMALL HELPERS
// ============================================================================

func (r *EmployeeRepositoryImpl) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, `SELECT 1 FROM employee_profiles LIMIT 1`)
	if err != nil {
		return fmt.Errorf("HR employee repository health check failed: %w", err)
	}
	return nil
}

func (r *EmployeeRepositoryImpl) UserExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.client.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE user_id = $1)`, userID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (r *EmployeeRepositoryImpl) IsUserEmployeeOfCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM company_employees
			WHERE user_id = $1 AND company_id = $2 AND is_active = true
		)`
	err := r.client.QueryRow(ctx, query, userID, companyID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (r *EmployeeRepositoryImpl) GetActiveDepartmentAssignment(ctx context.Context, userID uuid.UUID) (*employee.EmployeeDepartmentHistory, error) {
	query := `
		SELECT id, user_id, company_id, department_id, start_date, end_date,
		       change_reason, created_at
		FROM employee_department_history
		WHERE user_id = $1 AND end_date IS NULL
		LIMIT 1`

	row := r.client.QueryRow(ctx, query, userID)
	var history employee.EmployeeDepartmentHistory
	err := row.Scan(
		&history.ID, &history.UserID, &history.CompanyID, &history.DepartmentID,
		&history.StartDate, &history.EndDate, &history.ChangeReason, &history.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrNoActiveDepartmentAssignment
		}
		return nil, fmt.Errorf("failed to get active department assignment: %w", err)
	}
	return &history, nil
}

func (r *EmployeeRepositoryImpl) EnforceScheduledEmployeeExits(ctx context.Context, effectiveDate time.Time, enforcedBy uuid.UUID) (int, error) {
	var count int
	err := r.client.QueryRow(ctx, `SELECT enforce_scheduled_employee_exits($1, $2)`, effectiveDate, enforcedBy).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (r *EmployeeRepositoryImpl) RehireEmployee(ctx context.Context, companyID, userID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(ctx, `
		UPDATE employee_exit
		SET exit_state = 'rehired'
		WHERE company_id = $1 AND user_id = $2 AND exit_state = 'effective'`,
		companyID, userID); err != nil {
		return err
	}

	if _, err = tx.ExecContext(ctx, `
		UPDATE company_employees
		SET is_active = true
		WHERE company_id = $1 AND user_id = $2`,
		companyID, userID); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *EmployeeRepositoryImpl) GetActiveUsersByPosition(ctx context.Context, positionID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.client.Query(ctx, `
		SELECT ce.user_id FROM company_employees ce
		WHERE ce.position_id = $1 AND ce.is_active = true`, positionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, id)
	}
	return userIDs, nil
}

func (r *EmployeeRepositoryImpl) GetActiveEmployeesByCompany(ctx context.Context, companyID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.client.Query(ctx, `
		SELECT ce.user_id FROM company_employees ce
		WHERE ce.company_id = $1 AND ce.is_active = true`, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, id)
	}
	return userIDs, nil
}

func (r *EmployeeRepositoryImpl) GetCompanyEmployeeByUserID(ctx context.Context, userID uuid.UUID) (*employee.CompanyEmployee, error) {
	query := `
		SELECT company_id, user_id, employee_id, role_id, hire_date, is_active,
		       reports_to, position_id, created_at, updated_at
		FROM company_employees
		WHERE user_id = $1`

	row := r.client.QueryRow(ctx, query, userID)
	var ce employee.CompanyEmployee
	var reportsTo *uuid.UUID
	var positionID *uuid.UUID

	err := row.Scan(
		&ce.CompanyID, &ce.UserID, &ce.EmployeeID, &ce.RoleID,
		&ce.HireDate, &ce.IsActive, &reportsTo, &positionID,
		&ce.CreatedAt, &ce.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrCompanyEmployeeNotFound
		}
		return nil, err
	}
	if reportsTo != nil {
		ce.ReportsTo = reportsTo
	}
	if positionID != nil {
		ce.PositionID = positionID
	}
	return &ce, nil
}

func (r *EmployeeRepositoryImpl) GetEmploymentLocationID(ctx context.Context, companyID, userID uuid.UUID) (*uuid.UUID, error) {
	var locID sql.NullString
	query := `
		SELECT primary_location_id
		FROM company_employees
		WHERE company_id = $1 AND user_id = $2`

	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(&locID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrCompanyEmployeeNotFound
		}
		return nil, fmt.Errorf("failed to get employment location: %w", err)
	}
	if !locID.Valid || locID.String == "" {
		return nil, nil
	}
	id, err := uuid.Parse(locID.String)
	if err != nil {
		return nil, fmt.Errorf("invalid primary_location_id in DB: %w", err)
	}
	return &id, nil
}

// ============================================================================
// TX VARIANTS
// ============================================================================

// CreateEmployeeProfileTx inserts an employee_profiles row using the caller's
// transaction. Used by the atomic hire flow (CompanyService.AddMember) so the
// profile insert commits together with the user + roster inserts.
//
// ON CONFLICT (company_id, user_id) DO NOTHING makes the method re-entrant.
//
// Callers must populate the *Encrypted / *EncryptedDEK / *KeyID / EmailHash
// fields on the model before calling this method — encryption is done in the
// service layer. Plaintext PII columns have been dropped from the schema.
func (r *EmployeeRepositoryImpl) CreateEmployeeProfileTx(
	ctx context.Context,
	tx *sql.Tx,
	profile *employee.EmployeeProfile,
) error {
	const query = `
		INSERT INTO employee_profiles (
			employee_profile_id, user_id, company_id,
			gender,
			employment_type, employment_status,
			probation_end_date, confirmation_date,
			job_title, grade, cost_center, cost_center_id,
			email_hash, email_encrypted, email_encrypted_dek, email_key_id,
			tax_id_encrypted, tax_id_encrypted_dek, tax_id_key_id,
			social_security_id_encrypted, social_security_id_encrypted_dek, social_security_id_key_id,
			date_of_birth_encrypted, date_of_birth_encrypted_dek, date_of_birth_key_id,
			nationality_encrypted, nationality_encrypted_dek, nationality_key_id,
			marital_status_encrypted, marital_status_encrypted_dek, marital_status_key_id,
			created_at, updated_at
		) VALUES (
			$1,$2,$3, $4,
			$5,$6, $7,$8,
			$9,$10,$11,$12,
			$13,$14,$15,$16,
			$17,$18,$19, $20,$21,$22,
			$23,$24,$25, $26,$27,$28,
			$29,$30,$31, $32,$33
		)
		ON CONFLICT (company_id, user_id) DO NOTHING`

	_, err := tx.ExecContext(ctx, query,
		profile.EmployeeProfileID, profile.UserID, profile.CompanyID,
		profile.Gender,
		profile.EmploymentType, profile.EmploymentStatus,
		profile.ProbationEndDate, profile.ConfirmationDate,
		profile.JobTitle, profile.Grade, profile.CostCenter, profile.CostCenterID,
		profile.EmailHash, profile.EmailEncrypted, profile.EmailEncryptedDEK, profile.EmailKeyID,
		profile.TaxIDEncrypted, profile.TaxIDEncryptedDEK, profile.TaxIDKeyID,
		profile.SocialSecurityIDEncrypted, profile.SocialSecurityIDEncryptedDEK, profile.SocialSecurityIDKeyID,
		profile.DateOfBirthEncrypted, profile.DateOfBirthEncryptedDEK, profile.DateOfBirthKeyID,
		profile.NationalityEncrypted, profile.NationalityEncryptedDEK, profile.NationalityKeyID,
		profile.MaritalStatusEncrypted, profile.MaritalStatusEncryptedDEK, profile.MaritalStatusKeyID,
		profile.CreatedAt, profile.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create employee profile (tx): %w", err)
	}
	return nil
}
