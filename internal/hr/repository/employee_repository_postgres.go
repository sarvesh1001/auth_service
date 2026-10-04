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

	"github.com/jackc/pgtype" // for UUIDArray

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"
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
//
// NOTE ON POSITIONS
//
// A position is a "seat". Its definition (title, is_schedulable,
// attendance_required, overtime_allowed) lives on the `jobs` table and is
// referenced by positions.job_id. The seat itself carries location_id and
// work_center_code. Title is title_override (nullable) — the effective
// display title is COALESCE(p.title_override, j.job_title).
//
// The repository returns *employee.Position (base) for CRUD and
// *employee.PositionView (joined) for reads that need the job fields.

// EmployeeRepositoryImpl handles PostgreSQL HR employee operations
type EmployeeRepositoryImpl struct {
	client    *client.PostgresClient
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
	logger    *zap.Logger
}

// NewEmployeeRepository creates a new PostgreSQL employee repository
func NewEmployeeRepository(postgresClient *client.PostgresClient) EmployeeRepository {
	repo := &EmployeeRepositoryImpl{
		client:    postgresClient,
		stmtCache: make(map[string]*sql.Stmt),
		logger:    zap.L(),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// employeeProfileColumns is the canonical SELECT list for employee_profiles.
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
	// Fetch the effective position title (title_override > job_title).
	var jobTitle *string
	queryGetTitle := `
			SELECT COALESCE(p.title_override, j.job_title)
			FROM company_employees ce
			LEFT JOIN positions p ON ce.position_id = p.position_id
			LEFT JOIN jobs      j ON j.job_id        = p.job_id
			WHERE ce.user_id = $1 AND ce.company_id = $2
			LIMIT 1`

	err := r.client.QueryRow(ctx, queryGetTitle, profile.UserID, profile.CompanyID).Scan(&jobTitle)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("failed to get position title: %w", err)
	}
	profile.JobTitle = jobTitle

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
	const query = `
			INSERT INTO positions (
				position_id, company_id, department_id,
				job_id, location_id, title_override,
				is_open, work_center_code,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.client.Exec(ctx, query,
		position.PositionID,
		position.CompanyID,
		position.DepartmentID,
		position.JobID,
		position.LocationID,
		position.TitleOverride,
		position.IsOpen,
		position.WorkCenterCode,
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
	return nil, hrErrors.ErrPositionNotFound
}

func (r *EmployeeRepositoryImpl) GetPositionsByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*employee.Position, error) {
	const query = `
			SELECT
				position_id, company_id, department_id,
				job_id, location_id, title_override,
				is_open, work_center_code,
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

	const query = `
			UPDATE positions SET
				department_id    = $1,
				job_id           = $2,
				location_id      = $3,
				title_override   = $4,
				is_open          = $5,
				work_center_code = $6,
				updated_at       = $7
			WHERE position_id = $8`

	result, err := r.client.Exec(ctx, query,
		position.DepartmentID,
		position.JobID,
		position.LocationID,
		position.TitleOverride,
		position.IsOpen,
		position.WorkCenterCode,
		position.UpdatedAt,
		position.PositionID,
	)
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

	// ── total ─────────────────────────────────────────────────────
	var totalEmployees int
	if err := r.client.QueryRow(ctx,
		"SELECT COUNT(*) "+baseFrom, companyID, locationID,
	).Scan(&totalEmployees); err != nil {
		return nil, fmt.Errorf("failed to get total employees: %w", err)
	}
	stats["total_employees"] = totalEmployees

	// ── active (backwards-compat single counter) ──────────────────
	var activeEmployees int
	if err := r.client.QueryRow(ctx,
		"SELECT COUNT(*) "+baseFrom+" AND ep.employment_status = 'active'",
		companyID, locationID,
	).Scan(&activeEmployees); err != nil {
		return nil, fmt.Errorf("failed to get active employees: %w", err)
	}
	stats["active_employees"] = activeEmployees

	// ── NEW: per-status breakdown ─────────────────────────────────
	//
	// One GROUP BY gives every lifecycle counter the UI needs
	// (active, probation, notice, on_hold, terminated, resigned).
	// Statuses with zero rows do not appear in the result set, so we
	// pre-seed the map with all known values → the JSON always
	// carries a full key set and the client never sees undefined.
	byStatus := map[string]int{
		"active":     0,
		"probation":  0,
		"notice":     0,
		"on_hold":    0,
		"terminated": 0,
		"resigned":   0,
		"inactive":   0, // legacy bucket, harmless to include
	}
	statusRows, err := r.client.Query(ctx, `
		SELECT COALESCE(ep.employment_status, 'unknown') AS status,
		       COUNT(*)
		`+baseFrom+`
		GROUP BY ep.employment_status
	`, companyID, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employees by status: %w", err)
	}
	defer statusRows.Close()

	for statusRows.Next() {
		var status string
		var count int
		if err := statusRows.Scan(&status, &count); err != nil {
			continue
		}
		byStatus[status] = count
	}
	if err := statusRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating status counts: %w", err)
	}
	stats["by_status"] = byStatus

	// ── employment_type breakdown (unchanged) ─────────────────────
	typeRows, err := r.client.Query(ctx,
		"SELECT ep.employment_type, COUNT(*) "+baseFrom+" GROUP BY ep.employment_type",
		companyID, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employees by employment type: %w", err)
	}
	defer typeRows.Close()

	employmentTypeStats := make(map[string]int)
	for typeRows.Next() {
		var empType sql.NullString
		var count int
		if err := typeRows.Scan(&empType, &count); err != nil {
			continue
		}
		if empType.Valid {
			employmentTypeStats[empType.String] = count
		}
	}
	stats["employment_type_stats"] = employmentTypeStats

	// ── gender breakdown (unchanged) ──────────────────────────────
	genderRows, err := r.client.Query(ctx,
		"SELECT ep.gender, COUNT(*) "+baseFrom+" AND ep.gender IS NOT NULL GROUP BY ep.gender",
		companyID, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gender distribution: %w", err)
	}
	defer genderRows.Close()

	genderStats := make(map[string]int)
	for genderRows.Next() {
		var gender sql.NullString
		var count int
		if err := genderRows.Scan(&gender, &count); err != nil {
			continue
		}
		if gender.Valid {
			genderStats[gender.String] = count
		}
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

	var probationEndDate, confirmationDate sql.NullTime
	var gender, employmentType, employmentStatus,
		jobTitle, grade, costCenter sql.NullString
	var costCenterID uuid.NullUUID

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

// scanPosition mirrors the canonical positions SELECT list:
//
//	position_id, company_id, department_id,
//	job_id, location_id, title_override,
//	is_open, work_center_code,
//	created_at, updated_at
func (r *EmployeeRepositoryImpl) scanPosition(rows *sql.Rows) (*employee.Position, error) {
	var position employee.Position
	var locationID uuid.NullUUID
	var titleOverride sql.NullString
	var workCenterCode sql.NullString

	err := rows.Scan(
		&position.PositionID,
		&position.CompanyID,
		&position.DepartmentID,
		&position.JobID,
		&locationID,
		&titleOverride,
		&position.IsOpen,
		&workCenterCode,
		&position.CreatedAt,
		&position.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if locationID.Valid {
		id := locationID.UUID
		position.LocationID = &id
	}
	if titleOverride.Valid {
		position.TitleOverride = &titleOverride.String
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
		"get_position_view_by_id": `
		SELECT
			p.position_id, p.company_id, p.department_id,
			p.job_id, p.location_id, p.title_override,
			p.is_open, p.work_center_code,
			p.created_at, p.updated_at,
			j.job_code, j.job_title,
			j.is_schedulable, j.attendance_required, j.overtime_allowed,
			d.department_name,
			l.location_name,
			wc.name AS work_center_name
		FROM positions p
		INNER JOIN jobs j ON j.job_id = p.job_id
		LEFT JOIN departments d ON d.department_id = p.department_id
		LEFT JOIN locations l ON l.location_id = p.location_id
		LEFT JOIN attendance.work_centers wc
			ON wc.company_id = p.company_id
			AND wc.work_center_code = p.work_center_code
		WHERE p.position_id = $1`,
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
				SELECT
					position_id, company_id, department_id,
					job_id, location_id, title_override,
					is_open, work_center_code,
					created_at, updated_at
				FROM positions WHERE position_id = $1`,

		"get_open_positions": `
				SELECT
					position_id, company_id, department_id,
					job_id, location_id, title_override,
					is_open, work_center_code,
					created_at, updated_at
				FROM positions
				WHERE company_id = $1 AND is_open = true
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

// ============================================================================
// SEARCH + HYDRATE (location-scoped; encryption-agnostic)
// ============================================================================

func toUUIDArray(ids []uuid.UUID) pgtype.UUIDArray {
	if len(ids) == 0 {
		return pgtype.UUIDArray{Status: pgtype.Null}
	}
	arr := pgtype.UUIDArray{
		Elements: make([]pgtype.UUID, len(ids)),
		Status:   pgtype.Present,
	}
	for i, id := range ids {
		arr.Elements[i] = pgtype.UUID{
			Bytes:  [16]byte(id),
			Status: pgtype.Present,
		}
	}
	return arr
}

func (r *EmployeeRepositoryImpl) SearchEmployeeIDs(
	ctx context.Context,
	companyID uuid.UUID,
	query string,
	locationIDs []uuid.UUID,
	limit, offset int,
) ([]uuid.UUID, error) {
	startTime := time.Now()

	logger := r.logger
	if logger == nil {
		logger = zap.L()
	}

	if limit <= 0 || limit > 500 {
		limit = 30
	}
	if offset < 0 {
		offset = 0
	}

	trimmed := strings.TrimSpace(query)

	var qArg interface{}
	if trimmed == "" {
		qArg = nil
	} else {
		qArg = query
	}

	locArg := toUUIDArrayLiteral(locationIDs)

	logger.Info("repo.SearchEmployeeIDs entry",
		zap.String("company_id", companyID.String()),
		zap.String("query_raw", query),
		zap.String("query_trimmed", trimmed),
		zap.Int("query_len_trimmed", len(trimmed)),
		zap.Bool("query_arg_is_nil", qArg == nil),
		zap.Int("location_ids_count", len(locationIDs)),
		zap.Bool("location_arg_is_null", locArg == nil),
		zap.Int("limit", limit),
		zap.Int("offset", offset),
	)

	const sqlQuery = `
			SELECT user_id
			FROM search_company_employee_ids($1, $2, $3::uuid[], $4, $5)`

	rows, err := r.client.Query(ctx, sqlQuery, companyID, qArg, locArg, limit, offset)
	if err != nil {
		logger.Error("repo.SearchEmployeeIDs: query failed",
			zap.String("company_id", companyID.String()),
			zap.String("query_trimmed", trimmed),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to search company employee ids: %w", err)
	}
	defer rows.Close()

	ids := make([]uuid.UUID, 0, limit)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			logger.Error("repo.SearchEmployeeIDs: scan failed",
				zap.String("company_id", companyID.String()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to scan employee id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		logger.Error("repo.SearchEmployeeIDs: rows.Err",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("error iterating employee ids: %w", err)
	}

	logger.Info("repo.SearchEmployeeIDs success",
		zap.String("company_id", companyID.String()),
		zap.String("query_trimmed", trimmed),
		zap.Int("result_count", len(ids)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return ids, nil
}

func (r *EmployeeRepositoryImpl) GetEmployeeFullDetailsByIDs(
	ctx context.Context,
	companyID uuid.UUID,
	userIDs []uuid.UUID,
	locationIDs []uuid.UUID,
) ([]*employee.EmployeeFullDetailsExt, error) {
	startTime := time.Now()

	logger := r.logger
	if logger == nil {
		logger = zap.L()
	}

	logger.Info("repo.GetEmployeeFullDetailsByIDs entry",
		zap.String("company_id", companyID.String()),
		zap.Int("user_ids_count", len(userIDs)),
		zap.Int("location_ids_count", len(locationIDs)),
	)

	if len(userIDs) == 0 {
		logger.Info("repo.GetEmployeeFullDetailsByIDs: empty userIDs → short-circuit")
		return []*employee.EmployeeFullDetailsExt{}, nil
	}

	userArg := toUUIDArrayLiteral(userIDs)
	locArg := toUUIDArrayLiteral(locationIDs)

	const query = `
			SELECT
				-- company_employees
				ce.company_id, ce.user_id, ce.employee_id, ce.role_id,
				ce.hire_date, ce.is_active, ce.reports_to, ce.position_id,
				ce.primary_location_id, ce.location_access_scope,
				ce.created_at, ce.updated_at,

				-- users (identity + encrypted phone)
				u.username, u.full_name, u.phone_hash,
				u.phone_encrypted, u.phone_encrypted_dek, u.phone_key_id,
				u.created_at, u.last_login,

				-- joined names
				r.role_name,
				COALESCE(p.title_override, j.job_title) AS position_title,
				loc.location_name AS primary_location_name,
				d.department_id   AS department_id,
				d.department_name AS department_name,

				-- employee_profiles (non-PII)
				ep.employee_profile_id, ep.gender, ep.employment_type,
				ep.employment_status, ep.job_title, ep.grade,
				ep.cost_center, ep.cost_center_id,
				ep.probation_end_date, ep.confirmation_date,

				-- resolved cost-center name + code
				cc.cost_center_name, cc.cost_center_code,

				-- employee_profiles (encrypted PII)
				ep.email_hash,
				ep.email_encrypted, ep.email_encrypted_dek, ep.email_key_id,

				ep.tax_id_encrypted, ep.tax_id_encrypted_dek, ep.tax_id_key_id,

				ep.social_security_id_encrypted,
				ep.social_security_id_encrypted_dek,
				ep.social_security_id_key_id,

				ep.date_of_birth_encrypted,
				ep.date_of_birth_encrypted_dek,
				ep.date_of_birth_key_id,

				ep.nationality_encrypted,
				ep.nationality_encrypted_dek,
				ep.nationality_key_id,

				ep.marital_status_encrypted,
				ep.marital_status_encrypted_dek,
				ep.marital_status_key_id,

				ep.created_at AS profile_created_at,
				ep.updated_at AS profile_updated_at

			FROM company_employees ce
			JOIN users u   ON u.user_id = ce.user_id
			JOIN roles r   ON r.role_id = ce.role_id
			LEFT JOIN positions p
				ON p.position_id = ce.position_id
			LEFT JOIN jobs j
				ON j.job_id = p.job_id
			LEFT JOIN locations loc
				ON loc.location_id = ce.primary_location_id
			LEFT JOIN employee_department_history edh
				ON edh.user_id = ce.user_id
			AND edh.company_id = ce.company_id
			AND edh.end_date IS NULL
			LEFT JOIN departments d
				ON d.department_id = edh.department_id
			LEFT JOIN employee_profiles ep
				ON ep.company_id = ce.company_id
			AND ep.user_id = ce.user_id
			LEFT JOIN accounting.cost_centers cc
				ON cc.cost_center_id = ep.cost_center_id
			WHERE ce.company_id = $1
			AND ce.user_id = ANY($2::uuid[])
			AND (
					$3::uuid[] IS NULL
				OR cardinality($3::uuid[]) = 0
				OR ce.primary_location_id = ANY($3::uuid[])
			)`

	rows, err := r.client.Query(ctx, query, companyID, userArg, locArg)
	if err != nil {
		logger.Error("repo.GetEmployeeFullDetailsByIDs: query failed",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to hydrate employee details: %w", err)
	}
	defer rows.Close()

	out := make([]*employee.EmployeeFullDetailsExt, 0, len(userIDs))
	for rows.Next() {
		d, err := scanEmployeeFullDetailsExt(rows)
		if err != nil {
			logger.Error("repo.GetEmployeeFullDetailsByIDs: scan failed",
				zap.String("company_id", companyID.String()),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to scan employee details: %w", err)
		}
		logFullDetailsRowExt(logger, d)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		logger.Error("repo.GetEmployeeFullDetailsByIDs: rows.Err",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("error iterating employee details: %w", err)
	}

	logger.Info("repo.GetEmployeeFullDetailsByIDs success",
		zap.String("company_id", companyID.String()),
		zap.Int("requested", len(userIDs)),
		zap.Int("returned", len(out)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return out, nil
}

func scanEmployeeFullDetailsExt(rows *sql.Rows) (*employee.EmployeeFullDetailsExt, error) {
	var d employee.EmployeeFullDetailsExt

	var rosterCreatedAt, rosterUpdatedAt time.Time
	_ = rosterCreatedAt
	_ = rosterUpdatedAt

	var (
		fullName          sql.NullString
		reportsTo         uuid.NullUUID
		positionID        uuid.NullUUID
		primaryLocationID uuid.NullUUID
		positionTitle     sql.NullString
		primaryLocationNm sql.NullString
		departmentID      uuid.NullUUID
		departmentName    sql.NullString

		employeeProfileID uuid.NullUUID
		gender            sql.NullString
		employmentType    sql.NullString
		employmentStatus  sql.NullString
		jobTitle          sql.NullString
		grade             sql.NullString
		costCenter        sql.NullString

		costCenterID     uuid.NullUUID
		probationEndDate sql.NullTime
		confirmationDate sql.NullTime
		costCenterName   sql.NullString
		costCenterCode   sql.NullString

		lastLogin        sql.NullTime
		profileCreatedAt sql.NullTime
		profileUpdatedAt sql.NullTime

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

	if err := rows.Scan(
		&d.CompanyID, &d.UserID, &d.EmployeeID, &d.RoleID,
		&d.HireDate, &d.IsActive, &reportsTo, &positionID,
		&primaryLocationID, &d.LocationAccessScope,
		&rosterCreatedAt, &rosterUpdatedAt,

		&d.Username, &fullName, &d.PhoneHash,
		&d.PhoneEncrypted, &d.PhoneEncryptedDEK, &d.PhoneKeyID,
		&d.UserCreatedAt, &lastLogin,

		&d.RoleName,
		&positionTitle,
		&primaryLocationNm,
		&departmentID,
		&departmentName,

		&employeeProfileID, &gender, &employmentType,
		&employmentStatus, &jobTitle, &grade,
		&costCenter, &costCenterID,
		&probationEndDate, &confirmationDate,
		&costCenterName, &costCenterCode,

		&emailHash,
		&emailCT, &emailDEK, &emailKey,

		&taxCT, &taxDEK, &taxKey,
		&ssnCT, &ssnDEK, &ssnKey,
		&dobCT, &dobDEK, &dobKey,
		&natCT, &natDEK, &natKey,
		&marCT, &marDEK, &marKey,

		&profileCreatedAt, &profileUpdatedAt,
	); err != nil {
		return nil, err
	}

	if fullName.Valid {
		d.FullName = &fullName.String
	}
	if reportsTo.Valid {
		id := reportsTo.UUID
		d.ReportsTo = &id
	}
	if positionID.Valid {
		id := positionID.UUID
		d.PositionID = &id
	}
	if primaryLocationID.Valid {
		id := primaryLocationID.UUID
		d.PrimaryLocationID = &id
	}
	if positionTitle.Valid {
		d.PositionTitle = &positionTitle.String
	}
	if primaryLocationNm.Valid {
		d.PrimaryLocationName = &primaryLocationNm.String
	}
	if departmentID.Valid {
		id := departmentID.UUID
		d.DepartmentID = &id
	}
	if departmentName.Valid {
		d.DepartmentName = &departmentName.String
	}
	if lastLogin.Valid {
		d.UserLastLogin = &lastLogin.Time
	}
	if employeeProfileID.Valid {
		id := employeeProfileID.UUID
		d.EmployeeProfileID = &id
	}
	if gender.Valid {
		d.Gender = &gender.String
	}
	if employmentType.Valid {
		d.EmploymentType = &employmentType.String
	}
	if employmentStatus.Valid {
		d.EmploymentStatus = &employmentStatus.String
	}
	if jobTitle.Valid {
		d.JobTitle = &jobTitle.String
	}
	if grade.Valid {
		d.Grade = &grade.String
	}
	if costCenter.Valid {
		d.CostCenter = &costCenter.String
	}
	if profileCreatedAt.Valid {
		d.ProfileCreatedAt = &profileCreatedAt.Time
	}
	if profileUpdatedAt.Valid {
		d.ProfileUpdatedAt = &profileUpdatedAt.Time
	}

	if costCenterID.Valid {
		id := costCenterID.UUID
		d.CostCenterID = &id
	}
	if costCenterName.Valid {
		d.CostCenterName = &costCenterName.String
	}
	if costCenterCode.Valid {
		d.CostCenterCode = &costCenterCode.String
	}
	if probationEndDate.Valid {
		d.ProbationEndDate = &probationEndDate.Time
	}
	if confirmationDate.Valid {
		d.ConfirmationDate = &confirmationDate.Time
	}

	if emailHash.Valid {
		d.EmailHash = &emailHash.String
	}
	if len(emailCT) > 0 {
		d.EmailEncrypted = emailCT
	}
	if emailDEK.Valid {
		d.EmailEncryptedDEK = &emailDEK.String
	}
	if emailKey.Valid {
		id := emailKey.UUID
		d.EmailKeyID = &id
	}

	if len(taxCT) > 0 {
		d.TaxIDEncrypted = taxCT
	}
	if taxDEK.Valid {
		d.TaxIDEncryptedDEK = &taxDEK.String
	}
	if taxKey.Valid {
		id := taxKey.UUID
		d.TaxIDKeyID = &id
	}

	if len(ssnCT) > 0 {
		d.SocialSecurityIDEncrypted = ssnCT
	}
	if ssnDEK.Valid {
		d.SocialSecurityIDEncryptedDEK = &ssnDEK.String
	}
	if ssnKey.Valid {
		id := ssnKey.UUID
		d.SocialSecurityIDKeyID = &id
	}

	if len(dobCT) > 0 {
		d.DateOfBirthEncrypted = dobCT
	}
	if dobDEK.Valid {
		d.DateOfBirthEncryptedDEK = &dobDEK.String
	}
	if dobKey.Valid {
		id := dobKey.UUID
		d.DateOfBirthKeyID = &id
	}

	if len(natCT) > 0 {
		d.NationalityEncrypted = natCT
	}
	if natDEK.Valid {
		d.NationalityEncryptedDEK = &natDEK.String
	}
	if natKey.Valid {
		id := natKey.UUID
		d.NationalityKeyID = &id
	}

	if len(marCT) > 0 {
		d.MaritalStatusEncrypted = marCT
	}
	if marDEK.Valid {
		d.MaritalStatusEncryptedDEK = &marDEK.String
	}
	if marKey.Valid {
		id := marKey.UUID
		d.MaritalStatusKeyID = &id
	}

	return &d, nil
}

func toUUIDArrayLiteral(ids []uuid.UUID) interface{} {
	if len(ids) == 0 {
		return nil
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.String()
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func logFullDetailsRowExt(logger *zap.Logger, d *employee.EmployeeFullDetailsExt) {
	if logger == nil || d == nil {
		return
	}

	present := func(p *string) string {
		if p == nil {
			return "nil"
		}
		if *p == "" {
			return "empty"
		}
		return fmt.Sprintf("len=%d", len(*p))
	}
	presentUUID := func(p *uuid.UUID) string {
		if p == nil {
			return "nil"
		}
		return p.String()
	}
	presentTime := func(p *time.Time) string {
		if p == nil {
			return "nil"
		}
		return p.Format(time.RFC3339)
	}
	presentBytes := func(b []byte) string {
		if len(b) == 0 {
			return "empty"
		}
		return fmt.Sprintf("len=%d", len(b))
	}

	logger.Info("repo row — raw from DB",
		zap.String("user_id", d.UserID.String()),
		zap.String("username", d.Username),
		zap.String("full_name", present(d.FullName)),
		zap.String("gender", present(d.Gender)),
		zap.String("employment_type", present(d.EmploymentType)),
		zap.String("employment_status", present(d.EmploymentStatus)),
		zap.String("job_title", present(d.JobTitle)),
		zap.String("grade", present(d.Grade)),
		zap.String("cost_center", present(d.CostCenter)),
		zap.String("cost_center_id", presentUUID(d.CostCenterID)),
		zap.String("cost_center_name", present(d.CostCenterName)),
		zap.String("cost_center_code", present(d.CostCenterCode)),
		zap.String("probation_end_date", presentTime(d.ProbationEndDate)),
		zap.String("confirmation_date", presentTime(d.ConfirmationDate)),

		zap.String("phone_ct", presentBytes(d.PhoneEncrypted)),
		zap.String("phone_dek", d.PhoneEncryptedDEK),
		zap.String("phone_kid", d.PhoneKeyID.String()),

		zap.String("email_ct", presentBytes(d.EmailEncrypted)),
		zap.Any("email_dek", d.EmailEncryptedDEK),
		zap.Any("email_kid", d.EmailKeyID),

		zap.String("tax_ct", presentBytes(d.TaxIDEncrypted)),
		zap.Any("tax_dek", d.TaxIDEncryptedDEK),
		zap.Any("tax_kid", d.TaxIDKeyID),

		zap.String("ssn_ct", presentBytes(d.SocialSecurityIDEncrypted)),
		zap.Any("ssn_dek", d.SocialSecurityIDEncryptedDEK),
		zap.Any("ssn_kid", d.SocialSecurityIDKeyID),

		zap.String("dob_ct", presentBytes(d.DateOfBirthEncrypted)),
		zap.Any("dob_dek", d.DateOfBirthEncryptedDEK),
		zap.Any("dob_kid", d.DateOfBirthKeyID),

		zap.String("nat_ct", presentBytes(d.NationalityEncrypted)),
		zap.Any("nat_dek", d.NationalityEncryptedDEK),
		zap.Any("nat_kid", d.NationalityKeyID),

		zap.String("mar_ct", presentBytes(d.MaritalStatusEncrypted)),
		zap.Any("mar_dek", d.MaritalStatusEncryptedDEK),
		zap.Any("mar_kid", d.MaritalStatusKeyID),
	)
}

func (r *EmployeeRepositoryImpl) UpdateEmployeeProfileTx(
	ctx context.Context,
	tx *sql.Tx,
	profile *employee.EmployeeProfile,
) error {
	profile.UpdatedAt = time.Now().UTC()

	const query = `
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

	res, err := tx.ExecContext(ctx, query,
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
		return fmt.Errorf("failed to update employee profile (tx): %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeProfileNotFound
	}
	return nil
}

func (r *EmployeeRepositoryImpl) GetDueScheduledExits(
	ctx context.Context, effectiveDate time.Time,
) ([]EnforcedExitPair, error) {
	rows, err := r.client.Query(ctx, `
			SELECT company_id, user_id
			FROM employee_exit
			WHERE exit_state = 'scheduled'
			AND exit_date <= $1
		`, effectiveDate)
	if err != nil {
		return nil, fmt.Errorf("get due scheduled exits: %w", err)
	}
	defer rows.Close()

	var out []EnforcedExitPair
	for rows.Next() {
		var p EnforcedExitPair
		if err := rows.Scan(&p.CompanyID, &p.UserID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPositionViewByID returns a joined view: the seat + its job's
// definition + human-readable location & work-center names.
//
// Use this when you need job-level fields (is_schedulable,
// attendance_required, overtime_allowed, job_title) or joined names.
// Use GetPositionByID when you only need the seat row.
func (r *EmployeeRepositoryImpl) GetPositionViewByID(
	ctx context.Context,
	positionID uuid.UUID,
) (*employee.PositionView, error) {
	stmt, ok := r.getStmt("get_position_view_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_position_view_by_id")
	}

	rows, err := stmt.QueryContext(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position view: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanPositionView(rows)
	}
	return nil, hrErrors.ErrPositionNotFound
}

// scanPositionView mirrors the canonical positions-view SELECT list:
//
//	position_id, company_id, department_id,
//	job_id, location_id, title_override,
//	is_open, work_center_code,
//	created_at, updated_at,
//	job_code, job_title,
//	is_schedulable, attendance_required, overtime_allowed,
//	department_name, location_name, work_center_name
func (r *EmployeeRepositoryImpl) scanPositionView(rows *sql.Rows) (*employee.PositionView, error) {
	var pv employee.PositionView
	var locationID uuid.NullUUID
	var titleOverride sql.NullString
	var workCenterCode sql.NullString
	var departmentName sql.NullString
	var locationName sql.NullString
	var workCenterName sql.NullString

	err := rows.Scan(
		&pv.PositionID,
		&pv.CompanyID,
		&pv.DepartmentID,
		&pv.JobID,
		&locationID,
		&titleOverride,
		&pv.IsOpen,
		&workCenterCode,
		&pv.CreatedAt,
		&pv.UpdatedAt,
		&pv.JobCode,
		&pv.JobTitle,
		&pv.IsSchedulable,
		&pv.AttendanceRequired,
		&pv.OvertimeAllowed,
		&departmentName,
		&locationName,
		&workCenterName,
	)
	if err != nil {
		return nil, err
	}
	if locationID.Valid {
		id := locationID.UUID
		pv.LocationID = &id
	}
	if titleOverride.Valid {
		pv.TitleOverride = &titleOverride.String
	}
	if workCenterCode.Valid {
		pv.WorkCenterCode = &workCenterCode.String
	}
	if departmentName.Valid {
		pv.DepartmentName = &departmentName.String
	}
	if locationName.Valid {
		pv.LocationName = &locationName.String
	}
	if workCenterName.Valid {
		pv.WorkCenterName = &workCenterName.String
	}
	return &pv, nil
}

// PositionHasAssignedEmployees returns true when ANY active employee
// currently sits on the given seat. Replaces the paginated
// GetEmployeesByCompany(limit=1) check in CompanyService.DeletePosition,
// which silently missed employees beyond row #1.
func (r *EmployeeRepositoryImpl) PositionHasAssignedEmployees(
	ctx context.Context,
	companyID, positionID uuid.UUID,
) (bool, error) {
	const query = `
			SELECT EXISTS (
				SELECT 1
				FROM company_employees
				WHERE company_id = $1
				AND position_id = $2
				AND is_active = true
			)`
	var exists bool
	if err := r.client.QueryRow(ctx, query, companyID, positionID).Scan(&exists); err != nil {
		return false, fmt.Errorf("position_has_assigned_employees: %w", err)
	}
	return exists, nil
}

// --- attach these methods to the existing impl struct ---

func (r *EmployeeRepositoryImpl) CreateProbation(ctx context.Context, p *employee.EmployeeProbation) error {
	const q = `
			INSERT INTO employee_probation (
				probation_id, company_id, user_id, start_date, end_date,
				extension_count, pay_percentage, status, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW())`
	_, err := r.client.Exec(ctx, q,
		p.ProbationID, p.CompanyID, p.UserID, p.StartDate, p.EndDate,
		p.ExtensionCount, p.PayPercentage, p.Status)
	if err != nil {
		return fmt.Errorf("create probation: %w", err)
	}
	return nil
}

func (r *EmployeeRepositoryImpl) GetActiveProbation(ctx context.Context, companyID, userID uuid.UUID) (*employee.EmployeeProbation, error) {
	const q = `
			SELECT probation_id, company_id, user_id, start_date, end_date,
				extension_count, pay_percentage, status,
				outcome_reason, confirmed_at, confirmed_by, created_at, updated_at
			FROM employee_probation
			WHERE company_id = $1 AND user_id = $2
			AND status IN ('pending','extended')
			LIMIT 1`
	return r.scanProbation(r.client.QueryRow(ctx, q, companyID, userID))
}

func (r *EmployeeRepositoryImpl) UpdateProbationStatus(ctx context.Context, p *employee.EmployeeProbation) error {
	const q = `
			UPDATE employee_probation
			SET status         = $1,
				end_date       = $2,
				extension_count= $3,
				outcome_reason = $4,
				confirmed_at   = $5,
				confirmed_by   = $6,
				updated_at     = NOW()
			WHERE probation_id   = $7`
	res, err := r.client.Exec(ctx, q,
		p.Status, p.EndDate, p.ExtensionCount,
		p.OutcomeReason, p.ConfirmedAt, p.ConfirmedBy, p.ProbationID)
	if err != nil {
		return fmt.Errorf("update probation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return hrErrors.ErrEmployeeProfileNotFound // reuse or add ErrProbationNotFound
	}
	return nil
}

func (r *EmployeeRepositoryImpl) ListProbationsDueOn(ctx context.Context, asOf time.Time) ([]*employee.EmployeeProbation, error) {
	const q = `
			SELECT probation_id, company_id, user_id, start_date, end_date,
				extension_count, pay_percentage, status,
				outcome_reason, confirmed_at, confirmed_by, created_at, updated_at
			FROM employee_probation
			WHERE status IN ('pending','extended')
			AND end_date = $1::date`
	rows, err := r.client.Query(ctx, q, asOf)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*employee.EmployeeProbation
	for rows.Next() {
		p, err := r.scanProbationRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- Notice ----

func (r *EmployeeRepositoryImpl) CreateNotice(ctx context.Context, n *employee.EmployeeNotice) error {
	const q = `
			INSERT INTO employee_notice (
				notice_id, company_id, user_id, start_date, end_date,
				reason, initiated_by, served, pay_percentage, status,
				exit_id, created_at, created_by
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),$12)`
	_, err := r.client.Exec(ctx, q,
		n.NoticeID, n.CompanyID, n.UserID, n.StartDate, n.EndDate,
		n.Reason, n.InitiatedBy, n.Served, n.PayPercentage, n.Status,
		n.ExitID, n.CreatedBy)
	if err != nil {
		return fmt.Errorf("create notice: %w", err)
	}
	return nil
}

func (r *EmployeeRepositoryImpl) GetActiveNotice(ctx context.Context, companyID, userID uuid.UUID) (*employee.EmployeeNotice, error) {
	const q = `
			SELECT notice_id, company_id, user_id, start_date, end_date,
				reason, initiated_by, served, pay_percentage, status,
				exit_id, created_at, created_by
			FROM employee_notice
			WHERE company_id = $1 AND user_id = $2 AND status = 'active'
			LIMIT 1`
	return r.scanNotice(r.client.QueryRow(ctx, q, companyID, userID))
}

func (r *EmployeeRepositoryImpl) UpdateNoticeStatus(ctx context.Context, noticeID uuid.UUID, status string) error {
	_, err := r.client.Exec(ctx,
		`UPDATE employee_notice SET status = $1 WHERE notice_id = $2`,
		status, noticeID)
	return err
}

func (r *EmployeeRepositoryImpl) AttachNoticeToExit(ctx context.Context, noticeID, exitID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`UPDATE employee_notice SET exit_id = $1 WHERE notice_id = $2`,
		exitID, noticeID)
	return err
}

// ---- On hold ----

func (r *EmployeeRepositoryImpl) CreateOnHold(ctx context.Context, h *employee.EmployeeOnHold) error {
	const q = `
			INSERT INTO employee_on_hold (
				on_hold_id, company_id, user_id, start_date, end_date,
				reason, previous_status, pay_percentage, status,
				created_at, created_by
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),$10)`
	_, err := r.client.Exec(ctx, q,
		h.OnHoldID, h.CompanyID, h.UserID, h.StartDate, h.EndDate,
		h.Reason, h.PreviousStatus, h.PayPercentage, h.Status, h.CreatedBy)
	return err
}

func (r *EmployeeRepositoryImpl) GetActiveOnHold(ctx context.Context, companyID, userID uuid.UUID) (*employee.EmployeeOnHold, error) {
	const q = `
			SELECT on_hold_id, company_id, user_id, start_date, end_date,
				reason, previous_status, pay_percentage, status,
				ended_at, ended_by, created_at, created_by
			FROM employee_on_hold
			WHERE company_id = $1 AND user_id = $2 AND status = 'active'
			LIMIT 1`
	row := r.client.QueryRow(ctx, q, companyID, userID)
	var h employee.EmployeeOnHold
	var end, endedAt sql.NullTime
	var endedBy uuid.NullUUID
	var createdBy uuid.NullUUID
	if err := row.Scan(
		&h.OnHoldID, &h.CompanyID, &h.UserID, &h.StartDate, &end,
		&h.Reason, &h.PreviousStatus, &h.PayPercentage, &h.Status,
		&endedAt, &endedBy, &h.CreatedAt, &createdBy,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeProfileNotFound
		}
		return nil, err
	}
	if end.Valid {
		h.EndDate = &end.Time
	}
	if endedAt.Valid {
		h.EndedAt = &endedAt.Time
	}
	if endedBy.Valid {
		id := endedBy.UUID
		h.EndedBy = &id
	}
	if createdBy.Valid {
		id := createdBy.UUID
		h.CreatedBy = &id
	}
	return &h, nil
}

func (r *EmployeeRepositoryImpl) EndOnHoldRow(ctx context.Context, onHoldID, endedBy uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`UPDATE employee_on_hold SET status='ended', ended_at=NOW(), ended_by=$1
			WHERE on_hold_id=$2 AND status='active'`,
		endedBy, onHoldID)
	return err
}

// ---- Scheduled jobs ----

func (r *EmployeeRepositoryImpl) EnqueueScheduledJob(ctx context.Context, j *employee.ScheduledJob) error {
	const q = `
			INSERT INTO hr.scheduled_job (
				job_id, company_id, user_id, job_type, status,
				run_at, attempts, max_attempts, priority, payload
			) VALUES ($1,$2,$3,$4,'queued',$5,0,$6,$7,$8)
			ON CONFLICT (company_id, user_id, job_type)
				WHERE status IN ('queued','processing') AND user_id IS NOT NULL
			DO NOTHING`
	_, err := r.client.Exec(ctx, q,
		j.JobID, j.CompanyID, j.UserID, j.JobType,
		j.RunAt, j.MaxAttempts, j.Priority, j.Payload)
	return err
}

func (r *EmployeeRepositoryImpl) ClaimScheduledJobs(ctx context.Context, workerID string, batch int) ([]*employee.ScheduledJob, error) {
	const q = `
			WITH picked AS (
				SELECT job_id FROM hr.scheduled_job
				WHERE status = 'queued'
				AND run_at <= NOW()
				AND attempts < max_attempts
				ORDER BY priority ASC, run_at ASC
				LIMIT $1
				FOR UPDATE SKIP LOCKED
			)
			UPDATE hr.scheduled_job j
			SET status = 'processing',
				locked_by = $2,
				locked_at = NOW(),
				started_at = COALESCE(j.started_at, NOW()),
				attempts = j.attempts + 1
			FROM picked p
			WHERE j.job_id = p.job_id
			RETURNING j.job_id, j.company_id, j.user_id, j.job_type, j.status,
					j.run_at, j.attempts, j.max_attempts, j.priority,
					j.payload, j.created_at`
	rows, err := r.client.Query(ctx, q, batch, workerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*employee.ScheduledJob
	for rows.Next() {
		var j employee.ScheduledJob
		var uid uuid.NullUUID
		var payload []byte
		if err := rows.Scan(
			&j.JobID, &j.CompanyID, &uid, &j.JobType, &j.Status,
			&j.RunAt, &j.Attempts, &j.MaxAttempts, &j.Priority,
			&payload, &j.CreatedAt,
		); err != nil {
			return nil, err
		}
		if uid.Valid {
			id := uid.UUID
			j.UserID = &id
		}
		j.Payload = payload
		out = append(out, &j)
	}
	return out, rows.Err()
}

func (r *EmployeeRepositoryImpl) CompleteScheduledJob(ctx context.Context, jobID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`UPDATE hr.scheduled_job SET status='completed', completed_at=NOW() WHERE job_id=$1`,
		jobID)
	return err
}

func (r *EmployeeRepositoryImpl) FailScheduledJob(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	_, err := r.client.Exec(ctx,
		`UPDATE hr.scheduled_job
				SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
					error_message = $1,
					locked_by = NULL,
					locked_at = NULL,
					run_at = CASE WHEN attempts >= max_attempts THEN run_at
								ELSE NOW() + INTERVAL '5 minutes' END
			WHERE job_id = $2`,
		errMsg, jobID)
	return err
}

func (r *EmployeeRepositoryImpl) ApplyOnHoldExpiry(ctx context.Context, onHoldID uuid.UUID) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var companyID, userID uuid.UUID
	var prev string
	if err := tx.QueryRowContext(ctx,
		`SELECT company_id, user_id, previous_status
			FROM employee_on_hold
			WHERE on_hold_id = $1 AND status = 'active'
			FOR UPDATE`,
		onHoldID).Scan(&companyID, &userID, &prev); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE employee_on_hold SET status='ended', ended_at=NOW()
			WHERE on_hold_id = $1`, onHoldID); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE employee_profiles SET employment_status = $1, updated_at = NOW()
			WHERE company_id = $2 AND user_id = $3 AND employment_status = 'on_hold'`,
		prev, companyID, userID); err != nil {
		return err
	}

	return tx.Commit()
}

// ---- scanners ----

func (r *EmployeeRepositoryImpl) scanProbation(row *sql.Row) (*employee.EmployeeProbation, error) {
	var p employee.EmployeeProbation
	var outcomeReason sql.NullString
	var confirmedAt sql.NullTime
	var confirmedBy uuid.NullUUID

	if err := row.Scan(
		&p.ProbationID, &p.CompanyID, &p.UserID, &p.StartDate, &p.EndDate,
		&p.ExtensionCount, &p.PayPercentage, &p.Status,
		&outcomeReason, &confirmedAt, &confirmedBy,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeProfileNotFound
		}
		return nil, err
	}
	if outcomeReason.Valid {
		p.OutcomeReason = &outcomeReason.String
	}
	if confirmedAt.Valid {
		p.ConfirmedAt = &confirmedAt.Time
	}
	if confirmedBy.Valid {
		id := confirmedBy.UUID
		p.ConfirmedBy = &id
	}
	return &p, nil
}

func (r *EmployeeRepositoryImpl) scanProbationRows(rows *sql.Rows) (*employee.EmployeeProbation, error) {
	var p employee.EmployeeProbation
	var outcomeReason sql.NullString
	var confirmedAt sql.NullTime
	var confirmedBy uuid.NullUUID
	if err := rows.Scan(
		&p.ProbationID, &p.CompanyID, &p.UserID, &p.StartDate, &p.EndDate,
		&p.ExtensionCount, &p.PayPercentage, &p.Status,
		&outcomeReason, &confirmedAt, &confirmedBy,
		&p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if outcomeReason.Valid {
		p.OutcomeReason = &outcomeReason.String
	}
	if confirmedAt.Valid {
		p.ConfirmedAt = &confirmedAt.Time
	}
	if confirmedBy.Valid {
		id := confirmedBy.UUID
		p.ConfirmedBy = &id
	}
	return &p, nil
}

func (r *EmployeeRepositoryImpl) scanNotice(row *sql.Row) (*employee.EmployeeNotice, error) {
	var n employee.EmployeeNotice
	var reason sql.NullString
	var exitID uuid.NullUUID
	var createdBy uuid.NullUUID
	if err := row.Scan(
		&n.NoticeID, &n.CompanyID, &n.UserID, &n.StartDate, &n.EndDate,
		&reason, &n.InitiatedBy, &n.Served, &n.PayPercentage, &n.Status,
		&exitID, &n.CreatedAt, &createdBy,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeProfileNotFound
		}
		return nil, err
	}
	if reason.Valid {
		n.Reason = &reason.String
	}
	if exitID.Valid {
		id := exitID.UUID
		n.ExitID = &id
	}
	if createdBy.Valid {
		id := createdBy.UUID
		n.CreatedBy = &id
	}
	r.populateNoticeCounts(&n)
	return &n, nil
}

func (r *EmployeeRepositoryImpl) populateNoticeCounts(n *employee.EmployeeNotice) {
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

// CancelScheduledJobs marks every queued/processing job of the given type
// for the given (company, user) as cancelled. Pass userID == nil for the
// company-scoped (user_id IS NULL) jobs. Idempotent: already-terminal rows
// are left alone.
func (r *EmployeeRepositoryImpl) CancelScheduledJobs(
	ctx context.Context, companyID uuid.UUID, userID *uuid.UUID, jobType string,
) error {
	if userID != nil {
		_, err := r.client.Exec(ctx, `
				UPDATE hr.scheduled_job
				SET status       = 'cancelled',
					completed_at = NOW(),
					locked_by    = NULL,
					locked_at    = NULL
				WHERE company_id = $1
				AND user_id    = $2
				AND job_type   = $3
				AND status IN ('queued','processing')`,
			companyID, *userID, jobType)
		if err != nil {
			return fmt.Errorf("cancel scheduled jobs (user): %w", err)
		}
		return nil
	}

	_, err := r.client.Exec(ctx, `
			UPDATE hr.scheduled_job
			SET status       = 'cancelled',
				completed_at = NOW(),
				locked_by    = NULL,
				locked_at    = NULL
			WHERE company_id = $1
			AND user_id IS NULL
			AND job_type   = $2
			AND status IN ('queued','processing')`,
		companyID, jobType)
	if err != nil {
		return fmt.Errorf("cancel scheduled jobs (company): %w", err)
	}
	return nil
}

// CancelEmployeeExit flips a scheduled exit to 'cancelled'. Exits already in
// effective/cancelled/rehired are untouched — this is the inverse of
// enforce_scheduled_employee_exits for the "resignation withdrawn" path.
func (r *EmployeeRepositoryImpl) CancelEmployeeExit(
	ctx context.Context, exitID uuid.UUID,
) error {
	res, err := r.client.Exec(ctx, `
			UPDATE employee_exit
			SET exit_state = 'cancelled'
			WHERE exit_id    = $1
			AND exit_state = 'scheduled'`,
		exitID)
	if err != nil {
		return fmt.Errorf("cancel employee exit: %w", err)
	}
	// Zero rows is fine — the caller (CancelNotice) only reaches here when
	// notice.ExitID was set, and the "already cancelled" case is a no-op.
	_ = res
	return nil
}

// ============================================================================
// REACTIVATE EMPLOYEE
// ============================================================================

// ReactivateEmployee flips a terminated employee back to active.
//
//   - employee_profiles.employment_status   'terminated' -> 'active'
//   - company_employees.is_active           false        -> true
//   - employee_exit.exit_state              'effective'  -> 'rehired'
//
// Runs in a single transaction. Idempotent: if the profile is already
// 'active', returns nil without touching anything. If the profile doesn't
// exist, returns ErrEmployeeProfileNotFound.
//
// Leave entitlements are NOT re-resolved here — the service layer should
// enqueue a resolver job after this succeeds.
func (r *EmployeeRepositoryImpl) ReactivateEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
) error {
	startTime := time.Now()
	logger := r.logger
	if logger == nil {
		logger = zap.L()
	}

	logger.Info("repo.ReactivateEmployee entry",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
	)

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("repo.ReactivateEmployee: begin tx failed", zap.Error(err))
		return fmt.Errorf("reactivate employee: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock the profile row and read current status.
	var currentStatus sql.NullString
	err = tx.QueryRowContext(ctx, `
        SELECT employment_status
          FROM employee_profiles
         WHERE company_id = $1 AND user_id = $2
         FOR UPDATE
    `, companyID, userID).Scan(&currentStatus)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn("repo.ReactivateEmployee: profile not found",
				zap.String("company_id", companyID.String()),
				zap.String("user_id", userID.String()),
			)
			return hrErrors.ErrEmployeeProfileNotFound
		}
		logger.Error("repo.ReactivateEmployee: lock query failed", zap.Error(err))
		return fmt.Errorf("reactivate employee: lock profile: %w", err)
	}

	if currentStatus.Valid && currentStatus.String == "active" {
		logger.Info("repo.ReactivateEmployee: already active, short-circuit",
			zap.String("user_id", userID.String()),
		)
		// Still need to commit/rollback the lock cleanly.
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("reactivate employee: commit noop: %w", err)
		}
		return nil
	}

	// 1. employee_profiles
	res, err := tx.ExecContext(ctx, `
        UPDATE employee_profiles
           SET employment_status = 'active',
               updated_at        = NOW()
         WHERE company_id = $1
           AND user_id    = $2
           AND employment_status <> 'active'
    `, companyID, userID)
	if err != nil {
		logger.Error("repo.ReactivateEmployee: update profile failed", zap.Error(err))
		return fmt.Errorf("reactivate employee: update profile: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Raced with another caller — treat as success if status is now active.
		logger.Info("repo.ReactivateEmployee: profile update affected 0 rows (race?)",
			zap.String("user_id", userID.String()),
		)
	}

	// 2. company_employees — restore the roster row
	_, err = tx.ExecContext(ctx, `
        UPDATE company_employees
           SET is_active  = true,
               updated_at = NOW()
         WHERE company_id = $1
           AND user_id    = $2
    `, companyID, userID)
	if err != nil {
		logger.Error("repo.ReactivateEmployee: update roster failed", zap.Error(err))
		return fmt.Errorf("reactivate employee: update roster: %w", err)
	}

	// 3. employee_exit — mark the most recent effective exit as rehired
	_, err = tx.ExecContext(ctx, `
        UPDATE employee_exit
           SET exit_state = 'rehired'
         WHERE company_id = $1
           AND user_id    = $2
           AND exit_state = 'effective'
    `, companyID, userID)
	if err != nil {
		logger.Error("repo.ReactivateEmployee: update exit failed", zap.Error(err))
		return fmt.Errorf("reactivate employee: update exit: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("repo.ReactivateEmployee: commit failed", zap.Error(err))
		return fmt.Errorf("reactivate employee: commit: %w", err)
	}

	logger.Info("repo.ReactivateEmployee success",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
		zap.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// ============================================================================
// SEARCH BY STATUS (location-scoped)
// ============================================================================

// SearchEmployeeIDsByStatus is the status-aware sibling of SearchEmployeeIDs.
//
// status semantics:
//
//	""      -> no filter (same as calling SearchEmployeeIDs)
//	"all"   -> no filter (explicit)
//	other   -> exact match against employee_profiles.employment_status
//	           (e.g. "terminated", "probation", "notice", "on_leave")
//
// Location scoping is identical to SearchEmployeeIDs — pass nil for "all
// locations", a single-element slice for one location, or multiple for
// "SELECTED" scope.
func (r *EmployeeRepositoryImpl) SearchEmployeeIDsByStatus(
	ctx context.Context,
	companyID uuid.UUID,
	query string,
	locationIDs []uuid.UUID,
	status string,
	limit, offset int,
) ([]uuid.UUID, error) {
	startTime := time.Now()
	logger := r.logger
	if logger == nil {
		logger = zap.L()
	}

	if limit <= 0 || limit > 500 {
		limit = 30
	}
	if offset < 0 {
		offset = 0
	}

	trimmed := strings.TrimSpace(query)

	var qArg interface{}
	if trimmed == "" {
		qArg = nil
	} else {
		qArg = query
	}

	var statusArg interface{}
	if status == "" || status == "all" {
		statusArg = nil
	} else {
		statusArg = status
	}

	locArg := toUUIDArrayLiteral(locationIDs)

	logger.Info("repo.SearchEmployeeIDsByStatus entry",
		zap.String("company_id", companyID.String()),
		zap.String("query_raw", query),
		zap.String("query_trimmed", trimmed),
		zap.String("status", status),
		zap.Bool("status_arg_is_nil", statusArg == nil),
		zap.Int("location_ids_count", len(locationIDs)),
		zap.Bool("location_arg_is_null", locArg == nil),
		zap.Int("limit", limit),
		zap.Int("offset", offset),
	)

	const sqlQuery = `
        SELECT user_id
        FROM search_company_employee_ids_by_status($1, $2, $3::uuid[], $4, $5, $6)`

	rows, err := r.client.Query(ctx, sqlQuery,
		companyID, qArg, locArg, statusArg, limit, offset)
	if err != nil {
		logger.Error("repo.SearchEmployeeIDsByStatus: query failed",
			zap.String("company_id", companyID.String()),
			zap.String("query_trimmed", trimmed),
			zap.String("status", status),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to search company employee ids by status: %w", err)
	}
	defer rows.Close()

	ids := make([]uuid.UUID, 0, limit)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			logger.Error("repo.SearchEmployeeIDsByStatus: scan failed", zap.Error(err))
			return nil, fmt.Errorf("failed to scan employee id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		logger.Error("repo.SearchEmployeeIDsByStatus: rows.Err", zap.Error(err))
		return nil, fmt.Errorf("error iterating employee ids: %w", err)
	}

	logger.Info("repo.SearchEmployeeIDsByStatus success",
		zap.String("company_id", companyID.String()),
		zap.String("query_trimmed", trimmed),
		zap.String("status", status),
		zap.Int("result_count", len(ids)),
		zap.Duration("duration", time.Since(startTime)),
	)

	return ids, nil
}

// CountEmployeeIDsByStatus returns the total row count matching the same
// filters as SearchEmployeeIDsByStatus. Used by the HTTP handler to populate
// pagination metadata on the typeahead response.
func (r *EmployeeRepositoryImpl) CountEmployeeIDsByStatus(
	ctx context.Context,
	companyID uuid.UUID,
	query string,
	locationIDs []uuid.UUID,
	status string,
) (int, error) {
	startTime := time.Now()
	logger := r.logger
	if logger == nil {
		logger = zap.L()
	}

	trimmed := strings.TrimSpace(query)

	var qArg interface{}
	if trimmed == "" {
		qArg = nil
	} else {
		qArg = query
	}

	var statusArg interface{}
	if status == "" || status == "all" {
		statusArg = nil
	} else {
		statusArg = status
	}

	locArg := toUUIDArrayLiteral(locationIDs)

	logger.Info("repo.CountEmployeeIDsByStatus entry",
		zap.String("company_id", companyID.String()),
		zap.String("query_trimmed", trimmed),
		zap.String("status", status),
		zap.Int("location_ids_count", len(locationIDs)),
	)

	const sqlQuery = `
        SELECT count_company_employee_ids_by_status($1, $2, $3::uuid[], $4)`

	var total int
	err := r.client.QueryRow(ctx, sqlQuery,
		companyID, qArg, locArg, statusArg).Scan(&total)
	if err != nil {
		logger.Error("repo.CountEmployeeIDsByStatus: query failed",
			zap.String("company_id", companyID.String()),
			zap.String("status", status),
			zap.Error(err),
		)
		return 0, fmt.Errorf("failed to count company employee ids by status: %w", err)
	}

	logger.Info("repo.CountEmployeeIDsByStatus success",
		zap.String("company_id", companyID.String()),
		zap.String("status", status),
		zap.Int("total", total),
		zap.Duration("duration", time.Since(startTime)),
	)
	return total, nil
}
