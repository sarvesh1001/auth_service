package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/encryption"
	"auth-service/internal/util"
)

type scanner interface {
	Scan(dest ...interface{}) error
}

// StudentRepository defines all database operations for students.
type StudentRepository interface {
	Create(ctx context.Context, db DBTX, s *models.Student) error
	BulkCreate(ctx context.Context, db DBTX, students []*models.Student) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Student, error)
	GetByAdmissionNumber(ctx context.Context, db DBTX, companyID uuid.UUID, admissionNo string) (*models.Student, error)
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Student, error)
	List(ctx context.Context, db DBTX, filter StudentFilter, p Pagination, s Sort) ([]*models.Student, error)
	Count(ctx context.Context, db DBTX, filter StudentFilter) (int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Student, error)
	ExistsByAdmissionNumber(ctx context.Context, db DBTX, companyID uuid.UUID, admissionNo string) (bool, error)
	Update(ctx context.Context, db DBTX, s *models.Student) error
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Student, error)
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	UpdateContactInfo(ctx context.Context, db DBTX, id uuid.UUID, phone string, updatedBy *uuid.UUID) error
	Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	CountByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) (int64, error)
	CountBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	BulkUpdateStatus(ctx context.Context, db DBTX, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int) ([]*models.Student, error)
	AddDocument(ctx context.Context, db DBTX, doc *models.StudentDocument) error
	GetDocuments(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.StudentDocument, error)
	GetDocumentByID(ctx context.Context, db DBTX, documentID uuid.UUID) (*models.StudentDocument, error)
	UpdateDocument(ctx context.Context, db DBTX, doc *models.StudentDocument) error
	DeleteDocument(ctx context.Context, db DBTX, documentID uuid.UUID, deletedBy *uuid.UUID) error
	GetDocumentsByType(ctx context.Context, db DBTX, studentID uuid.UUID, docType string) ([]*models.StudentDocument, error)
	GetByEmail(ctx context.Context, db DBTX, companyID uuid.UUID, email string) (*models.Student, error)
	GetByPhone(ctx context.Context, db DBTX, companyID uuid.UUID, phone string) (*models.Student, error)
	// Previous Education methods
	AddPreviousEducation(ctx context.Context, db DBTX, prev *models.StudentPreviousEducation) error
	GetPreviousEducation(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.StudentPreviousEducation, error)
	GetPreviousEducationByID(ctx context.Context, db DBTX, prevEduID uuid.UUID) (*models.StudentPreviousEducation, error)
	UpdatePreviousEducation(ctx context.Context, db DBTX, prev *models.StudentPreviousEducation) error
	DeletePreviousEducation(ctx context.Context, db DBTX, prevEduID uuid.UUID) error
}

type studentRepository struct {
	logger     *zap.Logger
	encryption *encryption.EncryptionManager
}

var (
	ErrNotFound        = errors.New("resource not found")
	ErrVersionConflict = errors.New("version conflict")
)

// NewStudentRepository creates a new student repository with encryption support.
func NewStudentRepository(logger *zap.Logger, encryptionManager *encryption.EncryptionManager) StudentRepository {
	return &studentRepository{
		logger:     logger.Named("student_repo"),
		encryption: encryptionManager,
	}
}

var allowedStudentSortFields = map[string]bool{
	"created_at":    true,
	"updated_at":    true,
	"admission_no":  true,
	"status":        true,
	"date_of_birth": true,
	"first_name":    true,
	"last_name":     true,
}

func (r *studentRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedStudentSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY s.%s %s", field, dir), nil
}

func (r *studentRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// --- Encryption helpers -------------------------------------------------

func (r *studentRepository) encryptField(ctx context.Context, plaintext, purpose string) (*encryption.EncryptedData, error) {
	if plaintext == "" {
		return &encryption.EncryptedData{
			EncryptedValue: "",
			EncryptedDEK:   "",
			KeyID:          "",
		}, nil
	}
	return r.encryption.EncryptField(ctx, plaintext, purpose)
}

func (r *studentRepository) decryptField(ctx context.Context, encValue, encDEK, keyID string) (string, error) {
	if encValue == "" || encDEK == "" || keyID == "" {
		return "", nil
	}
	return r.encryption.DecryptField(ctx, &encryption.EncryptedData{
		EncryptedValue: encValue,
		EncryptedDEK:   encDEK,
		KeyID:          keyID,
	})
}

// --- Build filter ------------------------------------------------------

// --- Create ------------------------------------------------------------

func (r *studentRepository) Create(ctx context.Context, db DBTX, s *models.Student) error {
	// Encrypt sensitive fields
	encAadhar, err := r.encryptField(ctx, s.AadharNo, "aadhar")
	if err != nil {
		return err
	}
	encEmergencyPhone, err := r.encryptField(ctx, s.EmergencyContactPhone, "emergency_phone")
	if err != nil {
		return err
	}
	encPhone, err := r.encryptField(ctx, s.Phone, "student_phone")
	if err != nil {
		return err
	}
	encEmail, err := r.encryptField(ctx, s.Email, "student_email")
	if err != nil {
		return err
	}

	query := `
		INSERT INTO academics.students (
			company_id, first_name, last_name, admission_no,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			date_of_birth, gender, blood_group, nationality, religion, category,
			aadhar_no, aadhar_no_dek, aadhar_no_key_id,
			emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
			medical_conditions, status, version, created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12, $13, $14, $15, $16,
			$17, $18, $19,
			$20, $21, $22, $23,
			$24, $25, $26, $27, $28, NOW(), NOW())
		RETURNING student_id, created_at, updated_at
	`

	err = db.QueryRowContext(ctx, query,
		s.CompanyID, s.FirstName, s.LastName, s.AdmissionNo,
		encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
		encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
		s.DateOfBirth, s.Gender, s.BloodGroup, s.Nationality, s.Religion, s.Category,
		encAadhar.EncryptedValue, encAadhar.EncryptedDEK, encAadhar.KeyID,
		s.EmergencyContactName, encEmergencyPhone.EncryptedValue, encEmergencyPhone.EncryptedDEK, encEmergencyPhone.KeyID,
		s.MedicalConditions, s.Status, 0, s.CreatedBy, s.UpdatedBy,
	).Scan(&s.StudentID, &s.CreatedAt, &s.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create student",
			util.String("company_id", s.CompanyID.String()),
			util.String("admission_no", s.AdmissionNo),
			util.ErrorField(err))
		return fmt.Errorf("create student: %w", err)
	}
	return nil
}

// --- BulkCreate ---------------------------------------------------------

func (r *studentRepository) BulkCreate(ctx context.Context, db DBTX, students []*models.Student) error {
	if len(students) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.students (
			company_id, first_name, last_name, admission_no,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			date_of_birth, gender, blood_group, nationality, religion, category,
			aadhar_no, aadhar_no_dek, aadhar_no_key_id,
			emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
			medical_conditions, status, version, created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12, $13, $14, $15, $16,
			$17, $18, $19,
			$20, $21, $22, $23,
			$24, $25, $26, $27, $28, NOW(), NOW())
		RETURNING student_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, s := range students {
		// Encrypt per student
		encAadhar, err := r.encryptField(ctx, s.AadharNo, "aadhar")
		if err != nil {
			return err
		}
		encEmergencyPhone, err := r.encryptField(ctx, s.EmergencyContactPhone, "emergency_phone")
		if err != nil {
			return err
		}
		encPhone, err := r.encryptField(ctx, s.Phone, "student_phone")
		if err != nil {
			return err
		}
		encEmail, err := r.encryptField(ctx, s.Email, "student_email")
		if err != nil {
			return err
		}

		err = stmt.QueryRowContext(ctx,
			s.CompanyID, s.FirstName, s.LastName, s.AdmissionNo,
			encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
			encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
			s.DateOfBirth, s.Gender, s.BloodGroup, s.Nationality, s.Religion, s.Category,
			encAadhar.EncryptedValue, encAadhar.EncryptedDEK, encAadhar.KeyID,
			s.EmergencyContactName, encEmergencyPhone.EncryptedValue, encEmergencyPhone.EncryptedDEK, encEmergencyPhone.KeyID,
			s.MedicalConditions, s.Status, 0, s.CreatedBy, s.UpdatedBy,
		).Scan(&s.StudentID, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create student failed",
				util.String("company_id", s.CompanyID.String()),
				util.String("admission_no", s.AdmissionNo),
				util.ErrorField(err))
			return fmt.Errorf("bulk create student row: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// --- GetByID ------------------------------------------------------------

func (r *studentRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Student, error) {
	query := `
		SELECT
			student_id, company_id, first_name, last_name, admission_no,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			date_of_birth, gender, blood_group, nationality, religion, category,
			aadhar_no, aadhar_no_dek, aadhar_no_key_id,
			emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
			medical_conditions, status, version,
			created_at, updated_at, created_by, updated_by
		FROM academics.students
		WHERE student_id = $1 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStudent(ctx, row)
}

// --- GetByAdmissionNumber ------------------------------------------------

func (r *studentRepository) GetByAdmissionNumber(ctx context.Context, db DBTX, companyID uuid.UUID, admissionNo string) (*models.Student, error) {
	query := `
		SELECT
			student_id, company_id, first_name, last_name, admission_no,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			date_of_birth, gender, blood_group, nationality, religion, category,
			aadhar_no, aadhar_no_dek, aadhar_no_key_id,
			emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
			medical_conditions, status, version,
			created_at, updated_at, created_by, updated_by
		FROM academics.students
		WHERE company_id = $1 AND admission_no = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, admissionNo)
	return r.scanStudent(ctx, row)
}

// --- GetByIDs -----------------------------------------------------------

func (r *studentRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Student, error) {
	if len(ids) == 0 {
		return []*models.Student{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
		SELECT
			student_id, company_id, first_name, last_name, admission_no,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			date_of_birth, gender, blood_group, nationality, religion, category,
			aadhar_no, aadhar_no_dek, aadhar_no_key_id,
			emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
			medical_conditions, status, version,
			created_at, updated_at, created_by, updated_by
		FROM academics.students
		WHERE student_id IN (%s) AND deleted_at IS NULL
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get students by IDs", zap.Error(err))
		return nil, fmt.Errorf("get students by IDs: %w", err)
	}
	defer rows.Close()

	var result []*models.Student
	for rows.Next() {
		s, err := r.scanStudent(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- List ---------------------------------------------------------------

func (r *studentRepository) List(ctx context.Context, db DBTX, filter StudentFilter, p Pagination, s Sort) ([]*models.Student, error) {
	where, args := r.buildStudentFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	fromClause := "FROM academics.students s"
	needEnrollments := filter.CourseID != nil || filter.SectionID != nil || filter.TermID != nil || filter.JoinedFrom != nil || filter.JoinedTo != nil
	if needEnrollments {
		// Always join enrollments and section when any enrollment-related filter is present
		fromClause += " LEFT JOIN academics.enrollments e ON s.student_id = e.student_id AND e.status IN ('active','completed')"
		fromClause += " LEFT JOIN academics.section sec ON e.section_id = sec.section_id AND sec.deleted_at IS NULL"
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT
			s.student_id, s.company_id, s.first_name, s.last_name, s.admission_no,
			s.email, s.email_dek, s.email_key_id,
			s.phone, s.phone_dek, s.phone_key_id,
			s.date_of_birth, s.gender, s.blood_group, s.nationality, s.religion, s.category,
			s.aadhar_no, s.aadhar_no_dek, s.aadhar_no_key_id,
			s.emergency_contact_name, s.emergency_contact_phone, s.emergency_contact_phone_dek, s.emergency_contact_phone_key_id,
			s.medical_conditions, s.status, s.version,
			s.created_at, s.updated_at, s.created_by, s.updated_by
		%s
		%s %s
		LIMIT $%d OFFSET $%d
	`, fromClause, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list students",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list students: %w", err)
	}
	defer rows.Close()

	var result []*models.Student
	for rows.Next() {
		s, err := r.scanStudent(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Count --------------------------------------------------------------

func (r *studentRepository) Count(ctx context.Context, db DBTX, filter StudentFilter) (int64, error) {
	// Get base conditions that do not require joins
	where, args := r.buildBaseStudentFilter(filter)

	// Determine if we need to add an EXISTS clause for enrollment filters
	needEnrollments := filter.CourseID != nil || filter.SectionID != nil || filter.TermID != nil ||
		filter.JoinedFrom != nil || filter.JoinedTo != nil

	if needEnrollments {
		// Build the enrollment conditions inside the EXISTS subquery
		var enrollmentConditions []string
		idx := len(args) + 1

		if filter.CourseID != nil {
			enrollmentConditions = append(enrollmentConditions, fmt.Sprintf("sec.course_id = $%d", idx))
			args = append(args, *filter.CourseID)
			idx++
		}
		if filter.SectionID != nil {
			enrollmentConditions = append(enrollmentConditions, fmt.Sprintf("e.section_id = $%d", idx))
			args = append(args, *filter.SectionID)
			idx++
		}
		if filter.TermID != nil {
			enrollmentConditions = append(enrollmentConditions, fmt.Sprintf("sec.term_id = $%d", idx))
			args = append(args, *filter.TermID)
			idx++
		}
		if filter.JoinedFrom != nil {
			enrollmentConditions = append(enrollmentConditions, fmt.Sprintf("e.enrollment_date >= $%d", idx))
			args = append(args, *filter.JoinedFrom)
			idx++
		}
		if filter.JoinedTo != nil {
			enrollmentConditions = append(enrollmentConditions, fmt.Sprintf("e.enrollment_date <= $%d", idx))
			args = append(args, *filter.JoinedTo)
			idx++
		}

		existsClause := `
            EXISTS (
                SELECT 1
                FROM academics.enrollments e
                JOIN academics.section sec ON sec.section_id = e.section_id AND sec.deleted_at IS NULL
                WHERE e.student_id = s.student_id
                  AND e.status IN ('active','completed')
        `
		if len(enrollmentConditions) > 0 {
			existsClause += " AND " + strings.Join(enrollmentConditions, " AND ")
		}
		existsClause += ")"

		// Combine the base WHERE with the EXISTS clause
		if where == "" {
			where = "WHERE " + existsClause
		} else {
			where += " AND " + existsClause
		}
	}

	query := "SELECT COUNT(*) FROM academics.students s " + where
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count students",
			zap.Any("filter", filter),
			zap.Error(err))
		return 0, fmt.Errorf("count students: %w", err)
	}
	return count, nil
}

// --- ListActive ---------------------------------------------------------

func (r *studentRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Student, error) {
	active := "active"
	filter := StudentFilter{
		CompanyID: companyID,
		Status:    &active,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "admission_no", Direction: "ASC"})
}

// --- ExistsByAdmissionNumber --------------------------------------------

func (r *studentRepository) ExistsByAdmissionNumber(ctx context.Context, db DBTX, companyID uuid.UUID, admissionNo string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.students WHERE company_id = $1 AND admission_no = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, admissionNo).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check student existence by admission number",
			util.String("company_id", companyID.String()),
			util.String("admission_no", admissionNo),
			util.ErrorField(err))
		return false, fmt.Errorf("exists student by admission number: %w", err)
	}
	return exists, nil
}

// --- Update -------------------------------------------------------------

func (r *studentRepository) Update(ctx context.Context, db DBTX, s *models.Student) error {
	// Encrypt sensitive fields
	encAadhar, err := r.encryptField(ctx, s.AadharNo, "aadhar")
	if err != nil {
		return err
	}
	encEmergencyPhone, err := r.encryptField(ctx, s.EmergencyContactPhone, "emergency_phone")
	if err != nil {
		return err
	}
	encPhone, err := r.encryptField(ctx, s.Phone, "student_phone")
	if err != nil {
		return err
	}
	encEmail, err := r.encryptField(ctx, s.Email, "student_email")
	if err != nil {
		return err
	}

	query := `
		UPDATE academics.students
		SET
			first_name = $2,
			last_name = $3,
			admission_no = $4,
			email = $5,
			email_dek = $6,
			email_key_id = $7,
			phone = $8,
			phone_dek = $9,
			phone_key_id = $10,
			date_of_birth = $11,
			gender = $12,
			blood_group = $13,
			nationality = $14,
			religion = $15,
			category = $16,
			aadhar_no = $17,
			aadhar_no_dek = $18,
			aadhar_no_key_id = $19,
			emergency_contact_name = $20,
			emergency_contact_phone = $21,
			emergency_contact_phone_dek = $22,
			emergency_contact_phone_key_id = $23,
			medical_conditions = $24,
			status = $25,
			updated_by = $26,
			version = version + 1,
			updated_at = NOW()
		WHERE student_id = $1 AND version = $27 AND deleted_at IS NULL
		RETURNING updated_at, version
	`

	err = db.QueryRowContext(ctx, query,
		s.StudentID,
		s.FirstName, s.LastName, s.AdmissionNo,
		encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
		encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
		s.DateOfBirth, s.Gender, s.BloodGroup, s.Nationality, s.Religion, s.Category,
		encAadhar.EncryptedValue, encAadhar.EncryptedDEK, encAadhar.KeyID,
		s.EmergencyContactName, encEmergencyPhone.EncryptedValue, encEmergencyPhone.EncryptedDEK, encEmergencyPhone.KeyID,
		s.MedicalConditions, s.Status,
		s.UpdatedBy,
		s.Version,
	).Scan(&s.UpdatedAt, &s.Version)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Check if the record exists (not deleted) to distinguish between not found and version conflict
			var exists bool
			checkQuery := `SELECT EXISTS(SELECT 1 FROM academics.students WHERE student_id = $1 AND deleted_at IS NULL)`
			_ = db.QueryRowContext(ctx, checkQuery, s.StudentID).Scan(&exists)
			if exists {
				return fmt.Errorf("%w: student %s version mismatch", ErrVersionConflict, s.StudentID)
			}
			return fmt.Errorf("%w: student %s", ErrNotFound, s.StudentID)
		}
		r.logger.Error("failed to update student",
			util.String("id", s.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update student: %w", err)
	}
	return nil
}

// --- GetByIDForUpdate ---------------------------------------------------

func (r *studentRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Student, error) {
	query := `
		SELECT
			student_id, company_id, first_name, last_name, admission_no,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			date_of_birth, gender, blood_group, nationality, religion, category,
			aadhar_no, aadhar_no_dek, aadhar_no_key_id,
			emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
			medical_conditions, status, version,
			created_at, updated_at, created_by, updated_by
		FROM academics.students
		WHERE student_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStudent(ctx, row)
}

// --- UpdateStatus -------------------------------------------------------

func (r *studentRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.students SET status = $2, updated_by = $3, updated_at = NOW() WHERE student_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update student status",
			util.String("id", id.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("update student status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("student %s not found or deleted", id)
	}
	return nil
}

// --- UpdateContactInfo --------------------------------------------------

func (r *studentRepository) UpdateContactInfo(ctx context.Context, db DBTX, id uuid.UUID, phone string, updatedBy *uuid.UUID) error {
	// Encrypt phone
	encPhone, err := r.encryptField(ctx, phone, "student_phone")
	if err != nil {
		return err
	}

	query := `
		UPDATE academics.students
		SET phone = $2, phone_dek = $3, phone_key_id = $4, updated_by = $5, updated_at = NOW()
		WHERE student_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID, updatedBy)
	if err != nil {
		r.logger.Error("failed to update student contact info",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("update student contact info: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("student %s not found or deleted", id)
	}
	return nil
}

// --- Activate / Deactivate ----------------------------------------------

func (r *studentRepository) Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, id, "active", updatedBy)
}

func (r *studentRepository) Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, id, "inactive", updatedBy)
}

// --- Delete -------------------------------------------------------------

func (r *studentRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.students SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE student_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete student",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete student: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("student %s not found or already deleted", id)
	}
	return nil
}

// --- CountByCourse ------------------------------------------------------

func (r *studentRepository) CountByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM academics.students s
		WHERE s.deleted_at IS NULL
		AND EXISTS (
			SELECT 1
			FROM academics.enrollments e
			JOIN academics.section sec ON sec.section_id = e.section_id
			WHERE e.student_id = s.student_id
			  AND sec.course_id = $1
			  AND e.status IN ('active','completed')
		)
	`

	var count int64
	err := db.QueryRowContext(ctx, query, courseID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count students by course",
			util.String("course_id", courseID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("count by course: %w", err)
	}
	return count, nil
}

// --- CountBySection -----------------------------------------------------

func (r *studentRepository) CountBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM academics.students s
		WHERE s.deleted_at IS NULL
		AND EXISTS (
			SELECT 1
			FROM academics.enrollments e
			WHERE e.student_id = s.student_id
			  AND e.section_id = $1
			  AND e.status IN ('active','completed')
		)
	`

	var count int64
	err := db.QueryRowContext(ctx, query, sectionID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count students by section",
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("count by section: %w", err)
	}
	return count, nil
}

// --- BulkUpdateStatus ---------------------------------------------------

func (r *studentRepository) BulkUpdateStatus(ctx context.Context, db DBTX, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+2)
	args[0] = status
	args[1] = updatedBy
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+3)
		args[i+2] = id
	}
	query := fmt.Sprintf(`
		UPDATE academics.students
		SET status = $1, updated_by = $2, updated_at = NOW()
		WHERE student_id IN (%s) AND deleted_at IS NULL
	`, strings.Join(placeholders, ","))

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk update student status",
			zap.Int("count", len(ids)),
			zap.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("bulk update status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("no students updated")
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// --- Search -------------------------------------------------------------

func (r *studentRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int) ([]*models.Student, error) {
	if limit <= 0 {
		limit = 20
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return []*models.Student{}, nil
	}

	// For search, we only need basic fields, but we still need to return the model.
	// We'll scan only the plain columns (encrypted ones are not needed for search results).
	sqlQuery := `
		SELECT student_id, company_id, first_name, last_name, admission_no,
		       status, created_at
		FROM academics.students
		WHERE company_id = $1
		  AND deleted_at IS NULL
		  AND (
				first_name ILIKE $2 OR
				last_name ILIKE $2 OR
				admission_no ILIKE $2
			  )
		ORDER BY 
			similarity(first_name, $3) DESC,
			similarity(last_name, $3) DESC,
			first_name ASC
		LIMIT $4
	`

	rows, err := db.QueryContext(ctx, sqlQuery,
		companyID,
		"%"+query+"%",
		query,
		limit,
	)
	if err != nil {
		r.logger.Error("failed to search students",
			util.String("company_id", companyID.String()),
			util.String("query", query),
			util.ErrorField(err))
		return nil, fmt.Errorf("search students: %w", err)
	}
	defer rows.Close()

	var result []*models.Student
	for rows.Next() {
		var s models.Student
		var firstName, lastName, admissionNo sql.NullString

		if err := rows.Scan(
			&s.StudentID,
			&s.CompanyID,
			&firstName,
			&lastName,
			&admissionNo,
			&s.Status,
			&s.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan student: %w", err)
		}

		if firstName.Valid {
			s.FirstName = firstName.String
		}
		if lastName.Valid {
			s.LastName = lastName.String
		}
		if admissionNo.Valid {
			s.AdmissionNo = admissionNo.String
		}

		result = append(result, &s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- scanStudent --------------------------------------------------------

func (r *studentRepository) scanStudent(ctx context.Context, row scanner) (*models.Student, error) {
	var s models.Student

	// All encrypted fields as sql.NullString
	var (
		emailEnc, emailDEK, emailKeyID                sql.NullString
		phoneEnc, phoneDEK, phoneKeyID                sql.NullString
		aadharEnc, aadharDEK, aadharKeyID             sql.NullString
		emergPhoneEnc, emergPhoneDEK, emergPhoneKeyID sql.NullString
	)

	var (
		dateOfBirth          sql.NullTime
		createdBy, updatedBy uuid.NullUUID
	)

	err := row.Scan(
		&s.StudentID,
		&s.CompanyID,
		&s.FirstName,
		&s.LastName,
		&s.AdmissionNo,

		&emailEnc,
		&emailDEK,
		&emailKeyID,

		&phoneEnc,
		&phoneDEK,
		&phoneKeyID,

		&dateOfBirth,
		&s.Gender,
		&s.BloodGroup,
		&s.Nationality,
		&s.Religion,
		&s.Category,

		&aadharEnc,
		&aadharDEK,
		&aadharKeyID,

		&s.EmergencyContactName,
		&emergPhoneEnc,
		&emergPhoneDEK,
		&emergPhoneKeyID,

		&s.MedicalConditions,
		&s.Status,
		&s.Version,

		&s.CreatedAt,
		&s.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan student: %w", err)
	}

	// Decrypt
	if emailEnc.Valid {
		s.Email, _ = r.decryptField(ctx, emailEnc.String, emailDEK.String, emailKeyID.String)
	}
	if phoneEnc.Valid {
		s.Phone, _ = r.decryptField(ctx, phoneEnc.String, phoneDEK.String, phoneKeyID.String)
	}
	if aadharEnc.Valid {
		s.AadharNo, _ = r.decryptField(ctx, aadharEnc.String, aadharDEK.String, aadharKeyID.String)
	}
	if emergPhoneEnc.Valid {
		s.EmergencyContactPhone, _ = r.decryptField(ctx, emergPhoneEnc.String, emergPhoneDEK.String, emergPhoneKeyID.String)
	}

	if dateOfBirth.Valid {
		s.DateOfBirth = &dateOfBirth.Time
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}

	return &s, nil
}

// --- Document methods -------------------------------------------------

func (r *studentRepository) AddDocument(ctx context.Context, db DBTX, doc *models.StudentDocument) error {
	query := `
        INSERT INTO academics.student_documents (
            student_id, document_type, document_name, file_url,
            uploaded_at, verified, verified_by, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, NOW(), NOW())
        RETURNING document_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		doc.StudentID, doc.DocumentType, doc.DocumentName, doc.FileURL,
		doc.Verified, doc.VerifiedBy, doc.CreatedBy,
	).Scan(&doc.DocumentID, &doc.CreatedAt, &doc.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add student document",
			util.String("student_id", doc.StudentID.String()),
			util.String("document_type", doc.DocumentType),
			util.ErrorField(err))
		return fmt.Errorf("add student document: %w", err)
	}
	return nil
}

func (r *studentRepository) GetDocuments(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.StudentDocument, error) {
	query := `
        SELECT document_id, student_id, document_type, document_name, file_url,
               uploaded_at, verified, verified_by, created_at, updated_at, created_by
        FROM academics.student_documents
        WHERE student_id = $1
        ORDER BY created_at DESC
    `
	rows, err := db.QueryContext(ctx, query, studentID)
	if err != nil {
		r.logger.Error("failed to get student documents",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get student documents: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentDocument
	for rows.Next() {
		doc := &models.StudentDocument{}
		var createdBy uuid.NullUUID
		var verifiedBy uuid.NullUUID
		err := rows.Scan(
			&doc.DocumentID, &doc.StudentID, &doc.DocumentType, &doc.DocumentName, &doc.FileURL,
			&doc.UploadedAt, &doc.Verified, &verifiedBy, &doc.CreatedAt, &doc.UpdatedAt, &createdBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan document: %w", err)
		}
		if verifiedBy.Valid {
			doc.VerifiedBy = &verifiedBy.UUID
		}
		if createdBy.Valid {
			doc.CreatedBy = &createdBy.UUID
		}
		result = append(result, doc)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *studentRepository) GetDocumentByID(ctx context.Context, db DBTX, documentID uuid.UUID) (*models.StudentDocument, error) {
	query := `
        SELECT document_id, student_id, document_type, document_name, file_url,
               uploaded_at, verified, verified_by, created_at, updated_at, created_by
        FROM academics.student_documents
        WHERE document_id = $1
    `
	row := db.QueryRowContext(ctx, query, documentID)
	doc := &models.StudentDocument{}
	var createdBy uuid.NullUUID
	var verifiedBy uuid.NullUUID
	err := row.Scan(
		&doc.DocumentID, &doc.StudentID, &doc.DocumentType, &doc.DocumentName, &doc.FileURL,
		&doc.UploadedAt, &doc.Verified, &verifiedBy, &doc.CreatedAt, &doc.UpdatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get document by ID: %w", err)
	}
	if verifiedBy.Valid {
		doc.VerifiedBy = &verifiedBy.UUID
	}
	if createdBy.Valid {
		doc.CreatedBy = &createdBy.UUID
	}
	return doc, nil
}

func (r *studentRepository) UpdateDocument(ctx context.Context, db DBTX, doc *models.StudentDocument) error {
	query := `
        UPDATE academics.student_documents
        SET
            document_type = $2,
            document_name = $3,
            file_url = $4,
            verified = $5,
            verified_by = $6,
            updated_at = NOW()
        WHERE document_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		doc.DocumentID, doc.DocumentType, doc.DocumentName, doc.FileURL,
		doc.Verified, doc.VerifiedBy,
	).Scan(&doc.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: document %s", ErrNotFound, doc.DocumentID)
		}
		r.logger.Error("failed to update student document",
			util.String("document_id", doc.DocumentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update student document: %w", err)
	}
	return nil
}

func (r *studentRepository) DeleteDocument(ctx context.Context, db DBTX, documentID uuid.UUID, deletedBy *uuid.UUID) error {
	// Soft delete? The table has no deleted_at column per schema, so we'll do a physical delete.
	// If you prefer soft delete, you'd need to add deleted_at to the table.
	query := `DELETE FROM academics.student_documents WHERE document_id = $1`
	result, err := db.ExecContext(ctx, query, documentID)
	if err != nil {
		r.logger.Error("failed to delete student document",
			util.String("document_id", documentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete student document: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("document %s not found", documentID)
	}
	return nil
}

func (r *studentRepository) GetDocumentsByType(ctx context.Context, db DBTX, studentID uuid.UUID, docType string) ([]*models.StudentDocument, error) {
	query := `
        SELECT document_id, student_id, document_type, document_name, file_url,
               uploaded_at, verified, verified_by, created_at, updated_at, created_by
        FROM academics.student_documents
        WHERE student_id = $1 AND document_type = $2
        ORDER BY created_at DESC
    `
	rows, err := db.QueryContext(ctx, query, studentID, docType)
	if err != nil {
		r.logger.Error("failed to get student documents by type",
			util.String("student_id", studentID.String()),
			util.String("document_type", docType),
			util.ErrorField(err))
		return nil, fmt.Errorf("get documents by type: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentDocument
	for rows.Next() {
		doc := &models.StudentDocument{}
		var createdBy uuid.NullUUID
		var verifiedBy uuid.NullUUID
		err := rows.Scan(
			&doc.DocumentID, &doc.StudentID, &doc.DocumentType, &doc.DocumentName, &doc.FileURL,
			&doc.UploadedAt, &doc.Verified, &verifiedBy, &doc.CreatedAt, &doc.UpdatedAt, &createdBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan document: %w", err)
		}
		if verifiedBy.Valid {
			doc.VerifiedBy = &verifiedBy.UUID
		}
		if createdBy.Valid {
			doc.CreatedBy = &createdBy.UUID
		}
		result = append(result, doc)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Previous Education methods -----------------------------------------

func (r *studentRepository) AddPreviousEducation(ctx context.Context, db DBTX, prev *models.StudentPreviousEducation) error {
	query := `
        INSERT INTO academics.student_previous_education (
            student_id, school_name, board, year_of_passing, percentage, grade, qualification,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING prev_edu_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		prev.StudentID, prev.SchoolName, prev.Board, prev.YearOfPassing,
		prev.Percentage, prev.Grade, prev.Qualification,
	).Scan(&prev.PrevEduID, &prev.CreatedAt, &prev.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add previous education",
			util.String("student_id", prev.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add previous education: %w", err)
	}
	return nil
}

func (r *studentRepository) GetPreviousEducation(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.StudentPreviousEducation, error) {
	query := `
        SELECT prev_edu_id, student_id, school_name, board, year_of_passing,
               percentage, grade, qualification, created_at, updated_at
        FROM academics.student_previous_education
        WHERE student_id = $1
        ORDER BY year_of_passing DESC
    `
	rows, err := db.QueryContext(ctx, query, studentID)
	if err != nil {
		r.logger.Error("failed to get previous education",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get previous education: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentPreviousEducation
	for rows.Next() {
		prev := &models.StudentPreviousEducation{}
		err := rows.Scan(
			&prev.PrevEduID, &prev.StudentID, &prev.SchoolName, &prev.Board, &prev.YearOfPassing,
			&prev.Percentage, &prev.Grade, &prev.Qualification, &prev.CreatedAt, &prev.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan previous education: %w", err)
		}
		result = append(result, prev)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *studentRepository) GetPreviousEducationByID(ctx context.Context, db DBTX, prevEduID uuid.UUID) (*models.StudentPreviousEducation, error) {
	query := `
        SELECT prev_edu_id, student_id, school_name, board, year_of_passing,
               percentage, grade, qualification, created_at, updated_at
        FROM academics.student_previous_education
        WHERE prev_edu_id = $1
    `
	row := db.QueryRowContext(ctx, query, prevEduID)
	prev := &models.StudentPreviousEducation{}
	err := row.Scan(
		&prev.PrevEduID, &prev.StudentID, &prev.SchoolName, &prev.Board, &prev.YearOfPassing,
		&prev.Percentage, &prev.Grade, &prev.Qualification, &prev.CreatedAt, &prev.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get previous education by ID: %w", err)
	}
	return prev, nil
}

func (r *studentRepository) UpdatePreviousEducation(ctx context.Context, db DBTX, prev *models.StudentPreviousEducation) error {
	query := `
        UPDATE academics.student_previous_education
        SET
            school_name = $2,
            board = $3,
            year_of_passing = $4,
            percentage = $5,
            grade = $6,
            qualification = $7,
            updated_at = NOW()
        WHERE prev_edu_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		prev.PrevEduID, prev.SchoolName, prev.Board, prev.YearOfPassing,
		prev.Percentage, prev.Grade, prev.Qualification,
	).Scan(&prev.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: previous education %s", ErrNotFound, prev.PrevEduID)
		}
		r.logger.Error("failed to update previous education",
			util.String("prev_edu_id", prev.PrevEduID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update previous education: %w", err)
	}
	return nil
}

func (r *studentRepository) DeletePreviousEducation(ctx context.Context, db DBTX, prevEduID uuid.UUID) error {
	// Physical delete (no soft delete column)
	query := `DELETE FROM academics.student_previous_education WHERE prev_edu_id = $1`
	result, err := db.ExecContext(ctx, query, prevEduID)
	if err != nil {
		r.logger.Error("failed to delete previous education",
			util.String("prev_edu_id", prevEduID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete previous education: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("previous education %s not found", prevEduID)
	}
	return nil
}

func (r *studentRepository) GetByEmail(ctx context.Context, db DBTX, companyID uuid.UUID, email string) (*models.Student, error) {
	enc, err := r.encryptField(ctx, email, "student_email")
	if err != nil {
		return nil, fmt.Errorf("encrypt email: %w", err)
	}

	query := `
        SELECT
            student_id, company_id, first_name, last_name, admission_no,
            email, email_dek, email_key_id,
            phone, phone_dek, phone_key_id,
            date_of_birth, gender, blood_group, nationality, religion, category,
            aadhar_no, aadhar_no_dek, aadhar_no_key_id,
            emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
            medical_conditions, status, version,
            created_at, updated_at, created_by, updated_by
        FROM academics.students
        WHERE company_id = $1 AND email = $2 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID, enc.EncryptedValue)
	return r.scanStudent(ctx, row)
}

func (r *studentRepository) GetByPhone(ctx context.Context, db DBTX, companyID uuid.UUID, phone string) (*models.Student, error) {
	enc, err := r.encryptField(ctx, phone, "student_phone")
	if err != nil {
		return nil, fmt.Errorf("encrypt phone: %w", err)
	}

	query := `
        SELECT
            student_id, company_id, first_name, last_name, admission_no,
            email, email_dek, email_key_id,
            phone, phone_dek, phone_key_id,
            date_of_birth, gender, blood_group, nationality, religion, category,
            aadhar_no, aadhar_no_dek, aadhar_no_key_id,
            emergency_contact_name, emergency_contact_phone, emergency_contact_phone_dek, emergency_contact_phone_key_id,
            medical_conditions, status, version,
            created_at, updated_at, created_by, updated_by
        FROM academics.students
        WHERE company_id = $1 AND phone = $2 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID, enc.EncryptedValue)
	return r.scanStudent(ctx, row)
}

// buildBaseStudentFilter returns WHERE clause and args for filters that do NOT require joins.
// This includes: company_id, admission_number, status, is_active, search, and deleted_at.
func (r *studentRepository) buildBaseStudentFilter(filter StudentFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("s.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.AdmissionNumber != "" {
		conditions = append(conditions, fmt.Sprintf("s.admission_no = $%d", idx))
		args = append(args, filter.AdmissionNumber)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("s.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.IsActive != nil {
		if *filter.IsActive {
			conditions = append(conditions, "s.status = 'active'")
		} else {
			conditions = append(conditions, "s.status != 'active'")
		}
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(s.admission_no ILIKE $%d OR s.first_name ILIKE $%d OR s.last_name ILIKE $%d)", idx, idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "s.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// buildStudentFilter returns WHERE clause and args for full filtering (including enrollment conditions).
// This is used when the outer query joins the enrollments and section tables.
func (r *studentRepository) buildStudentFilter(filter StudentFilter) (string, []interface{}) {
	baseWhere, baseArgs := r.buildBaseStudentFilter(filter)
	var conditions []string
	args := baseArgs
	idx := len(args) + 1

	// Append enrollment conditions only if they are present.
	if filter.CourseID != nil {
		conditions = append(conditions, fmt.Sprintf("sec.course_id = $%d", idx))
		args = append(args, *filter.CourseID)
		idx++
	}
	if filter.SectionID != nil {
		conditions = append(conditions, fmt.Sprintf("e.section_id = $%d", idx))
		args = append(args, *filter.SectionID)
		idx++
	}
	if filter.TermID != nil {
		conditions = append(conditions, fmt.Sprintf("sec.term_id = $%d", idx))
		args = append(args, *filter.TermID)
		idx++
	}
	if filter.JoinedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("e.enrollment_date >= $%d", idx))
		args = append(args, *filter.JoinedFrom)
		idx++
	}
	if filter.JoinedTo != nil {
		conditions = append(conditions, fmt.Sprintf("e.enrollment_date <= $%d", idx))
		args = append(args, *filter.JoinedTo)
		idx++
	}

	if len(conditions) == 0 {
		return baseWhere, baseArgs
	}

	// Combine base WHERE with enrollment conditions (assumes joins exist).
	if baseWhere == "" {
		return "WHERE " + strings.Join(conditions, " AND "), args
	}
	return baseWhere + " AND " + strings.Join(conditions, " AND "), args
}
