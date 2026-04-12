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
	"auth-service/internal/util"
)

type TeacherRepository interface {
	Create(ctx context.Context, db DBTX, t *models.Teacher) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Teacher, error)
	GetByUserID(ctx context.Context, db DBTX, userID uuid.UUID) (*models.Teacher, error)
	GetByEmployeeCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Teacher, error)
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Teacher, error)
	List(ctx context.Context, db DBTX, filter TeacherFilter, p Pagination, s Sort) ([]*models.Teacher, error)
	Count(ctx context.Context, db DBTX, filter TeacherFilter) (int64, error)
	Update(ctx context.Context, db DBTX, t *models.Teacher) error
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	BulkCreate(ctx context.Context, db DBTX, teachers []*models.Teacher) error
	BulkUpdateStatus(ctx context.Context, db DBTX, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error
	CountByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) (int64, error)
	AddSubject(ctx context.Context, db DBTX, teacherID, subjectID uuid.UUID, isPrimary bool) error
	RemoveSubject(ctx context.Context, db DBTX, teacherID, subjectID uuid.UUID) error
	GetSubjectsByTeacher(ctx context.Context, db DBTX, teacherID uuid.UUID) ([]*models.TeacherSubject, error)
	GetTeachersBySubject(ctx context.Context, db DBTX, subjectID uuid.UUID) ([]*models.Teacher, error)
	UpdateSubjectPrimary(ctx context.Context, db DBTX, teacherID, subjectID uuid.UUID, isPrimary bool) error
	AddSection(ctx context.Context, db DBTX, teacherID, sectionID uuid.UUID, isClassTeacher bool) error
	RemoveSection(ctx context.Context, db DBTX, teacherID, sectionID uuid.UUID) error
	GetSectionsByTeacher(ctx context.Context, db DBTX, teacherID uuid.UUID) ([]*models.TeacherSection, error)
	GetTeachersBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) ([]*models.Teacher, error)
	UpdateClassTeacherStatus(ctx context.Context, db DBTX, teacherID, sectionID uuid.UUID, isClassTeacher bool) error
	SetSchedulePreference(ctx context.Context, db DBTX, pref *models.TeacherSchedulePreference) error
	GetSchedulePreferences(ctx context.Context, db DBTX, teacherID uuid.UUID) ([]*models.TeacherSchedulePreference, error)
	DeleteSchedulePreference(ctx context.Context, db DBTX, preferenceID uuid.UUID) error
	UpdateSchedulePreference(ctx context.Context, db DBTX, pref *models.TeacherSchedulePreference) error
	ClearSchedulePreferences(ctx context.Context, db DBTX, teacherID uuid.UUID) error
}

type teacherRepository struct {
	logger *zap.Logger
}

func NewTeacherRepository(logger *zap.Logger) TeacherRepository {
	return &teacherRepository{
		logger: logger.Named("teacher_repo"),
	}
}

var allowedTeacherSortFields = map[string]bool{
	"created_at":     true,
	"updated_at":     true,
	"employee_code":  true,
	"status":         true,
	"joining_date":   true,
	"specialization": true,
}

func (r *teacherRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedTeacherSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY t.%s %s", field, dir), nil
}

func (r *teacherRepository) validatePagination(p Pagination) (int, int) {
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

func (r *teacherRepository) buildTeacherFilter(filter TeacherFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1
	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("t.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("t.user_id = $%d", idx))
		args = append(args, *filter.UserID)
		idx++
	}
	if filter.EmployeeCode != "" {
		conditions = append(conditions, fmt.Sprintf("t.employee_code = $%d", idx))
		args = append(args, filter.EmployeeCode)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("t.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.IsActive != nil {
		if *filter.IsActive {
			conditions = append(conditions, "t.status = 'active'")
		} else {
			conditions = append(conditions, "t.status != 'active'")
		}
	}
	if filter.Specialization != "" {
		conditions = append(conditions, fmt.Sprintf("t.specialization ILIKE $%d", idx))
		args = append(args, "%"+filter.Specialization+"%")
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("t.employee_code ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "t.deleted_at IS NULL")
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// Create inserts a new teacher record (no version column)
func (r *teacherRepository) Create(ctx context.Context, db DBTX, t *models.Teacher) error {
	query := `
        INSERT INTO academics.teachers (
            company_id, user_id, employee_code, qualification, specialization,
            joining_date, status, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING teacher_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		t.CompanyID, t.UserID, t.EmployeeCode, t.Qualification, t.Specialization,
		t.JoiningDate, t.Status, t.CreatedBy, t.UpdatedBy,
	).Scan(&t.TeacherID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create teacher",
			util.String("company_id", t.CompanyID.String()),
			util.String("employee_code", t.EmployeeCode),
			util.ErrorField(err))
		return fmt.Errorf("create teacher: %w", err)
	}
	return nil
}

// BulkCreate inserts many teachers (no version)
func (r *teacherRepository) BulkCreate(ctx context.Context, db DBTX, teachers []*models.Teacher) error {
	if len(teachers) == 0 {
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
        INSERT INTO academics.teachers (
            company_id, user_id, employee_code, qualification, specialization,
            joining_date, status, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING teacher_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()
	for _, t := range teachers {
		err := stmt.QueryRowContext(ctx,
			t.CompanyID, t.UserID, t.EmployeeCode, t.Qualification, t.Specialization,
			t.JoiningDate, t.Status, t.CreatedBy, t.UpdatedBy,
		).Scan(&t.TeacherID, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create teacher failed",
				util.String("company_id", t.CompanyID.String()),
				util.String("employee_code", t.EmployeeCode),
				util.ErrorField(err))
			return fmt.Errorf("bulk create teacher row: %w", err)
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

// GetByID (no version column in SELECT)
func (r *teacherRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Teacher, error) {
	query := `
        SELECT
            teacher_id, company_id, user_id, employee_code, qualification, specialization,
            joining_date, status,
            created_at, updated_at, created_by, updated_by
        FROM academics.teachers
        WHERE teacher_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanTeacher(row)
}

// GetByUserID (no version)
func (r *teacherRepository) GetByUserID(ctx context.Context, db DBTX, userID uuid.UUID) (*models.Teacher, error) {
	query := `
        SELECT
            teacher_id, company_id, user_id, employee_code, qualification, specialization,
            joining_date, status,
            created_at, updated_at, created_by, updated_by
        FROM academics.teachers
        WHERE user_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, userID)
	return r.scanTeacher(row)
}

// GetByEmployeeCode (no version)
func (r *teacherRepository) GetByEmployeeCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Teacher, error) {
	query := `
        SELECT
            teacher_id, company_id, user_id, employee_code, qualification, specialization,
            joining_date, status,
            created_at, updated_at, created_by, updated_by
        FROM academics.teachers
        WHERE company_id = $1 AND employee_code = $2 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanTeacher(row)
}

// GetByIDs (no version)
func (r *teacherRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Teacher, error) {
	if len(ids) == 0 {
		return []*models.Teacher{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT
            teacher_id, company_id, user_id, employee_code, qualification, specialization,
            joining_date, status,
            created_at, updated_at, created_by, updated_by
        FROM academics.teachers
        WHERE teacher_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get teachers by IDs", zap.Error(err))
		return nil, fmt.Errorf("get teachers by IDs: %w", err)
	}
	defer rows.Close()
	var result []*models.Teacher
	for rows.Next() {
		t, err := r.scanTeacher(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// List (no version)
func (r *teacherRepository) List(ctx context.Context, db DBTX, filter TeacherFilter, p Pagination, s Sort) ([]*models.Teacher, error) {
	where, args := r.buildTeacherFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)
	query := fmt.Sprintf(`
        SELECT
            teacher_id, company_id, user_id, employee_code, qualification, specialization,
            joining_date, status,
            created_at, updated_at, created_by, updated_by
        FROM academics.teachers t
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list teachers",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list teachers: %w", err)
	}
	defer rows.Close()
	var result []*models.Teacher
	for rows.Next() {
		t, err := r.scanTeacher(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// Count unchanged
func (r *teacherRepository) Count(ctx context.Context, db DBTX, filter TeacherFilter) (int64, error) {
	where, args := r.buildTeacherFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.teachers t %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count teachers",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count teachers: %w", err)
	}
	return count, nil
}

// Update – removed version check (optimistic locking removed)
func (r *teacherRepository) Update(ctx context.Context, db DBTX, t *models.Teacher) error {
	query := `
        UPDATE academics.teachers
        SET
            user_id = $2,
            employee_code = $3,
            qualification = $4,
            specialization = $5,
            joining_date = $6,
            status = $7,
            updated_by = $8,
            updated_at = NOW()
        WHERE teacher_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		t.TeacherID,
		t.UserID,
		t.EmployeeCode,
		t.Qualification,
		t.Specialization,
		t.JoiningDate,
		t.Status,
		t.UpdatedBy,
	).Scan(&t.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			var exists bool
			checkQuery := `SELECT EXISTS(SELECT 1 FROM academics.teachers WHERE teacher_id = $1 AND deleted_at IS NULL)`
			_ = db.QueryRowContext(ctx, checkQuery, t.TeacherID).Scan(&exists)
			if exists {
				return fmt.Errorf("%w: teacher %s update failed (maybe no changes?)", ErrNotFound, t.TeacherID)
			}
			return fmt.Errorf("%w: teacher %s", ErrNotFound, t.TeacherID)
		}
		r.logger.Error("failed to update teacher",
			util.String("id", t.TeacherID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update teacher: %w", err)
	}
	return nil
}

// UpdateStatus unchanged (no version)
func (r *teacherRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.teachers SET status = $2, updated_by = $3, updated_at = NOW() WHERE teacher_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update teacher status",
			util.String("id", id.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("update teacher status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("teacher %s not found or deleted", id)
	}
	return nil
}

// Delete unchanged
func (r *teacherRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.teachers SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE teacher_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete teacher",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete teacher: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("teacher %s not found or already deleted", id)
	}
	return nil
}

// BulkUpdateStatus unchanged
func (r *teacherRepository) BulkUpdateStatus(ctx context.Context, db DBTX, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error {
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
        UPDATE academics.teachers
        SET status = $1, updated_by = $2, updated_at = NOW()
        WHERE teacher_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk update teacher status",
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
		return fmt.Errorf("no teachers updated")
	}
	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// CountByCompany unchanged
func (r *teacherRepository) CountByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.teachers WHERE company_id = $1 AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, companyID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count teachers by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("count by company: %w", err)
	}
	return count, nil
}

// AddSubject unchanged
func (r *teacherRepository) AddSubject(ctx context.Context, db DBTX, teacherID, subjectID uuid.UUID, isPrimary bool) error {
	query := `
        INSERT INTO academics.teacher_subjects (teacher_id, subject_id, is_primary, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (teacher_id, subject_id) DO NOTHING
    `
	result, err := db.ExecContext(ctx, query, teacherID, subjectID, isPrimary)
	if err != nil {
		r.logger.Error("failed to add teacher subject",
			util.String("teacher_id", teacherID.String()),
			util.String("subject_id", subjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add teacher subject: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("teacher subject already exists")
	}
	return nil
}

// RemoveSubject unchanged
func (r *teacherRepository) RemoveSubject(ctx context.Context, db DBTX, teacherID, subjectID uuid.UUID) error {
	query := `DELETE FROM academics.teacher_subjects WHERE teacher_id = $1 AND subject_id = $2`
	result, err := db.ExecContext(ctx, query, teacherID, subjectID)
	if err != nil {
		r.logger.Error("failed to remove teacher subject",
			util.String("teacher_id", teacherID.String()),
			util.String("subject_id", subjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("remove teacher subject: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("teacher subject not found")
	}
	return nil
}

// GetSubjectsByTeacher unchanged
func (r *teacherRepository) GetSubjectsByTeacher(ctx context.Context, db DBTX, teacherID uuid.UUID) ([]*models.TeacherSubject, error) {
	query := `
        SELECT id, teacher_id, subject_id, is_primary, created_at
        FROM academics.teacher_subjects
        WHERE teacher_id = $1
    `
	rows, err := db.QueryContext(ctx, query, teacherID)
	if err != nil {
		r.logger.Error("failed to get subjects by teacher",
			util.String("teacher_id", teacherID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get subjects by teacher: %w", err)
	}
	defer rows.Close()
	var result []*models.TeacherSubject
	for rows.Next() {
		var ts models.TeacherSubject
		if err := rows.Scan(&ts.ID, &ts.TeacherID, &ts.SubjectID, &ts.IsPrimary, &ts.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan teacher subject: %w", err)
		}
		result = append(result, &ts)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// GetTeachersBySubject unchanged
func (r *teacherRepository) GetTeachersBySubject(ctx context.Context, db DBTX, subjectID uuid.UUID) ([]*models.Teacher, error) {
	query := `
        SELECT t.teacher_id, t.company_id, t.user_id, t.employee_code, t.qualification,
               t.specialization, t.joining_date, t.status,
               t.created_at, t.updated_at, t.created_by, t.updated_by
        FROM academics.teachers t
        INNER JOIN academics.teacher_subjects ts ON t.teacher_id = ts.teacher_id
        WHERE ts.subject_id = $1 AND t.deleted_at IS NULL
    `
	rows, err := db.QueryContext(ctx, query, subjectID)
	if err != nil {
		r.logger.Error("failed to get teachers by subject",
			util.String("subject_id", subjectID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get teachers by subject: %w", err)
	}
	defer rows.Close()
	var result []*models.Teacher
	for rows.Next() {
		t, err := r.scanTeacher(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// UpdateSubjectPrimary unchanged
func (r *teacherRepository) UpdateSubjectPrimary(ctx context.Context, db DBTX, teacherID, subjectID uuid.UUID, isPrimary bool) error {
	query := `
        UPDATE academics.teacher_subjects
        SET is_primary = $3
        WHERE teacher_id = $1 AND subject_id = $2
    `
	result, err := db.ExecContext(ctx, query, teacherID, subjectID, isPrimary)
	if err != nil {
		r.logger.Error("failed to update teacher subject primary",
			util.String("teacher_id", teacherID.String()),
			util.String("subject_id", subjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update teacher subject primary: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("teacher subject not found")
	}
	return nil
}

// AddSection unchanged
func (r *teacherRepository) AddSection(ctx context.Context, db DBTX, teacherID, sectionID uuid.UUID, isClassTeacher bool) error {
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
	if isClassTeacher {
		var existing uuid.UUID
		checkQuery := `SELECT teacher_id FROM academics.teacher_sections WHERE section_id = $1 AND is_class_teacher = true`
		err = tx.QueryRowContext(ctx, checkQuery, sectionID).Scan(&existing)
		if err == nil {
			return fmt.Errorf("section %s already has a class teacher (%s)", sectionID, existing)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check class teacher: %w", err)
		}
	}
	query := `
        INSERT INTO academics.teacher_sections (teacher_id, section_id, is_class_teacher, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (teacher_id, section_id) DO UPDATE SET is_class_teacher = EXCLUDED.is_class_teacher
    `
	_, err = tx.ExecContext(ctx, query, teacherID, sectionID, isClassTeacher)
	if err != nil {
		r.logger.Error("failed to add teacher section",
			util.String("teacher_id", teacherID.String()),
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add teacher section: %w", err)
	}
	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// RemoveSection unchanged
func (r *teacherRepository) RemoveSection(ctx context.Context, db DBTX, teacherID, sectionID uuid.UUID) error {
	query := `DELETE FROM academics.teacher_sections WHERE teacher_id = $1 AND section_id = $2`
	result, err := db.ExecContext(ctx, query, teacherID, sectionID)
	if err != nil {
		r.logger.Error("failed to remove teacher section",
			util.String("teacher_id", teacherID.String()),
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("remove teacher section: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("teacher section not found")
	}
	return nil
}

// GetSectionsByTeacher unchanged
func (r *teacherRepository) GetSectionsByTeacher(ctx context.Context, db DBTX, teacherID uuid.UUID) ([]*models.TeacherSection, error) {
	query := `
        SELECT id, teacher_id, section_id, is_class_teacher, created_at
        FROM academics.teacher_sections
        WHERE teacher_id = $1
    `
	rows, err := db.QueryContext(ctx, query, teacherID)
	if err != nil {
		r.logger.Error("failed to get sections by teacher",
			util.String("teacher_id", teacherID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get sections by teacher: %w", err)
	}
	defer rows.Close()
	var result []*models.TeacherSection
	for rows.Next() {
		var ts models.TeacherSection
		if err := rows.Scan(&ts.ID, &ts.TeacherID, &ts.SectionID, &ts.IsClassTeacher, &ts.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan teacher section: %w", err)
		}
		result = append(result, &ts)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// GetTeachersBySection (no version in SELECT)
func (r *teacherRepository) GetTeachersBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) ([]*models.Teacher, error) {
	query := `
        SELECT t.teacher_id, t.company_id, t.user_id, t.employee_code, t.qualification,
               t.specialization, t.joining_date, t.status,
               t.created_at, t.updated_at, t.created_by, t.updated_by
        FROM academics.teachers t
        INNER JOIN academics.teacher_sections ts ON t.teacher_id = ts.teacher_id
        WHERE ts.section_id = $1 AND t.deleted_at IS NULL
    `
	rows, err := db.QueryContext(ctx, query, sectionID)
	if err != nil {
		r.logger.Error("failed to get teachers by section",
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get teachers by section: %w", err)
	}
	defer rows.Close()
	var result []*models.Teacher
	for rows.Next() {
		t, err := r.scanTeacher(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// UpdateClassTeacherStatus unchanged
func (r *teacherRepository) UpdateClassTeacherStatus(ctx context.Context, db DBTX, teacherID, sectionID uuid.UUID, isClassTeacher bool) error {
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
	if isClassTeacher {
		var existing uuid.UUID
		checkQuery := `SELECT teacher_id FROM academics.teacher_sections WHERE section_id = $1 AND is_class_teacher = true AND teacher_id != $2`
		err = tx.QueryRowContext(ctx, checkQuery, sectionID, teacherID).Scan(&existing)
		if err == nil {
			return fmt.Errorf("section %s already has a class teacher (%s)", sectionID, existing)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check class teacher: %w", err)
		}
	}
	query := `
        UPDATE academics.teacher_sections
        SET is_class_teacher = $3
        WHERE teacher_id = $1 AND section_id = $2
    `
	result, err := tx.ExecContext(ctx, query, teacherID, sectionID, isClassTeacher)
	if err != nil {
		r.logger.Error("failed to update class teacher status",
			util.String("teacher_id", teacherID.String()),
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update class teacher status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("teacher section not found")
	}
	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// SetSchedulePreference unchanged (no version)
func (r *teacherRepository) SetSchedulePreference(ctx context.Context, db DBTX, pref *models.TeacherSchedulePreference) error {
	query := `
        INSERT INTO academics.teacher_schedule_preferences
            (preference_id, teacher_id, day_of_week, preferred_start_time, preferred_end_time, created_at, updated_at, created_by)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), $6)
        ON CONFLICT (teacher_id, day_of_week) DO UPDATE SET
            preferred_start_time = EXCLUDED.preferred_start_time,
            preferred_end_time = EXCLUDED.preferred_end_time,
            updated_at = NOW()
        RETURNING preference_id
    `
	if pref.PreferenceID == uuid.Nil {
		pref.PreferenceID = uuid.New()
	}
	err := db.QueryRowContext(ctx, query,
		pref.PreferenceID, pref.TeacherID, pref.DayOfWeek,
		pref.PreferredStartTime, pref.PreferredEndTime,
		pref.CreatedBy,
	).Scan(&pref.PreferenceID)
	if err != nil {
		r.logger.Error("failed to set schedule preference",
			util.String("teacher_id", pref.TeacherID.String()),
			zap.Int("day_of_week", pref.DayOfWeek),
			util.ErrorField(err))
		return fmt.Errorf("set schedule preference: %w", err)
	}
	return nil
}

// GetSchedulePreferences unchanged
func (r *teacherRepository) GetSchedulePreferences(ctx context.Context, db DBTX, teacherID uuid.UUID) ([]*models.TeacherSchedulePreference, error) {
	query := `
        SELECT preference_id, teacher_id, day_of_week, preferred_start_time, preferred_end_time,
               created_at, updated_at, created_by
        FROM academics.teacher_schedule_preferences
        WHERE teacher_id = $1
        ORDER BY day_of_week
    `
	rows, err := db.QueryContext(ctx, query, teacherID)
	if err != nil {
		r.logger.Error("failed to get schedule preferences",
			util.String("teacher_id", teacherID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get schedule preferences: %w", err)
	}
	defer rows.Close()
	var result []*models.TeacherSchedulePreference
	for rows.Next() {
		var pref models.TeacherSchedulePreference
		var createdBy uuid.NullUUID
		err := rows.Scan(
			&pref.PreferenceID, &pref.TeacherID, &pref.DayOfWeek,
			&pref.PreferredStartTime, &pref.PreferredEndTime,
			&pref.CreatedAt, &pref.UpdatedAt, &createdBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan preference: %w", err)
		}
		if createdBy.Valid {
			pref.CreatedBy = &createdBy.UUID
		}
		result = append(result, &pref)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// DeleteSchedulePreference unchanged
func (r *teacherRepository) DeleteSchedulePreference(ctx context.Context, db DBTX, preferenceID uuid.UUID) error {
	query := `DELETE FROM academics.teacher_schedule_preferences WHERE preference_id = $1`
	result, err := db.ExecContext(ctx, query, preferenceID)
	if err != nil {
		r.logger.Error("failed to delete schedule preference",
			util.String("preference_id", preferenceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete schedule preference: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("preference not found")
	}
	return nil
}

// UpdateSchedulePreference unchanged
func (r *teacherRepository) UpdateSchedulePreference(ctx context.Context, db DBTX, pref *models.TeacherSchedulePreference) error {
	query := `
        UPDATE academics.teacher_schedule_preferences
        SET day_of_week = $3, preferred_start_time = $4, preferred_end_time = $5, updated_at = NOW()
        WHERE preference_id = $1 AND teacher_id = $2
        RETURNING preference_id
    `
	err := db.QueryRowContext(ctx, query,
		pref.PreferenceID, pref.TeacherID, pref.DayOfWeek,
		pref.PreferredStartTime, pref.PreferredEndTime,
	).Scan(&pref.PreferenceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return r.SetSchedulePreference(ctx, db, pref)
		}
		r.logger.Error("failed to update schedule preference",
			util.String("preference_id", pref.PreferenceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update schedule preference: %w", err)
	}
	return nil
}

// ClearSchedulePreferences unchanged
func (r *teacherRepository) ClearSchedulePreferences(ctx context.Context, db DBTX, teacherID uuid.UUID) error {
	query := `DELETE FROM academics.teacher_schedule_preferences WHERE teacher_id = $1`
	_, err := db.ExecContext(ctx, query, teacherID)
	if err != nil {
		r.logger.Error("failed to clear schedule preferences",
			util.String("teacher_id", teacherID.String()),
			util.ErrorField(err))
		return fmt.Errorf("clear schedule preferences: %w", err)
	}
	return nil
}

// scanTeacher – removed version column
func (r *teacherRepository) scanTeacher(row scanner) (*models.Teacher, error) {
	var t models.Teacher
	var joiningDate sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	err := row.Scan(
		&t.TeacherID,
		&t.CompanyID,
		&t.UserID,
		&t.EmployeeCode,
		&t.Qualification,
		&t.Specialization,
		&joiningDate,
		&t.Status,
		&t.CreatedAt,
		&t.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan teacher: %w", err)
	}
	if joiningDate.Valid {
		t.JoiningDate = &joiningDate.Time
	}
	if createdBy.Valid {
		t.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		t.UpdatedBy = &updatedBy.UUID
	}
	return &t, nil
}
