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

// GuardianRepository defines operations for guardians.
type GuardianRepository interface {
	Create(ctx context.Context, db DBTX, g *models.Guardian) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Guardian, error)
	GetByStudentID(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.Guardian, error)
	GetPrimaryGuardian(ctx context.Context, db DBTX, studentID uuid.UUID) (*models.Guardian, error)
	List(ctx context.Context, db DBTX, filter GuardianFilter, p Pagination, s Sort) ([]*models.Guardian, error)
	Count(ctx context.Context, db DBTX, filter GuardianFilter) (int64, error)
	Update(ctx context.Context, db DBTX, g *models.Guardian) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error
	BulkCreate(ctx context.Context, db DBTX, guardians []*models.Guardian) error
	SetPrimary(ctx context.Context, db DBTX, studentID, guardianID uuid.UUID) error // make this guardian primary and unset others
}

type guardianRepository struct {
	logger     *zap.Logger
	encryption *encryption.EncryptionManager
}

// NewGuardianRepository creates a new guardian repository with encryption.
func NewGuardianRepository(logger *zap.Logger, encryptionManager *encryption.EncryptionManager) GuardianRepository {
	return &guardianRepository{
		logger:     logger.Named("guardian_repo"),
		encryption: encryptionManager,
	}
}

// Allowed sort fields
var allowedGuardianSortFields = map[string]bool{
	"created_at":    true,
	"updated_at":    true,
	"guardian_name": true,
	"relation":      true,
	"is_primary":    true,
}

func (r *guardianRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedGuardianSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *guardianRepository) validatePagination(p Pagination) (int, int) {
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

// --- Encryption helpers ------------------------------------------------

func (r *guardianRepository) encryptField(ctx context.Context, plaintext, purpose string) (*encryption.EncryptedData, error) {
	if plaintext == "" {
		return &encryption.EncryptedData{
			EncryptedValue: "",
			EncryptedDEK:   "",
			KeyID:          "",
		}, nil
	}
	return r.encryption.EncryptField(ctx, plaintext, purpose)
}

func (r *guardianRepository) decryptField(ctx context.Context, encValue, encDEK, keyID string) (string, error) {
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

func (r *guardianRepository) buildGuardianFilter(filter GuardianFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.StudentID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", idx))
		args = append(args, filter.StudentID)
		idx++
	}

	if filter.IsPrimary != nil {
		conditions = append(conditions, fmt.Sprintf("is_primary = $%d", idx))
		args = append(args, *filter.IsPrimary)
		idx++
	}

	if filter.Relation != "" {
		conditions = append(conditions, fmt.Sprintf("relation = $%d", idx))
		args = append(args, filter.Relation)
		idx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("guardian_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// --- Create ------------------------------------------------------------

func (r *guardianRepository) Create(ctx context.Context, db DBTX, g *models.Guardian) error {
	encPhone, err := r.encryptField(ctx, g.Phone, "guardian_phone")
	if err != nil {
		return err
	}
	encEmail, err := r.encryptField(ctx, g.Email, "guardian_email")
	if err != nil {
		return err
	}

	query := `
        INSERT INTO academics.student_guardians (
            student_id, guardian_name, relation,
            phone, phone_dek, phone_key_id,
            email, email_dek, email_key_id,
            address, is_primary, occupation, income,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
        RETURNING guardian_id, created_at, updated_at
    `
	err = db.QueryRowContext(ctx, query,
		g.StudentID, g.GuardianName, g.Relation,
		encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
		encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
		g.Address, g.IsPrimary, g.Occupation, g.Income,
	).Scan(&g.GuardianID, &g.CreatedAt, &g.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create guardian",
			util.String("student_id", g.StudentID.String()),
			util.String("guardian_name", g.GuardianName),
			util.ErrorField(err))
		return fmt.Errorf("create guardian: %w", err)
	}
	return nil
}

// --- GetByID ------------------------------------------------------------

func (r *guardianRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Guardian, error) {
	query := `
        SELECT guardian_id, student_id, guardian_name, relation,
               phone, phone_dek, phone_key_id,
               email, email_dek, email_key_id,
               address, is_primary, occupation, income,
               created_at, updated_at
        FROM academics.student_guardians
        WHERE guardian_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanGuardian(ctx, row)
}

// --- GetByStudentID -----------------------------------------------------

func (r *guardianRepository) GetByStudentID(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.Guardian, error) {
	query := `
        SELECT guardian_id, student_id, guardian_name, relation,
               phone, phone_dek, phone_key_id,
               email, email_dek, email_key_id,
               address, is_primary, occupation, income,
               created_at, updated_at
        FROM academics.student_guardians
        WHERE student_id = $1
        ORDER BY is_primary DESC, guardian_name
    `
	rows, err := db.QueryContext(ctx, query, studentID)
	if err != nil {
		r.logger.Error("failed to get guardians by student ID",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get guardians by student ID: %w", err)
	}
	defer rows.Close()

	var guardians []*models.Guardian
	for rows.Next() {
		g, err := r.scanGuardian(ctx, rows)
		if err != nil {
			return nil, err
		}
		guardians = append(guardians, g)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return guardians, nil
}

// --- GetPrimaryGuardian -------------------------------------------------

func (r *guardianRepository) GetPrimaryGuardian(ctx context.Context, db DBTX, studentID uuid.UUID) (*models.Guardian, error) {
	query := `
        SELECT guardian_id, student_id, guardian_name, relation,
               phone, phone_dek, phone_key_id,
               email, email_dek, email_key_id,
               address, is_primary, occupation, income,
               created_at, updated_at
        FROM academics.student_guardians
        WHERE student_id = $1 AND is_primary = true
    `
	row := db.QueryRowContext(ctx, query, studentID)
	return r.scanGuardian(ctx, row)
}

// --- List ---------------------------------------------------------------

func (r *guardianRepository) List(ctx context.Context, db DBTX, filter GuardianFilter, p Pagination, s Sort) ([]*models.Guardian, error) {
	where, args := r.buildGuardianFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT guardian_id, student_id, guardian_name, relation,
               phone, phone_dek, phone_key_id,
               email, email_dek, email_key_id,
               address, is_primary, occupation, income,
               created_at, updated_at
        FROM academics.student_guardians
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list guardians",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list guardians: %w", err)
	}
	defer rows.Close()

	var result []*models.Guardian
	for rows.Next() {
		g, err := r.scanGuardian(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Count --------------------------------------------------------------

func (r *guardianRepository) Count(ctx context.Context, db DBTX, filter GuardianFilter) (int64, error) {
	where, args := r.buildGuardianFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_guardians %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count guardians",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count guardians: %w", err)
	}
	return count, nil
}

// --- Update -------------------------------------------------------------

func (r *guardianRepository) Update(ctx context.Context, db DBTX, g *models.Guardian) error {
	encPhone, err := r.encryptField(ctx, g.Phone, "guardian_phone")
	if err != nil {
		return err
	}
	encEmail, err := r.encryptField(ctx, g.Email, "guardian_email")
	if err != nil {
		return err
	}

	query := `
        UPDATE academics.student_guardians
        SET
            guardian_name = $2,
            relation = $3,
            phone = $4,
            phone_dek = $5,
            phone_key_id = $6,
            email = $7,
            email_dek = $8,
            email_key_id = $9,
            address = $10,
            is_primary = $11,
            occupation = $12,
            income = $13,
            updated_at = NOW()
        WHERE guardian_id = $1
        RETURNING updated_at
    `
	err = db.QueryRowContext(ctx, query,
		g.GuardianID,
		g.GuardianName,
		g.Relation,
		encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
		encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
		g.Address, g.IsPrimary, g.Occupation, g.Income,
	).Scan(&g.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: guardian %s", ErrNotFound, g.GuardianID)
		}
		r.logger.Error("failed to update guardian",
			util.String("id", g.GuardianID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update guardian: %w", err)
	}
	return nil
}

// --- Delete -------------------------------------------------------------

func (r *guardianRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_guardians WHERE guardian_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete guardian",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete guardian: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: guardian %s", ErrNotFound, id)
	}
	return nil
}

// --- BulkCreate ---------------------------------------------------------

func (r *guardianRepository) BulkCreate(ctx context.Context, db DBTX, guardians []*models.Guardian) error {
	if len(guardians) == 0 {
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
        INSERT INTO academics.student_guardians (
            student_id, guardian_name, relation,
            phone, phone_dek, phone_key_id,
            email, email_dek, email_key_id,
            address, is_primary, occupation, income,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
        RETURNING guardian_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, g := range guardians {
		encPhone, err := r.encryptField(ctx, g.Phone, "guardian_phone")
		if err != nil {
			return err
		}
		encEmail, err := r.encryptField(ctx, g.Email, "guardian_email")
		if err != nil {
			return err
		}

		err = stmt.QueryRowContext(ctx,
			g.StudentID, g.GuardianName, g.Relation,
			encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
			encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
			g.Address, g.IsPrimary, g.Occupation, g.Income,
		).Scan(&g.GuardianID, &g.CreatedAt, &g.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create guardian failed",
				util.String("student_id", g.StudentID.String()),
				util.String("guardian_name", g.GuardianName),
				util.ErrorField(err))
			return fmt.Errorf("bulk create guardian row: %w", err)
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

// --- SetPrimary ---------------------------------------------------------

func (r *guardianRepository) SetPrimary(ctx context.Context, db DBTX, studentID, guardianID uuid.UUID) error {
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

	// Unset all primary for this student
	_, err = tx.ExecContext(ctx, `
        UPDATE academics.student_guardians
        SET is_primary = false, updated_at = NOW()
        WHERE student_id = $1
    `, studentID)
	if err != nil {
		return fmt.Errorf("unset primary guardians: %w", err)
	}

	// Set the selected one as primary
	result, err := tx.ExecContext(ctx, `
        UPDATE academics.student_guardians
        SET is_primary = true, updated_at = NOW()
        WHERE guardian_id = $1 AND student_id = $2
    `, guardianID, studentID)
	if err != nil {
		return fmt.Errorf("set primary guardian: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("guardian %s not found for student %s", guardianID, studentID)
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// --- scanGuardian -------------------------------------------------------

func (r *guardianRepository) scanGuardian(ctx context.Context, row scanner) (*models.Guardian, error) {
	var g models.Guardian
	var phoneEnc, phoneDEK, phoneKeyID sql.NullString
	var emailEnc, emailDEK, emailKeyID sql.NullString
	var income sql.NullFloat64

	err := row.Scan(
		&g.GuardianID,
		&g.StudentID,
		&g.GuardianName,
		&g.Relation,
		&phoneEnc, &phoneDEK, &phoneKeyID,
		&emailEnc, &emailDEK, &emailKeyID,
		&g.Address,
		&g.IsPrimary,
		&g.Occupation,
		&income,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan guardian: %w", err)
	}

	// Decrypt
	if phoneEnc.Valid {
		g.Phone, _ = r.decryptField(ctx, phoneEnc.String, phoneDEK.String, phoneKeyID.String)
	}
	if emailEnc.Valid {
		g.Email, _ = r.decryptField(ctx, emailEnc.String, emailDEK.String, emailKeyID.String)
	}
	if income.Valid {
		g.Income = &income.Float64
	}

	return &g, nil
}
