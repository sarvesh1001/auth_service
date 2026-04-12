// internal/academics/repository/student_auth_repo.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/encryption"
	"auth-service/internal/util"
)

// StudentAuthRepository defines operations for student authentication.
type StudentAuthRepository interface {
	// GetByStudentID returns the auth record for a student (including encrypted fields).
	GetByStudentID(ctx context.Context, db DBTX, studentID uuid.UUID) (*models.StudentAuth, error)

	// SetPassword encrypts and stores the password for the student.
	SetPassword(ctx context.Context, db DBTX, studentID uuid.UUID, password string, updatedBy *uuid.UUID) error

	// VerifyPassword checks if the provided plaintext password matches the stored encrypted password.
	VerifyPassword(ctx context.Context, db DBTX, studentID uuid.UUID, password string) (bool, error)

	// HasPassword returns true if the student has a password set.
	HasPassword(ctx context.Context, db DBTX, studentID uuid.UUID) (bool, error)

	// UpdateLoginAttempts increments or sets the login attempts counter.
	// If attempts is provided, it sets that value; otherwise increments by 1.
	UpdateLoginAttempts(ctx context.Context, db DBTX, studentID uuid.UUID, attempts *int) error

	// RecordLoginSuccess resets attempts to 0, sets LastLoginAt to now, and clears locked_until.
	RecordLoginSuccess(ctx context.Context, db DBTX, studentID uuid.UUID) error

	// LockAccount sets LockedUntil to the given time (default: 30 minutes from now if not provided).
	LockAccount(ctx context.Context, db DBTX, studentID uuid.UUID, until *time.Time) error

	// IsLocked checks if the account is currently locked (locked_until > now).
	IsLocked(ctx context.Context, db DBTX, studentID uuid.UUID) (bool, error)

	// ResetPassword changes the password (similar to SetPassword but may require additional checks).
	ResetPassword(ctx context.Context, db DBTX, studentID uuid.UUID, newPassword string, updatedBy *uuid.UUID) error

	// DeletePassword removes the password (e.g., when disabling login for a student).
	DeletePassword(ctx context.Context, db DBTX, studentID uuid.UUID, updatedBy *uuid.UUID) error
}

type studentAuthRepository struct {
	logger     *zap.Logger
	encryption *encryption.EncryptionManager
}

// NewStudentAuthRepository creates a new student auth repository.
func NewStudentAuthRepository(logger *zap.Logger, encryptionManager *encryption.EncryptionManager) StudentAuthRepository {
	return &studentAuthRepository{
		logger:     logger.Named("student_auth_repo"),
		encryption: encryptionManager,
	}
}

// --- Helper encryption functions (reusing the same pattern) ---

func (r *studentAuthRepository) encryptPassword(ctx context.Context, plaintext string) (*encryption.EncryptedData, error) {
	if plaintext == "" {
		return &encryption.EncryptedData{
			EncryptedValue: "",
			EncryptedDEK:   "",
			KeyID:          "",
		}, nil
	}
	return r.encryption.EncryptField(ctx, plaintext, "student_password")
}

func (r *studentAuthRepository) decryptPassword(ctx context.Context, encValue, encDEK, keyID string) (string, error) {
	if encValue == "" || encDEK == "" || keyID == "" {
		return "", nil
	}
	return r.encryption.DecryptField(ctx, &encryption.EncryptedData{
		EncryptedValue: encValue,
		EncryptedDEK:   encDEK,
		KeyID:          keyID,
	})
}

// --- GetByStudentID ---

func (r *studentAuthRepository) GetByStudentID(ctx context.Context, db DBTX, studentID uuid.UUID) (*models.StudentAuth, error) {
	query := `
        SELECT student_auth_id, student_id,
               password, password_dek, password_key_id,
               last_login_at, login_attempts, locked_until,
               created_at, updated_at, created_by, updated_by, deleted_at
        FROM academics.student_auth
        WHERE student_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, studentID)
	return r.scanStudentAuth(ctx, row)
}

func (r *studentAuthRepository) scanStudentAuth(ctx context.Context, row scanner) (*models.StudentAuth, error) {
	var sa models.StudentAuth
	var (
		password, passwordDEK, passwordKeyID sql.NullString
		lastLoginAt, lockedUntil             sql.NullTime
		createdBy, updatedBy                 uuid.NullUUID
		deletedAt                            sql.NullTime
	)

	err := row.Scan(
		&sa.StudentAuthID,
		&sa.StudentID,
		&password,
		&passwordDEK,
		&passwordKeyID,
		&lastLoginAt,
		&sa.LoginAttempts,
		&lockedUntil,
		&sa.CreatedAt,
		&sa.UpdatedAt,
		&createdBy,
		&updatedBy,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan student auth: %w", err)
	}

	// Decrypt password fields if present
	if password.Valid {
		plain, _ := r.decryptPassword(ctx, password.String, passwordDEK.String, passwordKeyID.String)
		if plain != "" {
			sa.Password = &plain
		}
		// Store the encrypted values? Not needed in model; we only need plaintext for comparison.
		// But we'll store them if needed for re-encryption later.
		// For simplicity, we keep the encrypted fields in the model as optional strings.
		sa.PasswordDEK = &passwordDEK.String
		sa.PasswordKeyID = &passwordKeyID.String
	}

	if lastLoginAt.Valid {
		sa.LastLoginAt = &lastLoginAt.Time
	}
	if lockedUntil.Valid {
		sa.LockedUntil = &lockedUntil.Time
	}
	if createdBy.Valid {
		sa.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		sa.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		sa.DeletedAt = &deletedAt.Time
	}

	return &sa, nil
}

// --- SetPassword ---

func (r *studentAuthRepository) SetPassword(ctx context.Context, db DBTX, studentID uuid.UUID, password string, updatedBy *uuid.UUID) error {
	// Encrypt password
	enc, err := r.encryptPassword(ctx, password)
	if err != nil {
		return fmt.Errorf("encrypt password: %w", err)
	}

	// Check if record already exists
	existing, err := r.GetByStudentID(ctx, db, studentID)
	if err != nil {
		return err
	}

	if existing == nil {
		// Insert new record – existing is nil, so we cannot scan into it.
		// Create a new struct to hold the returned values.
		query := `
            INSERT INTO academics.student_auth (
                student_id, password, password_dek, password_key_id,
                login_attempts, created_by, updated_by, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, 0, $5, $6, NOW(), NOW())
            RETURNING student_auth_id, created_at, updated_at
        `
		var newAuth models.StudentAuth
		err = db.QueryRowContext(ctx, query,
			studentID,
			enc.EncryptedValue,
			enc.EncryptedDEK,
			enc.KeyID,
			updatedBy,
			updatedBy,
		).Scan(&newAuth.StudentAuthID, &newAuth.CreatedAt, &newAuth.UpdatedAt)
		if err != nil {
			r.logger.Error("failed to set password (insert)",
				util.String("student_id", studentID.String()),
				util.ErrorField(err))
			return fmt.Errorf("set password (insert): %w", err)
		}
		// newAuth is now populated; we don't need to assign it to existing
	} else {
		// Update existing record
		query := `
            UPDATE academics.student_auth
            SET password = $2, password_dek = $3, password_key_id = $4,
                updated_by = $5, updated_at = NOW()
            WHERE student_id = $1 AND deleted_at IS NULL
        `
		result, err := db.ExecContext(ctx, query,
			studentID,
			enc.EncryptedValue,
			enc.EncryptedDEK,
			enc.KeyID,
			updatedBy,
		)
		if err != nil {
			r.logger.Error("failed to set password (update)",
				util.String("student_id", studentID.String()),
				util.ErrorField(err))
			return fmt.Errorf("set password (update): %w", err)
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			return fmt.Errorf("no student auth record found for %s", studentID)
		}
	}
	return nil
}

// --- VerifyPassword ---

func (r *studentAuthRepository) VerifyPassword(ctx context.Context, db DBTX, studentID uuid.UUID, password string) (bool, error) {
	// Get the encrypted password
	query := `
        SELECT password, password_dek, password_key_id
        FROM academics.student_auth
        WHERE student_id = $1 AND deleted_at IS NULL
    `
	var encValue, encDEK, keyID sql.NullString
	err := db.QueryRowContext(ctx, query, studentID).Scan(&encValue, &encDEK, &keyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // No password set
		}
		return false, fmt.Errorf("query password: %w", err)
	}

	if !encValue.Valid || !encDEK.Valid || !keyID.Valid {
		return false, nil // No password
	}

	// Decrypt stored password
	storedPlain, err := r.decryptPassword(ctx, encValue.String, encDEK.String, keyID.String)
	if err != nil {
		r.logger.Error("failed to decrypt password for verification",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("decrypt password: %w", err)
	}

	// Compare plaintext
	return storedPlain == password, nil
}

// --- HasPassword ---

func (r *studentAuthRepository) HasPassword(ctx context.Context, db DBTX, studentID uuid.UUID) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1 FROM academics.student_auth
            WHERE student_id = $1 AND deleted_at IS NULL
              AND password IS NOT NULL AND password != ''
        )
    `
	var exists bool
	err := db.QueryRowContext(ctx, query, studentID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has password: %w", err)
	}
	return exists, nil
}

// --- UpdateLoginAttempts ---

func (r *studentAuthRepository) UpdateLoginAttempts(ctx context.Context, db DBTX, studentID uuid.UUID, attempts *int) error {
	var query string
	var args []interface{}

	if attempts != nil {
		query = `
            UPDATE academics.student_auth
            SET login_attempts = $2, updated_at = NOW()
            WHERE student_id = $1 AND deleted_at IS NULL
        `
		args = []interface{}{studentID, *attempts}
	} else {
		query = `
            UPDATE academics.student_auth
            SET login_attempts = login_attempts + 1, updated_at = NOW()
            WHERE student_id = $1 AND deleted_at IS NULL
        `
		args = []interface{}{studentID}
	}

	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to update login attempts",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update login attempts: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no student auth record for %s", studentID)
	}
	return nil
}

// --- RecordLoginSuccess ---

func (r *studentAuthRepository) RecordLoginSuccess(ctx context.Context, db DBTX, studentID uuid.UUID) error {
	query := `
        UPDATE academics.student_auth
        SET login_attempts = 0,
            last_login_at = NOW(),
            locked_until = NULL,
            updated_at = NOW()
        WHERE student_id = $1 AND deleted_at IS NULL
    `
	result, err := db.ExecContext(ctx, query, studentID)
	if err != nil {
		r.logger.Error("failed to record login success",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("record login success: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no student auth record for %s", studentID)
	}
	return nil
}

// --- LockAccount ---

func (r *studentAuthRepository) LockAccount(ctx context.Context, db DBTX, studentID uuid.UUID, until *time.Time) error {
	lockUntil := until
	if lockUntil == nil {
		// Default lock for 30 minutes
		t := time.Now().Add(30 * time.Minute)
		lockUntil = &t
	}

	query := `
        UPDATE academics.student_auth
        SET locked_until = $2, updated_at = NOW()
        WHERE student_id = $1 AND deleted_at IS NULL
    `
	result, err := db.ExecContext(ctx, query, studentID, lockUntil)
	if err != nil {
		r.logger.Error("failed to lock account",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("lock account: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no student auth record for %s", studentID)
	}
	return nil
}

// --- IsLocked ---

func (r *studentAuthRepository) IsLocked(ctx context.Context, db DBTX, studentID uuid.UUID) (bool, error) {
	query := `
        SELECT locked_until FROM academics.student_auth
        WHERE student_id = $1 AND deleted_at IS NULL
    `
	var lockedUntil sql.NullTime
	err := db.QueryRowContext(ctx, query, studentID).Scan(&lockedUntil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("is locked: %w", err)
	}
	if !lockedUntil.Valid {
		return false, nil
	}
	return lockedUntil.Time.After(time.Now()), nil
}

// --- ResetPassword ---

func (r *studentAuthRepository) ResetPassword(ctx context.Context, db DBTX, studentID uuid.UUID, newPassword string, updatedBy *uuid.UUID) error {
	// Simply call SetPassword
	return r.SetPassword(ctx, db, studentID, newPassword, updatedBy)
}

// --- DeletePassword ---

func (r *studentAuthRepository) DeletePassword(ctx context.Context, db DBTX, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
        UPDATE academics.student_auth
        SET password = NULL, password_dek = NULL, password_key_id = NULL,
            updated_by = $2, updated_at = NOW()
        WHERE student_id = $1 AND deleted_at IS NULL
    `
	result, err := db.ExecContext(ctx, query, studentID, updatedBy)
	if err != nil {
		r.logger.Error("failed to delete password",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete password: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no student auth record for %s", studentID)
	}
	return nil
}
