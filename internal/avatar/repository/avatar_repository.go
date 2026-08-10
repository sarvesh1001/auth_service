package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"auth-service/internal/avatar/errors"
	"auth-service/internal/avatar/models"
	"auth-service/internal/kyc/repository" // for DBTX interface

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AvatarRepository defines the data access operations
type AvatarRepository interface {
	Create(ctx context.Context, db repository.DBTX, avatar *models.Avatar) error
	GetByID(ctx context.Context, db repository.DBTX, id uuid.UUID) (*models.Avatar, error)
	// GetByUser returns only active avatars (is_active = true)
	GetByUser(ctx context.Context, db repository.DBTX, userID uuid.UUID) ([]*models.Avatar, error)
	// GetInactiveByUser returns only soft‑deleted avatars (is_active = false)
	GetInactiveByUser(ctx context.Context, db repository.DBTX, userID uuid.UUID) ([]*models.Avatar, error)
	GetPrimaryByUser(ctx context.Context, db repository.DBTX, userID uuid.UUID) (*models.Avatar, error)
	Update(ctx context.Context, db repository.DBTX, avatar *models.Avatar) error
	UpdateVariants(ctx context.Context, db repository.DBTX, id uuid.UUID, variants map[string]string) error
	UpdatePrimary(ctx context.Context, db repository.DBTX, userID uuid.UUID, avatarID uuid.UUID) error
	Delete(ctx context.Context, db repository.DBTX, id uuid.UUID) error
	// Reactivate sets is_active = true for a soft‑deleted avatar
	Reactivate(ctx context.Context, db repository.DBTX, id uuid.UUID) error
	Exists(ctx context.Context, db repository.DBTX, id uuid.UUID) (bool, error)
}

type avatarRepository struct {
	logger *zap.Logger
}

func NewAvatarRepository(logger *zap.Logger) AvatarRepository {
	return &avatarRepository{logger: logger.Named("avatar_repo")}
}

// helpers
func (r *avatarRepository) scanAvatar(row scanner) (*models.Avatar, error) {
	var a models.Avatar
	var variantsJSON []byte
	var hash sql.NullString
	var mime sql.NullString

	err := row.Scan(
		&a.ID,
		&a.UserID,
		&a.Type,
		&hash,
		&a.ObjectKey,
		&mime,
		&a.IsActive,
		&a.IsPrimary,
		&variantsJSON,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan avatar: %w", err)
	}
	if hash.Valid {
		a.Hash = hash.String
	}
	if mime.Valid {
		a.MimeType = mime.String
	}
	if len(variantsJSON) > 0 {
		if err := json.Unmarshal(variantsJSON, &a.Variants); err != nil {
			return nil, fmt.Errorf("unmarshal variants: %w", err)
		}
	}
	return &a, nil
}

// Create inserts a new avatar record
func (r *avatarRepository) Create(ctx context.Context, db repository.DBTX, avatar *models.Avatar) error {
	query := `
		INSERT INTO user_avatars (
			avatar_id, user_id, avatar_type, avatar_hash, avatar_object_key,
			avatar_mime_type, is_active, is_primary, variants, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	variantsJSON, _ := json.Marshal(avatar.Variants)
	err := db.QueryRowContext(ctx, query,
		avatar.ID,
		avatar.UserID,
		avatar.Type,
		avatar.Hash,
		avatar.ObjectKey,
		avatar.MimeType,
		avatar.IsActive,
		avatar.IsPrimary,
		variantsJSON,
	).Scan(&avatar.CreatedAt, &avatar.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create avatar: %w", err)
	}
	return nil
}

// GetByID retrieves an avatar by its ID
func (r *avatarRepository) GetByID(ctx context.Context, db repository.DBTX, id uuid.UUID) (*models.Avatar, error) {
	query := `
		SELECT avatar_id, user_id, avatar_type, avatar_hash, avatar_object_key,
			avatar_mime_type, is_active, is_primary, variants,
			created_at, updated_at
		FROM user_avatars
		WHERE avatar_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanAvatar(row)
}

// GetByUser returns only active avatars (is_active = true) for a user.
func (r *avatarRepository) GetByUser(ctx context.Context, db repository.DBTX, userID uuid.UUID) ([]*models.Avatar, error) {
	query := `
		SELECT avatar_id, user_id, avatar_type, avatar_hash, avatar_object_key,
			avatar_mime_type, is_active, is_primary, variants,
			created_at, updated_at
		FROM user_avatars
		WHERE user_id = $1 AND is_active = true
		ORDER BY is_primary DESC, created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get by user: %w", err)
	}
	defer rows.Close()
	var avatars []*models.Avatar
	for rows.Next() {
		av, err := r.scanAvatar(rows)
		if err != nil {
			return nil, err
		}
		avatars = append(avatars, av)
	}
	return avatars, rows.Err()
}

// GetInactiveByUser returns only soft‑deleted (is_active = false) avatars for a user.
func (r *avatarRepository) GetInactiveByUser(ctx context.Context, db repository.DBTX, userID uuid.UUID) ([]*models.Avatar, error) {
	query := `
		SELECT avatar_id, user_id, avatar_type, avatar_hash, avatar_object_key,
			avatar_mime_type, is_active, is_primary, variants,
			created_at, updated_at
		FROM user_avatars
		WHERE user_id = $1 AND is_active = false
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get inactive by user: %w", err)
	}
	defer rows.Close()
	var avatars []*models.Avatar
	for rows.Next() {
		av, err := r.scanAvatar(rows)
		if err != nil {
			return nil, err
		}
		avatars = append(avatars, av)
	}
	return avatars, rows.Err()
}

// GetPrimaryByUser returns the active primary avatar for a user
func (r *avatarRepository) GetPrimaryByUser(ctx context.Context, db repository.DBTX, userID uuid.UUID) (*models.Avatar, error) {
	query := `
		SELECT avatar_id, user_id, avatar_type, avatar_hash, avatar_object_key,
			avatar_mime_type, is_active, is_primary, variants,
			created_at, updated_at
		FROM user_avatars
		WHERE user_id = $1 AND is_primary = true AND is_active = true
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, userID)
	return r.scanAvatar(row)
}

// Update updates all fields (except variants, use UpdateVariants for that)
func (r *avatarRepository) Update(ctx context.Context, db repository.DBTX, avatar *models.Avatar) error {
	query := `
		UPDATE user_avatars SET
			avatar_type = $2,
			avatar_hash = $3,
			avatar_object_key = $4,
			avatar_mime_type = $5,
			is_active = $6,
			is_primary = $7,
			updated_at = NOW()
		WHERE avatar_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		avatar.ID,
		avatar.Type,
		avatar.Hash,
		avatar.ObjectKey,
		avatar.MimeType,
		avatar.IsActive,
		avatar.IsPrimary,
	).Scan(&avatar.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update avatar: %w", err)
	}
	return nil
}

// UpdateVariants updates only the variants JSONB
func (r *avatarRepository) UpdateVariants(ctx context.Context, db repository.DBTX, id uuid.UUID, variants map[string]string) error {
	variantsJSON, _ := json.Marshal(variants)
	query := `
		UPDATE user_avatars
		SET variants = $2, updated_at = NOW()
		WHERE avatar_id = $1
	`
	res, err := db.ExecContext(ctx, query, id, variantsJSON)
	if err != nil {
		return fmt.Errorf("update variants: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// UpdatePrimary atomically sets one avatar as primary for a user (sets all others to false)
func (r *avatarRepository) UpdatePrimary(ctx context.Context, db repository.DBTX, userID uuid.UUID, avatarID uuid.UUID) error {
	// We assume the caller provides a transaction if needed.
	// First, set all to false for this user
	_, err := db.ExecContext(ctx, `
		UPDATE user_avatars
		SET is_primary = false, updated_at = NOW()
		WHERE user_id = $1 AND is_primary = true
	`, userID)
	if err != nil {
		return fmt.Errorf("reset primary: %w", err)
	}
	// Then set the chosen one to true
	_, err = db.ExecContext(ctx, `
		UPDATE user_avatars
		SET is_primary = true, updated_at = NOW()
		WHERE avatar_id = $1
	`, avatarID)
	if err != nil {
		return fmt.Errorf("set primary: %w", err)
	}
	return nil
}

// Delete soft-deletes (sets is_active = false) an avatar
func (r *avatarRepository) Delete(ctx context.Context, db repository.DBTX, id uuid.UUID) error {
	query := `
		UPDATE user_avatars
		SET is_active = false, updated_at = NOW()
		WHERE avatar_id = $1 AND is_active = true
	`
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete avatar: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Reactivate sets is_active = true for the given avatar (soft‑delete undo)
func (r *avatarRepository) Reactivate(ctx context.Context, db repository.DBTX, id uuid.UUID) error {
	query := `
		UPDATE user_avatars
		SET is_active = true, updated_at = NOW()
		WHERE avatar_id = $1
	`
	res, err := db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("reactivate avatar: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// Exists checks if an avatar exists (optionally active)
func (r *avatarRepository) Exists(ctx context.Context, db repository.DBTX, id uuid.UUID) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_avatars WHERE avatar_id = $1)`, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}
