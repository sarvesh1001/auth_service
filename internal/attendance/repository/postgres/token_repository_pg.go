package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

type tokenRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewTokenRepository creates a new token repository.
func NewTokenRepository(pg *client.PostgresClient, logger *zap.Logger) repository.TokenRepository {
	return &tokenRepository{
		client: pg,
		logger: logger.Named("token_repo"),
	}
}

// CreateToken inserts a new device token.
func (r *tokenRepository) CreateToken(ctx context.Context, tx *sql.Tx, token *models.DeviceToken) error {
	if token.TokenID == uuid.Nil {
		token.TokenID = uuid.New()
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = token.CreatedAt
	}

	query := `
		INSERT INTO attendance.attendance_device_tokens (
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	metadataJSON, _ := json.Marshal(token.Metadata)

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		token.TokenID,
		token.CompanyID,
		token.DeviceID,
		token.SourceType,
		token.TokenHash,
		token.TokenVersion,
		token.IsActive,
		token.IssuedAt,
		token.ExpiresAt,
		token.RevokedAt,
		token.IssuedBy,
		token.RevokedBy,
		token.RevokeReason,
		metadataJSON,
		token.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create device token",
			util.String("token_id", token.TokenID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create token: %w", err)
	}
	return nil
}

// GetActiveTokenByHash retrieves an active token by its hash for a specific device.
func (r *tokenRepository) GetActiveTokenByHash(ctx context.Context, companyID uuid.UUID, deviceID, tokenHash string) (*models.DeviceToken, error) {
	query := `
		SELECT
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		FROM attendance.attendance_device_tokens
		WHERE company_id = $1
			AND device_id = $2
			AND token_hash = $3
			AND is_active = true
			AND (expires_at IS NULL OR expires_at > NOW())
			AND revoked_at IS NULL
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, deviceID, tokenHash)
	return r.scanToken(row)
}

// GetActiveTokensForDevice retrieves all active tokens for a device.
func (r *tokenRepository) GetActiveTokensForDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceToken, error) {
	query := `
		SELECT
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		FROM attendance.attendance_device_tokens
		WHERE company_id = $1
			AND device_id = $2
			AND is_active = true
			AND (expires_at IS NULL OR expires_at > NOW())
			AND revoked_at IS NULL
		ORDER BY issued_at DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("query active tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*models.DeviceToken
	for rows.Next() {
		token, err := r.scanTokenFromRows(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return tokens, nil
}

// RevokeToken revokes a specific token.
func (r *tokenRepository) RevokeToken(ctx context.Context, tokenID uuid.UUID, revokedBy *uuid.UUID, reason string) error {
	query := `
		UPDATE attendance.attendance_device_tokens
		SET is_active = false,
			revoked_at = NOW(),
			revoked_by = $1,
			revoke_reason = $2
		WHERE token_id = $3
			AND is_active = true
	`
	result, err := r.client.Exec(ctx, query, revokedBy, reason, tokenID)
	if err != nil {
		r.logger.Error("failed to revoke token",
			util.String("token_id", tokenID.String()),
			util.ErrorField(err))
		return fmt.Errorf("revoke token: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("token not found or already revoked")
	}
	return nil
}

// RevokeAllDeviceTokens revokes all active tokens for a device.
func (r *tokenRepository) RevokeAllDeviceTokens(ctx context.Context, companyID uuid.UUID, deviceID string, revokedBy *uuid.UUID, reason string) error {
	query := `
		UPDATE attendance.attendance_device_tokens
		SET is_active = false,
			revoked_at = NOW(),
			revoked_by = $1,
			revoke_reason = $2
		WHERE company_id = $3
			AND device_id = $4
			AND is_active = true
	`
	result, err := r.client.Exec(ctx, query, revokedBy, reason, companyID, deviceID)
	if err != nil {
		r.logger.Error("failed to revoke all device tokens",
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("revoke all tokens: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	r.logger.Info("revoked all device tokens",
		util.String("device_id", deviceID),
		util.Int64("count", rowsAffected))
	return nil
}

// RotateToken revokes the old token and creates a new one in a transaction.
func (r *tokenRepository) RotateToken(ctx context.Context, oldTokenID uuid.UUID, newToken *models.DeviceToken, revokedBy *uuid.UUID, reason string) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Revoke old token
	revokeQuery := `
		UPDATE attendance.attendance_device_tokens
		SET is_active = false,
			revoked_at = NOW(),
			revoked_by = $1,
			revoke_reason = $2
		WHERE token_id = $3
	`
	_, err = tx.ExecContext(ctx, revokeQuery, revokedBy, reason, oldTokenID)
	if err != nil {
		return fmt.Errorf("revoke old token: %w", err)
	}

	// Create new token
	createQuery := `
		INSERT INTO attendance.attendance_device_tokens (
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at,
			issued_by, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	if newToken.TokenID == uuid.Nil {
		newToken.TokenID = uuid.New()
	}
	if newToken.CreatedAt.IsZero() {
		newToken.CreatedAt = time.Now().UTC()
	}
	if newToken.IssuedAt.IsZero() {
		newToken.IssuedAt = newToken.CreatedAt
	}
	metadataJSON, _ := json.Marshal(newToken.Metadata)

	_, err = tx.ExecContext(ctx, createQuery,
		newToken.TokenID,
		newToken.CompanyID,
		newToken.DeviceID,
		newToken.SourceType,
		newToken.TokenHash,
		newToken.TokenVersion,
		newToken.IsActive,
		newToken.IssuedAt,
		newToken.ExpiresAt,
		newToken.IssuedBy,
		metadataJSON,
		newToken.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create new token: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// UpdateTokenLastUsed updates the last_used_at timestamp in metadata.
func (r *tokenRepository) UpdateTokenLastUsed(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE attendance.attendance_device_tokens
		SET metadata = jsonb_set(
			COALESCE(metadata, '{}'::jsonb),
			'{last_used_at}',
			to_jsonb(NOW())
		)
		WHERE token_id = $1
	`
	_, err := r.client.Exec(ctx, query, tokenID)
	if err != nil {
		r.logger.Error("failed to update token last used",
			util.String("token_id", tokenID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update token last used: %w", err)
	}
	return nil
}

// CleanupExpiredTokens removes tokens that expired or were revoked before a given time.
func (r *tokenRepository) CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error) {
	query := `
		DELETE FROM attendance.attendance_device_tokens
		WHERE (
			(expires_at IS NOT NULL AND expires_at < $1)
			OR (revoked_at IS NOT NULL AND revoked_at < $1)
		)
		AND created_at < $1
	`
	result, err := r.client.Exec(ctx, query, before)
	if err != nil {
		r.logger.Error("failed to cleanup expired tokens",
			util.Time("before", before),
			util.ErrorField(err))
		return 0, fmt.Errorf("cleanup tokens: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// GetTokenByID retrieves a token by its ID.
func (r *tokenRepository) GetTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.DeviceToken, error) {
	query := `
		SELECT
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		FROM attendance.attendance_device_tokens
		WHERE token_id = $1
	`
	row := r.client.QueryRow(ctx, query, tokenID)
	return r.scanToken(row)
}

// HealthCheck verifies database connectivity.
func (r *tokenRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.attendance_device_tokens LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// scanToken scans a single row from *sql.Row.
func (r *tokenRepository) scanToken(row *sql.Row) (*models.DeviceToken, error) {
	var token models.DeviceToken
	var metadataJSON []byte
	var revokeReason sql.NullString
	var issuedBy, revokedBy sql.NullString

	err := row.Scan(
		&token.TokenID,
		&token.CompanyID,
		&token.DeviceID,
		&token.SourceType,
		&token.TokenHash,
		&token.TokenVersion,
		&token.IsActive,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.RevokedAt,
		&issuedBy,
		&revokedBy,
		&revokeReason,
		&metadataJSON,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan token: %w", err)
	}
	if issuedBy.Valid {
		if v, err := uuid.Parse(issuedBy.String); err == nil {
			token.IssuedBy = &v
		}
	}
	if revokedBy.Valid {
		if v, err := uuid.Parse(revokedBy.String); err == nil {
			token.RevokedBy = &v
		}
	}
	if revokeReason.Valid {
		token.RevokeReason = &revokeReason.String
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &token.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &token, nil
}

// scanTokenFromRows scans a row from *sql.Rows.
func (r *tokenRepository) scanTokenFromRows(rows *sql.Rows) (*models.DeviceToken, error) {
	var token models.DeviceToken
	var metadataJSON []byte
	var revokeReason sql.NullString
	var issuedBy, revokedBy sql.NullString

	err := rows.Scan(
		&token.TokenID,
		&token.CompanyID,
		&token.DeviceID,
		&token.SourceType,
		&token.TokenHash,
		&token.TokenVersion,
		&token.IsActive,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.RevokedAt,
		&issuedBy,
		&revokedBy,
		&revokeReason,
		&metadataJSON,
		&token.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan token rows: %w", err)
	}
	if issuedBy.Valid {
		if v, err := uuid.Parse(issuedBy.String); err == nil {
			token.IssuedBy = &v
		}
	}
	if revokedBy.Valid {
		if v, err := uuid.Parse(revokedBy.String); err == nil {
			token.RevokedBy = &v
		}
	}
	if revokeReason.Valid {
		token.RevokeReason = &revokeReason.String
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &token.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &token, nil
}
