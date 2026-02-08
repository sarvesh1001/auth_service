package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type deviceTokenRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewDeviceTokenRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) DeviceTokenRepository {
	return &deviceTokenRepository{
		client: postgresClient,
		logger: logger,
	}
}

func (r *deviceTokenRepository) CreateToken(
	ctx context.Context,
	token *attendance.DeviceToken,
) error {
	query := `
		INSERT INTO attendance_device_tokens (
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12, $13,
			$14, $15
		)
	`

	_, err := r.client.Exec(ctx, query,
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
		token.Metadata, // ✅ JSONB handled automatically
		token.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create device token",
			util.String("device_id", token.DeviceID),
			util.String("company_id", token.CompanyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create device token: %w", err)
	}
	return nil
}

func (r *deviceTokenRepository) GetActiveTokenByHash(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID, tokenHash string,
) (*attendance.DeviceToken, error) {
	query := `
		SELECT
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		FROM attendance_device_tokens
		WHERE company_id = $1
			AND device_id = $2
			AND token_hash = $3
			AND is_active = true
			AND (expires_at IS NULL OR expires_at > NOW())
			AND revoked_at IS NULL
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceID, tokenHash)
	return r.scanDeviceToken(row)
}

func (r *deviceTokenRepository) GetActiveTokensForDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) ([]*attendance.DeviceToken, error) {
	query := `
		SELECT
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		FROM attendance_device_tokens
		WHERE company_id = $1
			AND device_id = $2
			AND is_active = true
			AND (expires_at IS NULL OR expires_at > NOW())
			AND revoked_at IS NULL
		ORDER BY issued_at DESC
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		r.logger.Error("Failed to get active tokens for device",
			util.String("device_id", deviceID),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get active tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*attendance.DeviceToken
	for rows.Next() {
		token, err := r.scanDeviceTokenFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}
		tokens = append(tokens, token)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return tokens, nil
}

func (r *deviceTokenRepository) RevokeToken(
	ctx context.Context,
	tokenID uuid.UUID,
	revokedBy *uuid.UUID,
	reason string,
) error {
	query := `
		UPDATE attendance_device_tokens
		SET is_active = false,
			revoked_at = NOW(),
			revoked_by = $1,
			revoke_reason = $2
		WHERE token_id = $3
			AND is_active = true
	`
	result, err := r.client.Exec(ctx, query, revokedBy, reason, tokenID)
	if err != nil {
		r.logger.Error("Failed to revoke token",
			util.String("token_id", tokenID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("token not found or already revoked")
	}
	return nil
}

func (r *deviceTokenRepository) RevokeAllDeviceTokens(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	revokedBy *uuid.UUID,
	reason string,
) error {
	query := `
		UPDATE attendance_device_tokens
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
		r.logger.Error("Failed to revoke all device tokens",
			util.String("device_id", deviceID),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to revoke all device tokens: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.logger.Info("Revoked device tokens",
		util.String("device_id", deviceID),
		util.Int64("tokens_revoked", rowsAffected),
	)

	return nil
}

func (r *deviceTokenRepository) RotateToken(
	ctx context.Context,
	oldTokenID uuid.UUID,
	newToken *attendance.DeviceToken,
	revokedBy *uuid.UUID,
	reason string,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	revokeQuery := `
		UPDATE attendance_device_tokens
		SET is_active = false,
			revoked_at = NOW(),
			revoked_by = $1,
			revoke_reason = $2
		WHERE token_id = $3
	`
	_, err = tx.ExecContext(ctx, revokeQuery, revokedBy, reason, oldTokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke old token: %w", err)
	}

	createQuery := `
		INSERT INTO attendance_device_tokens (
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at,
			issued_by, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
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
		newToken.Metadata, // ✅ JSONB
		newToken.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create new token: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (r *deviceTokenRepository) UpdateTokenLastUsed(
	ctx context.Context,
	tokenID uuid.UUID,
) error {
	query := `
		UPDATE attendance_device_tokens
		SET metadata = jsonb_set(
			COALESCE(metadata, '{}'::jsonb),
			'{last_used_at}',
			to_jsonb(NOW())
		)
		WHERE token_id = $1
	`
	_, err := r.client.Exec(ctx, query, tokenID)
	if err != nil {
		r.logger.Error("Failed to update token last used",
			util.String("token_id", tokenID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update token last used: %w", err)
	}
	return nil
}

func (r *deviceTokenRepository) CleanupExpiredTokens(
	ctx context.Context,
	before time.Time,
) (int64, error) {
	query := `
		DELETE FROM attendance_device_tokens
		WHERE (
			(expires_at IS NOT NULL AND expires_at < $1)
			OR (revoked_at IS NOT NULL AND revoked_at < $1)
		)
		AND created_at < $1
	`
	result, err := r.client.Exec(ctx, query, before)
	if err != nil {
		r.logger.Error("Failed to cleanup expired tokens",
			util.Time("before", before),
			util.ErrorField(err),
		)
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

func (r *deviceTokenRepository) GetTokenByID(
	ctx context.Context,
	tokenID uuid.UUID,
) (*attendance.DeviceToken, error) {
	query := `
		SELECT
			token_id, company_id, device_id, source_type,
			token_hash, token_version, is_active,
			issued_at, expires_at, revoked_at,
			issued_by, revoked_by, revoke_reason,
			metadata, created_at
		FROM attendance_device_tokens
		WHERE token_id = $1
	`
	row := r.client.QueryRow(ctx, query, tokenID)
	return r.scanDeviceToken(row)
}

func (r *deviceTokenRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance_device_tokens LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil && err != sql.ErrNoRows {
		r.logger.Error("Device token repository health check failed",
			util.ErrorField(err),
		)
		return fmt.Errorf("device token repository health check failed: %w", err)
	}
	return nil
}

func (r *deviceTokenRepository) scanDeviceToken(row *sql.Row) (*attendance.DeviceToken, error) {
	var token attendance.DeviceToken
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
		&token.Metadata, // ✅ JSONB Scan
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
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

	return &token, nil
}

func (r *deviceTokenRepository) scanDeviceTokenFromRows(rows *sql.Rows) (*attendance.DeviceToken, error) {
	var token attendance.DeviceToken
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
		&token.Metadata, // ✅ JSONB Scan
		&token.CreatedAt,
	)
	if err != nil {
		return nil, err
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

	return &token, nil
}
