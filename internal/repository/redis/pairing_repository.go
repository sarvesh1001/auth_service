package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"

	"github.com/redis/go-redis/v9"
)

// PairingRepository defines operations for pairing sessions.
type PairingRepository interface {
	CreatePairingSession(ctx context.Context, session *models.PairingSession) error
	GetPairingSession(ctx context.Context, sessionID string) (*models.PairingSession, error)
	UpdatePairingStatus(ctx context.Context, sessionID string, status string) error
	// ScanPairingSession marks a session as scanned and stores user/admin details.
	// Added companyID to store the user's company context.
	ScanPairingSession(ctx context.Context, sessionID, userID, phoneNumber, deviceID, sessionType, role string, permissions []string, companyID string) error
	ConfirmPairingSession(ctx context.Context, sessionID string) error
	DeletePairingSession(ctx context.Context, sessionID string) error
	CleanupExpiredSessions(ctx context.Context) (int, error)
}

// PairingRepositoryImpl implements PairingRepository using Redis.
type PairingRepositoryImpl struct {
	client *redis.Client
}

// NewPairingRepository creates a new pairing repository.
func NewPairingRepository(client *redis.Client) PairingRepository {
	return &PairingRepositoryImpl{
		client: client,
	}
}

const (
	pairingKeyPrefix = "pair:"
	cleanupBatchSize = 1000
)

// CreatePairingSession stores a new pairing session.
func (r *PairingRepositoryImpl) CreatePairingSession(ctx context.Context, session *models.PairingSession) error {
	key := pairingKeyPrefix + session.SessionID
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	ttl := time.Until(session.ExpiresAt)
	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}
	return nil
}

// GetPairingSession retrieves a session by ID.
// Returns apperrors.ErrNotFound if not found or expired.
func (r *PairingRepositoryImpl) GetPairingSession(ctx context.Context, sessionID string) (*models.PairingSession, error) {
	key := pairingKeyPrefix + sessionID
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	var session models.PairingSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		_ = r.client.Del(ctx, key).Err()
		return nil, apperrors.ErrNotFound
	}
	return &session, nil
}

// UpdatePairingStatus updates the status of a session.
func (r *PairingRepositoryImpl) UpdatePairingStatus(ctx context.Context, sessionID string, status string) error {
	session, err := r.GetPairingSession(ctx, sessionID)
	if err != nil {
		return err
	}
	session.Status = status
	if status == "scanned" {
		session.ScannedAt = time.Now()
	}
	if status == "confirmed" {
		session.ConfirmedAt = time.Now()
	}
	return r.CreatePairingSession(ctx, session)
}

// ScanPairingSession marks a session as scanned and fills user/device details.
// Now also stores the company ID from the authenticated user.
func (r *PairingRepositoryImpl) ScanPairingSession(
	ctx context.Context,
	sessionID, userID, phoneNumber, deviceID, sessionType, role string,
	permissions []string,
	companyID string, // 👈 NEW parameter
) error {
	session, err := r.GetPairingSession(ctx, sessionID)
	if err != nil {
		return err
	}
	session.Status = "scanned"
	session.UserID = userID
	session.PhoneNumber = phoneNumber
	session.DeviceID = deviceID
	session.CompanyID = companyID // 👈 store company ID
	session.SessionType = sessionType
	session.Role = role
	session.Permissions = permissions
	session.ScannedAt = time.Now()
	return r.CreatePairingSession(ctx, session)
}

// ConfirmPairingSession sets the status to "confirmed".
func (r *PairingRepositoryImpl) ConfirmPairingSession(ctx context.Context, sessionID string) error {
	return r.UpdatePairingStatus(ctx, sessionID, "confirmed")
}

// DeletePairingSession removes a session.
func (r *PairingRepositoryImpl) DeletePairingSession(ctx context.Context, sessionID string) error {
	key := pairingKeyPrefix + sessionID
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// CleanupExpiredSessions scans and deletes all expired sessions.
func (r *PairingRepositoryImpl) CleanupExpiredSessions(ctx context.Context) (int, error) {
	iter := r.client.Scan(ctx, 0, pairingKeyPrefix+"*", cleanupBatchSize).Iterator()
	var expiredKeys []string
	for iter.Next(ctx) {
		key := iter.Val()
		ttl, err := r.client.TTL(ctx, key).Result()
		if err != nil {
			continue
		}
		if ttl < 0 { // expired or no TTL
			expiredKeys = append(expiredKeys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("error scanning sessions: %w", err)
	}
	if len(expiredKeys) > 0 {
		if err := r.client.Del(ctx, expiredKeys...).Err(); err != nil {
			return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
		}
	}
	return len(expiredKeys), nil
}
