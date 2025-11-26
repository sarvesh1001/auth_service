package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

/* -----------------------------------------------------------
   INTERFACE (UPDATED)
----------------------------------------------------------- */

type PairingRepository interface {
	CreatePairingSession(ctx context.Context, session *models.PairingSession) error
	GetPairingSession(ctx context.Context, sessionID string) (*models.PairingSession, error)
	UpdatePairingStatus(ctx context.Context, sessionID string, status string) error

	// UPDATED: Extra fields for admin + user
	ScanPairingSession(
		ctx context.Context,
		sessionID,
		userID,
		phoneNumber,
		deviceID,
		sessionType,
		role string,
		permissions []string,
	) error

	ConfirmPairingSession(ctx context.Context, sessionID string) error
	DeletePairingSession(ctx context.Context, sessionID string) error
	CleanupExpiredSessions(ctx context.Context) (int, error)
}

/* -----------------------------------------------------------
   IMPLEMENTATION
----------------------------------------------------------- */

type PairingRepositoryImpl struct {
	client *redis.Client
	logger *zap.Logger
}

func NewPairingRepository(client *redis.Client, logger *zap.Logger) PairingRepository {
	return &PairingRepositoryImpl{
		client: client,
		logger: logger,
	}
}

const (
	pairingKeyPrefix = "pair:"
	pairingTTL       = 10 * time.Minute
	cleanupBatchSize = 1000
)

/* -----------------------------------------------------------
   CREATE SESSION
----------------------------------------------------------- */

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

	r.logger.Debug("Pairing session created",
		util.String("session_id", session.SessionID),
		util.String("status", session.Status),
		util.Duration("ttl", ttl),
	)

	return nil
}

/* -----------------------------------------------------------
   GET SESSION
----------------------------------------------------------- */

func (r *PairingRepositoryImpl) GetPairingSession(ctx context.Context, sessionID string) (*models.PairingSession, error) {
	key := pairingKeyPrefix + sessionID

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session models.PairingSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Expired? delete + return not found
	if time.Now().After(session.ExpiresAt) {
		r.DeletePairingSession(ctx, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

/* -----------------------------------------------------------
   UPDATE STATUS
----------------------------------------------------------- */

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

/* -----------------------------------------------------------
   SCAN SESSION (UPDATED FOR ADMIN + USER)
----------------------------------------------------------- */

func (r *PairingRepositoryImpl) ScanPairingSession(
	ctx context.Context,
	sessionID,
	userID,
	phoneNumber,
	deviceID,
	sessionType,
	role string,
	permissions []string,
) error {

	session, err := r.GetPairingSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.Status = "scanned"
	session.UserID = userID
	session.PhoneNumber = phoneNumber
	session.DeviceID = deviceID
	session.SessionType = sessionType
	session.Role = role
	session.Permissions = permissions
	session.ScannedAt = time.Now()

	return r.CreatePairingSession(ctx, session)
}

/* -----------------------------------------------------------
   CONFIRM SESSION
----------------------------------------------------------- */

func (r *PairingRepositoryImpl) ConfirmPairingSession(ctx context.Context, sessionID string) error {
	return r.UpdatePairingStatus(ctx, sessionID, "confirmed")
}

/* -----------------------------------------------------------
   DELETE SESSION
----------------------------------------------------------- */

func (r *PairingRepositoryImpl) DeletePairingSession(ctx context.Context, sessionID string) error {
	key := pairingKeyPrefix + sessionID
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

/* -----------------------------------------------------------
   CLEANUP EXPIRED SESSIONS
----------------------------------------------------------- */

func (r *PairingRepositoryImpl) CleanupExpiredSessions(ctx context.Context) (int, error) {
	iter := r.client.Scan(ctx, 0, pairingKeyPrefix+"*", cleanupBatchSize).Iterator()

	var expiredKeys []string

	for iter.Next(ctx) {
		key := iter.Val()

		ttl, err := r.client.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		// Expired keys have TTL < 0
		if ttl < 0 {
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
