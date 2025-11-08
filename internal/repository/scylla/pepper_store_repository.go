package scylla

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"auth-service/internal/hashing/pepperstore" // ✅ NEW

	"github.com/gocql/gocql"
	"go.uber.org/zap"

	"auth-service/internal/util"
)

// PepperStoreRepository handles pepper storage and retrieval
type PepperStoreRepository interface {
	GetPeppers(ctx context.Context) (map[int][]byte, error)
	SavePepper(ctx context.Context, version int, pepper []byte) error
	GetCurrentPepper(ctx context.Context) (int, []byte, error)
	CleanupOldPeppers(ctx context.Context, keepLast int) error
}

type PepperStoreRepositoryImpl struct {
	client *ScyllaClient
	logger *zap.Logger
}

var _ pepperstore.PepperStore = (*PepperStoreRepositoryImpl)(nil)

func NewPepperStoreRepository(client *ScyllaClient, logger *zap.Logger) PepperStoreRepository {
	return &PepperStoreRepositoryImpl{
		client: client,
		logger: logger,
	}
}

// GetPeppers retrieves all active peppers from the database
func (r *PepperStoreRepositoryImpl) GetPeppers(ctx context.Context) (map[int][]byte, error) {
	query := r.client.Query(`
		SELECT version, pepper, created_at 
		FROM pepper_store 
		WHERE is_active = true
		ALLOW FILTERING`)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	peppers := make(map[int][]byte)
	var version int
	var pepperB64 string
	var createdAt time.Time

	for iter.Scan(&version, &pepperB64, &createdAt) {
		pepper, err := base64.RawURLEncoding.DecodeString(pepperB64)
		if err != nil {
			r.logger.Error("Failed to decode pepper from database",
				util.ErrorField(err),
				util.Int("version", version),
			)
			continue
		}

		peppers[version] = pepper
		r.logger.Debug("Loaded pepper from database",
			util.Int("version", version),
			util.Time("created_at", createdAt),
		)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate pepper store: %w", err)
	}

	r.logger.Info("Loaded peppers from database",
		util.Int("count", len(peppers)),
	)

	return peppers, nil
}

// SavePepper saves a new pepper to the database
func (r *PepperStoreRepositoryImpl) SavePepper(ctx context.Context, version int, pepper []byte) error {
	pepperB64 := base64.RawURLEncoding.EncodeToString(pepper)
	now := time.Now().UTC()

	query := r.client.Query(`
		INSERT INTO pepper_store (version, pepper, created_at, is_active) 
		VALUES (?, ?, ?, ?)`,
		version, pepperB64, now, true,
	)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to save pepper version %d: %w", version, err)
	}

	r.logger.Info("Saved pepper to database",
		util.Int("version", version),
		util.Time("created_at", now),
	)

	return nil
}

// GetCurrentPepper gets the most recent active pepper
func (r *PepperStoreRepositoryImpl) GetCurrentPepper(ctx context.Context) (int, []byte, error) {
	query := r.client.Query(`
		SELECT version, pepper 
		FROM pepper_store 
		WHERE is_active = true 
		ORDER BY version DESC 
		LIMIT 1
		ALLOW FILTERING`)

	var version int
	var pepperB64 string

	if err := r.client.ScanWithRetry(query.WithContext(ctx), &version, &pepperB64); err != nil {
		if err == gocql.ErrNotFound {
			return 0, nil, fmt.Errorf("no active pepper found")
		}
		return 0, nil, fmt.Errorf("failed to get current pepper: %w", err)
	}

	pepper, err := base64.RawURLEncoding.DecodeString(pepperB64)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode current pepper: %w", err)
	}

	return version, pepper, nil
}

// CleanupOldPeppers deactivates old peppers, keeping only the specified number of recent ones
// CleanupOldPeppers deactivates old peppers, keeping only the specified number of recent ones
func (r *PepperStoreRepositoryImpl) CleanupOldPeppers(ctx context.Context, keepLast int) error {
	// Get all active pepper versions
	query := r.client.Query(`
		SELECT version 
		FROM pepper_store 
		WHERE is_active = true 
		ORDER BY version DESC
		ALLOW FILTERING`)

	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	var versions []int
	var version int

	for iter.Scan(&version) {
		versions = append(versions, version)
	}

	if err := iter.Close(); err != nil {
		return fmt.Errorf("failed to get pepper versions: %w", err)
	}

	// If we have more than keepLast versions, deactivate the old ones
	if len(versions) > keepLast {
		versionsToDeactivate := versions[keepLast:]

		batch := r.client.Batch(gocql.LoggedBatch).WithContext(ctx)
		for _, oldVersion := range versionsToDeactivate {
			batch.Query(`
				UPDATE pepper_store 
				SET is_active = false 
				WHERE version = ?`,
				oldVersion,
			)
			r.logger.Debug("Marking pepper for deactivation",
				util.Int("version", oldVersion),
			)
		}

		if err := r.client.ExecuteBatch(batch); err != nil {
			return fmt.Errorf("failed to deactivate old peppers: %w", err)
		}

		r.logger.Info("Cleaned up old peppers",
			util.Int("deactivated_count", len(versionsToDeactivate)),
			util.Int("remaining_active", keepLast),
		)
	}

	return nil
}
