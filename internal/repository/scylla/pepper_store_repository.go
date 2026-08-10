package scylla

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/hashing/pepperstore"

	"github.com/gocql/gocql"
)

type PepperStoreRepository interface {
	GetPeppers(ctx context.Context) (map[int][]byte, error)
	SavePepper(ctx context.Context, version int, pepper []byte) error
	GetCurrentPepper(ctx context.Context) (int, []byte, error)
	CleanupOldPeppers(ctx context.Context, keepLast int) error
}

type PepperStoreRepositoryImpl struct {
	client *ScyllaClient
}

var _ pepperstore.PepperStore = (*PepperStoreRepositoryImpl)(nil)

func NewPepperStoreRepository(client *ScyllaClient) PepperStoreRepository {
	return &PepperStoreRepositoryImpl{
		client: client,
	}
}

func (r *PepperStoreRepositoryImpl) GetPeppers(ctx context.Context) (map[int][]byte, error) {
	query := r.client.Query(`
		SELECT version, pepper, created_at
		FROM pepper_store
		WHERE is_active = true
		ALLOW FILTERING
	`)
	iter := query.WithContext(ctx).Iter()
	defer iter.Close()

	peppers := make(map[int][]byte)
	var version int
	var pepperB64 string
	var createdAt time.Time

	for iter.Scan(&version, &pepperB64, &createdAt) {
		pepper, err := base64.RawURLEncoding.DecodeString(pepperB64)
		if err != nil {
			continue
		}
		peppers[version] = pepper
	}
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate pepper store: %w", err)
	}
	if len(peppers) == 0 {
		return nil, apperrors.ErrNotFound
	}
	return peppers, nil
}

func (r *PepperStoreRepositoryImpl) SavePepper(ctx context.Context, version int, pepper []byte) error {
	pepperB64 := base64.RawURLEncoding.EncodeToString(pepper)
	now := time.Now().UTC()
	query := r.client.Query(`
		INSERT INTO pepper_store (version, pepper, created_at, is_active)
		VALUES (?, ?, ?, ?)
	`, version, pepperB64, now, true)

	if err := r.client.ExecuteWithRetry(query.WithContext(ctx), 3); err != nil {
		return fmt.Errorf("failed to save pepper version %d: %w", version, err)
	}
	return nil
}

func (r *PepperStoreRepositoryImpl) GetCurrentPepper(ctx context.Context) (int, []byte, error) {
	query := r.client.Query(`
		SELECT version, pepper
		FROM pepper_store
		WHERE is_active = true
		ORDER BY version DESC
		LIMIT 1
		ALLOW FILTERING
	`)

	var version int
	var pepperB64 string
	err := r.client.ScanWithRetry(query.WithContext(ctx), &version, &pepperB64)
	if err != nil {
		if err == gocql.ErrNotFound {
			return 0, nil, apperrors.ErrNotFound
		}
		return 0, nil, fmt.Errorf("failed to get current pepper: %w", err)
	}
	pepper, err := base64.RawURLEncoding.DecodeString(pepperB64)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode current pepper: %w", err)
	}
	return version, pepper, nil
}

func (r *PepperStoreRepositoryImpl) CleanupOldPeppers(ctx context.Context, keepLast int) error {
	query := r.client.Query(`
		SELECT version
		FROM pepper_store
		WHERE is_active = true
		ORDER BY version DESC
		ALLOW FILTERING
	`)
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

	if len(versions) > keepLast {
		versionsToDeactivate := versions[keepLast:]
		batch := r.client.Batch(gocql.LoggedBatch).WithContext(ctx)
		for _, oldVersion := range versionsToDeactivate {
			batch.Query(`
				UPDATE pepper_store
				SET is_active = false
				WHERE version = ?
			`, oldVersion)
		}
		if err := r.client.ExecuteBatch(batch); err != nil {
			return fmt.Errorf("failed to deactivate old peppers: %w", err)
		}
	}
	return nil
}
