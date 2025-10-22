package scylla

import (
    "context"
    "time"

    "auth-service/internal/models"

    "github.com/google/uuid"
)

// MPINRepository defines the interface for MPIN repository operations
type MPINRepository interface {
    // Core Operations
    CreateMPIN(ctx context.Context, mpin *models.MPINCredential) error
    GetMPINByUserID(ctx context.Context, userID uuid.UUID) (*models.MPINCredential, error)
    UpdateMPIN(ctx context.Context, userID uuid.UUID, mpinHash, salt string, pepperVersion int) error
    ValidateMPIN(ctx context.Context, userID uuid.UUID, mpinHash string) (*models.MPINCredential, error)
    IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) (int, error)
    LockMPIN(ctx context.Context, userID uuid.UUID, lockDuration time.Duration) error
    UnlockMPIN(ctx context.Context, userID uuid.UUID) error
    ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error

    // Device Management
    UpdateMPINDeviceBinding(ctx context.Context, userID uuid.UUID, deviceID string) error
    GetMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error)

    // Maintenance Operations
    GetLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error)
    CleanupUnlockedMPINs(ctx context.Context) (int, error)

    // Health & Monitoring
    HealthCheck(ctx context.Context) error
    GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
}
