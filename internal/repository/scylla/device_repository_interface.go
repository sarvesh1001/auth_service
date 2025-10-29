package scylla

import (
    "context"
    "time"
    
    "auth-service/internal/models"
    "github.com/google/uuid"
)

// DeviceRepository defines the interface for device management operations
// Optimized for 500M+ users with high-throughput requirements
type DeviceRepository interface {
    // Core Device Binding Operations
    
    // BindUserDevice creates or updates a device binding for a user
    // Uses prepared statements and retry logic for reliability
    BindUserDevice(ctx context.Context, userID uuid.UUID, deviceID, bindToken string) error
    
    // GetActiveDevice retrieves the currently active device for a user
    // Implements Redis caching for sub-millisecond lookups
    GetActiveDevice(ctx context.Context, userID uuid.UUID) (*models.UserActiveDevice, error)
    
    // UnbindUserDevice removes the device binding for a user
    // Includes cache invalidation
    UnbindUserDevice(ctx context.Context, userID uuid.UUID) error
    
    // UpdateDeviceSession updates the session ID for an active device
    // Used for session rotation and security
    UpdateDeviceSession(ctx context.Context, userID, sessionID uuid.UUID) error
    
    // ValidateDeviceBinding checks if a device binding is valid
    // Constant-time comparison to prevent timing attacks
    ValidateDeviceBinding(ctx context.Context, userID uuid.UUID, deviceID, bindToken string) (bool, error)
    
    // Device Analytics & Management
    
    // GetDeviceBindingHistory retrieves device binding history for a user
    // Supports pagination for large result sets
    GetDeviceBindingHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*models.UserActiveDevice, error)
    
    // GetUsersByDevice finds all users associated with a device ID
    // Used for fraud detection and device tracking
    GetUsersByDevice(ctx context.Context, deviceID string) ([]*models.UserActiveDevice, error)
    
    // CleanupOrphanedDevices removes device bindings older than cutoff time
    // Batch operation for efficient cleanup
    CleanupOrphanedDevices(ctx context.Context, cutoffTime time.Time) (int, error)
    
    // Batch Operations for High Throughput
    
    // BindUserDevicesBatch binds multiple devices in a single batch
    // Optimized for bulk operations with concurrency control
    BindUserDevicesBatch(ctx context.Context, bindings []models.UserActiveDevice) error
    
    // GetActiveDevicesBatch retrieves active devices for multiple users
    // Uses concurrent reads with errgroup
    GetActiveDevicesBatch(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]*models.UserActiveDevice, error)
    
    // UnbindUserDevicesBatch removes multiple device bindings
    // Includes batch cache invalidation
    UnbindUserDevicesBatch(ctx context.Context, userIDs []uuid.UUID) error
    
    // Health & Monitoring
    
    // HealthCheck verifies repository connectivity and health
    HealthCheck(ctx context.Context) error
    
    // GetRepositoryStats returns performance metrics
    GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
}
