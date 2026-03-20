package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/util"
)

// AuditService handles business logic for audit logging
type AuditService struct {
	repo   AuditRepository
	logger *zap.Logger
}

// NewAuditService creates a new audit service
func NewAuditService(repo AuditRepository, logger *zap.Logger) *AuditService {
	return &AuditService{
		repo:   repo,
		logger: logger,
	}
}

// ============================================================================
// WRITE OPERATIONS (Service Layer)
// ============================================================================

// LogAction creates an audit log entry
func (s *AuditService) LogAction(
	ctx context.Context,
	companyID *uuid.UUID,
	module string,
	action string,
	entityType string,
	entityID *uuid.UUID,
	actorType string,
	actorID *uuid.UUID,
	beforeState []byte,
	afterState []byte,
	metadata map[string]interface{},
) error {
	// Business logic validation
	if module == "" || action == "" || entityType == "" || actorType == "" {
		return fmt.Errorf("missing required audit fields")
	}

	// Convert metadata to JSON
	var metadataBytes []byte
	if metadata != nil {
		jsonBytes, err := json.Marshal(metadata)
		if err != nil {
			s.logger.Warn("Failed to marshal metadata", util.ErrorField(err))
			// Continue without metadata rather than fail the audit
		} else {
			metadataBytes = jsonBytes
		}
	}

	// Create audit log model
	auditLog := &AuditLog{
		AuditID:     uuid.New(),
		CompanyID:   companyID,
		Module:      module,
		Action:      action,
		EntityType:  entityType,
		EntityID:    entityID,
		ActorType:   actorType,
		ActorID:     actorID,
		BeforeState: beforeState,
		AfterState:  afterState,
		Metadata:    metadataBytes,
		CreatedAt:   time.Now().UTC(),
	}

	// Store in repository
	return s.repo.CreateAuditLog(ctx, auditLog)
}

// ===============================
// DEVICE ENROLLMENT AUDIT HELPERS
// ===============================

func (s *AuditService) LogDeviceEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	deviceUserCode string,
	userID uuid.UUID,
	enrolledBy uuid.UUID,
) error {

	metadata := map[string]interface{}{
		"device_id":        deviceID,
		"device_user_code": deviceUserCode,
	}

	return s.LogAction(
		ctx,
		&companyID,
		"attendance",
		"device_enroll",
		"device_enrollment",
		nil,
		"admin",
		&enrolledBy,
		nil,
		nil,
		metadata,
	)
}

func (s *AuditService) LogDeviceEnrollmentRevocation(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	deviceUserCode string,
	reason string,
	revokedBy uuid.UUID,
) error {

	metadata := map[string]interface{}{
		"device_id":        deviceID,
		"device_user_code": deviceUserCode,
		"reason":           reason,
	}

	return s.LogAction(
		ctx,
		&companyID,
		"attendance",
		"device_revoke",
		"device_enrollment",
		nil,
		"admin",
		&revokedBy,
		nil,
		nil,
		metadata,
	)
}
