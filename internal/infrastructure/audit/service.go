package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/util"
)

type AuditService struct {
	repo   AuditRepository
	logger *zap.Logger
}

func NewAuditService(repo AuditRepository, logger *zap.Logger) *AuditService {
	return &AuditService{
		repo:   repo,
		logger: logger,
	}
}

// ✅ LogAction now accepts a transaction pointer
func (s *AuditService) LogAction(
	ctx context.Context,
	tx *sql.Tx,
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
	if module == "" || action == "" || entityType == "" || actorType == "" {
		return fmt.Errorf("missing required audit fields")
	}

	var metadataBytes []byte
	if metadata != nil {
		jsonBytes, err := json.Marshal(metadata)
		if err != nil {
			s.logger.Warn("Failed to marshal metadata", util.ErrorField(err))
		} else {
			metadataBytes = jsonBytes
		}
	}

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

	// ✅ Use transaction‑aware repository method
	if tx == nil {
		// Fallback to non‑transactional (e.g., for background jobs)
		return s.repo.CreateAuditLog(ctx, auditLog)
	}
	return s.repo.CreateAuditLogWithTx(ctx, tx, auditLog)
}

// Helper methods also updated to accept tx
func (s *AuditService) LogDeviceEnrollment(
	ctx context.Context,
	tx *sql.Tx,
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
		ctx, tx,
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
	tx *sql.Tx,
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
		ctx, tx,
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
