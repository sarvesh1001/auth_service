package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/outbox"
)

// AuditService now uses outbox.Repository to reliably publish events.
// It holds a PostgresClient to create transactions if none is provided.
type AuditService struct {
	outboxRepo outbox.Repository
	pgClient   *client.PostgresClient
	logger     *zap.Logger
}

// NewAuditService creates a new audit service with outbox repository and PostgreSQL client.
func NewAuditService(
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) *AuditService {
	return &AuditService{
		outboxRepo: outboxRepo,
		pgClient:   pgClient,
		logger:     logger.Named("audit_service"),
	}
}

// LogAction stores an outbox event for the audit log.
// If tx is nil, it creates its own transaction.
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

	// Build the audit log struct (will be serialised as payload)
	var metadataBytes []byte
	if metadata != nil {
		jsonBytes, err := json.Marshal(metadata)
		if err != nil {
			s.logger.Warn("failed to marshal metadata", zap.Error(err))
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

	// Marshal entire audit log as JSON payload
	payload, err := json.Marshal(auditLog)
	if err != nil {
		return fmt.Errorf("failed to marshal audit log: %w", err)
	}

	getUUIDString := func(id *uuid.UUID) string {
		if id == nil {
			return ""
		}
		return id.String()
	}

	// Build outbox event
	event := &outbox.Event{
		EventID:       auditLog.AuditID.String(),
		AggregateType: entityType,
		AggregateID:   getUUIDString(entityID),
		EventType:     fmt.Sprintf("%s.%s", module, action),
		Topic:         "audit-logs",
		Payload:       payload,
		Headers: map[string]string{
			"audit_id":   auditLog.AuditID.String(),
			"company_id": getUUIDString(companyID),
			"module":     module,
			"action":     action,
			"event_type": fmt.Sprintf("%s.%s", module, action),
		},
	}

	// If no transaction is provided, create one.
	if tx == nil {
		tx, err = s.pgClient.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for outbox: %w", err)
		}
		defer tx.Rollback() // ignored if commit succeeds

		if err := s.outboxRepo.Store(ctx, tx, event); err != nil {
			return fmt.Errorf("failed to store outbox event: %w", err)
		}
		return tx.Commit()
	}

	// Use the provided transaction.
	if err := s.outboxRepo.Store(ctx, tx, event); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	s.logger.Debug("Audit event stored in outbox",
		zap.String("audit_id", auditLog.AuditID.String()),
		zap.String("module", module),
		zap.String("action", action),
	)

	return nil
}

// Helper methods remain unchanged – they call LogAction.

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
