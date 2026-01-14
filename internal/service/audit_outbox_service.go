package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type AuditOutboxService struct {
	postgresClient *client.PostgresClient
	kafkaProducer  *client.KafkaProducer
	logger         *zap.Logger
	batchSize      int
	pollInterval   time.Duration
	stopChan       chan struct{}
	isRunning      bool
	topicName      string
}

func NewAuditOutboxService(
	postgresClient *client.PostgresClient,
	kafkaProducer *client.KafkaProducer,
	batchSize int,
	pollInterval time.Duration,
	topicName string,
) *AuditOutboxService {
	logger := util.Get()
	return &AuditOutboxService{
		postgresClient: postgresClient,
		kafkaProducer:  kafkaProducer,
		logger:         logger,
		batchSize:      batchSize,
		pollInterval:   pollInterval,
		stopChan:       make(chan struct{}),
		isRunning:      false,
		topicName:      topicName,
	}
}

func (s *AuditOutboxService) Start(ctx context.Context) error {
	s.logger.Info("Starting audit outbox service",
		zap.String("topic", s.topicName),
		zap.Int("batch_size", s.batchSize),
		zap.Duration("poll_interval", s.pollInterval),
	)

	s.isRunning = true
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Audit outbox service stopped via context")
			s.isRunning = false
			return nil
		case <-s.stopChan:
			s.logger.Info("Audit outbox service stopped")
			s.isRunning = false
			return nil
		case <-ticker.C:
			if err := s.processOutboxBatch(ctx); err != nil {
				s.logger.Error("Failed to process outbox batch", zap.Error(err))
			}
		}
	}
}

func (s *AuditOutboxService) processOutboxBatch(ctx context.Context) error {
	db := s.postgresClient.DB
	if db == nil {
		return fmt.Errorf("postgres client not initialized")
	}

	sqlxDB := sqlx.NewDb(db, "postgres")
	tx, err := sqlxDB.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var lastProcessedID *string
	err = tx.GetContext(ctx, &lastProcessedID, `
		SELECT last_processed_id::text
		FROM audit.outbox_debounce
		ORDER BY last_processed_at DESC
		LIMIT 1
	`)
	if err != nil {
		s.logger.Warn("No debounce record found, starting from beginning")
	}

	query := `
		SELECT outbox_id, audit_id, operation, payload, created_at
		FROM audit.audit_logs_outbox
		WHERE processed_at IS NULL
		AND ($1::uuid IS NULL OR outbox_id > $1::uuid)
		ORDER BY outbox_id ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`
	rows, err := tx.QueryxContext(ctx, query, lastProcessedID, s.batchSize)
	if err != nil {
		return fmt.Errorf("failed to query outbox: %w", err)
	}
	defer rows.Close()

	var processedIDs []string
	var lastID string
	for rows.Next() {
		var outboxID, auditID string
		var operation string
		var payloadBytes []byte
		var createdAt time.Time

		if err := rows.Scan(&outboxID, &auditID, &operation, &payloadBytes, &createdAt); err != nil {
			s.logger.Error("Failed to scan outbox row", zap.Error(err))
			continue
		}

		auditEvent := models.AuditLogEvent{
			EventID:     outboxID,
			AuditID:     auditID,
			Timestamp:   createdAt,
			EventType:   "audit",
			CompanyID:   nil,
			Module:      "",
			Action:      "",
			EntityType:  "",
			EntityID:    nil,
			ActorType:   "",
			ActorID:     nil,
			BeforeState: nil,
			AfterState:  nil,
			Metadata:    nil,
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err == nil {
			if companyID, ok := payload["company_id"].(string); ok && companyID != "" {
				auditEvent.CompanyID = &companyID
			}
			if module, ok := payload["module"].(string); ok {
				auditEvent.Module = module
			}
			if action, ok := payload["action"].(string); ok {
				auditEvent.Action = action
			}
			if entityType, ok := payload["entity_type"].(string); ok {
				auditEvent.EntityType = entityType
			}
			if entityID, ok := payload["entity_id"].(string); ok && entityID != "" {
				auditEvent.EntityID = &entityID
			}
			if actorType, ok := payload["actor_type"].(string); ok {
				auditEvent.ActorType = actorType
			}
			if actorID, ok := payload["actor_id"].(string); ok && actorID != "" {
				auditEvent.ActorID = &actorID
			}
			auditEvent.BeforeState = payload["before_state"]
			auditEvent.AfterState = payload["after_state"]
			auditEvent.Metadata = payload["metadata"]
		}

		messageBytes, err := json.Marshal(auditEvent)
		if err != nil {
			s.logger.Error("Failed to marshal audit event", zap.Error(err))
			continue
		}

		if err := s.kafkaProducer.ProduceMessage(ctx, s.topicName, []byte(auditEvent.EventID), messageBytes, nil); err != nil {
			s.logger.Error("Failed to produce audit event to Kafka",
				zap.String("outbox_id", outboxID),
				zap.Error(err),
			)
			continue
		}

		processedIDs = append(processedIDs, outboxID)
		lastID = outboxID
	}

	if len(processedIDs) == 0 {
		return nil
	}

	// FIX: Use pq.Array for PostgreSQL array conversion
	updateQuery := `
		UPDATE audit.audit_logs_outbox
		SET processed_at = NOW()
		WHERE outbox_id = ANY($1::uuid[])
	`
	_, err = tx.ExecContext(ctx, updateQuery, pq.Array(processedIDs))
	if err != nil {
		return fmt.Errorf("failed to mark records as processed: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit.outbox_debounce (last_processed_id, last_processed_at, batch_size)
		VALUES ($1, NOW(), $2)
	`, lastID, len(processedIDs))
	if err != nil {
		return fmt.Errorf("failed to update debounce table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Info("Processed audit outbox batch",
		zap.Int("count", len(processedIDs)),
		zap.String("last_id", lastID),
	)
	return nil
}

func (s *AuditOutboxService) Stop() {
	if s.isRunning {
		close(s.stopChan)
		s.isRunning = false
		s.logger.Info("Audit outbox service stopping...")
	}
}

func (s *AuditOutboxService) HealthCheck(ctx context.Context) error {
	if err := s.postgresClient.HealthCheck(ctx); err != nil {
		return fmt.Errorf("postgres health check failed: %w", err)
	}

	if s.kafkaProducer == nil {
		return fmt.Errorf("kafka producer not initialized")
	}

	db := s.postgresClient.DB
	sqlxDB := sqlx.NewDb(db, "postgres")
	var count int
	err := sqlxDB.GetContext(ctx, &count, `
		SELECT COUNT(*)
		FROM audit.audit_logs_outbox
		WHERE processed_at IS NULL
	`)
	if err != nil {
		return fmt.Errorf("failed to check unprocessed records: %w", err)
	}

	s.logger.Debug("Audit outbox health check", zap.Int("pending_records", count))
	return nil
}
