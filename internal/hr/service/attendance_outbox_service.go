package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/util"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type AttendanceOutboxService struct {
	postgresClient *client.PostgresClient
	kafkaProducer  *client.KafkaProducer
	logger         *zap.Logger
	batchSize      int
	pollInterval   time.Duration
	stopChan       chan struct{}
	isRunning      bool
	topicName      string
}

func NewAttendanceOutboxService(
	postgresClient *client.PostgresClient,
	kafkaProducer *client.KafkaProducer,
	batchSize int,
	pollInterval time.Duration,
	topicName string,
) *AttendanceOutboxService {
	logger := util.Get()
	return &AttendanceOutboxService{
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

func (s *AttendanceOutboxService) Start(ctx context.Context) error {
	s.logger.Info("Starting attendance outbox service",
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
			s.logger.Info("Attendance outbox service stopped via context")
			s.isRunning = false
			return nil
		case <-s.stopChan:
			s.logger.Info("Attendance outbox service stopped")
			s.isRunning = false
			return nil
		case <-ticker.C:
			if err := s.processOutboxBatch(ctx); err != nil {
				s.logger.Error("Failed to process outbox batch", zap.Error(err))
			}
		}
	}
}

func (s *AttendanceOutboxService) processOutboxBatch(ctx context.Context) error {
	db := s.postgresClient.DB
	if db == nil {
		return fmt.Errorf("postgres client not initialized")
	}

	sqlxDB := sqlx.NewDb(db, "postgres")

	// Use a transaction for atomic processing
	tx, err := sqlxDB.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get unprocessed outbox records
	query := `
		SELECT outbox_id, aggregate_id, payload, created_at
		FROM attendance.attendance_events_outbox
		WHERE processed_at IS NULL
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`

	rows, err := tx.QueryxContext(ctx, query, s.batchSize)
	if err != nil {
		return fmt.Errorf("failed to query outbox: %w", err)
	}
	defer rows.Close()

	var processedIDs []string
	for rows.Next() {
		var outboxID, aggregateID string
		var payloadBytes []byte
		var createdAt time.Time

		if err := rows.Scan(&outboxID, &aggregateID, &payloadBytes, &createdAt); err != nil {
			s.logger.Error("Failed to scan outbox row", zap.Error(err))
			continue
		}

		// Create Kafka message
		message := map[string]interface{}{
			"outbox_id":    outboxID,
			"aggregate_id": aggregateID,
			"payload":      json.RawMessage(payloadBytes),
			"created_at":   createdAt,
		}

		messageBytes, err := json.Marshal(message)
		if err != nil {
			s.logger.Error("Failed to marshal outbox message", zap.Error(err))
			continue
		}

		// Send to Kafka
		if err := s.kafkaProducer.ProduceMessage(
			ctx,
			s.topicName,
			[]byte(outboxID),
			messageBytes,
			map[string]string{
				"event_type": "attendance.event.created",
			},
		); err != nil {
			s.logger.Error("Failed to produce attendance event to Kafka",
				zap.String("outbox_id", outboxID),
				zap.Error(err),
			)
			continue
		}

		processedIDs = append(processedIDs, outboxID)
	}

	if len(processedIDs) == 0 {
		return nil
	}

	// Mark records as processed
	updateQuery := `
		UPDATE attendance.attendance_events_outbox
		SET processed_at = NOW()
		WHERE outbox_id = ANY($1::uuid[])
	`

	_, err = tx.ExecContext(ctx, updateQuery, pq.Array(processedIDs))
	if err != nil {
		return fmt.Errorf("failed to mark records as processed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.logger.Info("Processed attendance outbox batch",
		zap.Int("count", len(processedIDs)),
		zap.Strings("processed_ids", processedIDs),
	)

	return nil
}

func (s *AttendanceOutboxService) Stop() {
	if s.isRunning {
		close(s.stopChan)
		s.isRunning = false
		s.logger.Info("Attendance outbox service stopping...")
	}
}

func (s *AttendanceOutboxService) HealthCheck(ctx context.Context) error {
	if err := s.postgresClient.HealthCheck(ctx); err != nil {
		return fmt.Errorf("postgres health check failed: %w", err)
	}

	if s.kafkaProducer == nil {
		return fmt.Errorf("kafka producer not initialized")
	}

	// Check for unprocessed records
	db := s.postgresClient.DB
	sqlxDB := sqlx.NewDb(db, "postgres")
	var count int
	err := sqlxDB.GetContext(ctx, &count, `
		SELECT COUNT(*)
		FROM attendance.attendance_events_outbox
		WHERE processed_at IS NULL
	`)
	if err != nil {
		return fmt.Errorf("failed to check unprocessed records: %w", err)
	}

	s.logger.Debug("Attendance outbox health check", zap.Int("pending_records", count))
	return nil
}
