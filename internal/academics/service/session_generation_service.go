package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// SessionGenerationService handles the background job that generates academic_session rows
// from active timetable entries for a given date range.
type SessionGenerationService interface {
	// GenerateSessions creates academic_session records for all active timetable entries
	// between startDate and endDate (inclusive). The jobID is a server‑generated UUID
	// used for idempotency and outbox aggregate identification.
	// Returns the number of sessions generated and any error.
	GenerateSessions(ctx context.Context, startDate, endDate time.Time, jobID string) (int, error)
}

type sessionGenerationService struct {
	timetableSvc     TimetableService
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewSessionGenerationService creates a new instance.
func NewSessionGenerationService(
	timetableSvc TimetableService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SessionGenerationService {
	return &sessionGenerationService{
		timetableSvc:     timetableSvc,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		pgClient:         pgClient,
		logger:           logger.Named("session_generation_service"),
	}
}

// GenerateSessions implements SessionGenerationService.
func (s *sessionGenerationService) GenerateSessions(ctx context.Context, startDate, endDate time.Time, jobID string) (int, error) {
	logger := s.logger.With(
		zap.String("method", "GenerateSessions"),
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate),
		zap.String("job_id", jobID),
	)

	// Validate inputs
	if startDate.After(endDate) {
		return 0, fmt.Errorf("%w: start_date must be before end_date", ErrInvalidInput)
	}

	// Idempotency key based on date range – calling the same range twice (even with different jobID) is idempotent
	idempotencyKey := fmt.Sprintf("session_gen:%s:%s", startDate.Format("20060102"), endDate.Format("20060102"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Try to retrieve stored result
	var existingResult struct {
		Count int `json:"count"`
	}
	err = s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingResult)
	if err == nil {
		logger.Info("idempotent request: session generation already performed", zap.Int("count", existingResult.Count))
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit tx: %w", err)
		}
		return existingResult.Count, nil
	}
	// If the error is not "not found", log a warning and continue (don't break idempotency)
	if err != sql.ErrNoRows {
		logger.Warn("idempotency store error", zap.Error(err))
	}

	// Perform the actual generation
	count, err := s.timetableSvc.GenerateSessionsForDateRange(ctx, startDate, endDate)
	if err != nil {
		logger.Error("failed to generate sessions", zap.Error(err))
		return 0, fmt.Errorf("generate sessions: %w", err)
	}

	// Store the result in idempotency store
	resultPayload := struct {
		Count       int       `json:"count"`
		GeneratedAt time.Time `json:"generated_at"`
	}{
		Count:       count,
		GeneratedAt: time.Now().UTC(),
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, resultPayload); err != nil {
		logger.Error("failed to store idempotency result", zap.Error(err))
		// Not fatal, but log error
	}

	// Audit log – adjust to correct signature
	if s.auditService != nil {
		_ = s.auditService.LogAction(
			ctx,
			tx,                  // *sql.Tx
			nil,                 // companyID *uuid.UUID
			"academics",         // module
			"generate",          // action
			"academic_sessions", // entityType
			nil,                 // entityID *uuid.UUID
			"system",            // userType
			nil,                 // userID *uuid.UUID
			nil,                 // oldData []byte
			nil,                 // newData []byte
			map[string]interface{}{ // metadata
				"job_id":     jobID,
				"start_date": startDate,
				"end_date":   endDate,
				"count":      count,
			},
		)
	}

	// Publish outbox event – aggregate_id is the jobID (a valid UUID string)
	payload, _ := json.Marshal(map[string]interface{}{
		"job_id":     jobID,
		"start_date": startDate,
		"end_date":   endDate,
		"count":      count,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_sessions",
		AggregateID:   jobID, // jobID is a UUID string, matches database column type
		EventType:     string(EventSessionsGenerated),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		// Not fatal, continue
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic sessions generated successfully", zap.Int("count", count))
	return count, nil
}
