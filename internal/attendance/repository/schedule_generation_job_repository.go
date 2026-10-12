package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// ScheduleGenerationJobRepository is the queue abstraction behind the async
// schedule generation pipeline. Every Enqueue* accepts a *sql.Tx so callers
// can commit the job atomically with a business change; pass nil to use the
// connection pool directly (handler-driven enqueues do this today).
//
// The Fetch/Mark/Release methods are consumed by the background worker and
// by the status endpoint the handler exposes after returning 202.
type ScheduleGenerationJobRepository interface {
	EnqueueUserGeneration(ctx context.Context, tx *sql.Tx, companyID, userID uuid.UUID, payload []byte, reason string) error
	EnqueueCompanyGeneration(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, payload []byte, reason string) error
	EnqueuePositionGeneration(ctx context.Context, tx *sql.Tx, companyID, positionID uuid.UUID, payload []byte, reason string) error
	MarkCompletedWithResult(
		ctx context.Context,
		jobID uuid.UUID,
		outcome *models.ScheduleGenerationOutcome,
	) error

	GetByID(ctx context.Context, jobID uuid.UUID) (*models.ScheduleGenerationJob, error)
	CountQueued(ctx context.Context) (int64, error)
	CountFailed(ctx context.Context, since *time.Time) (int64, error)
	CountStuck(ctx context.Context, threshold time.Duration) (int64, error)
	FetchNextRunnableJob(ctx context.Context, workerID string) (*models.ScheduleGenerationJob, error)
	MarkCompleted(ctx context.Context, jobID uuid.UUID) error
	MarkFailed(ctx context.Context, jobID uuid.UUID, errMsg string) error
	ReleaseStaleLocks(ctx context.Context, staleThreshold time.Duration) (int64, error)
}
