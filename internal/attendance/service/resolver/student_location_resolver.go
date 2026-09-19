package resolver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
)

type studentLocationResolver struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewStudentLocationResolver reads academics.students.location_id.
//
// A student's location is set at admission and changed only via transfer.
// It's the org unit the student belongs to — the campus/branch they are
// enrolled at — not the physical fence of a specific classroom.
func NewStudentLocationResolver(pg *client.PostgresClient, logger *zap.Logger) SubjectLocationResolver {
	return &studentLocationResolver{
		client: pg,
		logger: logger.Named("student_location_resolver"),
	}
}

func (r *studentLocationResolver) ResolveLocation(
	ctx context.Context,
	companyID uuid.UUID,
	_ string,
	subjectID uuid.UUID,
) (*uuid.UUID, error) {
	var locID sql.NullString

	query := `
		SELECT location_id
		FROM academics.students
		WHERE student_id = $1
		  AND company_id = $2
		  AND deleted_at IS NULL
	`

	err := r.client.QueryRow(ctx, query, subjectID, companyID).Scan(&locID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Student not found or soft-deleted. Not an error — return no location.
			return nil, nil
		}
		r.logger.Error("failed to resolve student location",
			zap.String("student_id", subjectID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("resolve student location: %w", err)
	}

	if !locID.Valid || locID.String == "" {
		// Student exists but has no location assigned. Surface as (nil, nil)
		// so the caller can decide — typically fall back to device geofence.
		return nil, nil
	}

	id, err := uuid.Parse(locID.String)
	if err != nil {
		r.logger.Error("invalid location_id in students table",
			zap.String("student_id", subjectID.String()),
			zap.String("location_id", locID.String))
		return nil, fmt.Errorf("invalid location_id in students table: %w", err)
	}
	return &id, nil
}
