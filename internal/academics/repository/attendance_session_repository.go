package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

type AttendanceSessionRepository interface {
	// Create inserts a new attendance session lock row.
	Create(ctx context.Context, db DBTX, as *models.AttendanceSession) error

	// GetBySessionID retrieves the attendance session lock for a given academic session.
	GetBySessionID(ctx context.Context, db DBTX, sessionID uuid.UUID) (*models.AttendanceSession, error)

	// ExistsBySessionID checks if a lock already exists for the session.
	ExistsBySessionID(ctx context.Context, db DBTX, sessionID uuid.UUID) (bool, error)

	// Delete removes the lock (optional, usually not needed).
	Delete(ctx context.Context, db DBTX, sessionID uuid.UUID) error
}

type attendanceSessionRepository struct {
	logger *zap.Logger
}

func NewAttendanceSessionRepository(logger *zap.Logger) AttendanceSessionRepository {
	return &attendanceSessionRepository{
		logger: logger.Named("attendance_session_repo"),
	}
}

func (r *attendanceSessionRepository) Create(ctx context.Context, db DBTX, as *models.AttendanceSession) error {
	query := `
		INSERT INTO academics.attendance_session (
			session_id, marked_by, source_type, status, created_at
		) VALUES ($1, $2, $3, $4, NOW())
		RETURNING session_mark_id
	`
	err := db.QueryRowContext(ctx, query,
		as.SessionID,
		as.MarkedBy,
		as.SourceType,
		as.Status,
	).Scan(&as.SessionMarkID)
	if err != nil {
		r.logger.Error("failed to create attendance session",
			util.String("session_id", as.SessionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create attendance session: %w", err)
	}
	return nil
}

func (r *attendanceSessionRepository) GetBySessionID(ctx context.Context, db DBTX, sessionID uuid.UUID) (*models.AttendanceSession, error) {
	query := `
		SELECT session_mark_id, session_id, marked_by, source_type, status, created_at
		FROM academics.attendance_session
		WHERE session_id = $1
	`
	row := db.QueryRowContext(ctx, query, sessionID)
	return r.scanAttendanceSession(row)
}

func (r *attendanceSessionRepository) ExistsBySessionID(ctx context.Context, db DBTX, sessionID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.attendance_session WHERE session_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, sessionID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence of attendance session",
			util.String("session_id", sessionID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists attendance session: %w", err)
	}
	return exists, nil
}

func (r *attendanceSessionRepository) Delete(ctx context.Context, db DBTX, sessionID uuid.UUID) error {
	query := `DELETE FROM academics.attendance_session WHERE session_id = $1`
	result, err := db.ExecContext(ctx, query, sessionID)
	if err != nil {
		r.logger.Error("failed to delete attendance session",
			util.String("session_id", sessionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete attendance session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("attendance session for session %s not found", sessionID)
	}
	return nil
}

func (r *attendanceSessionRepository) scanAttendanceSession(row scanner) (*models.AttendanceSession, error) {
	var as models.AttendanceSession
	var markedBy, sourceType sql.NullString
	var status sql.NullString

	err := row.Scan(
		&as.SessionMarkID,
		&as.SessionID,
		&markedBy,
		&sourceType,
		&status,
		&as.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan attendance session: %w", err)
	}

	if markedBy.Valid {
		if uid, err := uuid.Parse(markedBy.String); err == nil {
			as.MarkedBy = &uid
		}
	}
	if sourceType.Valid {
		st := models.AttendanceSourceType(sourceType.String)
		as.SourceType = &st
	}
	if status.Valid {
		as.Status = models.AttendanceSessionStatus(status.String)
	}
	return &as, nil
}
