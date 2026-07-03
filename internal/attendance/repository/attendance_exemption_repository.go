package repository

import (
	"context"
	"database/sql"
	"time"

	"auth-service/internal/attendance/models"

	"github.com/google/uuid"
)

type AttendanceExemptionRepository interface {
	// Create inserts a new exemption record.
	Create(ctx context.Context, tx *sql.Tx, exemption *models.AttendanceExemption) error
	// Update modifies an existing exemption.
	Update(ctx context.Context, tx *sql.Tx, exemption *models.AttendanceExemption) error
	// Delete removes an exemption by ID.
	Delete(ctx context.Context, tx *sql.Tx, exemptionID uuid.UUID) error
	// GetByID retrieves an exemption by its ID.
	GetByID(ctx context.Context, tx *sql.Tx, exemptionID uuid.UUID) (*models.AttendanceExemption, error)
	// GetActiveForSubject returns all active exemptions for a given subject on a specific date.
	GetActiveForSubject(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, date time.Time) ([]*models.AttendanceExemption, error)
	// GetForDateRange returns exemptions for a subject within a date range.
	GetForDateRange(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceExemption, error)
	// List returns a paginated list of exemptions matching the filter.
	List(ctx context.Context, tx *sql.Tx, filter ExemptionFilter, pag Pagination) ([]*models.AttendanceExemption, error)
	// Count returns the total number of exemptions matching the filter.
	Count(ctx context.Context, tx *sql.Tx, filter ExemptionFilter) (int64, error)
}

type ExemptionFilter struct {
	CompanyID   *uuid.UUID
	SubjectType *string
	SubjectID   *uuid.UUID
	FromDate    *time.Time
	ToDate      *time.Time
}
