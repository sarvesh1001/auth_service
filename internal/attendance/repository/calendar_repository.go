package repository

import (
	"context"

	"auth-service/internal/attendance/models"

	"github.com/google/uuid"
)

// CalendarRepository defines operations for work calendars
type CalendarRepository interface {
	// Create inserts a new work calendar
	Create(ctx context.Context, calendar *models.WorkCalendar) error

	// GetByID retrieves a calendar by its ID
	GetByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error)

	// GetByCompanyAndYear retrieves a calendar for a specific company and year
	GetByCompanyAndYear(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error)

	// GetByCompany retrieves all calendars for a company (optionally active only)
	GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCalendar, error)

	// Update updates an existing calendar
	Update(ctx context.Context, calendar *models.WorkCalendar) error

	// Delete soft-deletes a calendar (sets is_active = false) or hard deletes
	Delete(ctx context.Context, calendarID uuid.UUID) error

	// CheckExists checks if a calendar exists for the given company and year
	Exists(ctx context.Context, companyID uuid.UUID, year int) (bool, error)

	// List returns paginated calendars for a company with optional filters
	List(ctx context.Context, companyID uuid.UUID, filter CalendarFilter, pagination Pagination) ([]*models.WorkCalendar, int64, error)
}

// CalendarFilter defines optional filters for listing calendars
type CalendarFilter struct {
	Year     *int   `json:"year,omitempty"`
	IsActive *bool  `json:"is_active,omitempty"`
	Name     string `json:"name,omitempty"` // partial match
}

// Pagination is shared across repositories
type Pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}
