package repository

import (
	"context"

	"auth-service/internal/attendance/models"

	"github.com/google/uuid"
)

type CalendarRepository interface {
	Create(ctx context.Context, calendar *models.WorkCalendar) error
	GetByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error)
	GetByCompanyAndYear(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error)

	// GetByCompany returns calendars, optionally filtered. Use
	// CalendarFilter.LocationID to scope to a single location.
	GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCalendar, error)

	Update(ctx context.Context, calendar *models.WorkCalendar) error
	Delete(ctx context.Context, calendarID uuid.UUID) error
	Exists(ctx context.Context, companyID uuid.UUID, year int) (bool, error)

	// List returns paginated calendars for a company with optional filters.
	List(ctx context.Context, companyID uuid.UUID, filter CalendarFilter, pagination Pagination) ([]*models.WorkCalendar, int64, error)
}

type CalendarFilter struct {
	Year     *int   `json:"year,omitempty"`
	IsActive *bool  `json:"is_active,omitempty"`
	Name     string `json:"name,omitempty"`

	// LocationID is the employment location scope. nil = no filter (ALL).
	LocationID *uuid.UUID `json:"location_id,omitempty"`
}

type Pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}
