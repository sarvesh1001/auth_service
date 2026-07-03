package query

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
)

// QueryService provides high-level read operations for attendance data.
type QueryService interface {
	// --- Existing methods ---
	GetEventByID(ctx context.Context, eventID uuid.UUID) (*models.AttendanceEvent, error)
	ListEvents(ctx context.Context, filter EventFilter) ([]*models.AttendanceEvent, int64, error)
	GetDailySummary(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*models.AttendanceDailySummary, error)
	ListDailySummaries(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceDailySummary, error)
	ListCompanySummaries(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.AttendanceDailySummary, error)
	GetCompanyStats(ctx context.Context, companyID uuid.UUID, from, to time.Time) (*models.AttendanceStats, error)
	GetSubjectStats(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) (*models.UserAttendanceStats, error)
	GetAttendancePercentage(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) (float64, error)
	ListEventTypes(ctx context.Context, activeOnly bool) ([]*models.AttendanceEventType, error)
	ListSourceTypes(ctx context.Context) ([]*models.AttendanceSourceType, error)
	GetAttendancePolicyByID(ctx context.Context, policyID uuid.UUID) (*models.AttendancePolicy, error)
	GetAttendancePoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendancePolicy, error)

	// --- NEW: Session Summary methods ---
	GetSessionSummary(ctx context.Context, sessionID, subjectID uuid.UUID, subjectType string) (*models.AttendanceSessionSummary, error)
	ListSessionSummaries(ctx context.Context, filter repository.SessionSummaryFilter, page, pageSize int) ([]*models.AttendanceSessionSummary, int64, error)

	// --- NEW: Exemption methods ---
	GetExemptionsForSubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) ([]*models.AttendanceExemption, error)
	ListExemptions(ctx context.Context, filter repository.ExemptionFilter, page, pageSize int) ([]*models.AttendanceExemption, int64, error)
}

type EventFilter struct {
	CompanyID   uuid.UUID
	SubjectType *string
	SubjectID   *uuid.UUID
	EventTypes  []string
	SourceType  *string
	DeviceID    *string
	StartDate   time.Time
	EndDate     time.Time
	Page        int
	PageSize    int
}

type queryService struct {
	eventRepo          repository.EventRepository
	summaryRepo        repository.SummaryRepository
	sourceRepo         repository.SourceRepository
	policyRepo         repository.PolicyRepository
	sessionSummaryRepo repository.AttendanceSessionSummaryRepository // 👈 NEW
	exemptionRepo      repository.AttendanceExemptionRepository      // 👈 NEW
	logger             *zap.Logger
}

// NewQueryService creates a new query service.
// Now accepts sessionSummaryRepo and exemptionRepo.
func NewQueryService(
	eventRepo repository.EventRepository,
	summaryRepo repository.SummaryRepository,
	sourceRepo repository.SourceRepository,
	policyRepo repository.PolicyRepository,
	sessionSummaryRepo repository.AttendanceSessionSummaryRepository, // 👈 NEW PARAM
	exemptionRepo repository.AttendanceExemptionRepository, // 👈 NEW PARAM
	logger *zap.Logger,
) QueryService {
	return &queryService{
		eventRepo:          eventRepo,
		summaryRepo:        summaryRepo,
		sourceRepo:         sourceRepo,
		policyRepo:         policyRepo,
		sessionSummaryRepo: sessionSummaryRepo,
		exemptionRepo:      exemptionRepo,
		logger:             logger,
	}
}

// --- Existing methods (unchanged) ---

func (s *queryService) GetEventByID(ctx context.Context, eventID uuid.UUID) (*models.AttendanceEvent, error) {
	if eventID == uuid.Nil {
		return nil, fmt.Errorf("event ID is required")
	}
	return s.eventRepo.GetEventByID(ctx, eventID)
}

func (s *queryService) ListEvents(ctx context.Context, filter EventFilter) ([]*models.AttendanceEvent, int64, error) {
	if filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 || filter.PageSize > 1000 {
		filter.PageSize = 100
	}
	if filter.StartDate.IsZero() {
		filter.StartDate = time.Now().AddDate(0, 0, -30)
	}
	if filter.EndDate.IsZero() {
		filter.EndDate = time.Now()
	}
	if filter.StartDate.After(filter.EndDate) {
		return nil, 0, fmt.Errorf("start date cannot be after end date")
	}

	repoFilter := repository.EventFilter{
		CompanyID:   filter.CompanyID,
		SubjectType: filter.SubjectType,
		SubjectID:   filter.SubjectID,
		EventTypes:  filter.EventTypes,
		SourceType:  filter.SourceType,
		DeviceID:    filter.DeviceID,
		StartDate:   filter.StartDate,
		EndDate:     filter.EndDate,
		Page:        filter.Page,
		PageSize:    filter.PageSize,
	}
	return s.eventRepo.ListEvents(ctx, repoFilter)
}

func (s *queryService) GetDailySummary(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*models.AttendanceDailySummary, error) {
	if companyID == uuid.Nil || subjectID == uuid.Nil || subjectType == "" {
		return nil, fmt.Errorf("company_id, subject_id, and subject_type are required")
	}
	return s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, date)
}

func (s *queryService) ListDailySummaries(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceDailySummary, error) {
	if companyID == uuid.Nil || subjectID == uuid.Nil || subjectType == "" {
		return nil, fmt.Errorf("company_id, subject_id, and subject_type are required")
	}
	if from.After(to) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}
	if to.Sub(from).Hours()/24 > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days")
	}
	return s.summaryRepo.GetBySubjectRange(ctx, companyID, subjectID, subjectType, from, to)
}

func (s *queryService) ListCompanySummaries(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.AttendanceDailySummary, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	summaries, _, err := s.summaryRepo.GetByCompanyRange(ctx, companyID, from, to, 1, 100000)
	if err != nil {
		return nil, err
	}
	return summaries, nil
}

func (s *queryService) GetCompanyStats(ctx context.Context, companyID uuid.UUID, from, to time.Time) (*models.AttendanceStats, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if from.After(to) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}
	summaries, err := s.ListCompanySummaries(ctx, companyID, from, to)
	if err != nil {
		return nil, err
	}
	stats := &models.AttendanceStats{
		CompanyID:          companyID,
		StartDate:          from,
		EndDate:            to,
		TotalEmployees:     0,
		PresentCount:       0,
		AbsentCount:        0,
		LateCount:          0,
		HalfDayCount:       0,
		LeaveCount:         0,
		HolidayCount:       0,
		TotalWorkedHours:   0,
		TotalOvertimeHours: 0,
		AverageAttendance:  0,
	}
	var totalWorkedMin, totalOvertimeMin int
	subjectSet := make(map[string]bool)
	for _, sum := range summaries {
		key := sum.SubjectType + ":" + sum.SubjectID.String()
		if !subjectSet[key] {
			subjectSet[key] = true
			stats.TotalEmployees++
		}
		switch sum.Status {
		case models.StatusPresent:
			stats.PresentCount++
		case models.StatusAbsent:
			stats.AbsentCount++
		case models.StatusLate:
			stats.LateCount++
		case models.StatusHalfDay:
			stats.HalfDayCount++
		case models.StatusLeavePaid, models.StatusLeaveUnpaid:
			stats.LeaveCount++
		case models.StatusHoliday:
			stats.HolidayCount++
		}
		if sum.WorkedMinutes != nil {
			totalWorkedMin += *sum.WorkedMinutes
		}
		if sum.OvertimeMinutes != nil {
			totalOvertimeMin += *sum.OvertimeMinutes
		}
	}
	stats.TotalWorkedHours = float64(totalWorkedMin) / 60.0
	stats.TotalOvertimeHours = float64(totalOvertimeMin) / 60.0
	if len(summaries) > 0 {
		stats.AverageAttendance = float64(stats.PresentCount) / float64(len(summaries)) * 100
	}
	return stats, nil
}

func (s *queryService) GetSubjectStats(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) (*models.UserAttendanceStats, error) {
	if companyID == uuid.Nil || subjectID == uuid.Nil || subjectType == "" {
		return nil, fmt.Errorf("company_id, subject_id, and subject_type are required")
	}
	if from.After(to) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}
	summaries, err := s.ListDailySummaries(ctx, companyID, subjectID, subjectType, from, to)
	if err != nil {
		return nil, err
	}
	stats := &models.UserAttendanceStats{
		UserID:             subjectID,
		StartDate:          from,
		EndDate:            to,
		PresentDays:        0,
		AbsentDays:         0,
		LateDays:           0,
		HalfDays:           0,
		LeaveDays:          0,
		TotalWorkedHours:   0,
		TotalOvertimeHours: 0,
		AverageInTime:      "",
		AverageOutTime:     "",
		AttendancePercent:  0,
	}
	var totalWorkedMin, totalOvertimeMin int
	for _, sum := range summaries {
		switch sum.Status {
		case models.StatusPresent:
			stats.PresentDays++
		case models.StatusAbsent:
			stats.AbsentDays++
		case models.StatusLate:
			stats.LateDays++
		case models.StatusHalfDay:
			stats.HalfDays++
		case models.StatusLeavePaid, models.StatusLeaveUnpaid:
			stats.LeaveDays++
		}
		if sum.WorkedMinutes != nil {
			totalWorkedMin += *sum.WorkedMinutes
		}
		if sum.OvertimeMinutes != nil {
			totalOvertimeMin += *sum.OvertimeMinutes
		}
	}
	stats.TotalWorkedHours = float64(totalWorkedMin) / 60.0
	stats.TotalOvertimeHours = float64(totalOvertimeMin) / 60.0
	totalDays := len(summaries)
	if totalDays > 0 {
		stats.AttendancePercent = float64(stats.PresentDays) / float64(totalDays) * 100
	}
	return stats, nil
}

func (s *queryService) GetAttendancePercentage(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) (float64, error) {
	stats, err := s.GetSubjectStats(ctx, companyID, subjectID, subjectType, from, to)
	if err != nil {
		return 0, err
	}
	return stats.AttendancePercent, nil
}

func (s *queryService) ListEventTypes(ctx context.Context, activeOnly bool) ([]*models.AttendanceEventType, error) {
	return s.sourceRepo.GetEventTypes(ctx, activeOnly)
}

func (s *queryService) ListSourceTypes(ctx context.Context) ([]*models.AttendanceSourceType, error) {
	return s.sourceRepo.GetSourceTypes(ctx, true)
}

func (s *queryService) GetAttendancePolicyByID(ctx context.Context, policyID uuid.UUID) (*models.AttendancePolicy, error) {
	if policyID == uuid.Nil {
		return nil, fmt.Errorf("policy ID is required")
	}
	return s.policyRepo.GetPolicyByID(ctx, policyID)
}

func (s *queryService) GetAttendancePoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendancePolicy, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	return s.policyRepo.GetPoliciesByCompany(ctx, companyID, activeOnly)
}

// ─────────────────────────────────────────────────────────────
// NEW: Session Summary Methods
// ─────────────────────────────────────────────────────────────

func (s *queryService) GetSessionSummary(ctx context.Context, sessionID, subjectID uuid.UUID, subjectType string) (*models.AttendanceSessionSummary, error) {
	if sessionID == uuid.Nil || subjectID == uuid.Nil || subjectType == "" {
		return nil, fmt.Errorf("session_id, subject_id, and subject_type are required")
	}
	return s.sessionSummaryRepo.GetBySessionAndSubject(ctx, nil, sessionID, subjectID, subjectType)
}

func (s *queryService) ListSessionSummaries(ctx context.Context, filter repository.SessionSummaryFilter, page, pageSize int) ([]*models.AttendanceSessionSummary, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	pag := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	summaries, err := s.sessionSummaryRepo.List(ctx, nil, filter, pag)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.sessionSummaryRepo.Count(ctx, nil, filter)
	if err != nil {
		return nil, 0, err
	}
	return summaries, total, nil
}

// ─────────────────────────────────────────────────────────────
// NEW: Exemption Methods
// ─────────────────────────────────────────────────────────────

func (s *queryService) GetExemptionsForSubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) ([]*models.AttendanceExemption, error) {
	if companyID == uuid.Nil || subjectID == uuid.Nil || subjectType == "" {
		return nil, fmt.Errorf("company_id, subject_id, and subject_type are required")
	}
	return s.exemptionRepo.GetActiveForSubject(ctx, nil, companyID, subjectID, subjectType, date)
}

func (s *queryService) ListExemptions(ctx context.Context, filter repository.ExemptionFilter, page, pageSize int) ([]*models.AttendanceExemption, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	pag := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	exemptions, err := s.exemptionRepo.List(ctx, nil, filter, pag)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.exemptionRepo.Count(ctx, nil, filter)
	if err != nil {
		return nil, 0, err
	}
	return exemptions, total, nil
}
