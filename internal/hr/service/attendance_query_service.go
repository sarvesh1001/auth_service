package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// QUERY SERVICE TYPES
// ============================================================================

// AttendanceSearchFilters provides type-safe filtering
type AttendanceSearchFilters struct {
	UserID           *uuid.UUID
	UserIDs          []uuid.UUID
	EventType        *string
	EventTypes       []string
	SourceType       *string
	SourceTypes      []string
	StartDate        *time.Time
	EndDate          *time.Time
	DeviceID         *string
	MinWorkedMinutes *int
	MaxWorkedMinutes *int
	Status           *string
	Statuses         []string
}

// AttendanceSummaryStats provides typed statistics
type AttendanceSummaryStats struct {
	TotalRecords         int64            `json:"total_records"`
	PresentDays          int64            `json:"present_days"`
	AbsentDays           int64            `json:"absent_days"`
	HalfDays             int64            `json:"half_days"`
	LeaveDays            int64            `json:"leave_days"`
	LateCount            int64            `json:"late_count"`
	TotalLateMinutes     int64            `json:"total_late_minutes"`
	TotalWorkedMinutes   int64            `json:"total_worked_minutes"`
	TotalOvertimeMinutes int64            `json:"total_overtime_minutes"`
	AvgWorkedMinutes     float64          `json:"avg_worked_minutes"`
	AttendanceRate       float64          `json:"attendance_rate"`
	ByDepartment         map[string]int64 `json:"by_department"`
	ByStatus             map[string]int64 `json:"by_status"`
	ByDate               map[string]int64 `json:"by_date"` // date -> count
}

// AttendanceReport represents a generated report
type AttendanceReport struct {
	ReportID    uuid.UUID `json:"report_id"`
	ReportType  string    `json:"report_type"`
	CompanyID   uuid.UUID `json:"company_id"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Format      string    `json:"format"` // json, csv, pdf
	Status      string    `json:"status"` // pending, generating, completed, failed
	DownloadURL *string   `json:"download_url,omitempty"`
	FileSize    *int64    `json:"file_size,omitempty"`
	Error       *string   `json:"error,omitempty"`
}

// ============================================================================
// QUERY SERVICE INTERFACE
// ============================================================================

// AttendanceQueryService defines read-only attendance operations
type AttendanceQueryService interface {
	// Event Queries
	GetAttendanceEventByID(ctx context.Context, eventID uuid.UUID) (*attendance.AttendanceEvent, error)
	GetAttendanceEventsByUser(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
		limit int,
	) ([]*attendance.AttendanceEvent, error)

	GetAttendanceEventsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)

	SearchAttendanceEvents(
		ctx context.Context,
		companyID uuid.UUID,
		filters map[string]interface{},
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)

	SearchAttendanceEventsTyped(
		ctx context.Context,
		companyID uuid.UUID,
		filters AttendanceSearchFilters,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)

	// Policy Queries
	GetAttendancePolicyByID(ctx context.Context, policyID uuid.UUID) (*attendance.AttendancePolicy, error)
	GetAttendancePoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendancePolicy, error)
	GetUserCurrentAttendancePolicy(ctx context.Context, userID uuid.UUID, date time.Time) (*attendance.AttendancePolicy, error)

	// Summary Queries
	GetAttendanceDailySummaryByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*attendance.AttendanceDailySummary, error)
	GetAttendanceDailySummariesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*attendance.AttendanceDailySummary, error)
	GetAttendanceSummaryStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*AttendanceSummaryStats, error)

	// Reports
	GenerateAttendanceReport(
		ctx context.Context,
		companyID uuid.UUID,
		reportType string,
		startDate, endDate time.Time,
	) ([]byte, string, error)

	StreamAttendanceEvents(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		writer io.Writer,
		format string,
	) error

	// Health
	HealthCheck(ctx context.Context) error
}

// ============================================================================
// QUERY SERVICE IMPLEMENTATION
// ============================================================================

type attendanceQueryServiceImpl struct {
	attendanceRepo repository.AttendanceRepository
	logger         *zap.Logger
	mu             sync.RWMutex
	reportCache    map[uuid.UUID]*AttendanceReport
}

// NewAttendanceQueryService creates a new attendance query service
func NewAttendanceQueryService(
	attendanceRepo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendanceQueryService {
	return &attendanceQueryServiceImpl{
		attendanceRepo: attendanceRepo,
		logger:         logger,
		reportCache:    make(map[uuid.UUID]*AttendanceReport),
	}
}

// ============================================================================
// EVENT QUERIES
// ============================================================================

func (qs *attendanceQueryServiceImpl) GetAttendanceEventByID(
	ctx context.Context,
	eventID uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	event, err := qs.attendanceRepo.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event: %w", err)
	}

	qs.logger.Debug("Attendance event retrieved by ID",
		util.String("event_id", eventID.String()),
		util.Duration("duration", time.Since(startTime)))

	return event, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceEventsByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
	limit int,
) ([]*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	// Validate parameters
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Normalize dates to UTC for query
	startUTC := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	endUTC := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, time.UTC)

	// Validate date range (calendar days)
	calendarDays := int(endUTC.Sub(startUTC).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	events, err := qs.attendanceRepo.GetAttendanceEventsByUser(ctx, userID, startUTC, endUTC, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance events by user: %w", err)
	}

	qs.logger.Debug("Attendance events retrieved by user",
		util.String("user_id", userID.String()),
		util.Time("start_date", startUTC),
		util.Time("end_date", endUTC),
		util.Int("calendar_days", calendarDays),
		util.Int("limit", limit),
		util.Int("event_count", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceEventsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Normalize dates
	startUTC := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	endUTC := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, time.UTC)

	// Validate date range
	calendarDays := int(endUTC.Sub(startUTC).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, 0, fmt.Errorf("date range cannot exceed 31 days for company queries, got %d days", calendarDays)
	}

	offset := (page - 1) * pageSize

	events, totalCount, err := qs.attendanceRepo.GetAttendanceEventsByCompany(ctx, companyID, startUTC, endUTC, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get attendance events by company: %w", err)
	}

	qs.logger.Debug("Attendance events retrieved by company",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startUTC),
		util.Time("end_date", endUTC),
		util.Int("calendar_days", calendarDays),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, totalCount, nil
}

func (qs *attendanceQueryServiceImpl) SearchAttendanceEvents(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	offset := (page - 1) * pageSize

	events, totalCount, err := qs.attendanceRepo.SearchAttendanceEvents(ctx, companyID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search attendance events: %w", err)
	}

	qs.logger.Debug("Attendance events searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("pageSize", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, totalCount, nil
}

// SearchAttendanceEventsTyped provides type-safe searching
func (qs *attendanceQueryServiceImpl) SearchAttendanceEventsTyped(
	ctx context.Context,
	companyID uuid.UUID,
	filters AttendanceSearchFilters,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	// Convert typed filters to generic map for repository
	genericFilters := make(map[string]interface{})

	if filters.UserID != nil {
		genericFilters["user_id"] = *filters.UserID
	}

	if len(filters.UserIDs) > 0 {
		genericFilters["user_ids"] = filters.UserIDs
	}

	if filters.EventType != nil {
		genericFilters["event_type"] = *filters.EventType
	}

	if len(filters.EventTypes) > 0 {
		genericFilters["event_types"] = filters.EventTypes
	}

	if filters.StartDate != nil {
		genericFilters["start_date"] = *filters.StartDate
	}

	if filters.EndDate != nil {
		genericFilters["end_date"] = *filters.EndDate
	}

	if filters.DeviceID != nil {
		genericFilters["device_id"] = *filters.DeviceID
	}

	if filters.Status != nil {
		genericFilters["status"] = *filters.Status
	}

	if len(filters.Statuses) > 0 {
		genericFilters["statuses"] = filters.Statuses
	}

	return qs.SearchAttendanceEvents(ctx, companyID, genericFilters, page, pageSize)
}

// ============================================================================
// POLICY QUERIES
// ============================================================================

func (qs *attendanceQueryServiceImpl) GetAttendancePolicyByID(
	ctx context.Context,
	policyID uuid.UUID,
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	policy, err := qs.attendanceRepo.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policy: %w", err)
	}

	qs.logger.Debug("Attendance policy retrieved by ID",
		util.String("policy_id", policyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendancePoliciesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	policies, err := qs.attendanceRepo.GetAttendancePoliciesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policies by company: %w", err)
	}

	qs.logger.Debug("Attendance policies retrieved by company",
		util.String("company_id", companyID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

func (qs *attendanceQueryServiceImpl) GetUserCurrentAttendancePolicy(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	if date.IsZero() {
		date = time.Now().UTC()
	}

	policy, err := qs.attendanceRepo.GetUserCurrentAttendancePolicy(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get user current attendance policy: %w", err)
	}

	qs.logger.Debug("User current attendance policy retrieved",
		util.String("user_id", userID.String()),
		util.Time("date", date),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

// ============================================================================
// SUMMARY QUERIES
// ============================================================================

func (qs *attendanceQueryServiceImpl) GetAttendanceDailySummaryByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()

	// Normalize date to UTC
	dateUTC := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)

	summary, err := qs.attendanceRepo.GetAttendanceDailySummaryByUserDate(ctx, userID, dateUTC)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summary: %w", err)
	}

	qs.logger.Debug("Attendance daily summary retrieved by user and date",
		util.String("user_id", userID.String()),
		util.String("date", dateUTC.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceDailySummariesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()

	// Normalize dates
	startUTC := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	endUTC := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, time.UTC)

	// Validate date range using calendar days
	calendarDays := int(endUTC.Sub(startUTC).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	summaries, err := qs.attendanceRepo.GetAttendanceDailySummariesByUser(ctx, userID, startUTC, endUTC)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summaries by user: %w", err)
	}

	qs.logger.Debug("Attendance daily summaries retrieved by user",
		util.String("user_id", userID.String()),
		util.Time("start_date", startUTC),
		util.Time("end_date", endUTC),
		util.Int("calendar_days", calendarDays),
		util.Int("summary_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))

	return summaries, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceSummaryStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*AttendanceSummaryStats, error) {
	startTime := time.Now()

	// Normalize dates
	startUTC := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	endUTC := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, time.UTC)

	// Validate date range
	calendarDays := int(endUTC.Sub(startUTC).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days for statistics, got %d days", calendarDays)
	}

	// Get raw stats from repository
	rawStats, err := qs.attendanceRepo.GetAttendanceSummaryStats(ctx, companyID, startUTC, endUTC)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance summary stats: %w", err)
	}

	// Convert to typed stats
	stats := qs.convertToTypedStats(rawStats, calendarDays)

	qs.logger.Debug("Attendance summary stats retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startUTC),
		util.Time("end_date", endUTC),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

// ============================================================================
// REPORT GENERATION
// ============================================================================

func (qs *attendanceQueryServiceImpl) GenerateAttendanceReport(
	ctx context.Context,
	companyID uuid.UUID,
	reportType string,
	startDate, endDate time.Time,
) ([]byte, string, error) {
	startTime := time.Now()

	// Normalize dates
	startUTC := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	endUTC := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, time.UTC)

	// Validate date range
	calendarDays := int(endUTC.Sub(startUTC).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, "", fmt.Errorf("report period cannot exceed 31 days, got %d days", calendarDays)
	}

	var data []byte
	var contentType string
	var err error

	switch strings.ToLower(reportType) {
	case "department_summary":
		report, err := qs.GetAttendanceReportByDepartment(ctx, companyID, startUTC, endUTC)
		if err != nil {
			return nil, "", err
		}
		data, err = json.Marshal(report)
		contentType = "application/json"

	case "late_arrivals":
		report, err := qs.GetLateArrivalsReport(ctx, companyID, startUTC, endUTC)
		if err != nil {
			return nil, "", err
		}
		data, err = json.Marshal(report)
		contentType = "application/json"

	case "overtime":
		report, err := qs.GetOvertimeReport(ctx, companyID, startUTC, endUTC)
		if err != nil {
			return nil, "", err
		}
		data, err = json.Marshal(report)
		contentType = "application/json"

	case "csv":
		// Stream events with pagination to avoid memory issues
		data, err = qs.generateCSVReport(ctx, companyID, startUTC, endUTC)
		if err != nil {
			return nil, "", err
		}
		contentType = "text/csv"

	default:
		return nil, "", fmt.Errorf("unsupported report type: %s", reportType)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to generate %s report: %w", reportType, err)
	}

	qs.logger.Info("Attendance report generated",
		util.String("company_id", companyID.String()),
		util.String("report_type", reportType),
		util.Time("start_date", startUTC),
		util.Time("end_date", endUTC),
		util.Int("calendar_days", calendarDays),
		util.Int("data_size", len(data)),
		util.Duration("duration", time.Since(startTime)))

	return data, contentType, nil
}

// generateCSVReport generates CSV with streaming/pagination
func (qs *attendanceQueryServiceImpl) generateCSVReport(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"Event ID",
		"User ID",
		"Event Type",
		"Event Time (UTC)",
		"Source Type",
		"Device ID",
		"IP Address",
		"Company ID",
	}

	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Stream events with pagination
	page := 1
	pageSize := 1000

	for {
		events, totalCount, err := qs.GetAttendanceEventsByCompany(ctx, companyID, startDate, endDate, page, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch events for CSV: %w", err)
		}

		if len(events) == 0 {
			break
		}

		// Write events
		for _, event := range events {
			deviceID := ""
			if event.DeviceID != nil {
				deviceID = *event.DeviceID
			}

			ipAddress := ""
			if event.IPAddress != nil {
				ipAddress = *event.IPAddress
			}

			row := []string{
				event.AttendanceEventID.String(),
				event.UserID.String(),
				event.EventType,
				event.EventTime.Format(time.RFC3339),
				event.SourceType,
				deviceID,
				ipAddress,
				event.CompanyID.String(),
			}

			if err := writer.Write(row); err != nil {
				return nil, fmt.Errorf("failed to write CSV row: %w", err)
			}
		}

		qs.logger.Debug("CSV report batch processed",
			util.String("company_id", companyID.String()),
			util.Int("page", page),
			util.Int("batch_size", len(events)))

		// Check if we've processed all events
		if page*pageSize >= totalCount {
			break
		}

		page++
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV flush error: %w", err)
	}

	return []byte(buf.String()), nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceReportByDepartment(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	report, err := qs.attendanceRepo.GetAttendanceReportByDepartment(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance report by department: %w", err)
	}

	qs.logger.Debug("Attendance report by department retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Duration("duration", time.Since(startTime)))

	return report, nil
}

func (qs *attendanceQueryServiceImpl) GetLateArrivalsReport(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]map[string]interface{}, error) {
	startTime := time.Now()

	report, err := qs.attendanceRepo.GetLateArrivalsReport(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get late arrivals report: %w", err)
	}

	qs.logger.Debug("Late arrivals report retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("record_count", len(report)),
		util.Duration("duration", time.Since(startTime)))

	return report, nil
}

func (qs *attendanceQueryServiceImpl) GetOvertimeReport(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]map[string]interface{}, error) {
	startTime := time.Now()

	report, err := qs.attendanceRepo.GetOvertimeReport(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get overtime report: %w", err)
	}

	qs.logger.Debug("Overtime report retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("record_count", len(report)),
		util.Duration("duration", time.Since(startTime)))

	return report, nil
}

// StreamAttendanceEvents streams events directly to writer for large datasets
func (qs *attendanceQueryServiceImpl) StreamAttendanceEvents(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	writer io.Writer,
	format string,
) error {
	if format != "csv" && format != "jsonl" {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Normalize dates
	startUTC := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, time.UTC)
	endUTC := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 0, time.UTC)

	// Validate date range
	calendarDays := int(endUTC.Sub(startUTC).Hours()/24) + 1
	if calendarDays > 31 {
		return fmt.Errorf("streaming period cannot exceed 31 days, got %d days", calendarDays)
	}

	if format == "csv" {
		csvWriter := csv.NewWriter(writer)
		defer csvWriter.Flush()

		header := []string{"Event ID", "User ID", "Event Type", "Event Time", "Source Type"}
		if err := csvWriter.Write(header); err != nil {
			return err
		}

		// Stream with pagination
		page := 1
		pageSize := 1000

		for {
			events, totalCount, err := qs.GetAttendanceEventsByCompany(ctx, companyID, startUTC, endUTC, page, pageSize)
			if err != nil {
				return err
			}

			if len(events) == 0 {
				break
			}

			for _, event := range events {
				row := []string{
					event.AttendanceEventID.String(),
					event.UserID.String(),
					event.EventType,
					event.EventTime.Format(time.RFC3339),
					event.SourceType,
				}
				if err := csvWriter.Write(row); err != nil {
					return err
				}
			}

			if page*pageSize >= totalCount {
				break
			}
			page++
		}

		return csvWriter.Error()
	}

	// JSON Lines format
	page := 1
	pageSize := 1000

	for {
		events, totalCount, err := qs.GetAttendanceEventsByCompany(ctx, companyID, startUTC, endUTC, page, pageSize)
		if err != nil {
			return err
		}

		if len(events) == 0 {
			break
		}

		for _, event := range events {
			jsonData, err := json.Marshal(event)
			if err != nil {
				return err
			}

			if _, err := writer.Write(jsonData); err != nil {
				return err
			}
			if _, err := writer.Write([]byte("\n")); err != nil {
				return err
			}
		}

		if page*pageSize >= totalCount {
			break
		}
		page++
	}

	return nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (qs *attendanceQueryServiceImpl) convertToTypedStats(rawStats map[string]interface{}, calendarDays int) *AttendanceSummaryStats {
	stats := &AttendanceSummaryStats{
		ByDepartment: make(map[string]int64),
		ByStatus:     make(map[string]int64),
		ByDate:       make(map[string]int64),
	}

	// Extract values from raw stats
	if val, ok := rawStats["total_records"].(int); ok {
		stats.TotalRecords = int64(val)
	}

	if val, ok := rawStats["present_days"].(int); ok {
		stats.PresentDays = int64(val)
	}

	if val, ok := rawStats["absent_days"].(int); ok {
		stats.AbsentDays = int64(val)
	}

	if val, ok := rawStats["late_arrivals"].(int); ok {
		stats.LateCount = int64(val)
	}

	if val, ok := rawStats["total_overtime_minutes"].(int); ok {
		stats.TotalOvertimeMinutes = int64(val)
	}

	if val, ok := rawStats["avg_worked_minutes"].(float64); ok {
		stats.AvgWorkedMinutes = val
	}

	// Calculate attendance rate
	if stats.TotalRecords > 0 {
		stats.AttendanceRate = float64(stats.PresentDays+stats.HalfDays) / float64(stats.TotalRecords) * 100.0
	}

	// Extract status distribution
	if statusDist, ok := rawStats["status_distribution"].(map[string]int); ok {
		for status, count := range statusDist {
			stats.ByStatus[status] = int64(count)
		}
	}

	// Extract daily activity
	if dailyActivity, ok := rawStats["daily_activity"].(map[string]int); ok {
		for date, count := range dailyActivity {
			stats.ByDate[date] = int64(count)
		}
	}

	return stats
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (qs *attendanceQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.attendanceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}
