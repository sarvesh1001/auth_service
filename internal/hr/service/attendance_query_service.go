package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceQueryService interface {
	GetAttendanceEventByID(
		ctx context.Context,
		eventID uuid.UUID,
	) (*attendance.AttendanceEvent, error)
	GetAttendanceStats(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) (*attendance.AttendanceStats, error)

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
	SearchAttendanceEventsTyped(
		ctx context.Context,
		companyID uuid.UUID,
		filters AttendanceSearchFilters,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)
	GetUserAttendanceStats(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (*attendance.UserAttendanceStats, error)

	GetAttendancePolicyByID(
		ctx context.Context,
		policyID uuid.UUID,
	) (*attendance.AttendancePolicy, error)
	GetAttendancePoliciesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendancePolicy, error)
	GetUserCurrentAttendancePolicy(
		ctx context.Context,
		userID uuid.UUID,
		date time.Time,
	) (*attendance.AttendancePolicy, error)
	GetAttendanceDailySummaryByUserDate(
		ctx context.Context,
		userID uuid.UUID,
		date time.Time,
	) (*attendance.AttendanceDailySummary, error)
	GetAttendanceDailySummariesByUser(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]*attendance.AttendanceDailySummary, error)
	GetAttendanceSummaryStats(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) (*AttendanceSummaryStats, error)
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
	ListAttendanceEventTypes(
		ctx context.Context,
		activeOnly bool,
	) ([]*attendance.AttendanceEventType, error)
	ListAttendanceSourceTypes(
		ctx context.Context,
	) ([]*attendance.AttendanceSourceType, error)
	HealthCheck(ctx context.Context) error
}

type AttendanceSearchFilters struct {
	CompanyID    uuid.UUID
	UserID       *uuid.UUID
	StartDate    time.Time
	EndDate      time.Time
	EventTypes   []string // ✅ CHANGED (was EventType)
	SourceType   *string
	DepartmentID *uuid.UUID
	ShiftID      *uuid.UUID
}

type AttendanceSummaryStats struct {
	CompanyID           uuid.UUID                  `json:"company_id"`
	StartDate           time.Time                  `json:"start_date"`
	EndDate             time.Time                  `json:"end_date"`
	TotalEmployees      int                        `json:"total_employees"`
	SummaryByStatus     map[string]int             `json:"summary_by_status"`
	AverageHours        float64                    `json:"average_hours"`
	OvertimeHours       float64                    `json:"overtime_hours"`
	LateArrivals        int                        `json:"late_arrivals"`
	TopLateEmployees    []LateEmployeeSummary      `json:"top_late_employees"`
	DepartmentBreakdown map[string]DepartmentStats `json:"department_breakdown"`
}

type LateEmployeeSummary struct {
	UserID             uuid.UUID `json:"user_id"`
	Username           string    `json:"username"`
	FullName           string    `json:"full_name"`
	LateCount          int       `json:"late_count"`
	AverageLateMinutes int       `json:"average_late_minutes"`
}

type DepartmentStats struct {
	DepartmentID   uuid.UUID `json:"department_id"`
	DepartmentName string    `json:"department_name"`
	PresentCount   int       `json:"present_count"`
	AbsentCount    int       `json:"absent_count"`
	LateCount      int       `json:"late_count"`
	AverageHours   float64   `json:"average_hours"`
}

type attendanceQueryServiceImpl struct {
	attendanceRepo repository.AttendanceRepository
	logger         *zap.Logger
}

func NewAttendanceQueryService(
	attendanceRepo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendanceQueryService {
	return &attendanceQueryServiceImpl{
		attendanceRepo: attendanceRepo,
		logger:         logger,
	}
}

func (qs *attendanceQueryServiceImpl) GetAttendanceEventByID(
	ctx context.Context,
	eventID uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()
	if eventID == uuid.Nil {
		return nil, fmt.Errorf("event ID is required")
	}

	event, err := qs.attendanceRepo.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		qs.logger.Error("Failed to get attendance event by ID",
			util.String("event_id", eventID.String()),
			util.ErrorField(err))
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
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range
	maxDays := 90
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Set default limit if not provided
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	events, err := qs.attendanceRepo.GetAttendanceEventsByUser(ctx, userID, startDate, endDate, limit)
	if err != nil {
		qs.logger.Error("Failed to get attendance events by user",
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance events by user: %w", err)
	}

	qs.logger.Debug("Attendance events retrieved by user",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("limit", limit),
		util.Int("event_count", len(events)),
		util.Duration("duration", time.Since(startTime)))
	return events, nil
}

func (qs *attendanceQueryServiceImpl) SearchAttendanceEvents(
	ctx context.Context,
	companyID uuid.UUID,
	filters AttendanceSearchFilters,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {

	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}

	// Pagination defaults
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Date defaults
	if filters.StartDate.IsZero() {
		filters.StartDate = time.Now().AddDate(0, 0, -30)
	}
	if filters.EndDate.IsZero() {
		filters.EndDate = time.Now()
	}

	if filters.StartDate.After(filters.EndDate) {
		return nil, 0, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range
	maxDays := 90
	if filters.EndDate.Sub(filters.StartDate).Hours()/24 > float64(maxDays) {
		return nil, 0, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// 🔥 BUILD REPO FILTER
	repoFilter := repository.AttendanceEventFilter{
		CompanyID:  companyID,
		UserID:     filters.UserID,
		StartDate:  filters.StartDate,
		EndDate:    filters.EndDate,
		EventTypes: filters.EventTypes, // ✅ NEW
		SourceType: filters.SourceType,
		Page:       page,
		PageSize:   pageSize,
	}

	events, total, err := qs.attendanceRepo.SearchAttendanceEvents(ctx, repoFilter)
	if err != nil {
		qs.logger.Error(
			"Failed to search attendance events",
			util.String("company_id", companyID.String()),
			util.Time("start_date", filters.StartDate),
			util.Time("end_date", filters.EndDate),
			util.ErrorField(err),
		)
		return nil, 0, fmt.Errorf("failed to search attendance events: %w", err)
	}

	qs.logger.Debug(
		"Attendance events searched",
		util.String("company_id", companyID.String()),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_events", int(total)),
		util.Int("returned_events", len(events)),
		util.Duration("duration", time.Since(startTime)),
	)

	return events, int(total), nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceDailySummaryByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if date.IsZero() {
		date = time.Now()
	}

	summary, err := qs.attendanceRepo.GetAttendanceDailySummaryByUserDate(ctx, userID, date)
	if err != nil {
		qs.logger.Error("Failed to get attendance daily summary",
			util.String("user_id", userID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance daily summary: %w", err)
	}

	qs.logger.Debug("Attendance daily summary retrieved",
		util.String("user_id", userID.String()),
		util.String("date", date.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))
	return summary, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceDailySummariesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range
	maxDays := 365
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	summaries, err := qs.attendanceRepo.GetAttendanceDailySummariesByUser(ctx, userID, startDate, endDate)
	if err != nil {
		qs.logger.Error("Failed to get attendance daily summaries",
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance daily summaries: %w", err)
	}

	qs.logger.Debug("Attendance daily summaries retrieved",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("summary_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))
	return summaries, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*attendance.AttendanceStats, error) {
	startTime := time.Now()
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if startDate.IsZero() || endDate.IsZero() {
		return nil, fmt.Errorf("start date and end date are required")
	}
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	stats, err := qs.attendanceRepo.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		qs.logger.Error("Failed to get attendance stats",
			util.String("company_id", companyID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}

	if stats == nil {
		stats = &attendance.AttendanceStats{
			CompanyID:          companyID,
			StartDate:          startDate,
			EndDate:            endDate,
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
	}

	qs.logger.Debug("Attendance stats retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("total_employees", stats.TotalEmployees),
		util.Int("present_count", stats.PresentCount),
		util.Int("late_count", stats.LateCount),
		util.Float64("average_attendance", stats.AverageAttendance),
		util.Duration("duration", time.Since(startTime)))
	return stats, nil
}

func (qs *attendanceQueryServiceImpl) GetUserAttendanceStats(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (*attendance.UserAttendanceStats, error) {
	startTime := time.Now()
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if startDate.IsZero() || endDate.IsZero() {
		return nil, fmt.Errorf("start date and end date are required")
	}
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range
	maxDays := 365
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Check if user exists and has attendance profile
	_, err := qs.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}

	stats, err := qs.attendanceRepo.GetUserAttendanceStats(ctx, userID, startDate, endDate)
	if err != nil {
		qs.logger.Error("Failed to get user attendance stats",
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get user attendance stats: %w", err)
	}

	if stats == nil {
		stats = &attendance.UserAttendanceStats{
			UserID:             userID,
			StartDate:          startDate,
			EndDate:            endDate,
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
	}

	qs.logger.Debug("User attendance stats retrieved",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("present_days", stats.PresentDays),
		util.Int("absent_days", stats.AbsentDays),
		util.Int("late_days", stats.LateDays),
		util.Float64("attendance_percent", stats.AttendancePercent),
		util.Duration("duration", time.Since(startTime)))
	return stats, nil
}

func (qs *attendanceQueryServiceImpl) GenerateAttendanceReport(
	ctx context.Context,
	companyID uuid.UUID,
	reportType string,
	startDate, endDate time.Time,
) ([]byte, string, error) {
	startTime := time.Now()

	// Validate report type
	if reportType != "csv" && reportType != "json" {
		return nil, "", fmt.Errorf("unsupported report type: %s. Supported types: csv, json", reportType)
	}

	// Validate date range
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, "", fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Get attendance summaries for the date range
	summaries, _, err := qs.attendanceRepo.GetAttendanceDailySummariesByCompany(ctx, companyID, startDate, endDate, 1, 10000)
	if err != nil {
		qs.logger.Error("Failed to get attendance summaries for report",
			util.String("company_id", companyID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, "", fmt.Errorf("failed to get attendance summaries: %w", err)
	}

	// Generate report based on type
	var reportData []byte
	var contentType string

	switch reportType {
	case "csv":
		reportData, err = qs.generateCSVReport(summaries)
		contentType = "text/csv"
	case "json":
		reportData, err = qs.generateJSONReport(summaries)
		contentType = "application/json"
	}

	if err != nil {
		qs.logger.Error("Failed to generate attendance report",
			util.String("company_id", companyID.String()),
			util.String("report_type", reportType),
			util.ErrorField(err))
		return nil, "", fmt.Errorf("failed to generate %s report: %w", reportType, err)
	}

	qs.logger.Info("Attendance report generated",
		util.String("company_id", companyID.String()),
		util.String("report_type", reportType),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("record_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))
	return reportData, contentType, nil
}

func (qs *attendanceQueryServiceImpl) StreamAttendanceEvents(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	writer io.Writer,
	format string,
) error {
	startTime := time.Now()

	// Validate format
	if format != "csv" && format != "jsonl" {
		return fmt.Errorf("unsupported stream format: %s. Supported formats: csv, jsonl", format)
	}

	// Validate date range for streaming
	maxDays := 7
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return fmt.Errorf("date range cannot exceed %d days for streaming", maxDays)
	}

	page := 1
	pageSize := 1000
	totalEvents := 0

	for {
		// Get events in batches
		events, total, err := qs.attendanceRepo.GetAttendanceEventsByCompany(ctx, companyID, startDate, endDate, page, pageSize)
		if err != nil {
			qs.logger.Error("Failed to get attendance events for streaming",
				util.String("company_id", companyID.String()),
				util.Int("page", page),
				util.ErrorField(err))
			return fmt.Errorf("failed to get attendance events: %w", err)
		}

		if len(events) == 0 {
			break
		}

		// Stream events in the requested format
		switch format {
		case "csv":
			if err := qs.streamEventsAsCSV(events, writer, page == 1); err != nil {
				qs.logger.Error("Failed to stream events as CSV",
					util.String("company_id", companyID.String()),
					util.ErrorField(err))
				return err
			}
		case "jsonl":
			if err := qs.streamEventsAsJSONL(events, writer); err != nil {
				qs.logger.Error("Failed to stream events as JSONL",
					util.String("company_id", companyID.String()),
					util.ErrorField(err))
				return err
			}
		}

		totalEvents += len(events)

		// Check if we've processed all events
		if page*pageSize >= int(total) {
			break
		}

		page++

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	qs.logger.Info("Attendance events streamed",
		util.String("company_id", companyID.String()),
		util.String("format", format),
		util.Int("total_events", totalEvents),
		util.Duration("duration", time.Since(startTime)))
	return nil
}

func (qs *attendanceQueryServiceImpl) ListAttendanceEventTypes(
	ctx context.Context,
	activeOnly bool,
) ([]*attendance.AttendanceEventType, error) {
	startTime := time.Now()

	eventTypes, err := qs.attendanceRepo.GetAttendanceEventTypes(ctx)
	if err != nil {
		qs.logger.Error("Failed to get attendance event types",
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance event types: %w", err)
	}

	// Filter active types if requested
	if activeOnly {
		var activeTypes []*attendance.AttendanceEventType
		for _, et := range eventTypes {
			if et.IsActive {
				activeTypes = append(activeTypes, et)
			}
		}
		qs.logger.Debug("Active attendance event types retrieved",
			util.Int("count", len(activeTypes)),
			util.Duration("duration", time.Since(startTime)))
		return activeTypes, nil
	}

	qs.logger.Debug("All attendance event types retrieved",
		util.Int("count", len(eventTypes)),
		util.Duration("duration", time.Since(startTime)))
	return eventTypes, nil
}

func (qs *attendanceQueryServiceImpl) ListAttendanceSourceTypes(
	ctx context.Context,
) ([]*attendance.AttendanceSourceType, error) {
	startTime := time.Now()

	sourceTypes, err := qs.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		qs.logger.Error("Failed to get attendance source types",
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance source types: %w", err)
	}

	qs.logger.Debug("Attendance source types retrieved",
		util.Int("count", len(sourceTypes)),
		util.Duration("duration", time.Since(startTime)))
	return sourceTypes, nil
}

func (qs *attendanceQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.attendanceRepo.HealthCheck(ctx); err != nil {
		qs.logger.Error("Attendance repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

func (qs *attendanceQueryServiceImpl) generateCSVReport(summaries []*attendance.AttendanceDailySummary) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"Date", "User ID", "Status", "Worked Hours", "Overtime Hours",
		"Late Minutes", "Generated At",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// Write data rows
	for _, summary := range summaries {
		var workedHours, overtimeHours, lateMinutes string

		if summary.WorkedMinutes != nil {
			workedHours = fmt.Sprintf("%.2f", float64(*summary.WorkedMinutes)/60.0)
		}

		if summary.OvertimeMinutes != nil {
			overtimeHours = fmt.Sprintf("%.2f", float64(*summary.OvertimeMinutes)/60.0)
		}

		if summary.LateMinutes != nil {
			lateMinutes = fmt.Sprintf("%d", *summary.LateMinutes)
		}

		row := []string{
			summary.AttendanceDate.Format("2006-01-02"),
			summary.UserID.String(),
			summary.Status,
			workedHours,
			overtimeHours,
			lateMinutes,
			summary.GeneratedAt.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (qs *attendanceQueryServiceImpl) generateJSONReport(summaries []*attendance.AttendanceDailySummary) ([]byte, error) {
	report := map[string]interface{}{
		"summaries":    summaries,
		"generated_at": time.Now().UTC(),
		"total_count":  len(summaries),
	}
	return json.MarshalIndent(report, "", "  ")
}

func (qs *attendanceQueryServiceImpl) streamEventsAsCSV(events []*attendance.AttendanceEvent, writer io.Writer, writeHeader bool) error {
	csvWriter := csv.NewWriter(writer)

	// Write header if this is the first batch
	if writeHeader {
		header := []string{
			"Event ID", "User ID", "Event Type", "Event Time", "Source Type",
			"Device ID", "IP Address", "Created At", "Work Center Code", "Location ID",
		}
		if err := csvWriter.Write(header); err != nil {
			return err
		}
	}

	// Write event rows
	for _, event := range events {
		var deviceID, ipAddress, workCenterCode, locationID string

		if event.DeviceID != nil {
			deviceID = *event.DeviceID
		}

		if event.IPAddress != nil {
			ipAddress = *event.IPAddress
		}

		if event.Context.WorkCenterCode != nil {
			workCenterCode = *event.Context.WorkCenterCode
		}

		if event.Context.LocationID != nil {
			locationID = event.Context.LocationID.String()
		}

		row := []string{
			event.AttendanceEventID.String(),
			event.UserID.String(),
			event.EventType,
			event.EventTime.Format("2006-01-02 15:04:05"),
			event.SourceType,
			deviceID,
			ipAddress,
			event.CreatedAt.Format("2006-01-02 15:04:05"),
			workCenterCode,
			locationID,
		}

		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}

func (qs *attendanceQueryServiceImpl) streamEventsAsJSONL(events []*attendance.AttendanceEvent, writer io.Writer) error {
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}

		if _, err := writer.Write(data); err != nil {
			return err
		}

		if _, err := writer.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

// Helper method for backward compatibility (renamed from SearchAttendanceEventsTyped)
func (qs *attendanceQueryServiceImpl) SearchAttendanceEventsTyped(
	ctx context.Context,
	companyID uuid.UUID,
	filters AttendanceSearchFilters,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	return qs.SearchAttendanceEvents(ctx, companyID, filters, page, pageSize)
}

// Add this method to attendanceQueryServiceImpl in attendanceQueryService.go
func (qs *attendanceQueryServiceImpl) GetAttendanceEventsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}
	if startDate.IsZero() || endDate.IsZero() {
		return nil, 0, fmt.Errorf("start date and end date are required")
	}
	if startDate.After(endDate) {
		return nil, 0, fmt.Errorf("start date cannot be after end date")
	}

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Validate date range
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, 0, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Use repository method
	events, total, err := qs.attendanceRepo.GetAttendanceEventsByCompany(
		ctx, companyID, startDate, endDate, page, pageSize)
	if err != nil {
		qs.logger.Error("Failed to get attendance events by company",
			util.String("company_id", companyID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get attendance events by company: %w", err)
	}

	totalPages := (int(total) + pageSize - 1) / pageSize
	qs.logger.Debug("Attendance events retrieved by company",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_events", int(total)),
		util.Int("total_pages", totalPages),
		util.Int("returned_events", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, int(total), nil
}

// Add this method to attendanceQueryServiceImpl in attendanceQueryService.go
func (qs *attendanceQueryServiceImpl) GetAttendancePoliciesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}

	policies, err := qs.attendanceRepo.GetAttendancePoliciesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		qs.logger.Error("Failed to get attendance policies by company",
			util.String("company_id", companyID.String()),
			util.Bool("active_only", activeOnly),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance policies by company: %w", err)
	}

	qs.logger.Debug("Attendance policies retrieved by company",
		util.String("company_id", companyID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// ============================================
// POLICY QUERIES
// ============================================

func (qs *attendanceQueryServiceImpl) GetAttendancePolicyByID(
	ctx context.Context,
	policyID uuid.UUID,
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()
	if policyID == uuid.Nil {
		return nil, fmt.Errorf("policy ID is required")
	}

	policy, err := qs.attendanceRepo.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		qs.logger.Error("Failed to get attendance policy by ID",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance policy: %w", err)
	}

	qs.logger.Debug("Attendance policy retrieved by ID",
		util.String("policy_id", policyID.String()),
		util.Duration("duration", time.Since(startTime)))
	return policy, nil
}

func (qs *attendanceQueryServiceImpl) GetUserCurrentAttendancePolicy(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendancePolicy, error) {

	startTime := time.Now()

	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if date.IsZero() {
		date = time.Now()
	}

	// ------------------------------------------------------------
	// 1️⃣ USER-LEVEL POLICY (explicit assignment)
	// ------------------------------------------------------------
	userPolicy, err := qs.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, date)
	if err != nil {
		qs.logger.Error(
			"Failed to get user attendance policy",
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get user attendance policy: %w", err)
	}
	if userPolicy != nil {
		qs.logger.Debug(
			"Resolved attendance policy at USER level",
			util.String("user_id", userID.String()),
			util.String("policy_code", userPolicy.PolicyCode),
			util.Duration("duration", time.Since(startTime)),
		)
		return userPolicy, nil
	}

	// ------------------------------------------------------------
	// 2️⃣ POSITION-LEVEL POLICY
	// ------------------------------------------------------------
	companyEmployee, err := qs.attendanceRepo.GetCompanyEmployee(ctx, uuid.Nil, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company employee: %w", err)
	}

	if companyEmployee != nil && companyEmployee.PositionID != nil {

		positionPolicy, err := qs.attendanceRepo.GetPositionAttendancePolicy(
			ctx,
			*companyEmployee.PositionID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get position attendance policy: %w", err)
		}
		if positionPolicy != nil {
			qs.logger.Debug(
				"Resolved attendance policy at POSITION level",
				util.String("user_id", userID.String()),
				util.String("policy_code", positionPolicy.PolicyCode),
				util.Duration("duration", time.Since(startTime)),
			)
			return positionPolicy, nil
		}

		// --------------------------------------------------------
		// 3️⃣ WORK-CENTER POLICY (via position)
		// --------------------------------------------------------
		position, err := qs.attendanceRepo.GetPosition(ctx, *companyEmployee.PositionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get position: %w", err)
		}

		if position != nil && position.WorkCenterCode != nil {
			wcPolicy, err := qs.attendanceRepo.GetWorkCenterAttendancePolicy(
				ctx,
				companyEmployee.CompanyID,
				*position.WorkCenterCode,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to get work center attendance policy: %w", err)
			}
			if wcPolicy != nil {
				qs.logger.Debug(
					"Resolved attendance policy at WORK CENTER level",
					util.String("user_id", userID.String()),
					util.String("work_center_code", *position.WorkCenterCode),
					util.String("policy_code", wcPolicy.PolicyCode),
					util.Duration("duration", time.Since(startTime)),
				)
				return wcPolicy, nil
			}
		}
	}

	// ------------------------------------------------------------
	// 4️⃣ COMPANY DEFAULT POLICY (SAFE FALLBACK)
	// ------------------------------------------------------------
	defaultPolicy := &attendance.AttendancePolicy{
		PolicyID:   uuid.New(),
		PolicyCode: "DEFAULT",
		PolicyType: "company_default",
		Rules: attendance.PolicyRules{
			GracePeriod:         intPtr(15),
			MaxLateAllowed:      intPtr(60),
			HalfDayAfter:        intPtr(240),
			AutoCheckout:        boolPtr(false),
			OvertimeThreshold:   intPtr(15),
			AutoApproveOvertime: boolPtr(false),
			AllowShiftOverlap:   boolPtr(false),
		},
		IsActive: true,
	}

	qs.logger.Warn(
		"Falling back to DEFAULT attendance policy",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return defaultPolicy, nil
}

// ============================================
// DAILY SUMMARY QUERIES
// ============================================

// ============================================
// STATISTICS AND REPORTS
// ============================================

func (qs *attendanceQueryServiceImpl) GetAttendanceSummaryStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*AttendanceSummaryStats, error) {
	startTime := time.Now()
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	stats, err := qs.attendanceRepo.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}

	summaryStats := &AttendanceSummaryStats{
		CompanyID:      companyID,
		StartDate:      startDate,
		EndDate:        endDate,
		TotalEmployees: stats.TotalEmployees,
		SummaryByStatus: map[string]int{
			"present":  stats.PresentCount,
			"absent":   stats.AbsentCount,
			"late":     stats.LateCount,
			"half_day": stats.HalfDayCount,
			"leave":    stats.LeaveCount,
			"holiday":  stats.HolidayCount,
		},
		AverageHours:        stats.TotalWorkedHours,
		OvertimeHours:       stats.TotalOvertimeHours,
		LateArrivals:        stats.LateCount,
		TopLateEmployees:    []LateEmployeeSummary{},
		DepartmentBreakdown: map[string]DepartmentStats{},
	}

	qs.logger.Debug("Attendance summary stats retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("total_employees", stats.TotalEmployees),
		util.Int("present_count", stats.PresentCount),
		util.Int("late_count", stats.LateCount),
		util.Float64("average_attendance", stats.AverageAttendance),
		util.Duration("duration", time.Since(startTime)))
	return summaryStats, nil
}

func expandEventTypes(eventType string) []string {
	switch eventType {
	case "check_in":
		return []string{"check_in", "manual_check_in"}
	case "check_out":
		return []string{"check_out", "manual_check_out"}
	default:
		return []string{eventType}
	}
}
