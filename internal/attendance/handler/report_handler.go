// internal/attendance/handler/report_handler.go
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/query"
	"auth-service/internal/attendance/service/report"
)

// AttendanceReportHandler handles report generation and streaming.
type AttendanceReportHandler struct {
	reportService report.ReportService
	queryService  query.QueryService
	logger        *zap.Logger
}

// NewAttendanceReportHandler creates a new report handler.
func NewAttendanceReportHandler(
	reportService report.ReportService,
	queryService query.QueryService,
	logger *zap.Logger,
) *AttendanceReportHandler {
	return &AttendanceReportHandler{
		reportService: reportService,
		queryService:  queryService,
		logger:        logger,
	}
}

// GenerateReport generates a report (CSV or JSON) for events or summaries.
func (h *AttendanceReportHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	reportType := r.URL.Query().Get("type")
	if reportType == "" {
		reportType = "csv"
	}
	if reportType != "csv" && reportType != "json" {
		h.respondWithError(w, http.StatusBadRequest, "unsupported report type, use 'csv' or 'json'")
		return
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	subjectType := r.URL.Query().Get("subject_type")
	var subjectID *uuid.UUID
	if v := r.URL.Query().Get("subject_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
			return
		}
		subjectID = &id
	}

	includeEvents := r.URL.Query().Get("include_events") == "true"

	req := &report.ReportRequest{
		CompanyID:     companyID,
		SubjectType:   &subjectType,
		SubjectID:     subjectID,
		StartDate:     startDate,
		EndDate:       endDate,
		ReportType:    reportType,
		IncludeEvents: includeEvents,
	}

	data, contentType, err := h.reportService.GenerateReport(ctx, req)
	if err != nil {
		h.logger.Error("Failed to generate report",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate report")
		return
	}

	filename := fmt.Sprintf(
		"attendance_report_%s_%s_to_%s.%s",
		companyID.String()[:8],
		startDate.Format("20060102"),
		endDate.Format("20060102"),
		reportType,
	)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// StreamEvents streams attendance events in CSV or JSONL format.
func (h *AttendanceReportHandler) StreamEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" {
		h.respondWithError(w, http.StatusBadRequest, "unsupported format, use 'csv' or 'jsonl'")
		return
	}

	startDate, endDate, err := parseDateRange(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := query.EventFilter{
		CompanyID: companyID,
		StartDate: startDate,
		EndDate:   endDate,
		Page:      1,
		PageSize:  1000,
	}

	if v := r.URL.Query().Get("subject_type"); v != "" {
		filter.SubjectType = &v
	}
	if v := r.URL.Query().Get("subject_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
			return
		}
		filter.SubjectID = &id
	}
	if v := r.URL.Query().Get("event_type"); v != "" {
		filter.EventTypes = []string{v}
	}
	if v := r.URL.Query().Get("source_type"); v != "" {
		filter.SourceType = &v
	}
	if v := r.URL.Query().Get("device_id"); v != "" {
		filter.DeviceID = &v
	}

	// Fix: Replace ternary with if/else
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		filename := fmt.Sprintf("attendance_events_%s_to_%s.csv", startDate.Format("20060102"), endDate.Format("20060102"))
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}

	if err := h.reportService.StreamEvents(ctx, companyID, filter, w, format); err != nil {
		h.logger.Error("Failed to stream events",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		// Since headers may already be written, we can't return JSON
		http.Error(w, "failed to stream events", http.StatusInternalServerError)
		return
	}
}

// ---- Helpers ----

func parseDateRange(r *http.Request) (time.Time, time.Time, error) {
	startStr := r.URL.Query().Get("start_date")
	endStr := r.URL.Query().Get("end_date")

	start := time.Now().AddDate(0, 0, -30)
	end := time.Now()

	var err error
	if startStr != "" {
		start, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date format, use YYYY-MM-DD")
		}
	}
	if endStr != "" {
		end, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date format, use YYYY-MM-DD")
		}
	}
	if start.After(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("start_date cannot be after end_date")
	}
	return start, end, nil
}

func (h *AttendanceReportHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceReportHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
