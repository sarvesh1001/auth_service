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
	"auth-service/internal/locationctx"
)

type AttendanceReportHandler struct {
	reportService report.ReportService
	queryService  query.QueryService
	logger        *zap.Logger
}

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

// statusCapturingWriter wraps http.ResponseWriter and remembers whether
// WriteHeader has already been called. The report handler uses it to detect
// a partial-body situation where we can no longer set a 500.
type statusCapturingWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (s *statusCapturingWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.statusCode = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapturingWriter) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.statusCode = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusCapturingWriter) Header() http.Header {
	return s.ResponseWriter.Header()
}

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
		LocationID:    locationctx.Filter(ctx),
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

// StreamEvents streams attendance events as CSV or JSONL.
//
// FIX (Handler hygiene): the previous implementation called http.Error on
// failure, which does nothing if StreamEvents already wrote a 200 and some
// bytes. We now wrap the ResponseWriter in a status tracker. If the first
// byte was already emitted, the only honest thing to do is log the failure
// and stop — the client will see a truncated stream, which is detectable.
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
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		filename := fmt.Sprintf("attendance_events_%s_to_%s.csv", startDate.Format("20060102"), endDate.Format("20060102"))
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}

	sw := &statusCapturingWriter{ResponseWriter: w}
	locFilter := locationctx.Filter(ctx)
	if err := h.reportService.StreamEvents(ctx, companyID, locFilter, filter, sw, format); err != nil {
		h.logger.Error("Failed to stream events",
			zap.String("company_id", companyID.String()),
			zap.Int("status_code", sw.statusCode),
			zap.Bool("headers_flushed", sw.wroteHeader),
			zap.Error(err))
		if !sw.wroteHeader {
			// Safe to signal failure — nothing has been sent yet.
			http.Error(w, "failed to stream events", http.StatusInternalServerError)
			return
		}
		// Partial response already on the wire. Log and stop.
		return
	}
}

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