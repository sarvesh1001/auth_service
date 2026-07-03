package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/query"
)

type ReportService interface {
	GenerateReport(ctx context.Context, req *ReportRequest) ([]byte, string, error)
	StreamEvents(ctx context.Context, companyID uuid.UUID, filter query.EventFilter, writer io.Writer, format string) error
}

type ReportRequest struct {
	CompanyID     uuid.UUID
	SubjectType   *string
	SubjectID     *uuid.UUID
	StartDate     time.Time
	EndDate       time.Time
	ReportType    string // "csv" or "json"
	IncludeEvents bool
}

type reportService struct {
	queryService query.QueryService
	logger       *zap.Logger
}

func NewReportService(queryService query.QueryService, logger *zap.Logger) ReportService {
	return &reportService{
		queryService: queryService,
		logger:       logger,
	}
}

func (s *reportService) GenerateReport(ctx context.Context, req *ReportRequest) ([]byte, string, error) {
	if req.CompanyID == uuid.Nil {
		return nil, "", fmt.Errorf("company ID is required")
	}
	if req.StartDate.After(req.EndDate) {
		return nil, "", fmt.Errorf("start date cannot be after end date")
	}
	if req.ReportType != "csv" && req.ReportType != "json" {
		return nil, "", fmt.Errorf("unsupported report type: %s", req.ReportType)
	}

	var data interface{}
	var err error

	if req.IncludeEvents {
		filter := query.EventFilter{
			CompanyID:   req.CompanyID,
			SubjectType: req.SubjectType,
			SubjectID:   req.SubjectID,
			StartDate:   req.StartDate,
			EndDate:     req.EndDate,
			Page:        1,
			PageSize:    10000,
		}
		events, _, err := s.queryService.ListEvents(ctx, filter)
		if err != nil {
			return nil, "", err
		}
		data = events
	} else {
		var summaries []*models.AttendanceDailySummary
		if req.SubjectType != nil && req.SubjectID != nil {
			summaries, err = s.queryService.ListDailySummaries(ctx, req.CompanyID, *req.SubjectID, *req.SubjectType, req.StartDate, req.EndDate)
		} else {
			summaries, err = s.queryService.ListCompanySummaries(ctx, req.CompanyID, req.StartDate, req.EndDate)
		}
		if err != nil {
			return nil, "", err
		}
		data = summaries
	}

	var reportData []byte
	var contentType string
	switch req.ReportType {
	case "csv":
		reportData, err = s.generateCSV(data, req.IncludeEvents)
		contentType = "text/csv"
	case "json":
		reportData, err = json.MarshalIndent(data, "", "  ")
		contentType = "application/json"
	}
	if err != nil {
		return nil, "", err
	}
	return reportData, contentType, nil
}

func (s *reportService) StreamEvents(ctx context.Context, companyID uuid.UUID, filter query.EventFilter, writer io.Writer, format string) error {
	if format != "csv" && format != "jsonl" {
		return fmt.Errorf("unsupported stream format: %s", format)
	}
	filter.CompanyID = companyID
	filter.Page = 1
	filter.PageSize = 1000

	firstPage := true
	for {
		events, total, err := s.queryService.ListEvents(ctx, filter)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			break
		}
		if format == "csv" {
			if err := s.streamEventsAsCSV(events, writer, firstPage); err != nil {
				return err
			}
		} else {
			if err := s.streamEventsAsJSONL(events, writer); err != nil {
				return err
			}
		}
		firstPage = false
		if filter.Page*filter.PageSize >= int(total) {
			break
		}
		filter.Page++
	}
	return nil
}

// Helper methods
func (s *reportService) generateCSV(data interface{}, isEvents bool) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	var header []string
	if isEvents {
		header = []string{
			"Event ID", "Subject Type", "Subject ID", "Event Type", "Event Time",
			"Source Type", "Device ID", "IP Address", "Created At",
		}
	} else {
		header = []string{
			"Date", "Subject Type", "Subject ID", "Status", "Worked Minutes",
			"Overtime Minutes", "Late Minutes", "Expected Minutes",
		}
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	if isEvents {
		events := data.([]*models.AttendanceEvent)
		for _, e := range events {
			deviceID := ""
			if e.DeviceID != nil {
				deviceID = *e.DeviceID
			}
			ip := ""
			if e.IPAddress != nil {
				ip = *e.IPAddress
			}
			row := []string{
				e.AttendanceEventID.String(),
				e.SubjectType,
				e.SubjectID.String(),
				e.EventType,
				e.EventTime.Format(time.RFC3339),
				e.SourceType,
				deviceID,
				ip,
				e.CreatedAt.Format(time.RFC3339),
			}
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	} else {
		summaries := data.([]*models.AttendanceDailySummary)
		for _, s := range summaries {
			worked := ""
			if s.WorkedMinutes != nil {
				worked = fmt.Sprintf("%d", *s.WorkedMinutes)
			}
			overtime := ""
			if s.OvertimeMinutes != nil {
				overtime = fmt.Sprintf("%d", *s.OvertimeMinutes)
			}
			late := ""
			if s.LateMinutes != nil {
				late = fmt.Sprintf("%d", *s.LateMinutes)
			}
			expected := ""
			if s.ExpectedMinutes != nil {
				expected = fmt.Sprintf("%d", *s.ExpectedMinutes)
			}
			row := []string{
				s.AttendanceDate.Format("2006-01-02"),
				s.SubjectType,
				s.SubjectID.String(),
				s.Status,
				worked,
				overtime,
				late,
				expected,
			}
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *reportService) streamEventsAsCSV(events []*models.AttendanceEvent, writer io.Writer, writeHeader bool) error {
	csvWriter := csv.NewWriter(writer)
	if writeHeader {
		header := []string{
			"Event ID", "Subject Type", "Subject ID", "Event Type", "Event Time",
			"Source Type", "Device ID", "IP Address", "Created At",
		}
		if err := csvWriter.Write(header); err != nil {
			return err
		}
	}
	for _, e := range events {
		deviceID := ""
		if e.DeviceID != nil {
			deviceID = *e.DeviceID
		}
		ip := ""
		if e.IPAddress != nil {
			ip = *e.IPAddress
		}
		row := []string{
			e.AttendanceEventID.String(),
			e.SubjectType,
			e.SubjectID.String(),
			e.EventType,
			e.EventTime.Format(time.RFC3339),
			e.SourceType,
			deviceID,
			ip,
			e.CreatedAt.Format(time.RFC3339),
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func (s *reportService) streamEventsAsJSONL(events []*models.AttendanceEvent, writer io.Writer) error {
	for _, e := range events {
		data, err := json.Marshal(e)
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
