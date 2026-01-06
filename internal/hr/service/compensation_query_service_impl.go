package service

import (
	"auth-service/internal/hr/models/compensation"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// ============================================================================
// COMPENSATION QUERY SERVICE IMPLEMENTATION
// ============================================================================

type compensationQueryServiceImpl struct {
	compRepo repository.CompensationRepository
	logger   *zap.Logger
}

// NewCompensationQueryService creates a new compensation query service
func NewCompensationQueryService(
	compRepo repository.CompensationRepository,
	logger *zap.Logger,
) CompensationQueryService {
	return &compensationQueryServiceImpl{
		compRepo: compRepo,
		logger:   logger,
	}
}

// ============================================================================
// PAY UNIT QUERIES
// ============================================================================

func (qs *compensationQueryServiceImpl) GetPayUnitByID(ctx context.Context, payUnitID uuid.UUID) (*compensation.PayUnit, error) {
	startTime := time.Now()

	payUnit, err := qs.compRepo.GetPayUnitByID(ctx, payUnitID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pay unit: %w", err)
	}

	qs.logger.Debug("Pay unit retrieved by ID",
		util.String("pay_unit_id", payUnitID.String()),
		util.Duration("duration", time.Since(startTime)))

	return payUnit, nil
}

func (qs *compensationQueryServiceImpl) ListPayUnits(ctx context.Context) ([]*compensation.PayUnit, error) {
	startTime := time.Now()

	payUnits, err := qs.compRepo.ListPayUnits(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list pay units: %w", err)
	}

	qs.logger.Debug("Pay units listed",
		util.Int("pay_unit_count", len(payUnits)),
		util.Duration("duration", time.Since(startTime)))

	return payUnits, nil
}

// ============================================================================
// COMPENSATION STRUCTURE QUERIES
// ============================================================================

func (qs *compensationQueryServiceImpl) GetCompensationStructureByID(ctx context.Context, structureID uuid.UUID) (*compensation.CompensationStructure, error) {
	startTime := time.Now()

	structure, err := qs.compRepo.GetCompensationStructureByID(ctx, structureID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation structure: %w", err)
	}

	qs.logger.Debug("Compensation structure retrieved by ID",
		util.String("structure_id", structureID.String()),
		util.Duration("duration", time.Since(startTime)))

	return structure, nil
}
func (qs *compensationQueryServiceImpl) GetCompensationStructuresByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
	page, pageSize int,
) ([]*compensation.CompensationStructure, int, error) {
	startTime := time.Now()

	// Validate pagination
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// Get structures from repository
	structures, totalCount, err := qs.compRepo.GetCompensationStructuresByCompany(
		ctx,
		companyID,
		pageSize,
		offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get compensation structures by company: %w", err)
	}

	// Filter active only if requested
	if activeOnly {
		var activeStructures []*compensation.CompensationStructure
		for _, structure := range structures {
			if structure.IsActive {
				activeStructures = append(activeStructures, structure)
			}
		}
		structures = activeStructures
		// NOTE: totalCount remains DB total (document this in API)
	}

	qs.logger.Debug("Compensation structures retrieved by company",
		util.String("company_id", companyID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(structures)),
		util.Duration("duration", time.Since(startTime)),
	)

	return structures, totalCount, nil
}

func (qs *compensationQueryServiceImpl) GetCompensationStructureByCode(ctx context.Context, companyID uuid.UUID, structureCode string) (*compensation.CompensationStructure, error) {
	startTime := time.Now()

	structure, err := qs.compRepo.GetCompensationStructureByCode(ctx, companyID, structureCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation structure by code: %w", err)
	}

	qs.logger.Debug("Compensation structure retrieved by code",
		util.String("company_id", companyID.String()),
		util.String("structure_code", structureCode),
		util.Duration("duration", time.Since(startTime)))

	return structure, nil
}

// ============================================================================
// USER COMPENSATION QUERIES
// ============================================================================

func (qs *compensationQueryServiceImpl) GetUserCompensationByID(ctx context.Context, userID, structureID uuid.UUID, effectiveFrom time.Time) (*compensation.UserCompensation, error) {
	startTime := time.Now()

	comp, err := qs.compRepo.GetUserCompensationByID(ctx, userID, structureID, effectiveFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get user compensation: %w", err)
	}

	qs.logger.Debug("User compensation retrieved by ID",
		util.String("user_id", userID.String()),
		util.String("structure_id", structureID.String()),
		util.Time("effective_from", effectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return comp, nil
}

func (qs *compensationQueryServiceImpl) GetUserCompensationsByUser(ctx context.Context, userID uuid.UUID) ([]*compensation.UserCompensation, error) {
	startTime := time.Now()

	comps, err := qs.compRepo.GetUserCompensationsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user compensations by user: %w", err)
	}

	qs.logger.Debug("User compensations retrieved by user",
		util.String("user_id", userID.String()),
		util.Int("compensation_count", len(comps)),
		util.Duration("duration", time.Since(startTime)))

	return comps, nil
}

func (qs *compensationQueryServiceImpl) GetCurrentUserCompensation(ctx context.Context, userID uuid.UUID) (*compensation.UserCompensation, error) {
	startTime := time.Now()

	comp, err := qs.compRepo.GetCurrentUserCompensation(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current user compensation: %w", err)
	}

	qs.logger.Debug("Current user compensation retrieved",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return comp, nil
}

func (qs *compensationQueryServiceImpl) GetUserCompensationsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	page, pageSize int,
) ([]*compensation.UserCompensation, int, error) {
	startTime := time.Now()

	// Validate pagination
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// Get compensations from repository
	comps, totalCount, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get user compensations by company: %w", err)
	}

	qs.logger.Debug("User compensations retrieved by company",
		util.String("company_id", companyID.String()),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(comps)),
		util.Duration("duration", time.Since(startTime)))

	return comps, totalCount, nil
}

// ============================================================================
// ANALYTICS AND REPORTS
// ============================================================================

func (qs *compensationQueryServiceImpl) GetCompensationStatsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	startTime := time.Now()

	stats, err := qs.compRepo.GetCompensationStatsByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation stats by company: %w", err)
	}

	qs.logger.Debug("Compensation stats retrieved by company",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

func (qs *compensationQueryServiceImpl) GetAverageCTCByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]decimal.Decimal, error) {
	startTime := time.Now()

	averages, err := qs.compRepo.GetAverageCTCByDepartment(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get average CTC by department: %w", err)
	}

	qs.logger.Debug("Average CTC by department retrieved",
		util.String("company_id", companyID.String()),
		util.Int("department_count", len(averages)),
		util.Duration("duration", time.Since(startTime)))

	return averages, nil
}

func (qs *compensationQueryServiceImpl) GetCompensationTrends(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]map[string]interface{}, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days, got %d days", calendarDays)
	}

	trends, err := qs.compRepo.GetCompensationTrends(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get compensation trends: %w", err)
	}

	qs.logger.Debug("Compensation trends retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("trend_count", len(trends)),
		util.Duration("duration", time.Since(startTime)))

	return trends, nil
}

func (qs *compensationQueryServiceImpl) GenerateCompensationReport(
	ctx context.Context,
	companyID uuid.UUID,
	reportType string,
	startDate, endDate time.Time,
) ([]byte, string, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, "", fmt.Errorf("report period cannot exceed 90 days, got %d days", calendarDays)
	}

	var data []byte
	var contentType string
	var err error

	switch strings.ToLower(reportType) {
	case "salary_summary":
		data, contentType, err = qs.generateSalarySummaryReport(ctx, companyID, startDate, endDate)
	case "ctc_breakdown":
		data, contentType, err = qs.generateCTCBreakdownReport(ctx, companyID, startDate, endDate)
	case "payroll_forecast":
		data, contentType, err = qs.generatePayrollForecastReport(ctx, companyID, startDate, endDate)
	case "csv":
		data, contentType, err = qs.generateCSVReport(ctx, companyID, startDate, endDate)
	default:
		return nil, "", fmt.Errorf("unsupported report type: %s", reportType)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to generate %s report: %w", reportType, err)
	}

	qs.logger.Info("Compensation report generated",
		util.String("company_id", companyID.String()),
		util.String("report_type", reportType),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("data_size", len(data)),
		util.Duration("duration", time.Since(startTime)))

	return data, contentType, nil
}

// ============================================================================
// SEARCH AND FILTER
// ============================================================================

func (qs *compensationQueryServiceImpl) SearchCompensationStructures(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*compensation.CompensationStructure, int, error) {
	startTime := time.Now()

	// Validate pagination
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// Get all structures for the company
	structures, _, err := qs.compRepo.GetCompensationStructuresByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get compensation structures: %w", err)
	}

	// Apply filters
	var filteredStructures []*compensation.CompensationStructure
	for _, structure := range structures {
		if qs.matchesFilters(structure, filters) {
			filteredStructures = append(filteredStructures, structure)
		}
	}

	// Apply pagination
	startIdx := offset
	endIdx := offset + pageSize
	if startIdx > len(filteredStructures) {
		startIdx = len(filteredStructures)
	}
	if endIdx > len(filteredStructures) {
		endIdx = len(filteredStructures)
	}

	paginatedStructures := filteredStructures[startIdx:endIdx]

	qs.logger.Debug("Compensation structures searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", len(filteredStructures)),
		util.Int("returned_count", len(paginatedStructures)),
		util.Duration("duration", time.Since(startTime)))

	return paginatedStructures, len(filteredStructures), nil
}

func (qs *compensationQueryServiceImpl) SearchUserCompensations(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*compensation.UserCompensation, int, error) {
	startTime := time.Now()

	// Validate pagination
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// Get all compensations for the company
	comps, _, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get user compensations: %w", err)
	}

	// Apply filters
	var filteredComps []*compensation.UserCompensation
	for _, comp := range comps {
		if qs.matchesUserCompFilters(comp, filters) {
			filteredComps = append(filteredComps, comp)
		}
	}

	// Apply pagination
	startIdx := offset
	endIdx := offset + pageSize
	if startIdx > len(filteredComps) {
		startIdx = len(filteredComps)
	}
	if endIdx > len(filteredComps) {
		endIdx = len(filteredComps)
	}

	paginatedComps := filteredComps[startIdx:endIdx]

	qs.logger.Debug("User compensations searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", len(filteredComps)),
		util.Int("returned_count", len(paginatedComps)),
		util.Duration("duration", time.Since(startTime)))

	return paginatedComps, len(filteredComps), nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================
func (qs *compensationQueryServiceImpl) matchesFilters(
	structure *compensation.CompensationStructure,
	filters map[string]interface{},
) bool {
	for key, value := range filters {
		switch key {

		case "structure_code":
			if val, ok := value.(string); ok && structure.StructureCode != val {
				return false
			}

		case "name":
			if val, ok := value.(string); ok &&
				!strings.Contains(strings.ToLower(structure.Name), strings.ToLower(val)) {
				return false
			}

		case "is_active":
			if val, ok := value.(bool); ok {
				if structure.IsActive != val {
					return false
				}
			}

		case "currency":
			if val, ok := value.(string); ok && structure.Currency != val {
				return false
			}
		}
	}

	return true
}

func (qs *compensationQueryServiceImpl) matchesUserCompFilters(comp *compensation.UserCompensation, filters map[string]interface{}) bool {
	for key, value := range filters {
		switch key {
		case "user_id":
			if val, ok := value.(uuid.UUID); ok && comp.UserID != val {
				return false
			}
		case "structure_id":
			if val, ok := value.(uuid.UUID); ok && comp.StructureID != val {
				return false
			}
		case "effective_from":
			if val, ok := value.(time.Time); ok && !comp.EffectiveFrom.Equal(val) {
				return false
			}
		case "pay_unit_id":
			if val, ok := value.(uuid.UUID); ok {
				if comp.PayUnitID == nil || *comp.PayUnitID != val {
					return false
				}
			}
		}
	}
	return true
}

func (qs *compensationQueryServiceImpl) generateSalarySummaryReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]byte, string, error) {
	// Get compensation trends for the period
	trends, err := qs.GetCompensationTrends(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, "", err
	}

	// Get compensation stats
	stats, err := qs.GetCompensationStatsByCompany(ctx, companyID)
	if err != nil {
		return nil, "", err
	}

	// Get average CTC by department
	avgByDept, err := qs.GetAverageCTCByDepartment(ctx, companyID)
	if err != nil {
		// Log but continue
		qs.logger.Warn("Failed to get average CTC by department", util.ErrorField(err))
	}

	// Compile report
	report := map[string]interface{}{
		"company_id":  companyID.String(),
		"report_type": "salary_summary",
		"period": map[string]interface{}{
			"start_date": startDate.Format("2006-01-02"),
			"end_date":   endDate.Format("2006-01-02"),
			"days":       int(endDate.Sub(startDate).Hours()/24) + 1,
		},
		"summary_stats":         stats,
		"compensation_trends":   trends,
		"average_by_department": avgByDept,
		"generated_at":          time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal report: %w", err)
	}

	return data, "application/json", nil
}

func (qs *compensationQueryServiceImpl) generateCTCBreakdownReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]byte, string, error) {
	// Get all user compensations
	comps, _, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, "", err
	}

	// Process compensations
	var report []map[string]interface{}
	for _, comp := range comps {
		// Parse structure snapshot
		var structure compensation.CompensationStructure
		if err := json.Unmarshal(comp.StructureSnapshot, &structure); err != nil {
			qs.logger.Warn("Failed to parse structure snapshot",
				util.String("user_id", comp.UserID.String()),
				util.ErrorField(err))
			continue
		}

		// Get pay unit
		var payUnitName = "monthly"
		if comp.PayUnitID != nil {
			payUnit, err := qs.compRepo.GetPayUnitByID(ctx, *comp.PayUnitID)
			if err == nil && payUnit != nil {
				payUnitName = payUnit.Name
			}
		}

		// Calculate component breakdown
		breakdown, totalDeductions, totalAdditions := qs.calculateComponentBreakdownForReport(structure.Components, comp.CTCAmount)

		entry := map[string]interface{}{
			"user_id":             comp.UserID.String(),
			"structure_id":        comp.StructureID.String(),
			"structure_name":      structure.Name,
			"structure_code":      structure.StructureCode,
			"ctc_amount":          comp.CTCAmount.String(),
			"currency":            structure.Currency,
			"pay_unit":            payUnitName,
			"effective_from":      comp.EffectiveFrom.Format("2006-01-02"),
			"effective_to":        qs.formatDate(comp.EffectiveTo),
			"component_breakdown": breakdown,
			"total_additions":     totalAdditions.String(),
			"total_deductions":    totalDeductions.String(),
			"net_ctc":             comp.CTCAmount.Add(totalAdditions).Sub(totalDeductions).String(),
		}

		report = append(report, entry)
	}

	// Sort by CTC amount (descending)
	sort.Slice(report, func(i, j int) bool {
		ctcI, _ := decimal.NewFromString(report[i]["ctc_amount"].(string))
		ctcJ, _ := decimal.NewFromString(report[j]["ctc_amount"].(string))
		return ctcI.GreaterThan(ctcJ)
	})

	// Compile final report
	finalReport := map[string]interface{}{
		"company_id":  companyID.String(),
		"report_type": "ctc_breakdown",
		"period": map[string]interface{}{
			"start_date": startDate.Format("2006-01-02"),
			"end_date":   endDate.Format("2006-01-02"),
		},
		"employee_count": len(report),
		"breakdowns":     report,
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(finalReport, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal report: %w", err)
	}

	return data, "application/json", nil
}

func (qs *compensationQueryServiceImpl) generatePayrollForecastReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]byte, string, error) {
	// Calculate payroll for next 3 months
	var forecast []map[string]interface{}
	currentDate := startDate

	for i := 0; i < 3; i++ {
		monthStart := time.Date(currentDate.Year(), currentDate.Month(), 1, 0, 0, 0, 0, time.UTC)
		_ = monthStart.AddDate(0, 1, -1)

		// Get payroll for the month
		payroll, err := qs.CalculateMonthlyPayrollForReport(ctx, companyID, monthStart)
		if err != nil {
			qs.logger.Warn("Failed to calculate payroll for month",
				util.String("month", monthStart.Format("2006-01")),
				util.ErrorField(err))
			continue
		}

		monthForecast := map[string]interface{}{
			"month":               monthStart.Format("2006-01"),
			"employee_count":      len(payroll),
			"total_payroll":       qs.calculateTotalPayroll(payroll).String(),
			"payroll_by_employee": payroll,
		}

		forecast = append(forecast, monthForecast)
		currentDate = currentDate.AddDate(0, 1, 0)
	}

	// Compile report
	report := map[string]interface{}{
		"company_id":      companyID.String(),
		"report_type":     "payroll_forecast",
		"forecast_months": 3,
		"forecast":        forecast,
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal report: %w", err)
	}

	return data, "application/json", nil
}

func (qs *compensationQueryServiceImpl) generateCSVReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]byte, string, error) {
	// Get all user compensations
	comps, _, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, "", err
	}

	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"User ID",
		"Structure Code",
		"Structure Name",
		"CTC Amount",
		"Currency",
		"Pay Unit",
		"Effective From",
		"Effective To",
		"Status",
	}
	if err := writer.Write(header); err != nil {
		return nil, "", fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, comp := range comps {
		// Parse structure snapshot
		var structure compensation.CompensationStructure
		if err := json.Unmarshal(comp.StructureSnapshot, &structure); err != nil {
			continue
		}

		// Get pay unit
		var payUnitName = "monthly"
		if comp.PayUnitID != nil {
			payUnit, err := qs.compRepo.GetPayUnitByID(ctx, *comp.PayUnitID)
			if err == nil && payUnit != nil {
				payUnitName = payUnit.Name
			}
		}

		// Determine status
		status := "Active"
		if comp.EffectiveTo != nil && comp.EffectiveTo.Before(time.Now()) {
			status = "Ended"
		} else if comp.EffectiveFrom.After(time.Now()) {
			status = "Future"
		}

		row := []string{
			comp.UserID.String(),
			structure.StructureCode,
			structure.Name,
			comp.CTCAmount.String(),
			structure.Currency,
			payUnitName,
			comp.EffectiveFrom.Format("2006-01-02"),
			qs.formatDate(comp.EffectiveTo),
			status,
		}

		if err := writer.Write(row); err != nil {
			return nil, "", fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, "", fmt.Errorf("CSV flush error: %w", err)
	}

	return []byte(buf.String()), "text/csv", nil
}

// ============================================================================
// STREAMING REPORTS
// ============================================================================

func (qs *compensationQueryServiceImpl) StreamCompensationReport(
	ctx context.Context,
	companyID uuid.UUID,
	reportType string,
	startDate, endDate time.Time,
	writer io.Writer,
	format string,
) error {
	if format != "csv" && format != "jsonl" {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return fmt.Errorf("streaming period cannot exceed 90 days, got %d days", calendarDays)
	}

	if format == "csv" {
		csvWriter := csv.NewWriter(writer)
		defer csvWriter.Flush()

		header := []string{"User ID", "CTC Amount", "Currency", "Pay Unit", "Effective From", "Status"}
		if err := csvWriter.Write(header); err != nil {
			return err
		}

		// Stream with pagination
		page := 1
		pageSize := 1000

		for {
			comps, totalCount, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, pageSize, (page-1)*pageSize)
			if err != nil {
				return err
			}

			if len(comps) == 0 {
				break
			}

			for _, comp := range comps {
				// Parse structure snapshot
				var structure compensation.CompensationStructure
				if err := json.Unmarshal(comp.StructureSnapshot, &structure); err != nil {
					continue
				}

				// Get pay unit
				var payUnitName = "monthly"
				if comp.PayUnitID != nil {
					payUnit, err := qs.compRepo.GetPayUnitByID(ctx, *comp.PayUnitID)
					if err == nil && payUnit != nil {
						payUnitName = payUnit.Name
					}
				}

				// Determine status
				status := "Active"
				if comp.EffectiveTo != nil && comp.EffectiveTo.Before(time.Now()) {
					status = "Ended"
				}

				row := []string{
					comp.UserID.String(),
					comp.CTCAmount.String(),
					structure.Currency,
					payUnitName,
					comp.EffectiveFrom.Format("2006-01-02"),
					status,
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
		comps, totalCount, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, pageSize, (page-1)*pageSize)
		if err != nil {
			return err
		}

		if len(comps) == 0 {
			break
		}

		for _, comp := range comps {
			jsonData, err := json.Marshal(comp)
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
// UTILITY METHODS
// ============================================================================

func (qs *compensationQueryServiceImpl) calculateComponentBreakdownForReport(components []compensation.Component, ctcAmount decimal.Decimal) (map[string]interface{}, decimal.Decimal, decimal.Decimal) {
	breakdown := make(map[string]interface{})
	var totalDeductions, totalAdditions decimal.Decimal

	for _, component := range components {
		var amount decimal.Decimal

		switch component.Calc {
		case "fixed":
			if component.Value != nil {
				amount = *component.Value
			}
		case "percentage":
			if component.Value != nil {
				// Calculate percentage of CTC
				percentage := component.Value.Div(decimal.NewFromInt(100))
				amount = ctcAmount.Mul(percentage)
			}
		case "hourly":
			// For hourly, we need actual hours worked
			// Using a placeholder for now
			if component.Value != nil {
				amount = *component.Value
			}
		}

		componentData := map[string]interface{}{
			"amount":  amount.String(),
			"type":    component.Type,
			"calc":    component.Calc,
			"taxable": component.Taxable,
		}

		breakdown[component.Code] = componentData

		if component.Type == "earning" {
			totalAdditions = totalAdditions.Add(amount)
		} else if component.Type == "deduction" {
			totalDeductions = totalDeductions.Add(amount)
		}
	}

	return breakdown, totalDeductions, totalAdditions
}

func (qs *compensationQueryServiceImpl) CalculateMonthlyPayrollForReport(ctx context.Context, companyID uuid.UUID, monthYear time.Time) (map[string]decimal.Decimal, error) {
	// Get all user compensations
	comps, _, err := qs.compRepo.GetUserCompensationsByCompany(ctx, companyID, 1000, 0)
	if err != nil {
		return nil, err
	}

	payroll := make(map[string]decimal.Decimal)
	firstDay := time.Date(monthYear.Year(), monthYear.Month(), 1, 0, 0, 0, 0, time.UTC)
	lastDay := firstDay.AddDate(0, 1, -1)

	for _, comp := range comps {
		// Check if compensation is active for the given month
		if comp.EffectiveFrom.After(lastDay) {
			continue
		}
		if comp.EffectiveTo != nil && comp.EffectiveTo.Before(firstDay) {
			continue
		}

		// Parse structure snapshot
		var structure compensation.CompensationStructure
		if err := json.Unmarshal(comp.StructureSnapshot, &structure); err != nil {
			continue
		}

		// Get pay unit
		var payUnitName = "monthly"
		if comp.PayUnitID != nil {
			payUnit, err := qs.compRepo.GetPayUnitByID(ctx, *comp.PayUnitID)
			if err == nil && payUnit != nil {
				payUnitName = payUnit.Name
			}
		}

		// Calculate monthly salary based on pay unit
		var monthlySalary decimal.Decimal

		switch payUnitName {
		case "monthly":
			monthlySalary = comp.CTCAmount
		case "daily":
			// Assuming 26 working days in a month
			dailyRate := comp.CTCAmount.Div(decimal.NewFromInt(26))
			monthlySalary = dailyRate.Mul(decimal.NewFromInt(26))
		case "hourly":
			// Assuming 8 hours/day, 26 days/month = 208 hours/month
			hourlyRate := comp.CTCAmount.Div(decimal.NewFromInt(208))
			monthlySalary = hourlyRate.Mul(decimal.NewFromInt(208))
		default:
			monthlySalary = comp.CTCAmount
		}

		payroll[comp.UserID.String()] = monthlySalary
	}

	return payroll, nil
}

func (qs *compensationQueryServiceImpl) calculateTotalPayroll(payroll map[string]decimal.Decimal) decimal.Decimal {
	var total decimal.Decimal
	for _, amount := range payroll {
		total = total.Add(amount)
	}
	return total
}

func (qs *compensationQueryServiceImpl) formatDate(date *time.Time) string {
	if date == nil {
		return ""
	}
	return date.Format("2006-01-02")
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (qs *compensationQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.compRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("compensation repository health check failed: %w", err)
	}
	return nil
}
