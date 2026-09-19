package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

// ---------------------------------------------------------------------
// AttendanceRepository – minimal interface for fetching actual payable days.
// ---------------------------------------------------------------------
type AttendanceRepository interface {
	GetPayableDaysInRange(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (float64, error)
}

type CompensationService interface {
	GetCurrentSalary(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
	) (*models.EmployeeSalary, error)

	ResolveEarnings(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		periodStart time.Time,
		periodEnd time.Time,
		totalPeriodDays float64,
	) ([]*models.PayrollLedgerItem, error)

	ResolveCTC(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) (float64, error)

	ResolveSalaryStructure(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) (*models.SalaryStructureSnapshot, error)

	CalculateComponentAmount(
		component *models.SalaryStructureComponent,
		ctc float64,
		calculated map[string]float64,
	) (float64, error)

	ProrateAmount(
		amount float64,
		payableDays float64,
		totalDays float64,
	) float64

	GetSalaryAssignmentsInRange(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]models.EmployeeSalary, error)
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------
type compensationService struct {
	compRepo         repository.CompensationRepository
	payrollRepo      repository.PayrollRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new
	audit            *audit.AuditService
	idempotencyStore idempotency.Store
	logger           *zap.Logger
}

func NewCompensationService(
	compRepo repository.CompensationRepository,
	payrollRepo repository.PayrollRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	audit *audit.AuditService,
	idempotencyStore idempotency.Store,
	logger *zap.Logger,
) CompensationService {
	return &compensationService{
		compRepo:         compRepo,
		payrollRepo:      payrollRepo,
		employeeRepo:     employeeRepo,
		audit:            audit,
		idempotencyStore: idempotencyStore,
		logger:           logger.Named("compensation_service"),
	}
}

// ensureEmployeeInScope — same helper as bank service.
// Missing location context is treated as a system call (worker) and allowed.
func (s *compensationService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}

	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		// No location context → system call (payroll worker), allow.
		return nil
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}

	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, targetUserID)
	if err != nil {
		return err
	}
	if empLoc == nil {
		return ErrEmployeeHasNoLocation
	}
	if *empLoc != *locCtx.LocationID {
		return ErrEmployeeOutsideScope
	}
	return nil
}

// ---------------------------------------------------------------------
// Public Methods
// ---------------------------------------------------------------------

func (s *compensationService) ResolveEarnings(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
	totalPeriodDays float64,
) ([]*models.PayrollLedgerItem, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	startTime := time.Now()

	salaries, err := s.compRepo.GetEmployeeSalaryHistoryInRange(ctx, companyID, userID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to get salary history: %w", err)
	}
	if len(salaries) == 0 {
		return nil, fmt.Errorf("no active salary assignment in period [%s, %s] for user %s",
			periodStart.Format("2006-01-02"),
			periodEnd.Format("2006-01-02"),
			userID.String())
	}

	for _, sal := range salaries {
		if sal.MonthlyCTC < 0 {
			return nil, fmt.Errorf("negative monthly CTC (%.2f) on salary %s",
				sal.MonthlyCTC, sal.EmployeeSalaryID)
		}
		if sal.MonthlyCTC == 0 {
			s.logger.Warn("zero monthly CTC detected",
				zap.String("salary_id", sal.EmployeeSalaryID.String()),
				zap.Float64("ctc", 0))
		}
	}

	if err := s.validateAndSortSalaries(salaries); err != nil {
		return nil, fmt.Errorf("salary assignment validation failed: %w", err)
	}

	segments, err := s.buildSalarySegments(ctx, periodStart, periodEnd, salaries, totalPeriodDays)
	if err != nil {
		return nil, fmt.Errorf("failed to build salary segments: %w", err)
	}

	if err := s.validateTotalDays(segments, totalPeriodDays); err != nil {
		return nil, err
	}

	if err := s.validateCurrencyConsistency(segments); err != nil {
		return nil, fmt.Errorf("currency inconsistency: %w", err)
	}

	aggregated := make(map[string]*models.PayrollLedgerItem)

	for _, seg := range segments {
		structure := seg.Structure
		components := seg.Components

		compMetas, err := s.getComponentMetadata(ctx, companyID, components)
		if err != nil {
			return nil, fmt.Errorf("failed to get component metadata: %w", err)
		}

		if err := s.detectCircularDependency(components); err != nil {
			s.logger.Error("circular dependency detected in salary structure",
				zap.String("structure_id", structure.SalaryStructureID.String()),
				zap.Error(err))
			return nil, fmt.Errorf("salary structure %s has circular dependency: %w",
				structure.SalaryStructureID, err)
		}

		sortedComponents, err := s.topologicalSort(components)
		if err != nil {
			return nil, fmt.Errorf("failed to sort components: %w", err)
		}

		var segmentProrated map[string]*models.PayrollLedgerItem

		switch seg.PayType {
		case models.PayTypeMonthly:
			calculated, err := s.calculateFullMonthComponents(sortedComponents, seg.MonthlyCTC, compMetas)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate components for segment: %w", err)
			}
			if err := s.validateComponentSum(seg.MonthlyCTC, calculated, 0.01); err != nil {
				return nil, fmt.Errorf("CTC integrity violation in segment: %w", err)
			}
			segmentProrated = s.prorateSegment(calculated, seg.PayableDays, seg.TotalDays, compMetas)

		case models.PayTypeDailyWage:
			total := seg.MonthlyCTC * seg.PayableDays
			meta, ok := compMetas["DAILY_WAGE"]
			if !ok {
				s.logger.Warn("DAILY_WAGE component not found in metadata, using defaults",
					zap.String("company_id", companyID.String()))
				segmentProrated = map[string]*models.PayrollLedgerItem{
					"DAILY_WAGE": {
						ComponentCode: "DAILY_WAGE",
						ComponentType: models.ComponentTypeEarning,
						Description:   "Daily Wage",
						Amount:        total,
						IsTaxable:     true,
					},
				}
			} else {
				segmentProrated = map[string]*models.PayrollLedgerItem{
					"DAILY_WAGE": {
						ComponentCode: "DAILY_WAGE",
						ComponentType: meta.ComponentType,
						Description:   meta.Description,
						Amount:        total,
						IsTaxable:     meta.IsTaxable,
					},
				}
			}

		case models.PayTypeHourly:
			return nil, fmt.Errorf("hourly pay type not implemented yet")

		default:
			return nil, fmt.Errorf("unsupported pay type: %s", seg.PayType)
		}

		for code, item := range segmentProrated {
			if existing, ok := aggregated[code]; ok {
				existing.Amount = s.roundFloat(existing.Amount+item.Amount, 2)
			} else {
				item.Amount = s.roundFloat(item.Amount, 2)
				aggregated[code] = item
			}
		}
	}

	result := make([]*models.PayrollLedgerItem, 0, len(aggregated))
	for _, item := range aggregated {
		result = append(result, item)
	}

	ip, _ := ctx.Value("ip_address").(string)
	resultJSON, _ := json.Marshal(result)
	_ = s.audit.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"earnings.resolve",
		"payroll_ledger",
		nil,
		"system",
		nil,
		nil,
		resultJSON,
		map[string]interface{}{
			"ip":          ip,
			"user_id":     userID.String(),
			"period":      periodStart.Format("2006-01-02") + " to " + periodEnd.Format("2006-01-02"),
			"duration_ms": time.Since(startTime).Milliseconds(),
		},
	)

	return result, nil
}

func (s *compensationService) ResolveCTC(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (float64, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return 0, err
	}

	empSalary, err := s.compRepo.GetActiveEmployeeSalary(ctx, companyID, userID, asOf)
	if err != nil {
		return 0, fmt.Errorf("failed to get active salary: %w", err)
	}
	if empSalary == nil {
		return 0, nil
	}
	switch empSalary.PayType {
	case models.PayTypeMonthly, models.PayTypeDailyWage, models.PayTypeHourly:
		return empSalary.MonthlyCTC, nil
	default:
		return 0, fmt.Errorf("unsupported pay type: %s", empSalary.PayType)
	}
}

func (s *compensationService) ResolveSalaryStructure(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.SalaryStructureSnapshot, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	empSalary, err := s.compRepo.GetActiveEmployeeSalary(ctx, companyID, userID, asOf)
	if err != nil {
		return nil, fmt.Errorf("failed to get active salary: %w", err)
	}
	if empSalary == nil {
		return nil, nil
	}

	structure, components, err := s.compRepo.GetSalaryStructureWithComponents(
		ctx,
		empSalary.SalaryStructureID,
		companyID,
		asOf,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get salary structure: %w", err)
	}
	if structure == nil {
		return nil, fmt.Errorf("salary structure %s not found", empSalary.SalaryStructureID)
	}

	snapshot := &models.SalaryStructureSnapshot{
		Structure:  *structure,
		Components: components,
		ResolvedAt: time.Now().UTC(),
		Currency:   structure.CurrencyCode,
		MonthlyCTC: empSalary.MonthlyCTC,
		PayType:    empSalary.PayType,
		UserID:     userID,
		CompanyID:  companyID,
	}
	return snapshot, nil
}

func (s *compensationService) CalculateComponentAmount(
	component *models.SalaryStructureComponent,
	ctc float64,
	calculated map[string]float64,
) (float64, error) {
	switch component.CalculationType {
	case models.CalculationTypeFixed:
		return component.Value, nil
	case models.CalculationTypePercentage:
		var base float64
		if component.BasedOnComponent != nil && *component.BasedOnComponent != "" {
			val, ok := calculated[*component.BasedOnComponent]
			if !ok {
				return 0, fmt.Errorf("dependent component %s not calculated yet",
					*component.BasedOnComponent)
			}
			base = val
		} else {
			base = ctc
		}
		return base * (component.Value / 100.0), nil
	default:
		return 0, fmt.Errorf("unsupported calculation type: %s", component.CalculationType)
	}
}

func (s *compensationService) ProrateAmount(
	amount float64,
	payableDays float64,
	totalDays float64,
) float64 {
	if totalDays <= 0 || payableDays <= 0 {
		return 0
	}
	return (amount / totalDays) * payableDays
}

// ---------------------------------------------------------------------
// Private Helpers — unchanged
// ---------------------------------------------------------------------

type salarySegment struct {
	SalaryStructureID uuid.UUID
	MonthlyCTC        float64
	PayType           string
	EffectiveDate     time.Time
	StartDate         time.Time
	EndDate           time.Time
	PayableDays       float64
	TotalDays         float64
	CurrencyCode      string
	Structure         *models.SalaryStructure
	Components        []models.SalaryStructureComponent
}

func (s *compensationService) validateAndSortSalaries(salaries []models.EmployeeSalary) error {
	if len(salaries) == 0 {
		return nil
	}
	sorted := make([]models.EmployeeSalary, len(salaries))
	copy(sorted, salaries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EffectiveFrom.Before(sorted[j].EffectiveFrom)
	})
	for i := 0; i < len(sorted)-1; i++ {
		curr := sorted[i]
		next := sorted[i+1]
		if curr.EffectiveTo == nil {
			return fmt.Errorf("salary %s has no effective_to and overlaps with salary %s",
				curr.EmployeeSalaryID, next.EmployeeSalaryID)
		}
		if !curr.EffectiveTo.Before(next.EffectiveFrom) {
			return fmt.Errorf("overlapping salaries: %s (effective_to %s) and %s (effective_from %s)",
				curr.EmployeeSalaryID, curr.EffectiveTo.Format("2006-01-02"),
				next.EmployeeSalaryID, next.EffectiveFrom.Format("2006-01-02"))
		}
	}
	return nil
}

func (s *compensationService) buildSalarySegments(
	ctx context.Context,
	periodStart, periodEnd time.Time,
	salaries []models.EmployeeSalary,
	totalPeriodDays float64,
) ([]salarySegment, error) {
	var segments []salarySegment
	currentStart := periodStart
	for i, sal := range salaries {
		segStart := currentStart
		if sal.EffectiveFrom.After(segStart) {
			segStart = sal.EffectiveFrom
		}
		if i == 0 && segStart.After(periodStart) {
			return nil, fmt.Errorf("uncovered period from %s to %s",
				periodStart.Format("2006-01-02"),
				segStart.AddDate(0, 0, -1).Format("2006-01-02"))
		}
		segEnd := periodEnd
		if sal.EffectiveTo != nil && sal.EffectiveTo.Before(segEnd) {
			segEnd = *sal.EffectiveTo
		}
		if segStart.After(segEnd) {
			continue
		}
		segDays := segEnd.Sub(segStart).Hours()/24 + 1
		segTotalDays := segDays
		segPayableDays, err := s.payrollRepo.GetPayableDaysInRange(ctx, sal.CompanyID, sal.UserID, segStart, segEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch attendance for segment [%s, %s]: %w",
				segStart.Format("2006-01-02"),
				segEnd.Format("2006-01-02"),
				err)
		}
		if segPayableDays > segTotalDays {
			return nil, fmt.Errorf("attendance payable days (%.2f) exceed segment calendar days (%.2f) for [%s, %s]",
				segPayableDays, segTotalDays,
				segStart.Format("2006-01-02"),
				segEnd.Format("2006-01-02"))
		}
		structure, components, err := s.compRepo.GetSalaryStructureWithComponents(
			ctx,
			sal.SalaryStructureID,
			sal.CompanyID,
			segStart,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get salary structure for segment: %w", err)
		}
		if structure == nil {
			return nil, fmt.Errorf("salary structure %s not found for segment", sal.SalaryStructureID)
		}
		segments = append(segments, salarySegment{
			SalaryStructureID: sal.SalaryStructureID,
			MonthlyCTC:        sal.MonthlyCTC,
			PayType:           sal.PayType,
			EffectiveDate:     segStart,
			StartDate:         segStart,
			EndDate:           segEnd,
			PayableDays:       segPayableDays,
			TotalDays:         segTotalDays,
			CurrencyCode:      structure.CurrencyCode,
			Structure:         structure,
			Components:        components,
		})
		currentStart = segEnd.AddDate(0, 0, 1)
		if currentStart.After(periodEnd) {
			break
		}
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("no salary segments generated for period")
	}
	lastSeg := segments[len(segments)-1]
	if lastSeg.EndDate.Before(periodEnd) {
		return nil, fmt.Errorf("uncovered period from %s to %s",
			lastSeg.EndDate.AddDate(0, 0, 1).Format("2006-01-02"),
			periodEnd.Format("2006-01-02"))
	}
	return segments, nil
}

func (s *compensationService) validateTotalDays(segments []salarySegment, totalPeriodDays float64) error {
	var sum float64
	for _, seg := range segments {
		sum += seg.TotalDays
	}
	if math.Abs(sum-totalPeriodDays) > 0.000000001 {
		return fmt.Errorf("sum of segment days (%.2f) does not equal total period days (%.2f)",
			sum, totalPeriodDays)
	}
	return nil
}

func (s *compensationService) validateCurrencyConsistency(segments []salarySegment) error {
	if len(segments) == 0 {
		return nil
	}
	expected := segments[0].CurrencyCode
	for i, seg := range segments[1:] {
		if seg.CurrencyCode != expected {
			return fmt.Errorf("currency mismatch: segment 0 uses %s, segment %d uses %s",
				expected, i+1, seg.CurrencyCode)
		}
	}
	return nil
}

func (s *compensationService) getComponentMetadata(
	ctx context.Context,
	companyID uuid.UUID,
	components []models.SalaryStructureComponent,
) (map[string]*models.PayrollComponent, error) {
	if len(components) == 0 {
		return map[string]*models.PayrollComponent{}, nil
	}
	codes := make([]string, 0, len(components))
	for _, comp := range components {
		codes = append(codes, comp.ComponentCode)
	}
	metas, err := s.compRepo.GetComponentsByCodes(ctx, companyID, codes)
	if err != nil {
		return nil, err
	}
	metaMap := make(map[string]*models.PayrollComponent)
	for _, meta := range metas {
		metaMap[meta.ComponentCode] = meta
	}
	return metaMap, nil
}

func (s *compensationService) topologicalSort(
	components []models.SalaryStructureComponent,
) ([]models.SalaryStructureComponent, error) {
	graph := make(map[string][]string)
	indegree := make(map[string]int)
	compMap := make(map[string]models.SalaryStructureComponent)
	for _, comp := range components {
		compMap[comp.ComponentCode] = comp
		indegree[comp.ComponentCode] = 0
	}
	for _, comp := range components {
		if comp.BasedOnComponent != nil && *comp.BasedOnComponent != "" {
			dep := *comp.BasedOnComponent
			if _, exists := compMap[dep]; !exists {
				return nil, fmt.Errorf("component %s depends on missing component %s",
					comp.ComponentCode, dep)
			}
			graph[dep] = append(graph[dep], comp.ComponentCode)
		}
	}
	for _, deps := range graph {
		for _, dep := range deps {
			indegree[dep]++
		}
	}
	queue := []string{}
	for code, deg := range indegree {
		if deg == 0 {
			queue = append(queue, code)
		}
	}
	sorted := []models.SalaryStructureComponent{}
	for len(queue) > 0 {
		code := queue[0]
		queue = queue[1:]
		sorted = append(sorted, compMap[code])
		for _, neighbor := range graph[code] {
			indegree[neighbor]--
			if indegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}
	if len(sorted) != len(components) {
		return nil, fmt.Errorf("circular dependency detected – cannot topologically sort components")
	}
	return sorted, nil
}

func (s *compensationService) calculateFullMonthComponents(
	components []models.SalaryStructureComponent,
	ctc float64,
	metaMap map[string]*models.PayrollComponent,
) (map[string]float64, error) {
	calculated := make(map[string]float64)
	for _, comp := range components {
		meta, ok := metaMap[comp.ComponentCode]
		if !ok {
			return nil, fmt.Errorf("metadata missing for component %s", comp.ComponentCode)
		}
		if meta.ComponentType != models.ComponentTypeEarning {
			continue
		}
		amount, err := s.CalculateComponentAmount(&comp, ctc, calculated)
		if err != nil {
			return nil, fmt.Errorf("component %s: %w", comp.ComponentCode, err)
		}
		calculated[comp.ComponentCode] = amount
	}
	return calculated, nil
}

func (s *compensationService) prorateSegment(
	monthlyAmounts map[string]float64,
	payableDays, totalDays float64,
	metaMap map[string]*models.PayrollComponent,
) map[string]*models.PayrollLedgerItem {
	result := make(map[string]*models.PayrollLedgerItem)
	for code, monthly := range monthlyAmounts {
		prorated := s.ProrateAmount(monthly, payableDays, totalDays)
		if prorated <= 0 {
			continue
		}
		meta := metaMap[code]
		result[code] = &models.PayrollLedgerItem{
			ComponentCode: code,
			ComponentType: meta.ComponentType,
			Description:   meta.Description,
			Amount:        prorated,
			IsTaxable:     meta.IsTaxable,
		}
	}
	return result
}

func (s *compensationService) validateComponentSum(
	ctc float64,
	calculated map[string]float64,
	tolerance float64,
) error {
	var sum float64
	for _, amount := range calculated {
		sum += amount
	}
	if math.Abs(sum-ctc) > tolerance {
		return fmt.Errorf("component sum %.6f does not match CTC %.2f (diff: %.6f)",
			sum, ctc, sum-ctc)
	}
	return nil
}

func (s *compensationService) detectCircularDependency(
	components []models.SalaryStructureComponent,
) error {
	graph := make(map[string][]string)
	for _, comp := range components {
		if comp.BasedOnComponent != nil && *comp.BasedOnComponent != "" {
			graph[comp.ComponentCode] = append(graph[comp.ComponentCode], *comp.BasedOnComponent)
		}
	}
	visited := make(map[string]bool)
	stack := make(map[string]bool)
	var dfs func(node string) error
	dfs = func(node string) error {
		visited[node] = true
		stack[node] = true
		for _, dep := range graph[node] {
			if !visited[dep] {
				if err := dfs(dep); err != nil {
					return err
				}
			} else if stack[dep] {
				return fmt.Errorf("circular dependency: %s -> %s", node, dep)
			}
		}
		stack[node] = false
		return nil
	}
	for _, comp := range components {
		if !visited[comp.ComponentCode] {
			if err := dfs(comp.ComponentCode); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *compensationService) roundFloat(val float64, precision uint) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}

func (s *compensationService) GetSalaryAssignmentsInRange(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]models.EmployeeSalary, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	return s.compRepo.GetEmployeeSalaryHistoryInRange(ctx, companyID, userID, startDate, endDate)
}

func (s *compensationService) GetCurrentSalary(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) (*models.EmployeeSalary, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	today := time.Now().UTC()
	salary, err := s.compRepo.GetActiveEmployeeSalary(ctx, companyID, userID, today)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch active salary: %w", err)
	}
	return salary, nil
}
