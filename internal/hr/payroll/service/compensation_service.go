package service

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/hr/service" // import the audit package (adjust import path if needed)
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------
// AttendanceRepository – minimal interface for fetching actual payable days.
// In enterprise mode, this must NEVER return an error – the attendance
// service must provide a valid value or the payroll run fails.
// ---------------------------------------------------------------------
type AttendanceRepository interface {
	GetPayableDaysInRange(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (float64, error)
}

// ---------------------------------------------------------------------
// CompensationService – Enterprise‑grade implementation
//
// CONCURRENCY CONTRACT:
//
//	The CompensationRepository methods used inside ResolveEarnings MUST be
//	called with SELECT ... FOR UPDATE if the caller is inside a transaction.
//	The caller (PayrollCalculationService) is responsible for:
//	  1. Beginning a DB transaction
//	  2. Passing a context that allows the repository to acquire a
//	     transactional connection
//	  3. Committing/rolling back
//	This service does NOT manage transactions – it relies on the repository
//	to honour the isolation level and locking via the provided context.
//
// ---------------------------------------------------------------------
type CompensationService interface {
	// ResolveEarnings calculates all earning components for a payroll period.
	// Handles multiple salary segments automatically.
	//
	// totalPeriodDays MUST be the total calendar days of the payroll period
	// (e.g., 30 for a full month, 31 for a 31‑day period). It is used to
	// validate that the sum of calendar days across all salary segments equals
	// the full period. Do NOT pass payable days here – payable days are fetched
	// internally from the attendance repository per segment.
	//
	// Returns error if:
	//   - uncovered period exists (no salary assigned)
	//   - attendance repository fails
	//   - CTC integrity violation (>0.01 difference)
	//   - circular dependency
	//   - currency mismatch across segments
	//   - salary overlap detected
	//   - negative/zero CTC
	//   - attendance days exceed segment calendar days
	//   - component depends on missing component
	ResolveEarnings(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		periodStart time.Time,
		periodEnd time.Time,
		totalPeriodDays float64, // must equal sum(segment.TotalDays)
	) ([]*models.PayrollLedgerItem, error)

	// ResolveCTC returns the monthly CTC active on the given date.
	ResolveCTC(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) (float64, error)

	// ResolveSalaryStructure returns a full snapshot of the active salary structure.
	ResolveSalaryStructure(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) (*models.SalaryStructureSnapshot, error)

	// CalculateComponentAmount computes the monthly amount for a single component.
	// Returns full precision – no rounding.
	CalculateComponentAmount(
		component *models.SalaryStructureComponent,
		ctc float64,
		calculated map[string]float64,
	) (float64, error)

	// ProrateAmount reduces a monthly amount according to payable days.
	// Returns full precision – no rounding.
	ProrateAmount(
		amount float64,
		payableDays float64,
		totalDays float64,
	) float64
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------
type compensationService struct {
	compRepo    repository.CompensationRepository
	payrollRepo repository.PayrollRepository // ONLY for component metadata
	audit       *service.AuditService        // 🟢 Audit service injected (available for future compliance logging)
	logger      *zap.Logger
}

// NewCompensationService creates a new enterprise compensation service.
func NewCompensationService(
	compRepo repository.CompensationRepository,
	payrollRepo repository.PayrollRepository,
	audit *service.AuditService, // 🟢 Audit injection
	logger *zap.Logger,
) CompensationService {
	return &compensationService{
		compRepo:    compRepo,
		payrollRepo: payrollRepo,
		audit:       audit,
		logger:      logger.Named("compensation_service"),
	}
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
	start := time.Now()
	defer func() {
		s.logger.Debug("ResolveEarnings completed",
			util.String("user_id", userID.String()),
			util.Duration("duration", time.Since(start)),
		)
	}()

	// 1. Fetch ALL active salaries overlapping the period – MUST be FOR UPDATE
	//    if called within a transaction. Repository implementation decides.
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

	// 2. Validate no negative/zero CTC
	for _, sal := range salaries {
		if sal.MonthlyCTC < 0 {
			return nil, fmt.Errorf("negative monthly CTC (%.2f) on salary %s",
				sal.MonthlyCTC, sal.EmployeeSalaryID)
		}
		if sal.MonthlyCTC == 0 {
			s.logger.Warn("zero monthly CTC detected",
				util.String("salary_id", sal.EmployeeSalaryID.String()),
				util.Float64("ctc", 0))
			// Allow zero CTC – enterprise may allow interns/unpaid
		}
	}

	// 3. Sort and validate – HARD FAIL on overlap
	if err := s.validateAndSortSalaries(salaries); err != nil {
		return nil, fmt.Errorf("salary assignment validation failed: %w", err)
	}

	// 4. Build segments with actual attendance and currency pre‑fetched
	segments, err := s.buildSalarySegments(ctx, periodStart, periodEnd, salaries, totalPeriodDays)
	if err != nil {
		return nil, fmt.Errorf("failed to build salary segments: %w", err)
	}

	// 5. Validate total days consistency
	if err := s.validateTotalDays(segments, totalPeriodDays); err != nil {
		return nil, err
	}

	// 6. Validate currency consistency – now uses pre‑fetched currency
	if err := s.validateCurrencyConsistency(segments); err != nil {
		return nil, fmt.Errorf("currency inconsistency: %w", err)
	}

	// 7. Aggregate ledger items across all segments
	aggregated := make(map[string]*models.PayrollLedgerItem)

	for _, seg := range segments {
		// 7a. Get structure + components – already fetched during segment building (cached in seg)
		//     We stored seg.Structure and seg.Components to avoid duplicate DB calls.
		structure := seg.Structure
		components := seg.Components

		// 7b. Pre‑fetch component metadata (via PayrollRepository)
		compMetas, err := s.getComponentMetadata(ctx, components)
		if err != nil {
			return nil, fmt.Errorf("failed to get component metadata: %w", err)
		}

		// 7c. Detect circular dependencies (fail fast)
		if err := s.detectCircularDependency(components); err != nil {
			s.logger.Error("circular dependency detected in salary structure",
				util.String("structure_id", structure.SalaryStructureID.String()),
				util.ErrorField(err))
			return nil, fmt.Errorf("salary structure %s has circular dependency: %w",
				structure.SalaryStructureID, err)
		}

		// 7d. Topologically sort components
		sortedComponents, err := s.topologicalSort(components)
		if err != nil {
			return nil, fmt.Errorf("failed to sort components: %w", err)
		}

		var segmentProrated map[string]*models.PayrollLedgerItem

		switch seg.PayType {
		case models.PayTypeMonthly:
			// 7e. Calculate full monthly amounts (pre‑proration) – NO ROUNDING
			calculated, err := s.calculateFullMonthComponents(sortedComponents, seg.MonthlyCTC, compMetas)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate components for segment: %w", err)
			}

			// 7f. Validate CTC integrity (sum ≈ CTC) – raw values, tolerance 0.01
			if err := s.validateComponentSum(seg.MonthlyCTC, calculated, 0.01); err != nil {
				return nil, fmt.Errorf("CTC integrity violation in segment: %w", err)
			}

			// 7g. Prorate segment amounts – NO ROUNDING
			segmentProrated = s.prorateSegment(calculated, seg.PayableDays, seg.TotalDays, compMetas)

		case models.PayTypeDailyWage:
			// MonthlyCTC now means per-day wage
			total := seg.MonthlyCTC * seg.PayableDays

			// Note: "DAILY_WAGE" is a synthetic component code. In a full enterprise
			// implementation you might want to fetch metadata for it or make it
			// configurable, but this simple form works for the initial version.
			segmentProrated = map[string]*models.PayrollLedgerItem{
				"DAILY_WAGE": {
					ComponentCode: "DAILY_WAGE",
					ComponentType: models.ComponentTypeEarning,
					Description:   "Daily Wage",
					Amount:        total,
					IsTaxable:     true, // Typically daily wages are taxable
				},
			}

		case models.PayTypeHourly:
			return nil, fmt.Errorf("hourly pay type not implemented yet")

		default:
			return nil, fmt.Errorf("unsupported pay type: %s", seg.PayType)
		}

		// 7h. Merge into aggregated result – ROUND ONLY ONCE at addition
		for code, item := range segmentProrated {
			if existing, ok := aggregated[code]; ok {
				existing.Amount = s.roundFloat(existing.Amount+item.Amount, 2)
			} else {
				item.Amount = s.roundFloat(item.Amount, 2)
				aggregated[code] = item
			}
		}
	}

	// 8. Convert map to slice
	result := make([]*models.PayrollLedgerItem, 0, len(aggregated))
	for _, item := range aggregated {
		result = append(result, item)
	}
	return result, nil
}

func (s *compensationService) ResolveCTC(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) (float64, error) {
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
		PayType:    empSalary.PayType, // ⭐ NEW
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
// Private Helpers – Enterprise‑grade Validations
// ---------------------------------------------------------------------

// salarySegment now caches the entire structure and components to avoid double fetching.
type salarySegment struct {
	SalaryStructureID uuid.UUID
	MonthlyCTC        float64
	PayType           string // ⭐ NEW

	EffectiveDate time.Time // date used to resolve the salary structure version
	StartDate     time.Time
	EndDate       time.Time
	PayableDays   float64 // from attendance repo
	TotalDays     float64 // calendar days in this segment
	CurrencyCode  string
	Structure     *models.SalaryStructure           // 🟢 CACHED
	Components    []models.SalaryStructureComponent // 🟢 CACHED
}

// validateAndSortSalaries sorts by EffectiveFrom and HARD FAILS on overlap.
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

		// If current has no end date, it's an error (overlap with next)
		if curr.EffectiveTo == nil {
			return fmt.Errorf("salary %s has no effective_to and overlaps with salary %s",
				curr.EmployeeSalaryID, next.EmployeeSalaryID)
		}

		if !curr.EffectiveTo.Before(next.EffectiveFrom) {
			return fmt.Errorf("overlapping salaries: %s (effective_to %s) and %s (effective_from %s)",
				curr.EmployeeSalaryID, curr.EffectiveTo.Format("2006-01-02"),
				next.EmployeeSalaryID, next.EffectiveFrom.Format("2006-01-02"))
		}

		// Gap is allowed – may indicate unpaid leave or missing salary assignment.
		// If gap exists, it will be caught by uncovered period check later.
	}
	return nil
}

// buildSalarySegments now fetches the salary structure ONCE per segment and stores it.
// It also validates attendance ≤ calendar days and fails immediately if violated.
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

		// Uncovered before first salary
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

		// Calendar days in this segment
		segDays := segEnd.Sub(segStart).Hours()/24 + 1
		segTotalDays := segDays

		// Fetch attendance – MUST succeed
		segPayableDays, err := s.payrollRepo.GetPayableDaysInRange(ctx, sal.CompanyID, sal.UserID, segStart, segEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch attendance for segment [%s, %s]: %w",
				segStart.Format("2006-01-02"),
				segEnd.Format("2006-01-02"),
				err)
		}

		// Enterprise rule: attendance cannot exceed calendar days
		if segPayableDays > segTotalDays {
			return nil, fmt.Errorf("attendance payable days (%.2f) exceed segment calendar days (%.2f) for [%s, %s]",
				segPayableDays, segTotalDays,
				segStart.Format("2006-01-02"),
				segEnd.Format("2006-01-02"))
		}

		// Fetch salary structure ONCE – and cache it in the segment
		structure, components, err := s.compRepo.GetSalaryStructureWithComponents(
			ctx,
			sal.SalaryStructureID,
			sal.CompanyID,
			segStart, // effective as of segment start
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
			PayType:           sal.PayType, // ⭐ NEW

			EffectiveDate: segStart,
			StartDate:     segStart,
			EndDate:       segEnd,
			PayableDays:   segPayableDays,
			TotalDays:     segTotalDays,
			CurrencyCode:  structure.CurrencyCode,
			Structure:     structure,
			Components:    components,
		})

		currentStart = segEnd.AddDate(0, 0, 1)
		if currentStart.After(periodEnd) {
			break
		}
	}

	// After all segments, check if the entire period was covered
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

// validateTotalDays ensures that sum(segment.TotalDays) equals totalPeriodDays.
func (s *compensationService) validateTotalDays(segments []salarySegment, totalPeriodDays float64) error {
	var sum float64
	for _, seg := range segments {
		sum += seg.TotalDays
	}
	// Allow floating point rounding difference (1e-9)
	if math.Abs(sum-totalPeriodDays) > 0.000000001 {
		return fmt.Errorf("sum of segment days (%.2f) does not equal total period days (%.2f)",
			sum, totalPeriodDays)
	}
	return nil
}

// validateCurrencyConsistency uses pre‑cached currency codes.
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

// getComponentMetadata – unchanged, uses payrollRepo.
func (s *compensationService) getComponentMetadata(
	ctx context.Context,
	components []models.SalaryStructureComponent,
) (map[string]*models.PayrollComponent, error) {
	if len(components) == 0 {
		return map[string]*models.PayrollComponent{}, nil
	}
	codes := make([]string, 0, len(components))
	for _, comp := range components {
		codes = append(codes, comp.ComponentCode)
	}
	metas, err := s.compRepo.GetComponentsByCodes(ctx, codes)
	if err != nil {
		return nil, err
	}
	metaMap := make(map[string]*models.PayrollComponent)
	for _, meta := range metas {
		metaMap[meta.ComponentCode] = meta
	}
	return metaMap, nil
}

// topologicalSort with strict validation: missing dependency → error.
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

// calculateFullMonthComponents – unchanged.
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

// prorateSegment – unchanged.
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

// validateComponentSum – unchanged.
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

// detectCircularDependency – unchanged.
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

// roundFloat – unchanged.
func (s *compensationService) roundFloat(val float64, precision uint) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}
