package service

import (
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	attendanceRepo "auth-service/internal/attendance/repository"
	leaveRepo "auth-service/internal/hr/leave/repository"
	hrEmployee "auth-service/internal/hr/models/employee"
	hrRepo "auth-service/internal/hr/repository"
	hrService "auth-service/internal/hr/service"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap" // 👈 ADD THIS

	"auth-service/internal/client"
	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
)

type CompanyService struct {
	pgClient         *client.PostgresClient
	companyRepo      postgres.CompanyRepository
	locationRepo     postgres.LocationRepository
	locationService  *LocationService                    // 👈 ADD
	workCenterRepo   attendanceRepo.WorkCenterRepository // 👈 ADD
	employeeRepo     hrRepo.EmployeeRepository
	employeeService  *hrService.EmployeeService
	userService      *UserService
	planService      *SubscriptionPlanService
	paymentService   *PaymentService
	invoiceService   *SubscriptionInvoiceService
	reminderService  *ReminderService
	lifecycleService *SubscriptionLifecycleService
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	config           config.Config
	redisClient      *redis.Client
	resolverJobs     leaveRepo.ResolverJobRepository
}

func NewCompanyService(
	pgClient *client.PostgresClient,
	companyRepo postgres.CompanyRepository,
	locationRepo postgres.LocationRepository,
	locationService *LocationService, // 👈 ADD
	workCenterRepo attendanceRepo.WorkCenterRepository, // 👈 ADD
	employeeRepo hrRepo.EmployeeRepository,
	employeeService *hrService.EmployeeService,
	userService *UserService,
	planService *SubscriptionPlanService,
	paymentService *PaymentService,
	invoiceService *SubscriptionInvoiceService,
	reminderService *ReminderService,
	lifecycleService *SubscriptionLifecycleService,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	cfg config.Config,
	redisClient *redis.Client,
	resolverJobs leaveRepo.ResolverJobRepository,
) *CompanyService {
	return &CompanyService{
		pgClient:         pgClient,
		companyRepo:      companyRepo,
		locationRepo:     locationRepo,
		locationService:  locationService, // 👈 ADD
		workCenterRepo:   workCenterRepo,  // 👈 ADD
		employeeRepo:     employeeRepo,
		employeeService:  employeeService,
		userService:      userService,
		planService:      planService,
		paymentService:   paymentService,
		invoiceService:   invoiceService,
		reminderService:  reminderService,
		lifecycleService: lifecycleService,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		config:           cfg,
		redisClient:      redisClient,
		resolverJobs:     resolverJobs,
	}
}

// ============================================================
// Context-based permission helpers (unchanged)
// ============================================================

func (s *CompanyService) CheckMultiplePermissionsFromContext(ctx context.Context, permissions []string, checkAll bool) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return false, fmt.Errorf("%w: session type not found", appErrors.ErrUnauthorized)
	}
	if sessionType == "admin" {
		return true, nil
	}
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return false, fmt.Errorf("%w: permission mask not found", appErrors.ErrPermissionDenied)
	}
	if checkAll {
		return rbac.HasAllPermissions(permissionMask, permissions...), nil
	}
	return rbac.HasAnyPermission(permissionMask, permissions...), nil
}

func (s *CompanyService) GetPermissionsFromContext(ctx context.Context) ([]string, error) {
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return []string{}, nil
	}
	return rbac.GetPermissionsFromMask(permissionMask), nil
}

func (s *CompanyService) CheckPermissionFromContext(ctx context.Context, permissionName string) (bool, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return false, fmt.Errorf("%w: session type not found", appErrors.ErrUnauthorized)
	}
	if sessionType == "admin" {
		return true, nil
	}
	permissionMask, ok := ctx.Value("permission_mask").([]uint64)
	if !ok || permissionMask == nil {
		return false, fmt.Errorf("%w: permission mask not found", appErrors.ErrPermissionDenied)
	}
	return rbac.HasPermission(permissionMask, permissionName), nil
}

type CompanyStatusSnapshot struct {
	CompanyID           uuid.UUID  `json:"company_id"`
	SubscriptionStatus  string     `json:"subscription_status"`
	SubscriptionEndDate *time.Time `json:"subscription_end_date,omitempty"`
	TrialEndDate        *time.Time `json:"trial_end_date,omitempty"`
	GracePeriodDays     int        `json:"grace_period_days"`
	IsActive            bool       `json:"is_active"`
	CachedAt            time.Time  `json:"cached_at"`
}

func (s *CompanyService) IsCompanyAllowed(ctx context.Context, companyID uuid.UUID) (bool, string, error) {
	if companyID == uuid.Nil {
		return false, "", fmt.Errorf("%w: company_id is required", appErrors.ErrInvalidInput)
	}
	snap, err := s.getCachedCompanyStatus(ctx, companyID)
	if err != nil {
		return false, "", err
	}
	switch snap.SubscriptionStatus {
	case models.SubscriptionStatusTrial, models.SubscriptionStatusActive, models.SubscriptionStatusPastDue:
		return true, snap.SubscriptionStatus, nil
	default:
		return false, snap.SubscriptionStatus, nil
	}
}

func (s *CompanyService) getCachedCompanyStatus(ctx context.Context, companyID uuid.UUID) (*CompanyStatusSnapshot, error) {
	cacheKey := fmt.Sprintf("company:sub:%s", companyID.String())
	if s.redisClient != nil {
		if data, err := s.redisClient.Get(ctx, cacheKey).Bytes(); err == nil {
			var snap CompanyStatusSnapshot
			if err := json.Unmarshal(data, &snap); err == nil {
				return &snap, nil
			}
			_ = s.redisClient.Del(ctx, cacheKey).Err()
		}
	}
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	snap := &CompanyStatusSnapshot{
		CompanyID:           company.CompanyID,
		SubscriptionStatus:  company.SubscriptionStatus,
		SubscriptionEndDate: company.SubscriptionEndDate,
		TrialEndDate:        company.TrialEndDate,
		GracePeriodDays:     company.GracePeriodDays,
		IsActive:            company.IsActive,
		CachedAt:            time.Now().UTC(),
	}
	if s.redisClient != nil {
		if data, err := json.Marshal(snap); err == nil {
			_ = s.redisClient.Set(ctx, cacheKey, data, 10*time.Minute).Err()
		}
	}
	return snap, nil
}

func (s *CompanyService) InvalidateCompanyStatusCache(ctx context.Context, companyID uuid.UUID) {
	if s.redisClient == nil {
		return
	}
	_ = s.redisClient.Del(ctx, fmt.Sprintf("company:sub:%s", companyID.String())).Err()
}

func (s *CompanyService) WarmCompanyStatusCache(ctx context.Context, companyID uuid.UUID) {
	_, _ = s.getCachedCompanyStatus(ctx, companyID)
}

// ============================================================
// CreateCompanyRequest
// ============================================================

type CreateCompanyRequest struct {
	CompanyName             string   `json:"company_name"`
	OwnerPhone              string   `json:"owner_phone"`
	OwnerUsername           string   `json:"owner_username"`
	OwnerFullName           string   `json:"owner_full_name"`
	OwnerPositionTitle      string   `json:"owner_position_title"`
	OwnerJobCode            string   `json:"owner_job_code,omitempty"`
	SubscriptionTier        string   `json:"subscription_tier"`
	SubscriptionPlanCode    string   `json:"subscription_plan_code"`
	MaxEmployees            int      `json:"max_employees"`
	MaxLocations            int      `json:"max_locations"`
	DataRegion              string   `json:"data_region"`
	SubscriptionMonths      int      `json:"subscription_months"`
	SubscriptionDays        int      `json:"subscription_days"`
	Departments             []string `json:"departments"`
	FinancialYearStartMonth int      `json:"financial_year_start_month"`
	TrialDays               int      `json:"trial_days"`

	// ── NEW: timezone config ─────────────────────────────────────────
	// DefaultTimezone is required — the fallback for every subject
	// whose position/location/work-center has no explicit tz.
	// IANA name, e.g. 'Asia/Kolkata'.
	DefaultTimezone string `json:"default_timezone"`

	LocationCode string  `json:"location_code"`
	LocationName string  `json:"location_name"`
	AddressLine1 *string `json:"address_line1,omitempty"`
	AddressLine2 *string `json:"address_line2,omitempty"`
	City         *string `json:"city,omitempty"`
	State        *string `json:"state,omitempty"`
	Country      *string `json:"country,omitempty"`
	Pincode      *string `json:"pincode,omitempty"`

	// LocationTimezone is optional. When NULL, this location inherits
	// the company default. Set only if this site is in a different tz.
	LocationTimezone *string `json:"location_timezone,omitempty"`

	WorkCenterCode         string  `json:"work_center_code"`
	WorkCenterName         string  `json:"work_center_name"`
	WorkCenterDesc         *string `json:"work_center_desc,omitempty"`
	WorkCenterTZ           string  `json:"work_center_timezone"`
	WorkCenterActive       bool    `json:"work_center_active"`
	PositionWorkCenterCode *string `json:"position_work_center_code,omitempty"`

	// Owner employee profile — all optional / nullable.
	OwnerDateOfBirth      *time.Time `json:"owner_date_of_birth,omitempty"`
	OwnerGender           *string    `json:"owner_gender,omitempty"`
	OwnerMaritalStatus    *string    `json:"owner_marital_status,omitempty"`
	OwnerNationality      *string    `json:"owner_nationality,omitempty"`
	OwnerEmploymentType   *string    `json:"owner_employment_type,omitempty"`
	OwnerEmploymentStatus *string    `json:"owner_employment_status,omitempty"`
	OwnerProbationEndDate *time.Time `json:"owner_probation_end_date,omitempty"`
	OwnerConfirmationDate *time.Time `json:"owner_confirmation_date,omitempty"`
	OwnerGrade            *string    `json:"owner_grade,omitempty"`
	OwnerCostCenterID     *uuid.UUID `json:"owner_cost_center_id,omitempty"`
	OwnerCostCenter       *string    `json:"owner_cost_center,omitempty"`
	OwnerTaxID            *string    `json:"owner_tax_id,omitempty"`
	OwnerSocialSecurityID *string    `json:"owner_social_security_id,omitempty"`
	OwnerEmail            *string    `json:"owner_email,omitempty"`
}

// ============================================================
// CreateCompany — creates company + CEO job + admin dept + owner position.
//
// The repo's CreateCompany() transaction:
//  1. Inserts the company row.
//  2. Inserts the work center.
//  3. Creates the owner role.
//  4. Creates the "Administration" department.
//  5. Finds-or-creates the JOB for the owner (title = ownerJobTitle).
//  6. Inserts the owner POSITION referencing that job.
//  7. Grants owner role departments + permissions.
//  8. Inserts the owner's company_employees row.
//
// ============================================================
func (s *CompanyService) CreateCompany(
	ctx context.Context,
	req *CreateCompanyRequest,
	createdBy uuid.UUID,
) (*models.Company, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_company:%s:%s", req.CompanyName, req.OwnerPhone)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedCompany models.Company
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedCompany); err == nil {
		return &cachedCompany, nil
	}

	if req.MaxLocations < 1 || req.MaxLocations > 500 {
		return nil, fmt.Errorf("%w: max_locations must be between 1 and 500", appErrors.ErrInvalidInput)
	}
	if req.FinancialYearStartMonth < 1 || req.FinancialYearStartMonth > 12 {
		return nil, fmt.Errorf("%w: financial_year_start_month must be between 1 and 12", appErrors.ErrInvalidInput)
	}
	if req.SubscriptionMonths < 0 || req.SubscriptionMonths > 36 {
		return nil, fmt.Errorf("%w: subscription_months must be between 0 and 36", appErrors.ErrInvalidInput)
	}
	if req.SubscriptionDays < 0 || req.SubscriptionDays > 30 {
		return nil, fmt.Errorf("%w: subscription_days must be between 0 and 30", appErrors.ErrInvalidInput)
	}
	if req.TrialDays < 0 {
		return nil, fmt.Errorf("%w: trial_days cannot be negative", appErrors.ErrInvalidInput)
	}
	if req.LocationCode == "" || req.LocationName == "" {
		return nil, fmt.Errorf("%w: location_code and location_name are required", appErrors.ErrInvalidInput)
	}

	// ── NEW: timezone validation.
	//   • DefaultTimezone is required.
	//   • LocationTimezone is optional; if provided it must be valid.
	//   • WorkCenterTZ is validated by the work-center repo on insert.
	if req.DefaultTimezone == "" {
		return nil, fmt.Errorf("%w: default_timezone is required (IANA name, e.g. 'Asia/Kolkata')", appErrors.ErrInvalidInput)
	}
	if err := util.ValidateTimezone(req.DefaultTimezone); err != nil {
		return nil, fmt.Errorf("%w: default_timezone: %v", appErrors.ErrInvalidInput, err)
	}
	if req.LocationTimezone != nil && *req.LocationTimezone != "" {
		if err := util.ValidateTimezone(*req.LocationTimezone); err != nil {
			return nil, fmt.Errorf("%w: location_timezone: %v", appErrors.ErrInvalidInput, err)
		}
	}
	if req.WorkCenterTZ != "" {
		if err := util.ValidateTimezone(req.WorkCenterTZ); err != nil {
			return nil, fmt.Errorf("%w: work_center_timezone: %v", appErrors.ErrInvalidInput, err)
		}
	}

	ownerJobTitle := strings.TrimSpace(req.OwnerPositionTitle)
	if ownerJobTitle == "" {
		ownerJobTitle = "CEO"
	}

	var plan *models.SubscriptionPlan
	if req.SubscriptionPlanCode != "" {
		var err error
		plan, err = s.planService.GetPlanByCode(ctx, req.SubscriptionPlanCode)
		if err != nil {
			return nil, fmt.Errorf("%w: plan '%s' not found: %v", appErrors.ErrNotFound, req.SubscriptionPlanCode, err)
		}
	}

	var ownerUser *models.User
	existingUser, err := s.userService.GetUserByPhone(ctx, req.OwnerPhone)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			ownerUser, err = s.createOrFindUserForCompanyOwner(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to create owner user", appErrors.ErrInternal)
			}
		} else {
			return nil, fmt.Errorf("%w: failed to get user", appErrors.ErrInternal)
		}
	} else {
		ownerUser = existingUser
	}

	exists, err := s.companyRepo.CheckCompanyExists(ctx, req.CompanyName, ownerUser.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to validate company", appErrors.ErrInternal)
	}
	if exists {
		return nil, fmt.Errorf("%w: company with name '%s' already exists for this owner", appErrors.ErrDuplicate, req.CompanyName)
	}

	now := time.Now().UTC()
	var (
		subscriptionStart  *time.Time
		subscriptionEnd    *time.Time
		trialStart         *time.Time
		trialEnd           *time.Time
		subscriptionStatus = models.SubscriptionStatusPending
		subscriptionAmount = 0.0
		subscriptionPlanID *uuid.UUID
	)
	switch {
	case req.TrialDays > 0:
		subscriptionStatus = models.SubscriptionStatusTrial
		trialStart = &now
		trialEnd = pointerTime(now.AddDate(0, 0, req.TrialDays))
	case req.SubscriptionMonths > 0 || req.SubscriptionDays > 0:
		subscriptionStatus = models.SubscriptionStatusActive
		subscriptionStart = &now
		subscriptionEnd = pointerTime(now.AddDate(0, req.SubscriptionMonths, req.SubscriptionDays))
		if plan != nil {
			subscriptionAmount = plan.Price
			pid := plan.PlanID
			subscriptionPlanID = &pid
		}
	default:
		subscriptionStatus = models.SubscriptionStatusPending
		subscriptionStart = nil
		subscriptionEnd = nil
		subscriptionAmount = 0
		subscriptionPlanID = nil
	}

	maxEmployees := req.MaxEmployees
	if maxEmployees == 0 {
		maxEmployees = 10
	}

	company := &models.Company{
		CompanyID:               uuid.New(),
		CompanyName:             req.CompanyName,
		OwnerUserID:             ownerUser.UserID,
		SubscriptionTier:        req.SubscriptionTier,
		SubscriptionStatus:      subscriptionStatus,
		MaxEmployees:            maxEmployees,
		MaxLocations:            req.MaxLocations,
		SubscriptionAmount:      subscriptionAmount,
		DataRegion:              req.DataRegion,
		DefaultTimezone:         req.DefaultTimezone, // ← NEW
		IsActive:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
		SubscriptionStartDate:   subscriptionStart,
		SubscriptionEndDate:     subscriptionEnd,
		FinancialYearStartMonth: req.FinancialYearStartMonth,
		GracePeriodDays:         3,
		SubscriptionPlanID:      subscriptionPlanID,
		TrialStartDate:          trialStart,
		TrialEndDate:            trialEnd,
	}

	positionWorkCenter := req.PositionWorkCenterCode
	if positionWorkCenter == nil {
		positionWorkCenter = &req.WorkCenterCode
	}

	workCenter := &models.WorkCenter{
		WorkCenterCode: req.WorkCenterCode,
		CompanyID:      uuid.Nil,
		Name:           req.WorkCenterName,
		Description:    req.WorkCenterDesc,
		Timezone:       req.WorkCenterTZ,
		IsActive:       req.WorkCenterActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	position := &models.Position{
		PositionID:     uuid.New(),
		CompanyID:      uuid.Nil,
		DepartmentID:   uuid.Nil,
		IsOpen:         false,
		WorkCenterCode: positionWorkCenter,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.companyRepo.CreateCompany(
		ctx, company, req.Departments, ownerJobTitle, position, workCenter,
	); err != nil {
		return nil, fmt.Errorf("%w: failed to create company: %v", appErrors.ErrInternal, err)
	}

	// ── default location — carries optional tz override ──────────────
	location := &models.Location{
		LocationID:   uuid.New(),
		CompanyID:    company.CompanyID,
		LocationCode: req.LocationCode,
		LocationName: req.LocationName,
		AddressLine1: req.AddressLine1,
		AddressLine2: req.AddressLine2,
		City:         req.City,
		State:        req.State,
		Country:      req.Country,
		Pincode:      req.Pincode,
		Timezone:     req.LocationTimezone, // ← NEW (nil → inherit company default)
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.locationRepo.CreateLocation(ctx, s.pgClient.Pool(), location); err != nil {
		return nil, fmt.Errorf("%w: failed to create default location: %v", appErrors.ErrInternal, err)
	}

	if err := s.companyRepo.SetWorkCenterLocation(
		ctx, s.pgClient.Pool(), company.CompanyID, req.WorkCenterCode, location.LocationID,
	); err != nil {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil,
				"company", "work_center_location_link_failed", "company",
				&company.CompanyID, "system", nil, nil, nil,
				map[string]interface{}{
					"error":            err.Error(),
					"company_id":       company.CompanyID.String(),
					"work_center_code": req.WorkCenterCode,
					"location_id":      location.LocationID.String(),
				})
		}
	}

	if err := s.companyRepo.UpdateEmployeeLocationSettings(
		ctx, s.pgClient.Pool(), company.CompanyID, ownerUser.UserID, &location.LocationID, models.LocationScopeAll,
	); err != nil {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "company", "location_assignment_failed", "employee",
				&ownerUser.UserID, "system", nil, nil, nil, map[string]interface{}{
					"error": err.Error(), "company_id": company.CompanyID.String(),
				})
		}
	} else {
		history := &models.EmployeeLocationHistory{
			ID:           uuid.New(),
			UserID:       ownerUser.UserID,
			CompanyID:    company.CompanyID,
			LocationID:   location.LocationID,
			StartDate:    now,
			EndDate:      nil,
			ChangeReason: "initial assignment on company creation",
			CreatedAt:    now,
		}
		if err := s.locationRepo.AddLocationHistory(ctx, s.pgClient.Pool(), history); err != nil {
			if s.auditService != nil {
				_ = s.auditService.LogAction(ctx, nil, nil, "company", "location_history_write_failed", "employee",
					&ownerUser.UserID, "system", nil, nil, nil, map[string]interface{}{
						"error": err.Error(), "company_id": company.CompanyID.String(),
						"location_id": location.LocationID.String(),
					})
			}
		}
	}

	ownerStatus := "active"
	if req.OwnerEmploymentStatus != nil && *req.OwnerEmploymentStatus != "" {
		ownerStatus = *req.OwnerEmploymentStatus
	}

	profileCtx := context.WithValue(ctx, "idempotency_key",
		fmt.Sprintf("owner_profile:%s", company.CompanyID.String()))

	ownerProfile := &hrEmployee.EmployeeProfile{
		EmployeeProfileID: uuid.New(),
		UserID:            ownerUser.UserID,
		CompanyID:         company.CompanyID,
		DateOfBirth:       req.OwnerDateOfBirth,
		Gender:            req.OwnerGender,
		MaritalStatus:     req.OwnerMaritalStatus,
		Nationality:       req.OwnerNationality,
		TaxID:             req.OwnerTaxID,
		SocialSecurityID:  req.OwnerSocialSecurityID,
		Email:             req.OwnerEmail,
		EmploymentType:    req.OwnerEmploymentType,
		EmploymentStatus:  &ownerStatus,
		ProbationEndDate:  req.OwnerProbationEndDate,
		ConfirmationDate:  req.OwnerConfirmationDate,
		JobTitle:          &ownerJobTitle,
		Grade:             req.OwnerGrade,
		CostCenter:        req.OwnerCostCenter,
		CostCenterID:      req.OwnerCostCenterID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if _, err := s.employeeService.CreateEmployeeProfile(
		profileCtx, ownerProfile, "admin", createdBy,
		map[string]interface{}{"source": "create_company", "company_id": company.CompanyID.String()},
	); err != nil {
		return nil, fmt.Errorf("%w: failed to create owner employee profile: %v", appErrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, company)
	s.InvalidateCompanyStatusCache(ctx, company.CompanyID)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "company", "create_company", "admin",
			&createdBy, "admin", &createdBy, nil, nil, map[string]interface{}{
				"company_id":           company.CompanyID.String(),
				"company_name":         req.CompanyName,
				"owner_user_id":        ownerUser.UserID.String(),
				"owner_job_title":      ownerJobTitle,
				"subscription_tier":    req.SubscriptionTier,
				"subscription_plan":    req.SubscriptionPlanCode,
				"subscription_status":  subscriptionStatus,
				"subscription_months":  req.SubscriptionMonths,
				"subscription_days":    req.SubscriptionDays,
				"trial_days":           req.TrialDays,
				"max_locations":        req.MaxLocations,
				"max_employees":        maxEmployees,
				"default_timezone":     req.DefaultTimezone,  // ← NEW
				"location_timezone":    req.LocationTimezone, // ← NEW
				"work_center_timezone": req.WorkCenterTZ,     // ← NEW
				"ip_address":           ip,
			})
	}
	return company, nil
}
func (s *CompanyService) createOrFindUserForCompanyOwner(ctx context.Context, req *CreateCompanyRequest) (*models.User, error) {
	user, err := s.userService.CreateUser(ctx, s.pgClient.Pool(), &UserCreateRequest{
		Username:          req.OwnerUsername,
		FullName:          req.OwnerFullName,
		PhoneNumber:       req.OwnerPhone,
		DeviceID:          "company-setup",
		DeviceFingerprint: "company-setup",
		DataRegion:        req.DataRegion,
		ConsentAgreed:     true,
		ConsentVersion:    "v1.0",
		KYCStatus:         models.KYCStatusPending,
		KYCLevel:          models.KYCLevelBasic,
	})
	if err == nil {
		return user, nil
	}
	if strings.Contains(err.Error(), "username already exists") {
		uniqueUsername := fmt.Sprintf("%s_%s", req.OwnerUsername, generateRandomString(6))
		user, err = s.userService.CreateUser(ctx, s.pgClient.Pool(), &UserCreateRequest{
			Username:          uniqueUsername,
			FullName:          req.OwnerFullName,
			PhoneNumber:       req.OwnerPhone,
			DeviceID:          "company-setup",
			DeviceFingerprint: "company-setup",
			DataRegion:        req.DataRegion,
			ConsentAgreed:     true,
			ConsentVersion:    "v1.0",
			KYCStatus:         models.KYCStatusPending,
			KYCLevel:          models.KYCLevelBasic,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: failed to create user with unique username", appErrors.ErrInternal)
		}
		return user, nil
	}
	return nil, err
}

// ============================================================
// Company getters / updaters (unchanged)
// ============================================================

func (s *CompanyService) GetCompany(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return company, nil
}

func (s *CompanyService) GetCompanyDetail(ctx context.Context, companyID uuid.UUID) (*models.CompanyDetailView, error) {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	view := models.NewCompanyDetailView(company)
	if company.SubscriptionPlanID != nil && s.planService != nil {
		plan, perr := s.planService.GetPlanByID(ctx, *company.SubscriptionPlanID)
		if perr == nil && plan != nil {
			view.SubscriptionPlanCode = &plan.PlanCode
			view.SubscriptionPlanName = &plan.PlanName
		}
	}
	return view, nil
}

func (s *CompanyService) GetCompanyByID(ctx context.Context, companyID uuid.UUID) (*models.Company, error) {
	return s.GetCompany(ctx, companyID)
}

func (s *CompanyService) GetCompaniesByOwner(ctx context.Context, ownerUserID uuid.UUID) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesByOwner(ctx, ownerUserID)
}

func (s *CompanyService) UpdateCompany(ctx context.Context, company *models.Company) error {
	if err := s.companyRepo.UpdateCompany(ctx, company); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, company.CompanyID)
	return nil
}

func (s *CompanyService) UpdateCompanyStatus(ctx context.Context, companyID uuid.UUID, isActive bool, updatedBy uuid.UUID) error {
	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, isActive); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)
	return nil
}

func (s *CompanyService) UpdateSubscription(ctx context.Context, companyID uuid.UUID, tier, status string, maxEmployees int, updatedBy uuid.UUID) error {
	if err := s.companyRepo.UpdateSubscription(ctx, companyID, tier, status, maxEmployees); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)
	return nil
}

func (s *CompanyService) ListCompanies(ctx context.Context, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.ListCompanies(ctx, limit, offset)
}

func (s *CompanyService) ListCompaniesByTier(ctx context.Context, tier string, limit, offset int) ([]*models.Company, int, error) {
	return s.companyRepo.GetCompaniesByTier(ctx, tier, limit, offset)
}

func (s *CompanyService) GetCompaniesWithExpiringSubscription(ctx context.Context, days int, limit int) ([]*models.Company, error) {
	return s.companyRepo.GetCompaniesWithExpiringSubscription(ctx, days, limit)
}

func (s *CompanyService) DeactivateCompany(ctx context.Context, companyID uuid.UUID, reason string, updatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: company is already inactive", appErrors.ErrInvalidState)
	}
	if err := s.companyRepo.DeactivateCompany(ctx, companyID, reason); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)
	return nil
}

func (s *CompanyService) ReactivateCompany(ctx context.Context, companyID uuid.UUID, reactivatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if company.IsActive {
		return fmt.Errorf("%w: company is already active", appErrors.ErrInvalidState)
	}
	if err := s.companyRepo.UpdateCompanyStatus(ctx, companyID, true); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)
	return nil
}

func (s *CompanyService) DeleteCompany(ctx context.Context, companyID uuid.UUID, deletedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if company.IsActive {
		return fmt.Errorf("%w: cannot delete active company; deactivate first", appErrors.ErrInvalidState)
	}
	if err := s.companyRepo.DeleteCompany(ctx, companyID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)
	return nil
}

func (s *CompanyService) ExtendSubscription(ctx context.Context, companyID uuid.UUID, additionalMonths, additionalDays int, extendedBy uuid.UUID) error {
	if additionalMonths < 0 || additionalDays < 0 {
		return fmt.Errorf("%w: additional months/days cannot be negative", appErrors.ErrInvalidInput)
	}
	if additionalMonths == 0 && additionalDays == 0 {
		return fmt.Errorf("%w: at least one of additional_months or additional_days must be > 0", appErrors.ErrInvalidInput)
	}
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: cannot extend subscription for inactive company", appErrors.ErrInvalidState)
	}
	now := time.Now().UTC()
	beforeStatus := company.SubscriptionStatus
	switch company.SubscriptionStatus {
	case models.SubscriptionStatusActive, models.SubscriptionStatusPastDue:
		base := now
		if company.SubscriptionEndDate != nil {
			base = *company.SubscriptionEndDate
		}
		newEnd := base.AddDate(0, additionalMonths, additionalDays)
		company.SubscriptionEndDate = &newEnd
		if company.SubscriptionStartDate == nil {
			company.SubscriptionStartDate = &now
		}
		company.SubscriptionStatus = models.SubscriptionStatusActive
	case models.SubscriptionStatusTrial:
		base := now
		if company.TrialEndDate != nil && company.TrialEndDate.After(now) {
			base = *company.TrialEndDate
		}
		newEnd := base.AddDate(0, additionalMonths, additionalDays)
		company.SubscriptionStartDate = &base
		company.SubscriptionEndDate = &newEnd
		company.SubscriptionStatus = models.SubscriptionStatusActive
	default:
		newEnd := now.AddDate(0, additionalMonths, additionalDays)
		company.SubscriptionStartDate = &now
		company.SubscriptionEndDate = &newEnd
		company.SubscriptionStatus = models.SubscriptionStatusActive
	}
	company.UpdatedAt = now
	if err := s.companyRepo.UpdateCompany(ctx, company); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "extend", "admin",
			&extendedBy, "admin", &extendedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(), "previous_status": beforeStatus,
				"new_status":        company.SubscriptionStatus,
				"additional_months": additionalMonths, "additional_days": additionalDays,
				"new_start_date": company.SubscriptionStartDate, "new_end_date": company.SubscriptionEndDate,
			})
	}
	return nil
}

// ============================================================
// Employee getters (unchanged)
// ============================================================

func (s *CompanyService) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (*models.CompanyEmployee, error) {
	emp, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return emp, nil
}

func (s *CompanyService) ListEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]models.EmployeeSummary, int, error) {
	return s.companyRepo.GetEmployeeSummariesByCompany(ctx, s.pgClient.Pool(), companyID, limit, offset)
}

func (s *CompanyService) ListActiveEmployees(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyEmployee, int, error) {
	return s.companyRepo.ListActiveEmployees(ctx, companyID, limit, offset)
}

func (s *CompanyService) UpdateEmployeeRole(ctx context.Context, companyID, userID, newRoleID, updatedBy uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_employee_role:%s:%s", companyID.String(), userID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	emp, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	newRole, err := s.companyRepo.GetRole(ctx, newRoleID)
	if err != nil {
		return fmt.Errorf("%w: new role not found", appErrors.ErrNotFound)
	}
	if newRole.CompanyID != companyID {
		return fmt.Errorf("%w: new role does not belong to company", appErrors.ErrInvalidInput)
	}
	if emp.ReportsTo != nil {
		if err := s.validateReportsTo(ctx, companyID, emp.ReportsTo); err != nil {
			emp.ReportsTo = nil
		}
	}
	emp.RoleID = newRoleID
	emp.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateEmployee(ctx, emp); err != nil {
		return fmt.Errorf("%w: failed to update employee role", appErrors.ErrInternal)
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_role", "admin",
			&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(), "user_id": userID.String(),
				"new_role_id": newRoleID.String(), "ip_address": ip,
			})
	}
	return nil
}

func (s *CompanyService) RemoveEmployee(ctx context.Context, companyID, userID uuid.UUID, removedBy uuid.UUID) error {
	if userID == removedBy {
		return fmt.Errorf("%w: cannot remove yourself", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.DeactivateEmployee(ctx, companyID, userID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.resolverJobs.EnqueueEndEntitlements(ctx, tx, companyID, userID, "exit")
	}); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "remove_employee", "admin",
			&removedBy, "admin", &removedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(), "user_id": userID.String(),
			})
	}
	return nil
}

func (s *CompanyService) ReactivateEmployee(ctx context.Context, companyID, userID, reactivatedBy uuid.UUID) error {
	if err := s.companyRepo.ReactivateEmployee(ctx, companyID, userID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		return s.resolverJobs.EnqueueUserResolution(ctx, tx, companyID, userID, "rehire")
	}); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "reactivate_employee", "admin",
			&reactivatedBy, "admin", &reactivatedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(), "user_id": userID.String(),
			})
	}
	return nil
}

func (s *CompanyService) GetEmployeeCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetEmployeeCount(ctx, companyID)
}

func (s *CompanyService) IsUserActiveEmployee(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	return s.companyRepo.IsUserActiveEmployee(ctx, companyID, userID)
}

func (s *CompanyService) GetEmployeesByUser(ctx context.Context, userID uuid.UUID) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetEmployeesByUser(ctx, userID)
}

func (s *CompanyService) GetCompaniesByEmployeePhone(ctx context.Context, employeePhone string) ([]*models.Company, error) {
	user, err := s.userService.GetUserByPhone(ctx, employeePhone)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get user", appErrors.ErrNotFound)
	}
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var companies []*models.Company
	seen := make(map[uuid.UUID]bool)
	for _, emp := range employees {
		if !emp.IsActive || seen[emp.CompanyID] {
			continue
		}
		company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
		if err != nil {
			continue
		}
		if company.IsActive {
			companies = append(companies, company)
			seen[emp.CompanyID] = true
		}
	}
	if len(companies) == 0 {
		return nil, fmt.Errorf("%w: no active companies found", appErrors.ErrNotFound)
	}
	return companies, nil
}
func (s *CompanyService) UpdateEmployeePosition(ctx context.Context, companyID, userID uuid.UUID, positionID *uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_employee_position:%s:%s", companyID.String(), userID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	employee, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	if !employee.IsActive {
		return fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}

	if positionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), *positionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != companyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open", appErrors.ErrInvalidState)
		}
		roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
		if err != nil {
			return fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
		}
		found := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to role", appErrors.ErrInvalidInput)
		}
	}

	// Update + enqueue in one tx. companyRepo.UpdateEmployeePosition accepts
	// client.DBTX, so it works with either Pool() or *sql.Tx — passing tx
	// makes the resolver job part of the same commit.
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		if err := s.companyRepo.UpdateEmployeePosition(ctx, tx, companyID, userID, positionID); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		return s.resolverJobs.EnqueueUserResolution(ctx, tx, companyID, userID, "position change")
	}); err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_position", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": companyID.String(), "user_id": userID.String(),
				"position_id": positionID, "ip_address": ip,
			})
	}
	return nil
}

func (s *CompanyService) GetEmployeeWithPosition(ctx context.Context, companyID, userID uuid.UUID) (*models.EmployeeWithPositionDetails, error) {
	employee, err := s.companyRepo.GetEmployeeWithPosition(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return employee, nil
}

type UpdateEmployeeRequest struct {
	CompanyID  uuid.UUID
	UserID     uuid.UUID
	EmployeeID *string
	RoleID     *uuid.UUID
	PositionID *uuid.UUID
	ReportsTo  *uuid.UUID
	IsActive   *bool
	HireDate   *time.Time
}

func (s *CompanyService) UpdateEmployee(ctx context.Context, req *UpdateEmployeeRequest) error {
	skipIdempotency := false
	if val, ok := ctx.Value("disable_idempotency").(bool); ok {
		skipIdempotency = val
	}
	var idempKey string
	if !skipIdempotency {
		idempKey, _ = ctx.Value("idempotency_key").(string)
		if idempKey == "" {
			idempKey = fmt.Sprintf("update_employee:%s:%s", req.CompanyID.String(), req.UserID.String())
		}
		var processed bool
		if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
			return nil
		}
	}
	ip, _ := ctx.Value("ip_address").(string)

	existing, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), req.CompanyID, req.UserID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
		}
		return fmt.Errorf("%w: failed to get employee", appErrors.ErrInternal)
	}

	updated := *existing
	if req.EmployeeID != nil {
		updated.EmployeeID = *req.EmployeeID
	}
	if req.RoleID != nil {
		updated.RoleID = *req.RoleID
	}
	if req.PositionID != nil {
		updated.PositionID = req.PositionID
	}
	if req.ReportsTo != nil {
		updated.ReportsTo = req.ReportsTo
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}
	if req.HireDate != nil {
		updated.HireDate = *req.HireDate
	}
	updated.UpdatedAt = time.Now().UTC()

	if req.RoleID != nil {
		role, err := s.companyRepo.GetRole(ctx, *req.RoleID)
		if err != nil {
			return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
		}
		if role.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: role does not belong to company", appErrors.ErrInvalidInput)
		}
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, *req.RoleID)
		if err != nil || len(roleDepts) == 0 {
			return fmt.Errorf("%w: role is not assigned to any department", appErrors.ErrInvalidState)
		}
	}

	if req.PositionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), *req.PositionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open for assignment", appErrors.ErrInvalidState)
		}
		var roleID uuid.UUID
		if req.RoleID != nil {
			roleID = *req.RoleID
		} else {
			roleID = existing.RoleID
		}
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, roleID)
		if err != nil {
			return err
		}
		found := false
		for _, rd := range roleDepts {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to the role", appErrors.ErrInvalidInput)
		}
	}

	if req.ReportsTo != nil {
		if *req.ReportsTo == req.UserID {
			return fmt.Errorf("%w: employee cannot report to themselves", appErrors.ErrInvalidInput)
		}
		isActive, err := s.companyRepo.IsUserActiveEmployee(ctx, req.CompanyID, *req.ReportsTo)
		if err != nil || !isActive {
			return fmt.Errorf("%w: reports-to employee not found or not active", appErrors.ErrInvalidInput)
		}
	}

	// Snapshot the current position so we can detect a change.
	oldPositionID := existing.PositionID

	// Wrap update + enqueue in a single tx so they succeed or fail together.
	if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		if err := s.companyRepo.UpdateEmployeeTx(ctx, tx, &updated); err != nil {
			return fmt.Errorf("%w: failed to update employee", appErrors.ErrInternal)
		}
		if !uuidPtrEqual(oldPositionID, updated.PositionID) {
			if err := s.resolverJobs.EnqueueUserResolution(
				ctx, tx, req.CompanyID, req.UserID, "position change",
			); err != nil {
				return fmt.Errorf("%w: failed to enqueue resolver job: %v", appErrors.ErrInternal, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if !skipIdempotency {
		_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "update_employee", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(),
				"user_id":    req.UserID.String(),
				"updates": map[string]interface{}{
					"employee_id": req.EmployeeID, "role_id": req.RoleID,
					"position_id": req.PositionID, "reports_to": req.ReportsTo,
					"is_active": req.IsActive, "hire_date": req.HireDate,
				},
				"ip_address": ip,
			})
	}
	return nil
}

func (s *CompanyService) GetUserDepartments(ctx context.Context, companyID, userID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentsByUserID(ctx, s.pgClient.Pool(), companyID, userID)
}

type EmployeeProfileResponse struct {
	CompanyID      uuid.UUID  `json:"company_id"`
	UserID         uuid.UUID  `json:"user_id"`
	Username       string     `json:"username"`
	FullName       string     `json:"full_name"`
	Phone          string     `json:"phone"`
	Email          *string    `json:"email,omitempty"`
	EmployeeID     string     `json:"employee_id"`
	RoleID         uuid.UUID  `json:"role_id"`
	RoleName       string     `json:"role_name"`
	PositionID     *uuid.UUID `json:"position_id,omitempty"`
	PositionTitle  *string    `json:"position_title,omitempty"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
	DepartmentName *string    `json:"department_name,omitempty"`
	ReportsTo      *uuid.UUID `json:"reports_to,omitempty"`
	ReportsToName  *string    `json:"reports_to_name,omitempty"`
	HireDate       time.Time  `json:"hire_date"`
	IsActive       bool       `json:"is_active"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (s *CompanyService) GetEmployeeProfile(ctx context.Context, companyID, userID uuid.UUID) (*EmployeeProfileResponse, error) {
	employee, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return nil, err
	}
	user, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	phone, err := s.userService.DecryptPhoneNumber(ctx, user)
	if err != nil {
		phone = ""
	}
	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, err
	}
	var positionTitle *string
	var deptID *uuid.UUID
	var deptName *string

	if employee.PositionID != nil {
		// Repo now returns *models.PositionView with joined job + location.
		position, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), *employee.PositionID)
		if err == nil {
			t := position.EffectiveTitle()
			positionTitle = &t
			deptID = &position.DepartmentID
			if position.DepartmentName != nil {
				deptName = position.DepartmentName
			}
		}
	}

	var reportsToName *string
	if employee.ReportsTo != nil {
		reportsToUser, err := s.userService.GetUserByID(ctx, *employee.ReportsTo)
		if err == nil && reportsToUser != nil {
			reportsToName = &reportsToUser.FullName
		}
	}

	return &EmployeeProfileResponse{
		CompanyID:      companyID,
		UserID:         user.UserID,
		Username:       user.Username,
		FullName:       user.FullName,
		Phone:          phone,
		EmployeeID:     employee.EmployeeID,
		RoleID:         employee.RoleID,
		RoleName:       role.RoleName,
		PositionID:     employee.PositionID,
		PositionTitle:  positionTitle,
		DepartmentID:   deptID,
		DepartmentName: deptName,
		ReportsTo:      employee.ReportsTo,
		ReportsToName:  reportsToName,
		HireDate:       employee.HireDate,
		IsActive:       employee.IsActive,
		CreatedAt:      employee.CreatedAt,
		UpdatedAt:      employee.UpdatedAt,
	}, nil
}

// ============================================================
// Roles (unchanged)
// ============================================================

type CreateRoleRequest struct {
	CompanyID     uuid.UUID   `json:"company_id" validate:"required"`
	RoleName      string      `json:"role_name" validate:"required"`
	RoleLevel     int         `json:"role_level" validate:"required,min=1,max=1000"`
	Description   string      `json:"description"`
	DepartmentIDs []uuid.UUID `json:"department_ids"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
	CreatedBy     uuid.UUID   `json:"created_by" validate:"required"`
}

func (s *CompanyService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_role:%s:%s", req.CompanyID.String(), req.RoleName)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedRole models.Role
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedRole); err == nil {
		return &cachedRole, nil
	}

	for _, deptID := range req.DepartmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), deptID)
		if err != nil {
			return nil, fmt.Errorf("%w: department not found: %s", appErrors.ErrNotFound, deptID)
		}
		if dept.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: department %s does not belong to company", appErrors.ErrInvalidInput, deptID)
		}
	}

	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get permissions", appErrors.ErrInternal)
	}
	permMap := make(map[uuid.UUID]*models.Permission)
	for _, perm := range allPerms {
		permMap[perm.PermissionID] = perm
	}

	departmentModules := make(map[string]bool)
	for _, deptID := range req.DepartmentIDs {
		dept, _ := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), deptID)
		if dept.SystemDepartmentID != nil {
			systemDept, err := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), *dept.SystemDepartmentID)
			if err == nil {
				departmentModules[systemDept.ModuleCode] = true
			}
		}
	}

	for _, permID := range req.PermissionIDs {
		perm, exists := permMap[permID]
		if !exists {
			return nil, fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, permID)
		}
		if !departmentModules[perm.Module] {
			return nil, fmt.Errorf("%w: permission '%s' module '%s' not compatible with departments", appErrors.ErrInvalidInput, perm.PermissionName, perm.Module)
		}
	}

	existingRoles, _, err := s.companyRepo.GetRolesByCompany(ctx, req.CompanyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check existing roles", appErrors.ErrInternal)
	}
	for _, role := range existingRoles {
		if strings.EqualFold(role.RoleName, req.RoleName) {
			return nil, fmt.Errorf("%w: role with name '%s' already exists", appErrors.ErrDuplicate, req.RoleName)
		}
	}

	role := &models.Role{
		RoleID:       uuid.New(),
		RoleName:     req.RoleName,
		RoleLevel:    req.RoleLevel,
		CompanyID:    req.CompanyID,
		IsSystemRole: false,
		Description:  req.Description,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := s.companyRepo.CreateRole(ctx, role, req.DepartmentIDs); err != nil {
		return nil, fmt.Errorf("%w: failed to create role", appErrors.ErrInternal)
	}
	if len(req.PermissionIDs) > 0 {
		_ = s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, req.PermissionIDs, req.CreatedBy)
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, role)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "create_role", "admin",
			&req.CreatedBy, "admin", &req.CreatedBy, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(), "role_id": role.RoleID.String(),
				"role_name": req.RoleName, "role_level": req.RoleLevel, "ip_address": ip,
			})
	}
	return role, nil
}

func (s *CompanyService) CreateRoleAdmin(ctx context.Context, req *CreateRoleRequest) (*models.Role, error) {
	return s.CreateRole(ctx, req)
}

func (s *CompanyService) GetRole(ctx context.Context, roleID uuid.UUID) (*models.Role, error) {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return role, nil
}

func (s *CompanyService) GetRolesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Role, int, error) {
	return s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
}

func (s *CompanyService) ListRoles(ctx context.Context, companyID uuid.UUID, limit, offset int, includePermissions bool) ([]*models.Role, int, error) {
	roles, total, err := s.companyRepo.GetRolesByCompany(ctx, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if includePermissions {
		for _, role := range roles {
			perms, err := s.companyRepo.GetRolePermissions(ctx, role.RoleID)
			if err == nil {
				_ = perms
			}
		}
	}
	return roles, total, nil
}

func (s *CompanyService) DeleteRole(ctx context.Context, roleID uuid.UUID, deletedBy uuid.UUID) error {
	role, err := s.companyRepo.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.IsSystemRole {
		return fmt.Errorf("%w: cannot delete system roles", appErrors.ErrSystemRole)
	}
	employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, s.pgClient.Pool(), roleID, 1, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to check assignments", appErrors.ErrInternal)
	}
	if len(employees) > 0 {
		return fmt.Errorf("%w: role is in use and cannot be deleted", appErrors.ErrRoleInUse)
	}
	if err := s.companyRepo.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "delete_role", "admin",
			&deletedBy, "admin", &deletedBy, nil, nil, map[string]interface{}{
				"role_id": roleID.String(), "role_name": role.RoleName,
			})
	}
	return nil
}

type UpdateRoleRequest struct {
	CompanyID          uuid.UUID
	RoleID             uuid.UUID
	RoleName           string
	Description        string
	AddDepartments     []string
	RemoveDepartments  []string
	AddPermissions     []string
	RemovePermissions  []string
	ReplacePermissions []string
	UpdatedBy          uuid.UUID
}

func (s *CompanyService) UpdateRole(ctx context.Context, req UpdateRoleRequest) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_role:%s", req.RoleID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.IsSystemRole {
		return fmt.Errorf("%w: cannot update system roles", appErrors.ErrSystemRole)
	}
	if role.CompanyID != req.CompanyID {
		return fmt.Errorf("%w: role does not belong to specified company", appErrors.ErrInvalidInput)
	}

	role.RoleName = req.RoleName
	role.Description = req.Description
	role.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateRole(ctx, role); err != nil {
		return fmt.Errorf("%w: failed to update role", appErrors.ErrInternal)
	}

	if len(req.AddDepartments) > 0 || len(req.RemoveDepartments) > 0 {
		if err := s.updateRoleDepartments(ctx, req, role); err != nil {
			return err
		}
	}

	if len(req.ReplacePermissions) > 0 {
		if err := s.replaceRolePermissions(ctx, req, role); err != nil {
			return err
		}
	} else {
		if err := s.updateRolePermissions(ctx, req, role); err != nil {
			return err
		}
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "update_role", "admin",
			&req.UpdatedBy, "admin", &req.UpdatedBy, nil, nil, map[string]interface{}{
				"role_id": req.RoleID.String(), "role_name": req.RoleName, "ip_address": ip,
			})
	}
	return nil
}

func (s *CompanyService) updateRoleDepartments(ctx context.Context, req UpdateRoleRequest, role *models.Role) error {
	currentDepts, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: failed to get current departments", appErrors.ErrInternal)
	}
	currentDeptMap := make(map[string]uuid.UUID)
	for _, dept := range currentDepts {
		currentDeptMap[dept.DepartmentName] = dept.DepartmentID
	}
	for _, deptName := range req.AddDepartments {
		if _, exists := currentDeptMap[deptName]; exists {
			continue
		}
		dept, err := s.companyRepo.GetDepartmentByName(ctx, s.pgClient.Pool(), role.CompanyID, deptName)
		if err != nil {
			return fmt.Errorf("%w: department not found: %s", appErrors.ErrNotFound, deptName)
		}
		if err := s.validatePermissionDepartmentCompatibilityForUpdate(ctx, []uuid.UUID{dept.DepartmentID}, req); err != nil {
			return err
		}
		if err := s.companyRepo.CreateRoleDepartment(ctx, role.RoleID, dept.DepartmentID); err != nil {
			return fmt.Errorf("%w: failed to add department", appErrors.ErrInternal)
		}
	}
	for _, deptName := range req.RemoveDepartments {
		deptID, exists := currentDeptMap[deptName]
		if !exists {
			continue
		}
		if err := s.companyRepo.RemoveRoleDepartment(ctx, role.RoleID, deptID); err != nil {
			return fmt.Errorf("%w: failed to remove department", appErrors.ErrInternal)
		}
	}
	return nil
}

func (s *CompanyService) replaceRolePermissions(ctx context.Context, req UpdateRoleRequest, role *models.Role) error {
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[string]uuid.UUID)
	for _, perm := range allPerms {
		permMap[perm.PermissionName] = perm.PermissionID
	}
	var permIDs []uuid.UUID
	for _, name := range req.ReplacePermissions {
		id, exists := permMap[name]
		if !exists {
			return fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, name)
		}
		permIDs = append(permIDs, id)
	}
	currentDepts, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var deptIDs []uuid.UUID
	for _, dept := range currentDepts {
		deptIDs = append(deptIDs, dept.DepartmentID)
	}
	if len(deptIDs) > 0 && len(permIDs) > 0 {
		compatible, errMsg, err := s.ValidatePermissionDepartmentCompatibility(ctx, deptIDs, permIDs)
		if err != nil {
			return err
		}
		if !compatible {
			return fmt.Errorf("%w: %s", appErrors.ErrInvalidInput, errMsg)
		}
	}
	if err := s.companyRepo.ReplaceRolePermissions(ctx, role.RoleID, permIDs, req.UpdatedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *CompanyService) updateRolePermissions(ctx context.Context, req UpdateRoleRequest, role *models.Role) error {
	currentPerms, err := s.companyRepo.GetRolePermissions(ctx, role.RoleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	currentMap := make(map[string]bool)
	for _, p := range currentPerms {
		currentMap[p.PermissionName] = true
	}
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[string]uuid.UUID)
	for _, p := range allPerms {
		permMap[p.PermissionName] = p.PermissionID
	}
	var toAdd []uuid.UUID
	for _, name := range req.AddPermissions {
		if currentMap[name] {
			continue
		}
		id, exists := permMap[name]
		if !exists {
			return fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, name)
		}
		toAdd = append(toAdd, id)
	}
	var toRemove []uuid.UUID
	for _, name := range req.RemovePermissions {
		if !currentMap[name] {
			continue
		}
		id, exists := permMap[name]
		if !exists {
			return fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, name)
		}
		toRemove = append(toRemove, id)
	}
	currentDepts, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var deptIDs []uuid.UUID
	for _, dept := range currentDepts {
		deptIDs = append(deptIDs, dept.DepartmentID)
	}
	if len(deptIDs) > 0 && len(toAdd) > 0 {
		compatible, errMsg, err := s.ValidatePermissionDepartmentCompatibility(ctx, deptIDs, toAdd)
		if err != nil {
			return err
		}
		if !compatible {
			return fmt.Errorf("%w: %s", appErrors.ErrInvalidInput, errMsg)
		}
	}
	if len(toAdd) > 0 {
		if err := s.companyRepo.GrantMultipleRolePermissions(ctx, role.RoleID, toAdd, req.UpdatedBy); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}
	if len(toRemove) > 0 {
		if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, role.RoleID, toRemove); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
	}
	return nil
}

type MapRoleToDepartmentRequest struct {
	RoleID       uuid.UUID `json:"role_id" validate:"required"`
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	MappedBy     uuid.UUID `json:"mapped_by" validate:"required"`
}

func (s *CompanyService) MapRoleToDepartment(ctx context.Context, req *MapRoleToDepartmentRequest) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("map_role_dept:%s:%s", req.RoleID.String(), req.DepartmentID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	department, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), req.DepartmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if role.CompanyID != department.CompanyID {
		return fmt.Errorf("%w: role and department must belong to same company", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.CreateRoleDepartment(ctx, req.RoleID, req.DepartmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "map_role_department", "admin",
			&req.MappedBy, "admin", &req.MappedBy, nil, nil, map[string]interface{}{
				"role_id": req.RoleID.String(), "department_id": req.DepartmentID.String(),
				"ip_address": ip,
			})
	}
	return nil
}

func (s *CompanyService) RemoveRoleFromDepartment(ctx context.Context, roleID, departmentID, removedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.RemoveRoleDepartment(ctx, roleID, departmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "role", "unmap_role_department", "admin",
			&removedBy, "admin", &removedBy, nil, nil, map[string]interface{}{
				"role_id": roleID.String(), "department_id": departmentID.String(),
			})
	}
	return nil
}

func (s *CompanyService) GetRoleDepartments(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRoleDepartments(ctx, roleID)
}

func (s *CompanyService) GetDepartmentRoles(ctx context.Context, departmentID uuid.UUID) ([]*models.Role, error) {
	department, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		return nil, err
	}
	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, department.CompanyID, 1000, 0)
	if err != nil {
		return nil, err
	}
	var departmentRoles []*models.Role
	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, dept := range roleDepts {
			if dept.DepartmentID == departmentID {
				departmentRoles = append(departmentRoles, role)
				break
			}
		}
	}
	return departmentRoles, nil
}

func (s *CompanyService) GrantRolePermission(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.GrantRolePermission(ctx, roleID, permissionID, grantedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "permission", "grant", "admin",
			&grantedBy, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"role_id": roleID.String(), "permission_id": permissionID.String(),
			})
	}
	return nil
}

func (s *CompanyService) GrantRolePermissionAdmin(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID) error {
	return s.GrantRolePermission(ctx, roleID, permissionID, grantedBy)
}

func (s *CompanyService) RevokeRolePermission(ctx context.Context, roleID, permissionID, revokedBy uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.RevokeRolePermission(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "permission", "revoke", "admin",
			&revokedBy, "admin", &revokedBy, nil, nil, map[string]interface{}{
				"role_id": roleID.String(), "permission_id": permissionID.String(),
			})
	}
	return nil
}

func (s *CompanyService) RevokeRolePermissionAdmin(ctx context.Context, roleID, permissionID, revokedBy uuid.UUID) error {
	return s.RevokeRolePermission(ctx, roleID, permissionID, revokedBy)
}

type GrantRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"role_id" validate:"required"`
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
}

func (s *CompanyService) GrantRolePermissions(ctx context.Context, req *GrantRolePermissionsRequest) error {
	if _, err := s.companyRepo.GetRole(ctx, req.RoleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		return fmt.Errorf("%w: user ID not found", appErrors.ErrUnauthorized)
	}
	grantedBy, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("%w: invalid user ID", appErrors.ErrInvalidInput)
	}
	if err := s.companyRepo.GrantMultipleRolePermissions(ctx, req.RoleID, req.PermissionIDs, grantedBy); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "permission", "grant_multiple", "admin",
			&grantedBy, "admin", &grantedBy, nil, nil, map[string]interface{}{
				"role_id": req.RoleID.String(), "permission_count": len(req.PermissionIDs),
			})
	}
	return nil
}

func (s *CompanyService) RevokeRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if _, err := s.companyRepo.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.RevokeMultipleRolePermissions(ctx, roleID, permissionIDs); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *CompanyService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	return s.companyRepo.GetRolePermissions(ctx, roleID)
}

func (s *CompanyService) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	perm, err := s.companyRepo.GetPermissionByName(ctx, name)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: permission not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return perm, nil
}

func (s *CompanyService) GetPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

func (s *CompanyService) GetAllPermissions(ctx context.Context, module, category, tier string) ([]*models.Permission, error) {
	all, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var filtered []*models.Permission
	for _, p := range all {
		if module != "" && p.Module != module {
			continue
		}
		if category != "" && p.Category != category {
			continue
		}
		if tier != "" && p.RequiresTier != tier {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered, nil
}

func (s *CompanyService) CreatePermission(ctx context.Context, permissionName, description, category, module, requiresTier string) (*models.Permission, error) {
	perm := &models.Permission{
		PermissionID:   uuid.New(),
		PermissionName: permissionName,
		Description:    description,
		Category:       category,
		Module:         module,
		RequiresTier:   requiresTier,
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.companyRepo.CreatePermission(ctx, perm); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return perm, nil
}

func (s *CompanyService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*models.Permission, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[uuid.UUID]*models.Permission)
	for _, emp := range employees {
		if emp.IsActive {
			perms, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
			if err == nil {
				for _, p := range perms {
					permMap[p.PermissionID] = p
				}
			}
		}
	}
	result := make([]*models.Permission, 0, len(permMap))
	for _, p := range permMap {
		result = append(result, p)
	}
	return result, nil
}

func (s *CompanyService) GetUserPermissionBitmask(ctx context.Context, companyID, userID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
}

func (s *CompanyService) GetRolePermissionBitmask(ctx context.Context, roleID uuid.UUID) ([]uint64, error) {
	return s.companyRepo.GetRolePermissionBitmask(ctx, roleID)
}

func (s *CompanyService) GetPermissionsWithBitIndex(ctx context.Context) ([]*models.PermissionWithBitIndex, error) {
	return s.companyRepo.GetPermissionsWithBitIndex(ctx)
}

// ============================================================
// Departments (unchanged)
// ============================================================

type CreateDepartmentRequest struct {
	CompanyID          uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentName     string     `json:"department_name" validate:"required"`
	SystemDepartmentID uuid.UUID  `json:"system_department_id" validate:"required"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id,omitempty"`
}

func (s *CompanyService) CreateDepartment(ctx context.Context, req *CreateDepartmentRequest) (*models.Department, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_dept:%s:%s", req.CompanyID.String(), req.DepartmentName)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var cachedDept models.Department
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedDept); err == nil {
		return &cachedDept, nil
	}

	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if !company.IsActive {
		return nil, fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}
	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), req.SystemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: system department not found", appErrors.ErrNotFound)
	}
	existing, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, s.pgClient.Pool(), req.CompanyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check existing", appErrors.ErrInternal)
	}
	for _, d := range existing {
		if strings.EqualFold(d.DepartmentName, req.DepartmentName) {
			return nil, fmt.Errorf("%w: department name already exists", appErrors.ErrDuplicate)
		}
		if d.SystemDepartmentID != nil && *d.SystemDepartmentID == req.SystemDepartmentID {
			return nil, fmt.Errorf("%w: system department already assigned", appErrors.ErrDuplicate)
		}
	}
	if req.ParentDepartmentID != nil {
		parent, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), *req.ParentDepartmentID)
		if err != nil {
			return nil, fmt.Errorf("%w: parent department not found", appErrors.ErrNotFound)
		}
		if parent.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: parent department does not belong to company", appErrors.ErrInvalidInput)
		}
	}
	dept := &models.Department{
		DepartmentID:       uuid.New(),
		CompanyID:          req.CompanyID,
		DepartmentName:     req.DepartmentName,
		SystemDepartmentID: &req.SystemDepartmentID,
		ParentDepartmentID: req.ParentDepartmentID,
		IsActive:           true,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	if err := s.companyRepo.CreateDepartment(ctx, dept); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, req.CompanyID, 1000)
	if err == nil && ownerRole != nil {
		_ = s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, dept.DepartmentID)
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, dept)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "create", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID.String(), "department_id": dept.DepartmentID.String(),
				"department_name": req.DepartmentName, "system_department": systemDept.Name,
				"ip_address": ip,
			})
	}
	return dept, nil
}

func (s *CompanyService) GetDepartment(ctx context.Context, departmentID uuid.UUID) (*models.Department, error) {
	dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return dept, nil
}

func (s *CompanyService) ListDepartments(ctx context.Context, companyID uuid.UUID, limit, offset int, includeEmployees bool) ([]*models.Department, int, error) {
	depts, total, err := s.companyRepo.GetDepartmentsByCompany(ctx, s.pgClient.Pool(), companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return depts, total, nil
}

func (s *CompanyService) GetDepartmentsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.Department, int, error) {
	return s.companyRepo.GetDepartmentsByCompany(ctx, s.pgClient.Pool(), companyID, limit, offset)
}

func (s *CompanyService) UpdateDepartment(ctx context.Context, departmentID uuid.UUID, name string, updatedBy uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	dept.DepartmentName = name
	dept.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateDepartment(ctx, dept); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "update", "admin",
			&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(), "new_name": name,
			})
	}
	return nil
}

func (s *CompanyService) RenameDepartment(ctx context.Context, companyID, departmentID uuid.UUID, newName string) error {
	return s.UpdateDepartment(ctx, departmentID, newName, uuid.Nil)
}

func (s *CompanyService) DeactivateDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if !dept.IsActive {
		return fmt.Errorf("%w: department already deactivated", appErrors.ErrInvalidState)
	}
	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, dept.CompanyID, 1000, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to get roles", appErrors.ErrInternal)
	}
	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, rd := range roleDepts {
			if rd.DepartmentID == departmentID {
				employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, s.pgClient.Pool(), role.RoleID, 1, 0)
				if err == nil && len(employees) > 0 {
					return fmt.Errorf("%w: department has active employees", appErrors.ErrConflict)
				}
				break
			}
		}
	}
	dept.IsActive = false
	dept.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateDepartment(ctx, dept); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "deactivate", "admin",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(),
			})
	}
	return nil
}

func (s *CompanyService) ActivateDepartment(ctx context.Context, companyID uuid.UUID, departmentID uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if dept.IsActive {
		return fmt.Errorf("%w: department already active", appErrors.ErrInvalidState)
	}
	dept.IsActive = true
	dept.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateDepartment(ctx, dept); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *CompanyService) DeleteDepartment(ctx context.Context, departmentID, adminID uuid.UUID) error {
	dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, dept.CompanyID, 1000, 0)
	if err != nil {
		return fmt.Errorf("%w: failed to get roles", appErrors.ErrInternal)
	}
	for _, role := range roles {
		roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if err != nil {
			continue
		}
		for _, rd := range roleDepts {
			if rd.DepartmentID == departmentID {
				employees, _, err := s.companyRepo.GetEmployeesByRole(ctx, s.pgClient.Pool(), role.RoleID, 1, 0)
				if err == nil && len(employees) > 0 {
					return fmt.Errorf("%w: department has employees", appErrors.ErrConflict)
				}
				break
			}
		}
	}
	_ = s.companyRepo.RemoveAllRoleDepartments(ctx, s.pgClient.Pool(), departmentID)
	if err := s.companyRepo.DeleteDepartment(ctx, s.pgClient.Pool(), departmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "delete", "admin",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{
				"department_id": departmentID.String(), "department_name": dept.DepartmentName,
			})
	}
	return nil
}

func (s *CompanyService) SoftDeleteDepartment(ctx context.Context, companyID uuid.UUID, departmentID uuid.UUID) error {
	return s.companyRepo.SoftDeleteDepartment(ctx, companyID, departmentID)
}

func (s *CompanyService) GetDepartmentHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentHierarchy(ctx, s.pgClient.Pool(), companyID)
}

type UpdateDepartmentParentRequest struct {
	DepartmentID       uuid.UUID  `json:"department_id" validate:"required"`
	ParentDepartmentID *uuid.UUID `json:"parent_department_id"`
}

func (s *CompanyService) UpdateDepartmentParent(ctx context.Context, req *UpdateDepartmentParentRequest, updatedBy uuid.UUID) error {
	_, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), req.DepartmentID)
	if err != nil {
		return fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if err := s.companyRepo.UpdateDepartmentParent(ctx, s.pgClient.Pool(), req.DepartmentID, req.ParentDepartmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *CompanyService) GetDepartmentChildren(ctx context.Context, departmentID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentChildren(ctx, s.pgClient.Pool(), departmentID)
}

func (s *CompanyService) GetDepartmentTree(ctx context.Context, departmentID uuid.UUID) ([]*models.DepartmentTree, error) {
	return s.companyRepo.GetDepartmentTree(ctx, s.pgClient.Pool(), departmentID)
}

func (s *CompanyService) GetDepartmentParents(ctx context.Context, departmentID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDepartmentParents(ctx, s.pgClient.Pool(), departmentID)
}

func (s *CompanyService) MoveDepartmentWithEmployees(ctx context.Context, departmentID uuid.UUID, newParentDepartmentID *uuid.UUID, movedBy uuid.UUID) error {
	if err := s.companyRepo.MoveDepartmentWithEmployees(ctx, departmentID, newParentDepartmentID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *CompanyService) GetRootDepartments(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRootDepartments(ctx, s.pgClient.Pool(), companyID)
}

func (s *CompanyService) ValidateDepartmentHierarchy(ctx context.Context, departmentID uuid.UUID, newParentDepartmentID *uuid.UUID) (bool, error) {
	if newParentDepartmentID == nil {
		return true, nil
	}
	parent, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), *newParentDepartmentID)
	if err != nil {
		return false, err
	}
	current, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), departmentID)
	if err != nil {
		return false, err
	}
	return parent.CompanyID == current.CompanyID, nil
}

func (s *CompanyService) GetActiveDepartmentCount(ctx context.Context, companyID uuid.UUID) (int, error) {
	return s.companyRepo.GetActiveDepartmentCount(ctx, s.pgClient.Pool(), companyID)
}

func (s *CompanyService) GetDeactivatedDepartments(ctx context.Context, companyID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetDeactivatedDepartments(ctx, s.pgClient.Pool(), companyID)
}

func (s *CompanyService) CreateSubDepartment(ctx context.Context, companyID uuid.UUID, parentDepartmentID uuid.UUID, departmentName string) (*models.Department, error) {
	parent, err := s.companyRepo.GetDepartmentByID(ctx, s.pgClient.Pool(), parentDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: parent not found", appErrors.ErrNotFound)
	}
	if parent.CompanyID != companyID {
		return nil, fmt.Errorf("%w: parent does not belong to company", appErrors.ErrInvalidInput)
	}
	if parent.SystemDepartmentID == nil {
		return nil, fmt.Errorf("%w: parent missing system mapping", appErrors.ErrInvalidState)
	}
	return s.companyRepo.CreateSubDepartment(ctx, companyID, parentDepartmentID, departmentName, *parent.SystemDepartmentID)
}

func (s *CompanyService) AdminAddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error) {
	return s.CreateDepartment(ctx, &CreateDepartmentRequest{
		CompanyID: companyID, DepartmentName: departmentName, SystemDepartmentID: systemDepartmentID,
	})
}

func (s *CompanyService) GetSystemDepartments(ctx context.Context) ([]*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartments(ctx, s.pgClient.Pool())
}

func (s *CompanyService) GetSystemDepartmentByModule(ctx context.Context, module string) (*models.SystemDepartment, error) {
	return s.companyRepo.GetSystemDepartmentByModule(ctx, s.pgClient.Pool(), module)
}

// ============================================================
// POSITIONS — NEW SCHEMA
//   • JobID (from job catalog) + LocationID + TitleOverride
//   • No more is_schedulable / attendance_required / overtime_allowed
//     (those live on jobs)
// ============================================================

type CreatePositionRequest struct {
	CompanyID      uuid.UUID  `json:"company_id" validate:"required"`
	DepartmentID   uuid.UUID  `json:"department_id" validate:"required"`
	JobID          uuid.UUID  `json:"job_id" validate:"required"` // 👈 NEW
	LocationID     *uuid.UUID `json:"location_id,omitempty"`      // 👈 NEW
	TitleOverride  *string    `json:"title_override,omitempty"`   // 👈 renamed from Title
	IsOpen         *bool      `json:"is_open,omitempty"`
	WorkCenterCode *string    `json:"work_center_code,omitempty" validate:"omitempty,max=100"`
}

func (s *CompanyService) CreatePosition(ctx context.Context, req *CreatePositionRequest, createdBy uuid.UUID) (*models.Position, error) {
	department, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), req.DepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: department not found", appErrors.ErrNotFound)
	}
	if department.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("%w: department does not belong to company", appErrors.ErrInvalidInput)
	}

	// Validate job
	job, err := s.companyRepo.GetJobByID(ctx, req.JobID)
	if err != nil {
		return nil, fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
	}
	if job.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("%w: job does not belong to company", appErrors.ErrInvalidInput)
	}
	if !job.IsActive {
		return nil, fmt.Errorf("%w: job is not active", appErrors.ErrInvalidState)
	}

	// Validate location if provided
	if req.LocationID != nil {
		loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), *req.LocationID)
		if err != nil {
			return nil, fmt.Errorf("%w: location not found", appErrors.ErrNotFound)
		}
		if loc.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: location does not belong to company", appErrors.ErrInvalidInput)
		}
	}

	// Validate work center if provided
	if req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
		exists, err := s.companyRepo.WorkCenterExists(ctx, s.pgClient.Pool(), req.CompanyID, *req.WorkCenterCode)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to validate work center", appErrors.ErrInternal)
		}
		if !exists {
			return nil, fmt.Errorf("%w: work center does not exist", appErrors.ErrNotFound)
		}
	}

	// Uniqueness check (company, department, title_override, location)
	exists, err := s.companyRepo.PositionExists(
		ctx, s.pgClient.Pool(), req.CompanyID, req.DepartmentID,
		req.TitleOverride, req.LocationID,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check uniqueness", appErrors.ErrInternal)
	}
	if exists {
		return nil, fmt.Errorf("%w: position with this title already exists at this location", appErrors.ErrDuplicate)
	}

	isOpen := true
	if req.IsOpen != nil {
		isOpen = *req.IsOpen
	}

	now := time.Now().UTC()
	position := &models.Position{
		PositionID:     uuid.New(),
		CompanyID:      req.CompanyID,
		DepartmentID:   req.DepartmentID,
		JobID:          req.JobID,
		LocationID:     req.LocationID,
		TitleOverride:  req.TitleOverride,
		IsOpen:         isOpen,
		WorkCenterCode: req.WorkCenterCode,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.companyRepo.CreatePosition(ctx, s.pgClient.Pool(), position); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "position", "create", "admin",
			&createdBy, "admin", &createdBy, nil, nil, map[string]interface{}{
				"company_id":    req.CompanyID.String(),
				"department_id": req.DepartmentID.String(),
				"job_id":        req.JobID.String(),
				"position_id":   position.PositionID.String(),
			})
	}
	return position, nil
}

type UpdatePositionRequest struct {
	PositionID     uuid.UUID  `json:"position_id" validate:"required"`
	DepartmentID   uuid.UUID  `json:"department_id" validate:"required"`
	JobID          uuid.UUID  `json:"job_id" validate:"required"` // 👈 NEW
	LocationID     *uuid.UUID `json:"location_id,omitempty"`      // 👈 NEW
	TitleOverride  *string    `json:"title_override,omitempty"`   // 👈 renamed
	IsOpen         bool       `json:"is_open"`
	WorkCenterCode *string    `json:"work_center_code,omitempty" validate:"omitempty,max=100"`
}

func (s *CompanyService) UpdatePosition(ctx context.Context, req *UpdatePositionRequest, updatedBy uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_position:%s", req.PositionID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// Fetch existing as a PositionView (joined data).
	existingView, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), req.PositionID)
	if err != nil {
		return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
	}

	// Validate department change
	if req.DepartmentID != existingView.DepartmentID {
		newDept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), req.DepartmentID)
		if err != nil {
			return fmt.Errorf("%w: new department not found", appErrors.ErrNotFound)
		}
		if newDept.CompanyID != existingView.CompanyID {
			return fmt.Errorf("%w: new department does not belong to same company", appErrors.ErrInvalidInput)
		}
	}

	// Validate job change
	if req.JobID != existingView.JobID {
		job, err := s.companyRepo.GetJobByID(ctx, req.JobID)
		if err != nil {
			return fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		if job.CompanyID != existingView.CompanyID {
			return fmt.Errorf("%w: job does not belong to company", appErrors.ErrInvalidInput)
		}
		if !job.IsActive {
			return fmt.Errorf("%w: job is not active", appErrors.ErrInvalidState)
		}
	}

	// Validate location change
	if req.LocationID != nil {
		loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), *req.LocationID)
		if err != nil {
			return fmt.Errorf("%w: location not found", appErrors.ErrNotFound)
		}
		if loc.CompanyID != existingView.CompanyID {
			return fmt.Errorf("%w: location does not belong to company", appErrors.ErrInvalidInput)
		}
	}

	// Validate work center
	if req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
		exists, err := s.companyRepo.WorkCenterExists(ctx, s.pgClient.Pool(), existingView.CompanyID, *req.WorkCenterCode)
		if err != nil {
			return fmt.Errorf("%w: failed to validate work center", appErrors.ErrInternal)
		}
		if !exists {
			return fmt.Errorf("%w: work center does not exist", appErrors.ErrNotFound)
		}
	}

	// Detect whether the work center actually changed. If it did, every
	// employee currently assigned to this seat needs their leave entitlements
	// recomputed — work_center_code is part of the (company, position,
	// work_center) resolution key.
	wcChanged := !strPtrEqual(existingView.WorkCenterCode, req.WorkCenterCode)

	// Build the new Position (full struct) for the repo Update.
	updated := &models.Position{
		PositionID:     existingView.PositionID,
		CompanyID:      existingView.CompanyID,
		DepartmentID:   req.DepartmentID,
		JobID:          req.JobID,
		LocationID:     req.LocationID,
		TitleOverride:  req.TitleOverride,
		IsOpen:         req.IsOpen,
		WorkCenterCode: req.WorkCenterCode,
		CreatedAt:      existingView.CreatedAt,
		UpdatedAt:      time.Now().UTC(),
	}
	if err := s.companyRepo.UpdatePosition(ctx, s.pgClient.Pool(), updated); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// Fan out: if the WC changed, enqueue a resolve_position job. The worker
	// lists every active employee on this seat and re-runs the resolver for
	// each. Failures here do NOT roll back the position update (it's already
	// committed by the repo call above); log-and-continue is the right
	// trade-off — a stale entitlement is recoverable via a manual Resolve,
	// a rolled-back position update is not.
	if wcChanged {
		if err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
			return s.resolverJobs.EnqueuePositionResolution(
				ctx, tx, existingView.CompanyID, req.PositionID, "work_center change",
			)
		}); err != nil {
			if s.auditService != nil {
				_ = s.auditService.LogAction(ctx, nil, nil, "position", "wc_fanout_enqueue_failed", "admin",
					&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
						"position_id": req.PositionID.String(),
						"company_id":  existingView.CompanyID.String(),
						"error":       err.Error(),
						"ip_address":  ip,
					})
			}
			// Do not return — position update already persisted.
		}
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "position", "update", "admin",
			&updatedBy, "admin", &updatedBy, nil, nil, map[string]interface{}{
				"position_id": req.PositionID.String(),
				"job_id":      req.JobID.String(),
				"wc_changed":  wcChanged,
				"ip_address":  ip,
			})
	}
	return nil
}

func (s *CompanyService) UpdatePositionStatus(ctx context.Context, positionID uuid.UUID, isOpen bool, updatedBy uuid.UUID) error {
	view, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), positionID)
	if err != nil {
		return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
	}
	updated := &models.Position{
		PositionID:     view.PositionID,
		CompanyID:      view.CompanyID,
		DepartmentID:   view.DepartmentID,
		JobID:          view.JobID,
		LocationID:     view.LocationID,
		TitleOverride:  view.TitleOverride,
		IsOpen:         isOpen,
		WorkCenterCode: view.WorkCenterCode,
		CreatedAt:      view.CreatedAt,
		UpdatedAt:      time.Now().UTC(),
	}
	if err := s.companyRepo.UpdatePosition(ctx, s.pgClient.Pool(), updated); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

// GetPosition returns the joined view (job title, location name, WC name).
func (s *CompanyService) GetPosition(ctx context.Context, positionID uuid.UUID) (*models.PositionView, error) {
	pos, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), positionID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return pos, nil
}

func (s *CompanyService) ListPositions(ctx context.Context, companyID uuid.UUID, departmentID *uuid.UUID, onlyOpen bool, limit, offset int) ([]*models.PositionView, int, error) {
	var positions []*models.PositionView
	var total int
	var err error
	if departmentID != nil {
		positions, total, err = s.companyRepo.GetPositionsByDepartment(ctx, s.pgClient.Pool(), *departmentID, limit, offset, onlyOpen)
	} else {
		positions, total, err = s.companyRepo.GetPositionsByCompany(ctx, s.pgClient.Pool(), companyID, limit, offset, onlyOpen)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return positions, total, nil
}

func (s *CompanyService) DeletePosition(ctx context.Context, positionID, deletedBy uuid.UUID) error {
	pos, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), positionID)
	if err != nil {
		return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
	}

	// Targeted check — sees every employee on the seat, not just the first page.
	hasAssigned, err := s.employeeRepo.PositionHasAssignedEmployees(
		ctx, pos.CompanyID, positionID,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if hasAssigned {
		return fmt.Errorf("%w: position has employees assigned", appErrors.ErrConflict)
	}

	if err := s.companyRepo.DeletePosition(ctx, s.pgClient.Pool(), positionID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "position", "delete", "admin",
			&deletedBy, "admin", &deletedBy, nil, nil, map[string]interface{}{
				"position_id": positionID.String(),
				"job_id":      pos.JobID.String(),
			})
	}
	return nil
}

func (s *CompanyService) GetOpenPositions(ctx context.Context, companyID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.PositionView, int, error) {
	return s.companyRepo.GetOpenPositions(ctx, s.pgClient.Pool(), companyID, isOpen, limit, offset)
}

func (s *CompanyService) GetPositionsByDepartment(ctx context.Context, companyID, departmentID uuid.UUID, isOpen *bool, limit, offset int) ([]*models.PositionView, int, error) {
	onlyOpen := false
	if isOpen != nil {
		onlyOpen = *isOpen
	}
	return s.companyRepo.GetPositionsByDepartment(ctx, s.pgClient.Pool(), departmentID, limit, offset, onlyOpen)
}

// ============================================================
// Permission checks / Company context (unchanged)
// ============================================================

type PermissionCheckRequest struct {
	CompanyID      uuid.UUID `json:"company_id" validate:"required"`
	UserID         uuid.UUID `json:"user_id" validate:"required"`
	PermissionName string    `json:"permission_name" validate:"required"`
	Module         string    `json:"module,omitempty"`
}

type PermissionCheckResult struct {
	HasPermission bool              `json:"has_permission"`
	IsOwner       bool              `json:"is_owner"`
	Checks        map[string]bool   `json:"checks"`
	Details       *PermissionDetail `json:"details,omitempty"`
	Message       string            `json:"message,omitempty"`
}

type PermissionDetail struct {
	CompanyID      string `json:"company_id"`
	UserID         string `json:"user_id"`
	RoleID         string `json:"role_id"`
	RoleName       string `json:"role_name"`
	DepartmentID   string `json:"department_id"`
	SystemModule   string `json:"system_module"`
	PermissionName string `json:"permission_name"`
	RequiredModule string `json:"required_module"`
}

func (s *CompanyService) CheckPermission(ctx context.Context, req *PermissionCheckRequest) (*PermissionCheckResult, error) {
	result := &PermissionCheckResult{HasPermission: false, Checks: make(map[string]bool)}

	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if company.OwnerUserID == req.UserID {
		result.HasPermission = true
		result.IsOwner = true
		result.Checks["is_owner"] = true
		result.Checks["has_employee_record"] = true
		result.Checks["role_has_permission"] = true
		result.Checks["role_belongs_to_department"] = true
		result.Checks["module_access"] = true
		return result, nil
	}

	employee, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), req.CompanyID, req.UserID)
	if err != nil {
		result.Checks["has_employee_record"] = false
		result.Message = "User is not an active employee"
		return result, nil
	}
	if !employee.IsActive {
		result.Checks["has_employee_record"] = false
		result.Message = "Employee record is not active"
		return result, nil
	}
	result.Checks["has_employee_record"] = true

	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
	}
	if len(roleDepartments) == 0 {
		result.Checks["has_department"] = false
		result.Message = "Role has no department"
		return result, nil
	}
	result.Checks["has_department"] = true

	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrInternal)
	}
	permission, err := s.companyRepo.GetPermissionByName(ctx, req.PermissionName)
	if err != nil {
		result.Checks["role_has_permission"] = false
		result.Message = "Permission not found"
		return result, nil
	}
	hasPerm, err := s.companyRepo.CheckRolePermission(ctx, employee.RoleID, permission.PermissionID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check permission", appErrors.ErrInternal)
	}
	result.Checks["role_has_permission"] = hasPerm
	if !hasPerm {
		result.Message = "Role does not have permission"
		return result, nil
	}
	moduleMatch := false
	var matchingDept *models.Department
	for _, dept := range roleDepartments {
		if dept.SystemDepartmentID == nil {
			continue
		}
		systemDept, err := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), *dept.SystemDepartmentID)
		if err != nil {
			continue
		}
		if permission.Module == systemDept.ModuleCode {
			moduleMatch = true
			matchingDept = dept
			break
		}
	}
	result.Checks["module_access"] = moduleMatch
	if !moduleMatch {
		result.Message = fmt.Sprintf("Permission module '%s' not in department modules", permission.Module)
		return result, nil
	}
	result.HasPermission = true
	result.Details = &PermissionDetail{
		CompanyID: req.CompanyID.String(), UserID: req.UserID.String(),
		RoleID: employee.RoleID.String(), RoleName: role.RoleName,
		DepartmentID: matchingDept.DepartmentID.String(), SystemModule: matchingDept.ModuleCode,
		PermissionName: req.PermissionName, RequiredModule: permission.Module,
	}
	return result, nil
}

func (s *CompanyService) CheckUserPermission(ctx context.Context, companyID, userID uuid.UUID, permissionName string) (bool, error) {
	req := &PermissionCheckRequest{CompanyID: companyID, UserID: userID, PermissionName: permissionName}
	result, err := s.CheckPermission(ctx, req)
	if err != nil {
		return false, err
	}
	return result.HasPermission, nil
}

func (s *CompanyService) BulkPermissionCheck(ctx context.Context, companyID, userID uuid.UUID, permissionNames []string) (map[string]bool, error) {
	results := make(map[string]bool)
	for _, name := range permissionNames {
		has, err := s.CheckUserPermission(ctx, companyID, userID, name)
		if err != nil {
			results[name] = false
			continue
		}
		results[name] = has
	}
	return results, nil
}

type CompanyContext struct {
	CompanyID        string   `json:"company_id"`
	EmployeeID       string   `json:"employee_id"`
	RoleID           string   `json:"role_id"`
	RoleLevel        int      `json:"role_level"`
	RoleName         string   `json:"role_name"`
	DepartmentID     string   `json:"department_id"`
	DepartmentName   string   `json:"department_name"`
	SystemModule     string   `json:"system_module"`
	Permissions      []string `json:"permissions"`
	SubscriptionTier string   `json:"subscription_tier"`
	IsOwner          bool     `json:"is_owner"`
	IsManager        bool     `json:"is_manager"`
}

func (s *CompanyService) GetCompanyContext(ctx context.Context, userID uuid.UUID) (*CompanyContext, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if len(employees) == 0 {
		return nil, fmt.Errorf("%w: user is not an employee", appErrors.ErrNotFound)
	}
	emp := employees[0]
	if !emp.IsActive {
		return nil, fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}
	company, err := s.companyRepo.GetCompany(ctx, emp.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	role, err := s.companyRepo.GetRole(ctx, emp.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
	if err != nil {
		roleDepts = []*models.Department{}
	}
	var deptID, deptName, sysModule string
	if len(roleDepts) > 0 {
		dept := roleDepts[0]
		deptID = dept.DepartmentID.String()
		deptName = dept.DepartmentName
		if dept.SystemDepartmentID != nil {
			sys, _ := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), *dept.SystemDepartmentID)
			if sys != nil {
				sysModule = sys.ModuleCode
			}
		}
	}
	perms, err := s.companyRepo.GetUserPermissions(ctx, emp.CompanyID, userID)
	if err != nil {
		perms = []*models.Permission{}
	}
	permStrs := make([]string, len(perms))
	for i, p := range perms {
		permStrs[i] = p.PermissionName
	}
	return &CompanyContext{
		CompanyID: company.CompanyID.String(), EmployeeID: emp.EmployeeID,
		RoleID: emp.RoleID.String(), RoleLevel: role.RoleLevel, RoleName: role.RoleName,
		DepartmentID: deptID, DepartmentName: deptName, SystemModule: sysModule,
		Permissions: permStrs, SubscriptionTier: company.SubscriptionTier,
		IsOwner: company.OwnerUserID == userID, IsManager: role.RoleLevel <= 200,
	}, nil
}

func (s *CompanyService) GetCompanyContextForCompany(ctx context.Context, userID, companyID uuid.UUID) (*CompanyContext, error) {
	employee, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	if !employee.IsActive {
		return nil, fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if company.SubscriptionEndDate != nil && company.SubscriptionEndDate.Before(time.Now()) {
		return nil, fmt.Errorf("%w: subscription expired", appErrors.ErrInvalidState)
	}
	if !company.IsActive {
		return nil, fmt.Errorf("%w: company not active", appErrors.ErrInvalidState)
	}
	role, err := s.companyRepo.GetRole(ctx, employee.RoleID)
	if err != nil {
		return nil, fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	roleDepts, err := s.companyRepo.GetRoleDepartments(ctx, employee.RoleID)
	if err != nil {
		roleDepts = []*models.Department{}
	}
	var deptID, deptName, sysModule string
	if len(roleDepts) > 0 {
		dept := roleDepts[0]
		deptID = dept.DepartmentID.String()
		deptName = dept.DepartmentName
		if dept.SystemDepartmentID != nil {
			sys, _ := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), *dept.SystemDepartmentID)
			if sys != nil {
				sysModule = sys.ModuleCode
			}
		}
	}
	perms, err := s.companyRepo.GetUserPermissions(ctx, companyID, userID)
	if err != nil {
		perms = []*models.Permission{}
	}
	permStrs := make([]string, len(perms))
	for i, p := range perms {
		permStrs[i] = p.PermissionName
	}
	return &CompanyContext{
		CompanyID: company.CompanyID.String(), EmployeeID: employee.EmployeeID,
		RoleID: employee.RoleID.String(), RoleLevel: role.RoleLevel, RoleName: role.RoleName,
		DepartmentID: deptID, DepartmentName: deptName, SystemModule: sysModule,
		Permissions: permStrs, SubscriptionTier: company.SubscriptionTier,
		IsOwner: company.OwnerUserID == userID, IsManager: role.RoleLevel <= 200,
	}, nil
}

func (s *CompanyService) AuthorizeUserLogin(ctx context.Context, phoneNumber string) (*models.User, error) {
	user, err := s.userService.GetUserByPhone(ctx, phoneNumber)
	if err != nil {
		return nil, fmt.Errorf("%w: user not found", appErrors.ErrNotFound)
	}
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get employees", appErrors.ErrInternal)
	}
	for _, emp := range employees {
		if emp.IsActive {
			return user, nil
		}
	}
	return nil, fmt.Errorf("%w: user is not an active employee", appErrors.ErrPermissionDenied)
}

type BulkAssignment struct {
	UserID    uuid.UUID `json:"user_id"`
	RoleID    uuid.UUID `json:"role_id"`
	ReportsTo uuid.UUID `json:"reports_to,omitempty"`
}

func (s *CompanyService) BulkAssignRoles(ctx context.Context, companyID uuid.UUID, assignments []BulkAssignment, assignedBy uuid.UUID) (map[uuid.UUID]string, error) {
	results := make(map[uuid.UUID]string)
	for _, assignment := range assignments {
		emp, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, assignment.UserID)
		if err != nil {
			results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
			continue
		}
		if assignment.ReportsTo != uuid.Nil {
			if err := s.validateReportsTo(ctx, companyID, &assignment.ReportsTo); err != nil {
				results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
				continue
			}
			emp.ReportsTo = &assignment.ReportsTo
		}
		emp.RoleID = assignment.RoleID
		emp.UpdatedAt = time.Now().UTC()
		if err := s.companyRepo.UpdateEmployee(ctx, emp); err != nil {
			results[assignment.UserID] = fmt.Sprintf("Error: %v", err)
			continue
		}
		results[assignment.UserID] = "Success"
	}
	return results, nil
}

func (s *CompanyService) AssignManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, assignedBy uuid.UUID) error {
	managerEmp, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, managerID)
	if err != nil {
		return fmt.Errorf("%w: manager not found", appErrors.ErrNotFound)
	}
	perms, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
	if err != nil {
		return fmt.Errorf("%w: failed to get permissions", appErrors.ErrInternal)
	}
	permIDs := make([]uuid.UUID, len(perms))
	for i, p := range perms {
		permIDs[i] = p.PermissionID
	}
	return s.companyRepo.GrantMultipleRolePermissions(ctx, managerEmp.RoleID, permIDs, assignedBy)
}

func (s *CompanyService) RevokeManagerPermissions(ctx context.Context, companyID, managerID uuid.UUID, permissionNames []string, revokedBy uuid.UUID) error {
	managerEmp, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, managerID)
	if err != nil {
		return fmt.Errorf("%w: manager not found", appErrors.ErrNotFound)
	}
	perms, err := s.companyRepo.GetPermissionsByNames(ctx, permissionNames)
	if err != nil {
		return fmt.Errorf("%w: failed to get permissions", appErrors.ErrInternal)
	}
	permIDs := make([]uuid.UUID, len(perms))
	for i, p := range perms {
		permIDs[i] = p.PermissionID
	}
	return s.companyRepo.RevokeMultipleRolePermissions(ctx, managerEmp.RoleID, permIDs)
}

func (s *CompanyService) GetManagerPermissions(ctx context.Context, managerID uuid.UUID) ([]string, error) {
	return s.companyRepo.GetUserPermissionNames(ctx, managerID)
}

func (s *CompanyService) ValidatePermissionSubset(ctx context.Context, managerPermissions, requestedPermissions []string) bool {
	managerSet := make(map[string]bool)
	for _, p := range managerPermissions {
		managerSet[p] = true
	}
	for _, p := range requestedPermissions {
		if !managerSet[p] {
			return false
		}
	}
	return true
}

func (s *CompanyService) ValidatePermissionDepartmentCompatibility(ctx context.Context, departmentIDs []uuid.UUID, permissionIDs []uuid.UUID) (bool, string, error) {
	if len(departmentIDs) == 0 || len(permissionIDs) == 0 {
		return true, "", nil
	}
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[uuid.UUID]*models.Permission)
	for _, p := range allPerms {
		permMap[p.PermissionID] = p
	}
	departmentModules := make(map[string]bool)
	for _, deptID := range departmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), deptID)
		if err != nil {
			return false, "", fmt.Errorf("%w: department not found: %s", appErrors.ErrNotFound, deptID)
		}
		if dept.SystemDepartmentID != nil {
			sys, err := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), *dept.SystemDepartmentID)
			if err == nil {
				departmentModules[sys.ModuleCode] = true
			}
		}
	}
	for _, permID := range permissionIDs {
		perm, exists := permMap[permID]
		if !exists {
			return false, "", fmt.Errorf("%w: permission not found: %s", appErrors.ErrNotFound, permID)
		}
		if !departmentModules[perm.Module] {
			return false, fmt.Sprintf("Permission '%s' module '%s' not compatible with departments", perm.PermissionName, perm.Module), nil
		}
	}
	return true, "", nil
}

func (s *CompanyService) validatePermissionDepartmentCompatibilityForUpdate(ctx context.Context, departmentIDs []uuid.UUID, req UpdateRoleRequest) error {
	allPerms, err := s.companyRepo.GetAllPermissions(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	permMap := make(map[string]uuid.UUID)
	for _, p := range allPerms {
		permMap[p.PermissionName] = p.PermissionID
	}
	var permIDs []uuid.UUID
	for _, name := range req.AddPermissions {
		if id, exists := permMap[name]; exists {
			permIDs = append(permIDs, id)
		}
	}
	if len(req.ReplacePermissions) > 0 {
		permIDs = nil
		for _, name := range req.ReplacePermissions {
			if id, exists := permMap[name]; exists {
				permIDs = append(permIDs, id)
			}
		}
	}
	if len(departmentIDs) > 0 && len(permIDs) > 0 {
		compatible, errMsg, err := s.ValidatePermissionDepartmentCompatibility(ctx, departmentIDs, permIDs)
		if err != nil {
			return err
		}
		if !compatible {
			return fmt.Errorf("%w: %s", appErrors.ErrInvalidInput, errMsg)
		}
	}
	return nil
}

func (s *CompanyService) GetPermissionsByDepartmentModules(ctx context.Context, departmentIDs []uuid.UUID) ([]*models.Permission, error) {
	if len(departmentIDs) == 0 {
		return []*models.Permission{}, nil
	}
	var sysDeptIDs []uuid.UUID
	for _, deptID := range departmentIDs {
		dept, err := s.companyRepo.GetDepartment(ctx, s.pgClient.Pool(), deptID)
		if err != nil {
			continue
		}
		if dept.SystemDepartmentID != nil {
			sysDeptIDs = append(sysDeptIDs, *dept.SystemDepartmentID)
		}
	}
	if len(sysDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}
	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, sysDeptIDs, "", "", "")
}

func (s *CompanyService) GetPermissionsByCompanyDepartments(ctx context.Context, companyID uuid.UUID, module, category, tier string) ([]*models.Permission, error) {
	depts, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, s.pgClient.Pool(), companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var sysDeptIDs []uuid.UUID
	for _, d := range depts {
		if d.SystemDepartmentID != nil {
			sysDeptIDs = append(sysDeptIDs, *d.SystemDepartmentID)
		}
	}
	adminSys, err := s.companyRepo.GetSystemDepartmentByModule(ctx, s.pgClient.Pool(), "administration")
	if err == nil {
		sysDeptIDs = append(sysDeptIDs, adminSys.SystemDepartmentID)
	}
	if len(sysDeptIDs) == 0 {
		return []*models.Permission{}, nil
	}
	return s.companyRepo.GetPermissionsBySystemDepartments(ctx, sysDeptIDs, module, category, tier)
}

func (s *CompanyService) validateReportsTo(ctx context.Context, companyID uuid.UUID, userID *uuid.UUID) error {
	if userID == nil {
		return nil
	}
	_, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, *userID)
	if err != nil {
		return fmt.Errorf("%w: reports_to user not employee", appErrors.ErrInvalidInput)
	}
	return nil
}

func (s *CompanyService) GetCompanyStats(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error) {
	return s.companyRepo.GetCompanyStats(ctx, companyID)
}

func (s *CompanyService) HealthCheck(ctx context.Context) error {
	return s.companyRepo.HealthCheck(ctx)
}

// ============================================================
// Search (unchanged)
// ============================================================

type SearchCompaniesRequest = models.CompanySearchRequest
type SearchCompaniesResponse = models.CompanySearchResponse
type CompanySearchResult = models.CompanySearchResult

func (s *CompanyService) SearchCompanies(ctx context.Context, req *models.CompanySearchRequest) (*models.CompanySearchResponse, error) {
	searchType := req.SearchType
	if searchType == "all" {
		if len(req.Query) < 3 {
			searchType = "autocomplete"
		} else {
			searchType = "fulltext"
		}
	}
	companies, total, err := s.companyRepo.SearchCompaniesByName(ctx, req.Query, searchType, req.Filters, req.Limit, req.Offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	results := make([]*models.CompanySearchResult, len(companies))
	for i, c := range companies {
		results[i] = &models.CompanySearchResult{
			CompanyID: c.CompanyID, CompanyName: c.CompanyName, OwnerUserID: c.OwnerUserID,
			SubscriptionTier: c.SubscriptionTier, SubscriptionStatus: c.SubscriptionStatus,
			MaxEmployees: c.MaxEmployees, IsActive: c.IsActive, DataRegion: c.DataRegion,
			CreatedAt: c.CreatedAt, RelevanceScore: 1.0 - float64(i)*0.01, MatchType: searchType,
		}
	}
	page := (req.Offset / req.Limit) + 1
	hasMore := req.Offset+req.Limit < total
	return &models.CompanySearchResponse{Companies: results, Total: total, Page: page, PageSize: req.Limit, HasMore: hasMore}, nil
}

func (s *CompanyService) SearchCompaniesByOwner(ctx context.Context, ownerID uuid.UUID, query string, isActive *bool, limit int, offset int) (*models.CompanySearchResponse, error) {
	companies, total, err := s.companyRepo.SearchCompaniesByOwnerAndName(ctx, ownerID, query, isActive, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	results := make([]*models.CompanySearchResult, len(companies))
	for i, c := range companies {
		matchType := "owner_search"
		if query != "" {
			if len(query) < 3 {
				matchType = "autocomplete"
			} else {
				matchType = "fulltext"
			}
		}
		results[i] = &models.CompanySearchResult{
			CompanyID: c.CompanyID, CompanyName: c.CompanyName, OwnerUserID: c.OwnerUserID,
			SubscriptionTier: c.SubscriptionTier, SubscriptionStatus: c.SubscriptionStatus,
			MaxEmployees: c.MaxEmployees, IsActive: c.IsActive, DataRegion: c.DataRegion,
			CreatedAt: c.CreatedAt, RelevanceScore: 1.0 - float64(i)*0.01, MatchType: matchType,
		}
	}
	page := (offset / limit) + 1
	hasMore := offset+limit < total
	return &models.CompanySearchResponse{Companies: results, Total: total, Page: page, PageSize: limit, HasMore: hasMore}, nil
}

func (s *CompanyService) GetCompanySuggestions(ctx context.Context, prefix string, limit int) ([]string, error) {
	if len(prefix) < 2 {
		return []string{}, nil
	}
	return s.companyRepo.GetCompanySuggestions(ctx, prefix, limit)
}

func (s *CompanyService) GetCompanySearchAnalytics(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.companyRepo.GetCompanySearchStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	companyMetrics, err := s.companyRepo.GetCompanyStats(ctx, uuid.Nil)
	if err == nil {
		stats["company_metrics"] = companyMetrics
	}
	return stats, nil
}

func (s *CompanyService) BenchmarkCompanySearch(ctx context.Context, testQueries []string, iterations int) (map[string]interface{}, error) {
	if iterations <= 0 || iterations > 100 {
		iterations = 10
	}
	results := make(map[string]interface{})
	queryTimes := map[string][]time.Duration{}
	for _, q := range testQueries {
		for i := 0; i < iterations; i++ {
			start := time.Now()
			_, _, err := s.companyRepo.SearchCompaniesByName(ctx, q, "fulltext", nil, 10, 0)
			if err == nil {
				queryTimes[q] = append(queryTimes[q], time.Since(start))
			}
		}
	}
	stats := map[string]map[string]interface{}{}
	for q, durations := range queryTimes {
		if len(durations) == 0 {
			continue
		}
		var total time.Duration
		min, max := durations[0], durations[0]
		for _, d := range durations {
			total += d
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}
		avg := total / time.Duration(len(durations))
		stats[q] = map[string]interface{}{
			"iterations": len(durations), "avg_ms": avg.Milliseconds(),
			"min_ms": min.Milliseconds(), "max_ms": max.Milliseconds(), "total_ms": total.Milliseconds(),
		}
	}
	results["benchmark_results"] = stats
	results["test_queries"] = testQueries
	results["iterations"] = iterations
	results["timestamp"] = time.Now().UTC()
	return results, nil
}

type SearchDepartmentsRequest struct {
	Query           string `json:"q"`
	Limit           int    `json:"limit,omitempty"`
	Offset          int    `json:"offset,omitempty"`
	IncludeInactive bool   `json:"include_inactive,omitempty"`
}

type DepartmentSearchResponse struct {
	Departments []*models.DepartmentSearchResult `json:"departments"`
	Total       int                              `json:"total"`
	Page        int                              `json:"page"`
	Limit       int                              `json:"limit"`
	HasMore     bool                             `json:"has_more"`
}

func (s *CompanyService) SearchDepartments(ctx context.Context, companyID uuid.UUID, req *SearchDepartmentsRequest) (*DepartmentSearchResponse, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 20
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	depts, total, err := s.companyRepo.SearchDepartments(ctx, s.pgClient.Pool(), companyID, req.Query, req.Limit, req.Offset, req.IncludeInactive)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	page := 1
	if req.Limit > 0 {
		page = (req.Offset / req.Limit) + 1
	}
	hasMore := (req.Offset + len(depts)) < total
	return &DepartmentSearchResponse{Departments: depts, Total: total, Page: page, Limit: req.Limit, HasMore: hasMore}, nil
}

func (s *CompanyService) GetDepartmentSuggestions(ctx context.Context, companyID uuid.UUID, prefix string, limit int) ([]*models.Department, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	return s.companyRepo.GetDepartmentSuggestions(ctx, s.pgClient.Pool(), companyID, prefix, limit)
}

func (s *CompanyService) GetUserHierarchy(ctx context.Context, userID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	employees, err := s.companyRepo.GetEmployeesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var hierarchy []*models.EmployeeHierarchy
	for _, emp := range employees {
		if emp.IsActive {
			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
			roleDepts, _ := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
			var deptName string
			var deptID *uuid.UUID
			if len(roleDepts) > 0 {
				deptName = roleDepts[0].DepartmentName
				deptID = &roleDepts[0].DepartmentID
			}
			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
				CompanyID: emp.CompanyID, UserID: emp.UserID, EmployeeID: emp.EmployeeID,
				RoleName: role.RoleName, RoleLevel: role.RoleLevel,
				DepartmentID: deptID, Department: deptName,
				ReportsTo: emp.ReportsTo, IsActive: emp.IsActive,
			})
		}
	}
	return hierarchy, nil
}

func (s *CompanyService) GetEmployeeHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	employees, _, err := s.companyRepo.GetEmployeesByCompany(ctx, s.pgClient.Pool(), companyID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	var hierarchy []*models.EmployeeHierarchy
	for _, emp := range employees {
		if emp.IsActive {
			role, _ := s.companyRepo.GetRole(ctx, emp.RoleID)
			roleDepts, _ := s.companyRepo.GetRoleDepartments(ctx, emp.RoleID)
			var deptName string
			var deptID *uuid.UUID
			if len(roleDepts) > 0 {
				deptName = roleDepts[0].DepartmentName
				deptID = &roleDepts[0].DepartmentID
			}
			hierarchy = append(hierarchy, &models.EmployeeHierarchy{
				CompanyID: emp.CompanyID, UserID: emp.UserID, EmployeeID: emp.EmployeeID,
				RoleName: role.RoleName, RoleLevel: role.RoleLevel,
				DepartmentID: deptID, Department: deptName,
				ReportsTo: emp.ReportsTo, IsActive: emp.IsActive,
			})
		}
	}
	return hierarchy, nil
}

func (s *CompanyService) GetCompanyHierarchy(ctx context.Context, companyID uuid.UUID) ([]*models.EmployeeHierarchy, error) {
	return s.companyRepo.GetEmployeeHierarchy(ctx, companyID)
}

func (s *CompanyService) GetUsersWithPermission(ctx context.Context, companyID uuid.UUID, permissionName string, limit int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersWithPermission(ctx, s.pgClient.Pool(), companyID, permissionName, limit)
}

func (s *CompanyService) GetUsersByRoleLevel(ctx context.Context, companyID uuid.UUID, minLevel, maxLevel int) ([]*models.CompanyEmployee, error) {
	return s.companyRepo.GetUsersByRoleLevel(ctx, s.pgClient.Pool(), companyID, minLevel, maxLevel)
}

func (s *CompanyService) ListPermissionsByModule(ctx context.Context, module string) ([]*models.Permission, error) {
	return s.companyRepo.GetPermissionsByModule(ctx, module)
}

func (s *CompanyService) GetDepartmentLoad(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetDepartmentLoad(ctx, companyID)
}

func (s *CompanyService) GetRoleDistribution(ctx context.Context, companyID uuid.UUID) (map[string]int, error) {
	return s.companyRepo.GetRoleDistribution(ctx, companyID)
}

func (s *CompanyService) AddDepartment(ctx context.Context, companyID uuid.UUID, departmentName string, systemDepartmentID uuid.UUID) (*models.Department, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_dept:%s:%s", companyID.String(), departmentName)
	}
	ip, _ := ctx.Value("ip_address").(string)
	var cachedDept models.Department
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedDept); err == nil {
		return &cachedDept, nil
	}
	systemDept, err := s.companyRepo.GetSystemDepartment(ctx, s.pgClient.Pool(), systemDepartmentID)
	if err != nil {
		return nil, fmt.Errorf("%w: system department not found", appErrors.ErrNotFound)
	}
	existing, _, err := s.companyRepo.GetDepartmentsByCompany(ctx, s.pgClient.Pool(), companyID, 1, 0)
	if err == nil {
		for _, d := range existing {
			if strings.EqualFold(d.DepartmentName, departmentName) {
				return nil, fmt.Errorf("%w: department name already exists", appErrors.ErrDuplicate)
			}
		}
	}
	department := &models.Department{
		DepartmentID: uuid.New(), CompanyID: companyID, DepartmentName: departmentName,
		SystemDepartmentID: &systemDepartmentID, IsActive: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.companyRepo.CreateDepartment(ctx, department); err != nil {
		return nil, fmt.Errorf("%w: failed to create department", appErrors.ErrInternal)
	}
	ownerRole, err := s.companyRepo.GetSystemRoleByLevel(ctx, companyID, 1000)
	if err == nil {
		_ = s.companyRepo.CreateRoleDepartment(ctx, ownerRole.RoleID, department.DepartmentID)
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, department)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "department", "add_department", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id": companyID.String(), "department_id": department.DepartmentID.String(),
				"department_name": departmentName, "system_department": systemDept.Name, "ip_address": ip,
			})
	}
	return department, nil
}

func (s *CompanyService) GetRoleDepartmentsForPermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Department, error) {
	return s.companyRepo.GetRoleDepartmentsForPermission(ctx, s.pgClient.Pool(), roleID)
}

type UpdateCompanyRequest struct {
	CompanyName             *string `json:"company_name,omitempty"`
	DataRegion              *string `json:"data_region,omitempty"`
	DefaultTimezone         *string `json:"default_timezone,omitempty"` // ← NEW
	FinancialYearStartMonth *int    `json:"financial_year_start_month,omitempty"`
	MaxEmployees            *int    `json:"max_employees,omitempty"`
	MaxLocations            *int    `json:"max_locations,omitempty"`
	IsActive                *bool   `json:"is_active,omitempty"`
	SubscriptionPlanCode    *string `json:"subscription_plan_code,omitempty"`
	SubscriptionStatus      *string `json:"subscription_status,omitempty"`
	GracePeriodDays         *int    `json:"grace_period_days,omitempty"`
	ExtendByMonths          *int    `json:"extend_by_months,omitempty"`
	ExtendByDays            *int    `json:"extend_by_days,omitempty"`
	SubscriptionStartDate   *string `json:"subscription_start_date,omitempty"`
	SubscriptionEndDate     *string `json:"subscription_end_date,omitempty"`
	TrialStartDate          *string `json:"trial_start_date,omitempty"`
	TrialEndDate            *string `json:"trial_end_date,omitempty"`
}

func (s *CompanyService) UpdateCompanyWithOptions(ctx context.Context, companyID uuid.UUID, req *UpdateCompanyRequest, updatedBy uuid.UUID) error {
	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return err
	}
	before := &models.Company{}
	*before = *company

	if req.CompanyName != nil {
		company.CompanyName = *req.CompanyName
	}
	if req.DataRegion != nil {
		company.DataRegion = *req.DataRegion
	}

	// ── NEW: DefaultTimezone update.
	// Rejecting empty string forces the caller to either omit the field
	// or supply a real IANA name. Never let the tz go blank.
	if req.DefaultTimezone != nil {
		if *req.DefaultTimezone == "" {
			return fmt.Errorf("%w: default_timezone cannot be empty", appErrors.ErrInvalidInput)
		}
		if err := util.ValidateTimezone(*req.DefaultTimezone); err != nil {
			return fmt.Errorf("%w: default_timezone: %v", appErrors.ErrInvalidInput, err)
		}
		company.DefaultTimezone = *req.DefaultTimezone
	}

	if req.FinancialYearStartMonth != nil {
		if *req.FinancialYearStartMonth < 1 || *req.FinancialYearStartMonth > 12 {
			return fmt.Errorf("%w: financial_year_start_month must be between 1 and 12", appErrors.ErrInvalidInput)
		}
		company.FinancialYearStartMonth = *req.FinancialYearStartMonth
	}
	if req.MaxEmployees != nil {
		if *req.MaxEmployees < 1 {
			return fmt.Errorf("%w: max_employees must be at least 1", appErrors.ErrInvalidInput)
		}
		company.MaxEmployees = *req.MaxEmployees
	}
	if req.MaxLocations != nil {
		if *req.MaxLocations < 1 || *req.MaxLocations > 500 {
			return fmt.Errorf("%w: max_locations must be between 1 and 500", appErrors.ErrInvalidInput)
		}
		company.MaxLocations = *req.MaxLocations
	}
	if req.IsActive != nil {
		company.IsActive = *req.IsActive
	}
	if req.SubscriptionPlanCode != nil && *req.SubscriptionPlanCode != "" {
		plan, err := s.planService.GetPlanByCode(ctx, *req.SubscriptionPlanCode)
		if err != nil {
			return fmt.Errorf("%w: plan with code '%s' not found", appErrors.ErrNotFound, *req.SubscriptionPlanCode)
		}
		company.SubscriptionPlanID = &plan.PlanID
		company.SubscriptionAmount = plan.Price
	}
	if req.SubscriptionStatus != nil {
		validStatuses := map[string]bool{
			models.SubscriptionStatusPending: true, models.SubscriptionStatusTrial: true,
			models.SubscriptionStatusActive: true, models.SubscriptionStatusPastDue: true,
			models.SubscriptionStatusExpired: true, models.SubscriptionStatusCancelled: true,
		}
		if !validStatuses[*req.SubscriptionStatus] {
			return fmt.Errorf("%w: invalid subscription status '%s'", appErrors.ErrInvalidInput, *req.SubscriptionStatus)
		}
		company.SubscriptionStatus = *req.SubscriptionStatus
	}
	if req.GracePeriodDays != nil {
		if *req.GracePeriodDays < 0 {
			return fmt.Errorf("%w: grace_period_days cannot be negative", appErrors.ErrInvalidInput)
		}
		company.GracePeriodDays = *req.GracePeriodDays
	}
	if req.ExtendByMonths != nil || req.ExtendByDays != nil {
		months := 0
		days := 0
		if req.ExtendByMonths != nil {
			months = *req.ExtendByMonths
		}
		if req.ExtendByDays != nil {
			days = *req.ExtendByDays
		}
		if company.SubscriptionEndDate == nil {
			now := time.Now().UTC()
			company.SubscriptionEndDate = &now
		}
		newEnd := company.SubscriptionEndDate.AddDate(0, months, days)
		company.SubscriptionEndDate = &newEnd
	}
	if req.SubscriptionStartDate != nil {
		t, err := time.Parse(time.RFC3339, *req.SubscriptionStartDate)
		if err != nil {
			return fmt.Errorf("%w: invalid subscription_start_date format, use RFC3339", appErrors.ErrInvalidInput)
		}
		company.SubscriptionStartDate = &t
	}
	if req.SubscriptionEndDate != nil {
		t, err := time.Parse(time.RFC3339, *req.SubscriptionEndDate)
		if err != nil {
			return fmt.Errorf("%w: invalid subscription_end_date format, use RFC3339", appErrors.ErrInvalidInput)
		}
		company.SubscriptionEndDate = &t
	}
	if req.TrialStartDate != nil {
		t, err := time.Parse(time.RFC3339, *req.TrialStartDate)
		if err != nil {
			return fmt.Errorf("%w: invalid trial_start_date format, use RFC3339", appErrors.ErrInvalidInput)
		}
		company.TrialStartDate = &t
	}
	if req.TrialEndDate != nil {
		t, err := time.Parse(time.RFC3339, *req.TrialEndDate)
		if err != nil {
			return fmt.Errorf("%w: invalid trial_end_date format, use RFC3339", appErrors.ErrInvalidInput)
		}
		company.TrialEndDate = &t
	}

	company.UpdatedAt = time.Now().UTC()
	if err := s.companyRepo.UpdateCompany(ctx, company); err != nil {
		return fmt.Errorf("%w: failed to update company", appErrors.ErrInternal)
	}
	s.InvalidateCompanyStatusCache(ctx, companyID)

	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		beforeJSON, _ := json.Marshal(before)
		afterJSON, _ := json.Marshal(company)
		_ = s.auditService.LogAction(ctx, nil, nil, "company", "update_details", "company",
			&companyID, "admin", &updatedBy, beforeJSON, afterJSON,
			map[string]interface{}{
				"updated_by":       updatedBy.String(),
				"ip_address":       ip,
				"timezone_changed": req.DefaultTimezone != nil && *req.DefaultTimezone != before.DefaultTimezone, // ← NEW
			})
	}
	return nil
}
func pointerTime(t time.Time) *time.Time { return &t }

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

// ============================================================
// AddMember — unified member creation.
//
// Accepts either:
//   • PositionID → link to an existing position, OR
//   • JobID + (LocationID, WorkCenterCode, DepartmentID) → auto-create
//     a position on the fly inside the transaction.
//
// All writes happen in ONE transaction:
//   users, company_employees, employee_profiles,
//   employee_location_access, employee_location_history,
//   [optional] positions, leave.resolver_job
// ============================================================

type AddMemberRequest struct {
	CompanyID   uuid.UUID  `json:"-"`
	MemberType  string     `json:"member_type,omitempty" validate:"omitempty,oneof=employee manager"`
	PhoneNumber string     `json:"phone" validate:"required"`
	Username    string     `json:"username" validate:"required,min=3,max=100,alphanum"`
	FullName    string     `json:"full_name" validate:"required,max=255"`
	EmployeeID  string     `json:"employee_id,omitempty"`
	RoleID      uuid.UUID  `json:"role_id" validate:"required"`
	ReportsTo   *uuid.UUID `json:"reports_to,omitempty"`

	// --- Position assignment (choose ONE of PositionID or JobID) ---
	PositionID *uuid.UUID `json:"position_id,omitempty"` // existing seat
	JobID      *uuid.UUID `json:"job_id,omitempty"`      // 👈 NEW — job catalog
	// Optional when JobID is used to auto-create the position:
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`    // 👈 NEW
	LocationID     *uuid.UUID `json:"location_id,omitempty"`      // 👈 NEW
	WorkCenterCode *string    `json:"work_center_code,omitempty"` // 👈 NEW
	TitleOverride  *string    `json:"title_override,omitempty"`   // 👈 NEW

	// --- Location access ---
	PrimaryLocationID   *uuid.UUID                            `json:"primary_location_id,omitempty"`
	LocationAccessScope string                                `json:"location_access_scope,omitempty" validate:"omitempty,oneof=PRIMARY SELECTED ALL"`
	SelectedLocations   []models.EmployeeLocationGrantRequest `json:"selected_locations,omitempty"`
	SelectedLocationIDs []uuid.UUID                           `json:"selected_location_ids,omitempty"`

	// --- HR profile ---
	DateOfBirth      *time.Time `json:"date_of_birth,omitempty"`
	Gender           *string    `json:"gender,omitempty"`
	MaritalStatus    *string    `json:"marital_status,omitempty"`
	Nationality      *string    `json:"nationality,omitempty"`
	EmploymentType   *string    `json:"employment_type,omitempty"`
	EmploymentStatus *string    `json:"employment_status,omitempty"`
	ProbationEndDate *time.Time `json:"probation_end_date,omitempty"`
	ConfirmationDate *time.Time `json:"confirmation_date,omitempty"`
	Grade            *string    `json:"grade,omitempty"`
	CostCenterID     *uuid.UUID `json:"cost_center_id,omitempty"`
	CostCenter       *string    `json:"cost_center,omitempty"`
	TaxID            *string    `json:"tax_id,omitempty"`
	SocialSecurityID *string    `json:"social_security_id,omitempty"`
	Email            *string    `json:"email,omitempty"`
}

func (s *CompanyService) AddMember(ctx context.Context, req *AddMemberRequest) error {
	if req.MemberType == "" {
		req.MemberType = "employee"
	}
	if req.MemberType != "employee" && req.MemberType != "manager" {
		return fmt.Errorf("%w: invalid member_type '%s'", appErrors.ErrInvalidInput, req.MemberType)
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("add_member:%s:%s:%s", req.CompanyID.String(), req.MemberType, req.PhoneNumber)
	}
	ip, _ := ctx.Value("ip_address").(string)

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	company, err := s.companyRepo.GetCompany(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}

	activeCount, err := s.companyRepo.GetActiveEmployeeCount(ctx, req.CompanyID)
	if err != nil {
		return fmt.Errorf("%w: failed to get active employee count", appErrors.ErrInternal)
	}
	if activeCount >= company.MaxEmployees {
		return fmt.Errorf("%w: max employee limit reached (%d/%d)", appErrors.ErrConflict, activeCount, company.MaxEmployees)
	}

	role, err := s.companyRepo.GetRole(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
	}
	if role.CompanyID != req.CompanyID {
		return fmt.Errorf("%w: role does not belong to company", appErrors.ErrInvalidInput)
	}
	if req.MemberType == "manager" && role.RoleLevel < 500 {
		return fmt.Errorf("%w: role level must be 500 or higher for managers", appErrors.ErrInvalidInput)
	}

	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, req.RoleID)
	if err != nil {
		return fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
	}
	if len(roleDepartments) == 0 {
		return fmt.Errorf("%w: role is not assigned to any department", appErrors.ErrInvalidState)
	}

	// ------------------------------------------------------------
	// Resolve the effective position: existing PositionID, OR
	// auto-create from JobID + optional LocationID + WorkCenterCode.
	// ------------------------------------------------------------
	var (
		effectivePositionID *uuid.UUID = req.PositionID
		newPositionID       *uuid.UUID
		resolvedWCLoc       *uuid.UUID
	)

	if effectivePositionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), *effectivePositionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open", appErrors.ErrInvalidState)
		}
		found := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to role", appErrors.ErrInvalidInput)
		}

		if position.WorkCenterCode != nil && *position.WorkCenterCode != "" {
			wc, werr := s.workCenterRepo.GetByCode(ctx, req.CompanyID, *position.WorkCenterCode)
			if werr != nil {
				return fmt.Errorf("%w: failed to load work center: %v", appErrors.ErrInternal, werr)
			}
			if wc != nil && wc.LocationID != nil {
				resolvedWCLoc = wc.LocationID
			}
		}
	} else if req.JobID != nil {
		job, err := s.companyRepo.GetJobByID(ctx, *req.JobID)
		if err != nil {
			return fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		if job.CompanyID != req.CompanyID {
			return fmt.Errorf("%w: job does not belong to company", appErrors.ErrInvalidInput)
		}
		if !job.IsActive {
			return fmt.Errorf("%w: job is not active", appErrors.ErrInvalidState)
		}

		deptID := roleDepartments[0].DepartmentID
		if req.DepartmentID != nil {
			match := false
			for _, rd := range roleDepartments {
				if rd.DepartmentID == *req.DepartmentID {
					match = true
					deptID = *req.DepartmentID
					break
				}
			}
			if !match {
				return fmt.Errorf("%w: department is not assigned to the role", appErrors.ErrInvalidInput)
			}
		}
		_ = deptID

		if req.LocationID != nil {
			loc, err := s.locationRepo.GetLocation(ctx, s.pgClient.Pool(), *req.LocationID)
			if err != nil {
				return fmt.Errorf("%w: location not found", appErrors.ErrNotFound)
			}
			if loc.CompanyID != req.CompanyID {
				return fmt.Errorf("%w: location does not belong to company", appErrors.ErrInvalidInput)
			}
			if !loc.IsActive {
				return fmt.Errorf("%w: location is not active", appErrors.ErrInvalidState)
			}
		}

		if req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
			wc, err := s.workCenterRepo.GetByCode(ctx, req.CompanyID, *req.WorkCenterCode)
			if err != nil {
				return fmt.Errorf("%w: failed to load work center: %v", appErrors.ErrInternal, err)
			}
			if wc == nil {
				return fmt.Errorf("%w: work center not found", appErrors.ErrNotFound)
			}
			if !wc.IsActive {
				return fmt.Errorf("%w: work center is not active", appErrors.ErrInvalidState)
			}
			if wc.LocationID == nil {
				return fmt.Errorf("%w: work center has no location assigned", appErrors.ErrInvalidState)
			}
			resolvedWCLoc = wc.LocationID

			if req.LocationID != nil && *req.LocationID != *resolvedWCLoc {
				return fmt.Errorf(
					"%w: position location does not match work center location",
					appErrors.ErrInvalidInput,
				)
			}
		}

		pid := uuid.New()
		newPositionID = &pid
	} else {
		return fmt.Errorf("%w: either position_id or job_id is required", appErrors.ErrInvalidInput)
	}

	primaryLoc, effectiveScope, err := s.locationService.ValidateProspectiveLocationAccess(
		ctx, req.CompanyID, req, resolvedWCLoc,
	)
	if err != nil {
		return err
	}
	req.PrimaryLocationID = primaryLoc
	req.LocationAccessScope = effectiveScope
	if resolvedWCLoc != nil {
		req.LocationID = resolvedWCLoc
	}

	if err := s.validateReportsTo(ctx, req.CompanyID, req.ReportsTo); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
	}

	employeeID := req.EmployeeID
	if employeeID == "" {
		prefix := "EMP"
		if req.MemberType == "manager" {
			prefix = "MGR"
		}
		employeeID = fmt.Sprintf("%s-%s", prefix, uuid.New().String()[:8])
	}
	reportsTo := req.ReportsTo
	if reportsTo == nil {
		reportsTo = &company.OwnerUserID
	}
	now := time.Now().UTC()

	hasLocationInput := req.PrimaryLocationID != nil ||
		req.LocationAccessScope != "" ||
		len(req.SelectedLocations) > 0 ||
		len(req.SelectedLocationIDs) > 0 ||
		resolvedWCLoc != nil

	var resolvedUser *models.User

	txErr := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		user, uerr := s.userService.GetUserByPhoneTx(ctx, tx, req.PhoneNumber)
		if uerr != nil && !errors.Is(uerr, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: failed to look up user by phone: %v", appErrors.ErrInternal, uerr)
		}
		if uerr == nil {
			resolvedUser = user
		} else {
			created, cerr := s.userService.CreateUser(ctx, tx, &UserCreateRequest{
				Username:          req.Username,
				FullName:          req.FullName,
				PhoneNumber:       req.PhoneNumber,
				DeviceID:          "company-assigned",
				DeviceFingerprint: "company-assigned",
				DataRegion:        company.DataRegion,
				ConsentAgreed:     true,
				ConsentVersion:    "v1.0",
				KYCStatus:         models.KYCStatusPending,
				KYCLevel:          models.KYCLevelBasic,
			})
			if cerr != nil {
				return fmt.Errorf("%w: failed to create user: %v", appErrors.ErrInternal, cerr)
			}
			resolvedUser = created
		}

		existingEmp, err := s.companyRepo.GetEmployee(ctx, tx, req.CompanyID, resolvedUser.UserID)
		if err == nil && existingEmp != nil && existingEmp.IsActive {
			return fmt.Errorf("%w: user is already an active employee", appErrors.ErrDuplicate)
		}
		if err != nil && !errors.Is(err, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: failed to check existing employee: %v", appErrors.ErrInternal, err)
		}

		if effectivePositionID == nil && newPositionID != nil {
			deptID := roleDepartments[0].DepartmentID
			if req.DepartmentID != nil {
				deptID = *req.DepartmentID
			}
			pos := &models.Position{
				PositionID:     *newPositionID,
				CompanyID:      req.CompanyID,
				DepartmentID:   deptID,
				JobID:          *req.JobID,
				LocationID:     req.LocationID,
				TitleOverride:  req.TitleOverride,
				IsOpen:         true,
				WorkCenterCode: req.WorkCenterCode,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := s.companyRepo.CreatePosition(ctx, tx, pos); err != nil {
				return fmt.Errorf("%w: failed to create position: %v", appErrors.ErrInternal, err)
			}
			effectivePositionID = newPositionID
		}

		emp := &models.CompanyEmployee{
			CompanyID:  req.CompanyID,
			UserID:     resolvedUser.UserID,
			EmployeeID: employeeID,
			RoleID:     req.RoleID,
			PositionID: effectivePositionID,
			HireDate:   now,
			IsActive:   true,
			ReportsTo:  reportsTo,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.companyRepo.CreateEmployee(ctx, tx, emp); err != nil {
			return fmt.Errorf("%w: failed to add member: %v", appErrors.ErrInternal, err)
		}

		status := "active"
		if req.EmploymentStatus != nil && *req.EmploymentStatus != "" {
			status = *req.EmploymentStatus
		}
		profile := &hrEmployee.EmployeeProfile{
			EmployeeProfileID: uuid.New(),
			UserID:            resolvedUser.UserID,
			CompanyID:         req.CompanyID,
			DateOfBirth:       req.DateOfBirth,
			Gender:            req.Gender,
			MaritalStatus:     req.MaritalStatus,
			Nationality:       req.Nationality,
			EmploymentType:    req.EmploymentType,
			EmploymentStatus:  &status,
			ProbationEndDate:  req.ProbationEndDate,
			ConfirmationDate:  req.ConfirmationDate,
			Grade:             req.Grade,
			CostCenterID:      req.CostCenterID,
			CostCenter:        req.CostCenter,
			TaxID:             req.TaxID,
			SocialSecurityID:  req.SocialSecurityID,
			Email:             req.Email,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		actorType := "system"
		actorID := uuid.Nil
		if st, ok := ctx.Value("session_type").(string); ok && st != "" {
			actorType = st
		}
		if uidStr, ok := ctx.Value("user_id").(string); ok && uidStr != "" {
			if uid, perr := uuid.Parse(uidStr); perr == nil {
				actorID = uid
			}
		}
		if _, err := s.employeeService.CreateEmployeeProfileInTx(
			ctx, tx, profile, actorType, actorID,
			map[string]interface{}{
				"source":      "add_member",
				"company_id":  req.CompanyID.String(),
				"member_type": req.MemberType,
			},
		); err != nil {
			return fmt.Errorf("%w: failed to create employee profile: %v", appErrors.ErrInternal, err)
		}

		if hasLocationInput {
			if err := s.assignMemberLocationsTx(ctx, tx, req.CompanyID, resolvedUser.UserID, req); err != nil {
				return fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
			}
		}

		if err := s.resolverJobs.EnqueueUserResolution(ctx, tx,
			req.CompanyID, resolvedUser.UserID, "onboarding"); err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		return txErr
	}

	// ─────────────────────────────────────────────────────────
	// NEW: open the probation row after the tx commits.
	//
	// StartProbation uses the non-tx repo (it opens its own tx for the
	// scheduled-job enqueue), so it MUST run outside this function's
	// transaction. If the hire carries a probation_end_date, this creates
	// the employee_probation row and enqueues the T-14/T-7/T-3/T+1 jobs
	// that HRLifecycleWorker fires later.
	//
	// Non-fatal: if this fails, the member is still created. Log and
	// continue; HR can re-open the probation window via the update path
	// if needed.
	// ─────────────────────────────────────────────────────────
	if req.ProbationEndDate != nil && resolvedUser != nil {
		if _, err := s.employeeService.StartProbation(
			ctx,
			req.CompanyID,
			resolvedUser.UserID,
			now,
			*req.ProbationEndDate,
			100,
		); err != nil {
			zap.L().Warn("AddMember: StartProbation post-commit failed",
				zap.String("company_id", req.CompanyID.String()),
				zap.String("user_id", resolvedUser.UserID.String()),
				zap.Time("probation_end_date", *req.ProbationEndDate),
				zap.Error(err),
			)
			if s.auditService != nil {
				_ = s.auditService.LogAction(ctx, nil, nil,
					"employee", "start_probation_failed", "employee",
					&resolvedUser.UserID, "system", nil, nil, nil,
					map[string]interface{}{
						"company_id":         req.CompanyID.String(),
						"user_id":            resolvedUser.UserID.String(),
						"probation_end_date": req.ProbationEndDate,
						"error":              err.Error(),
					})
			}
		}
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	if s.auditService != nil && resolvedUser != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "employee", "add_member", "admin",
			nil, "admin", nil, nil, nil, map[string]interface{}{
				"company_id":   req.CompanyID.String(),
				"user_id":      resolvedUser.UserID.String(),
				"role_id":      req.RoleID.String(),
				"member_type":  req.MemberType,
				"job_id":       req.JobID,
				"position_id":  effectivePositionID,
				"has_location": hasLocationInput,
				"has_profile":  true,
				"ip_address":   ip,
			})
	}
	return nil
}

// assignMemberLocationsTx (unchanged logic; signature preserved).
func (s *CompanyService) assignMemberLocationsTx(
	ctx context.Context,
	tx *sql.Tx,
	companyID, userID uuid.UUID,
	req *AddMemberRequest,
) error {
	scope := req.LocationAccessScope
	if scope == "" {
		if req.PrimaryLocationID != nil {
			scope = models.LocationScopePrimary
		} else {
			scope = models.LocationScopeAll
		}
	}
	if scope != models.LocationScopePrimary &&
		scope != models.LocationScopeSelected &&
		scope != models.LocationScopeAll {
		return fmt.Errorf("%w: invalid location_access_scope '%s'", appErrors.ErrInvalidInput, scope)
	}

	var primaryLocID uuid.UUID
	if req.PrimaryLocationID != nil && *req.PrimaryLocationID != uuid.Nil {
		loc, err := s.locationRepo.GetLocation(ctx, tx, *req.PrimaryLocationID)
		if err != nil {
			if errors.Is(err, appErrors.ErrNotFound) {
				return fmt.Errorf("%w: primary location not found", appErrors.ErrNotFound)
			}
			return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		if loc.CompanyID != companyID {
			return fmt.Errorf("%w: primary location does not belong to company", appErrors.ErrInvalidInput)
		}
		if !loc.IsActive {
			return fmt.Errorf("%w: primary location is not active", appErrors.ErrInvalidInput)
		}
		primaryLocID = *req.PrimaryLocationID
	}
	if scope == models.LocationScopePrimary && primaryLocID == uuid.Nil {
		return fmt.Errorf("%w: primary_location_id required for PRIMARY scope", appErrors.ErrInvalidInput)
	}

	if scope == models.LocationScopeSelected {
		grants, err := s.resolveMemberGrantsTx(ctx, tx, companyID, req)
		if err != nil {
			return err
		}
		if len(grants) == 0 {
			return fmt.Errorf("%w: at least one selected location required for SELECTED scope", appErrors.ErrInvalidInput)
		}
		for locID, level := range grants {
			access := &models.EmployeeLocationAccess{
				CompanyID: companyID, UserID: userID, LocationID: locID,
				AccessLevel: level, GrantedAt: time.Now().UTC(),
			}
			if err := s.locationRepo.AddLocationAccess(ctx, tx, access); err != nil {
				return fmt.Errorf("%w: failed to grant access to %s: %v", appErrors.ErrInternal, locID, err)
			}
		}
	}

	if err := s.companyRepo.UpdateEmployeeLocationSettings(ctx, tx, companyID, userID, &primaryLocID, scope); err != nil {
		return fmt.Errorf("%w: failed to set location settings: %v", appErrors.ErrInternal, err)
	}

	if primaryLocID != uuid.Nil {
		history := &models.EmployeeLocationHistory{
			ID: uuid.New(), UserID: userID, CompanyID: companyID,
			LocationID: primaryLocID, StartDate: time.Now().UTC(),
			EndDate: nil, ChangeReason: "initial assignment on member creation",
			CreatedAt: time.Now().UTC(),
		}
		if err := s.locationRepo.AddLocationHistory(ctx, tx, history); err != nil {
			return fmt.Errorf("%w: failed to write location history: %v", appErrors.ErrInternal, err)
		}
	}
	return nil
}

func (s *CompanyService) resolveMemberGrantsTx(
	ctx context.Context,
	tx *sql.Tx,
	companyID uuid.UUID,
	req *AddMemberRequest,
) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(req.SelectedLocations)+len(req.SelectedLocationIDs))
	for _, id := range req.SelectedLocationIDs {
		if id != uuid.Nil {
			out[id] = models.AccessLevelView
		}
	}
	for _, g := range req.SelectedLocations {
		if g.LocationID == uuid.Nil {
			continue
		}
		level := g.AccessLevel
		if level == "" {
			level = models.AccessLevelView
		}
		if level != models.AccessLevelView && level != models.AccessLevelManage {
			return nil, fmt.Errorf("%w: invalid access_level '%s'", appErrors.ErrInvalidInput, level)
		}
		out[g.LocationID] = level
	}
	for locID := range out {
		loc, err := s.locationRepo.GetLocation(ctx, tx, locID)
		if err != nil {
			if errors.Is(err, appErrors.ErrNotFound) {
				return nil, fmt.Errorf("%w: selected location %s not found", appErrors.ErrInvalidInput, locID)
			}
			return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
		}
		if loc.CompanyID != companyID {
			return nil, fmt.Errorf("%w: selected location %s does not belong to company", appErrors.ErrInvalidInput, locID)
		}
		if !loc.IsActive {
			return nil, fmt.Errorf("%w: selected location %s is not active", appErrors.ErrInvalidInput, locID)
		}
	}
	return out, nil
}

// ============================================================
// UpdateMemberRequest / UpdateMember (unchanged from previous)
// ============================================================

type UpdateMemberRequest struct {
	Username            *string                                `json:"username,omitempty"`
	FullName            *string                                `json:"full_name,omitempty"`
	RoleID              *uuid.UUID                             `json:"role_id,omitempty"`
	PositionID          *uuid.UUID                             `json:"position_id,omitempty"`
	ReportsTo           *uuid.UUID                             `json:"reports_to,omitempty"`
	PrimaryLocationID   *uuid.UUID                             `json:"primary_location_id,omitempty"`
	LocationAccessScope *string                                `json:"location_access_scope,omitempty"`
	SelectedLocations   *[]models.EmployeeLocationGrantRequest `json:"selected_locations,omitempty"`
	Email               *string                                `json:"email,omitempty"`
	TaxID               *string                                `json:"tax_id,omitempty"`
	SocialSecurityID    *string                                `json:"social_security_id,omitempty"`
	DateOfBirth         *time.Time                             `json:"date_of_birth,omitempty"`
	Gender              *string                                `json:"gender,omitempty"`
	MaritalStatus       *string                                `json:"marital_status,omitempty"`
	Nationality         *string                                `json:"nationality,omitempty"`
	EmploymentType      *string                                `json:"employment_type,omitempty"`
	EmploymentStatus    *string                                `json:"employment_status,omitempty"`
	ProbationEndDate    *time.Time                             `json:"probation_end_date,omitempty"`
	ConfirmationDate    *time.Time                             `json:"confirmation_date,omitempty"`
	Grade               *string                                `json:"grade,omitempty"`
	CostCenter          *string                                `json:"cost_center,omitempty"`
	CostCenterID        *uuid.UUID                             `json:"cost_center_id,omitempty"`
}

func (s *CompanyService) UpdateMember(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	req *UpdateMemberRequest,
	updatedBy uuid.UUID,
) error {
	if req == nil {
		return fmt.Errorf("%w: empty request", appErrors.ErrInvalidInput)
	}
	if companyID == uuid.Nil || userID == uuid.Nil {
		return fmt.Errorf("%w: company_id and user_id are required", appErrors.ErrInvalidInput)
	}

	ip, _ := ctx.Value("ip_address").(string)
	now := time.Now().UTC()

	company, err := s.companyRepo.GetCompany(ctx, companyID)
	if err != nil {
		return fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
	}
	if !company.IsActive {
		return fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}

	existingEmp, err := s.companyRepo.GetEmployee(ctx, s.pgClient.Pool(), companyID, userID)
	if err != nil {
		return fmt.Errorf("%w: employee not found", appErrors.ErrNotFound)
	}
	if !existingEmp.IsActive {
		return fmt.Errorf("%w: employee is not active", appErrors.ErrInvalidState)
	}

	effectiveRoleID := existingEmp.RoleID
	if req.RoleID != nil {
		effectiveRoleID = *req.RoleID
		role, err := s.companyRepo.GetRole(ctx, effectiveRoleID)
		if err != nil {
			return fmt.Errorf("%w: role not found", appErrors.ErrNotFound)
		}
		if role.CompanyID != companyID {
			return fmt.Errorf("%w: role does not belong to company", appErrors.ErrInvalidInput)
		}
	}

	roleDepartments, err := s.companyRepo.GetRoleDepartments(ctx, effectiveRoleID)
	if err != nil {
		return fmt.Errorf("%w: failed to get role departments", appErrors.ErrInternal)
	}
	if len(roleDepartments) == 0 {
		return fmt.Errorf("%w: role is not assigned to any department", appErrors.ErrInvalidState)
	}

	if req.PositionID != nil {
		position, err := s.companyRepo.GetPosition(ctx, s.pgClient.Pool(), *req.PositionID)
		if err != nil {
			return fmt.Errorf("%w: position not found", appErrors.ErrNotFound)
		}
		if position.CompanyID != companyID {
			return fmt.Errorf("%w: position does not belong to company", appErrors.ErrInvalidInput)
		}
		if !position.IsOpen {
			return fmt.Errorf("%w: position is not open", appErrors.ErrInvalidState)
		}
		found := false
		for _, rd := range roleDepartments {
			if rd.DepartmentID == position.DepartmentID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: position's department not assigned to role", appErrors.ErrInvalidInput)
		}
	}

	if req.ReportsTo != nil {
		if *req.ReportsTo == userID {
			return fmt.Errorf("%w: employee cannot report to themselves", appErrors.ErrInvalidInput)
		}
		if err := s.validateReportsTo(ctx, companyID, req.ReportsTo); err != nil {
			return fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
		}
	}

	existingUser, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: user not found", appErrors.ErrNotFound)
	}
	existingProfile, err := s.employeeRepo.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		return fmt.Errorf("%w: employee profile not found", appErrors.ErrNotFound)
	}

	needsLocationChange := req.PrimaryLocationID != nil ||
		req.LocationAccessScope != nil ||
		req.SelectedLocations != nil

	// Captured outside the closure so we can inspect the post-update
	// employment_status + probation_end_date after commit.
	var finalProfile *hrEmployee.EmployeeProfile

	txErr := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		if req.Username != nil || req.FullName != nil {
			if req.Username != nil {
				existingUser.Username = strings.TrimSpace(*req.Username)
			}
			if req.FullName != nil {
				existingUser.FullName = strings.TrimSpace(*req.FullName)
			}
			if err := s.userService.UpdateUserTx(ctx, tx, existingUser); err != nil {
				return err
			}
		}

		oldPositionID := existingEmp.PositionID

		roster := *existingEmp
		if req.RoleID != nil {
			roster.RoleID = *req.RoleID
		}
		if req.PositionID != nil {
			roster.PositionID = req.PositionID
		}
		if req.ReportsTo != nil {
			roster.ReportsTo = req.ReportsTo
		}
		roster.UpdatedAt = now
		if err := s.companyRepo.UpdateEmployeeTx(ctx, tx, &roster); err != nil {
			return fmt.Errorf("%w: failed to update roster: %v", appErrors.ErrInternal, err)
		}

		if !uuidPtrEqual(oldPositionID, roster.PositionID) {
			if err := s.resolverJobs.EnqueueUserResolution(
				ctx, tx, companyID, userID, "position change",
			); err != nil {
				return fmt.Errorf("%w: failed to enqueue resolver job: %v", appErrors.ErrInternal, err)
			}
		}

		if needsLocationChange {
			if err := s.locationRepo.DeleteAllLocationAccessForUser(ctx, tx, companyID, userID); err != nil {
				return fmt.Errorf("%w: failed to clear location grants: %v", appErrors.ErrInternal, err)
			}
			locReq := &AddMemberRequest{CompanyID: companyID, LocationAccessScope: ""}
			if req.LocationAccessScope != nil {
				locReq.LocationAccessScope = *req.LocationAccessScope
			}
			if req.PrimaryLocationID != nil {
				locReq.PrimaryLocationID = req.PrimaryLocationID
			}
			if req.SelectedLocations != nil {
				locReq.SelectedLocations = *req.SelectedLocations
			}
			if err := s.assignMemberLocationsTx(ctx, tx, companyID, userID, locReq); err != nil {
				return fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
			}
		}

		profile := *existingProfile
		if req.Email != nil {
			profile.Email = req.Email
		}
		if req.TaxID != nil {
			profile.TaxID = req.TaxID
		}
		if req.SocialSecurityID != nil {
			profile.SocialSecurityID = req.SocialSecurityID
		}
		if req.DateOfBirth != nil {
			profile.DateOfBirth = req.DateOfBirth
		}
		if req.Gender != nil {
			profile.Gender = req.Gender
		}
		if req.MaritalStatus != nil {
			profile.MaritalStatus = req.MaritalStatus
		}
		if req.Nationality != nil {
			profile.Nationality = req.Nationality
		}
		if req.EmploymentType != nil {
			profile.EmploymentType = req.EmploymentType
		}
		if req.EmploymentStatus != nil {
			profile.EmploymentStatus = req.EmploymentStatus
		}
		if req.ProbationEndDate != nil {
			profile.ProbationEndDate = req.ProbationEndDate
		}
		if req.ConfirmationDate != nil {
			profile.ConfirmationDate = req.ConfirmationDate
		}
		if req.Grade != nil {
			profile.Grade = req.Grade
		}
		if req.CostCenter != nil {
			profile.CostCenter = req.CostCenter
		}
		if req.CostCenterID != nil {
			profile.CostCenterID = req.CostCenterID
		}
		profile.UpdatedAt = now

		actorType := "system"
		actorID := updatedBy
		if st, ok := ctx.Value("session_type").(string); ok && st != "" {
			actorType = st
		}
		updatedProfile, err := s.employeeService.UpdateEmployeeProfileInTx(
			ctx, tx, &profile, actorType, actorID,
			map[string]interface{}{"source": "update_member", "company_id": companyID.String()},
		)
		if err != nil {
			return fmt.Errorf("%w: failed to update profile: %v", appErrors.ErrInternal, err)
		}
		finalProfile = updatedProfile
		return nil
	})
	if txErr != nil {
		return txErr
	}

	// ─────────────────────────────────────────────────────────
	// NEW: if this update just flipped the employee into probation
	// with a future end date and there's no open employee_probation
	// row, open one and enqueue the reminder jobs.
	//
	// Runs AFTER the tx commits because StartProbation uses the non-tx
	// repo. The GetActiveProbation guard prevents double-opening when
	// the caller updates an already-probationary employee.
	// ─────────────────────────────────────────────────────────
	if finalProfile != nil &&
		finalProfile.EmploymentStatus != nil &&
		*finalProfile.EmploymentStatus == "probation" &&
		finalProfile.ProbationEndDate != nil {

		hasOpenProbation := false
		if _, perr := s.employeeRepo.GetActiveProbation(ctx, companyID, userID); perr == nil {
			hasOpenProbation = true
		}

		if !hasOpenProbation {
			if _, err := s.employeeService.StartProbation(
				ctx,
				companyID,
				userID,
				now,
				*finalProfile.ProbationEndDate,
				100,
			); err != nil {
				zap.L().Warn("UpdateMember: StartProbation post-commit failed",
					zap.String("company_id", companyID.String()),
					zap.String("user_id", userID.String()),
					zap.Time("probation_end_date", *finalProfile.ProbationEndDate),
					zap.Error(err),
				)
				if s.auditService != nil {
					_ = s.auditService.LogAction(ctx, nil, nil,
						"employee", "start_probation_failed", "employee",
						&userID, "system", nil, nil, nil,
						map[string]interface{}{
							"company_id":         companyID.String(),
							"user_id":            userID.String(),
							"probation_end_date": finalProfile.ProbationEndDate,
							"error":              err.Error(),
						})
				}
			}
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "employee", "update_member", "hr",
			&updatedBy, "hr", &updatedBy, nil, nil, map[string]interface{}{
				"company_id": companyID.String(),
				"user_id":    userID.String(),
				"ip_address": ip,
			})
	}
	return nil
}

// uuidPtrEqual returns true when both pointers are nil or point to equal
// UUIDs. Used to detect "did this field actually change?" across updates
// where the caller may or may not have provided the field.
func uuidPtrEqual(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// strPtrEqual returns true when both pointers are nil or point to equal
// strings. Same shape as uuidPtrEqual; used for work-center-code comparison
// in UpdatePosition.
func strPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// ============================================================
// GetEmployeeFormOptions — single-call prefetch for the HR form.
//
// requestedLocationHeader:
//
//	""       → caller's full scope (all locations they can see)
//	"ALL"    → same as "" (explicit company-wide)
//	<uuid>   → narrow positions & work centers to that location
//	           (+ universal rows where location_id IS NULL)
//
// The caller's own scope is ALWAYS enforced first — even if the
// header names a location outside the caller's set, we 403.
//
// The full scope-aware location list is returned in
// `AllowedLocations` regardless of the filter, so the client
// still knows what locations the new employee could be granted.
// ============================================================
func (s *CompanyService) GetEmployeeFormOptions(
	ctx context.Context,
	companyID, callerUserID uuid.UUID,
	requestedLocationHeader string,
) (*models.EmployeeFormOptions, error) {
	if companyID == uuid.Nil || callerUserID == uuid.Nil {
		return nil, fmt.Errorf(
			"%w: company_id and caller_user_id are required",
			appErrors.ErrInvalidInput,
		)
	}

	// --- Caller must be an active member of this company ---------
	callerEmp, err := s.companyRepo.GetEmployee(
		ctx, s.pgClient.Pool(), companyID, callerUserID,
	)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf(
				"%w: caller is not a member of this company",
				appErrors.ErrPermissionDenied,
			)
		}
		return nil, fmt.Errorf(
			"%w: failed to verify caller membership: %v",
			appErrors.ErrInternal, err,
		)
	}
	if !callerEmp.IsActive {
		return nil, fmt.Errorf(
			"%w: caller is not an active employee",
			appErrors.ErrPermissionDenied,
		)
	}

	// --- 1. Caller's allowed locations (scope = PRIMARY | SELECTED | ALL) ---
	myLocs, err := s.locationService.GetMyLocations(ctx, companyID, callerUserID)
	if err != nil {
		return nil, err
	}

	scopeLocationIDs := make([]uuid.UUID, 0, len(myLocs.Locations))
	for _, l := range myLocs.Locations {
		if l == nil || l.Location.LocationID == uuid.Nil {
			continue
		}
		scopeLocationIDs = append(scopeLocationIDs, l.Location.LocationID)
	}

	var primaryPtr *uuid.UUID
	if myLocs.PrimaryLocationID != uuid.Nil {
		id := myLocs.PrimaryLocationID
		primaryPtr = &id
	}

	// ---------------------------------------------------------
	// 2. Determine the effective location filter.
	//
	// If the client sent a concrete UUID, narrow to that one — but
	// ONLY after verifying it's inside the caller's allowed set.
	// Otherwise fall back to the caller's full scope (which is what
	// an empty or "ALL" header means).
	// ---------------------------------------------------------
	effectiveLocationIDs := scopeLocationIDs

	header := strings.TrimSpace(requestedLocationHeader)
	if header != "" && !strings.EqualFold(header, "ALL") {
		requested, perr := uuid.Parse(header)
		if perr != nil || requested == uuid.Nil {
			return nil, fmt.Errorf(
				"%w: invalid X-Location-ID header value",
				appErrors.ErrInvalidInput,
			)
		}

		// The requested location must be inside the caller's scope,
		// otherwise we'd be leaking positions the caller can't touch.
		inScope := false
		for _, id := range scopeLocationIDs {
			if id == requested {
				inScope = true
				break
			}
		}
		if !inScope {
			return nil, fmt.Errorf(
				"%w: location %s is not in the caller's scope",
				appErrors.ErrPermissionDenied, requested,
			)
		}

		effectiveLocationIDs = []uuid.UUID{requested}
	}

	// --- 3. Roles (each with its departments) ----------------
	roles, _, err := s.companyRepo.GetRolesByCompany(ctx, companyID, 200, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch roles: %v", appErrors.ErrInternal, err)
	}

	rolesWithDeps := make([]*models.RoleWithDepartments, 0, len(roles))
	for _, role := range roles {
		deps, depErr := s.companyRepo.GetRoleDepartments(ctx, role.RoleID)
		if depErr != nil {
			deps = []*models.Department{}
		}
		rolesWithDeps = append(rolesWithDeps, &models.RoleWithDepartments{
			RoleID:       role.RoleID,
			RoleName:     role.RoleName,
			RoleLevel:    role.RoleLevel,
			Description:  role.Description,
			IsSystemRole: role.IsSystemRole,
			Departments:  deps,
		})
	}

	// --- 4. Positions — filtered by the effective location set ----
	positions, _, err := s.companyRepo.GetPositionsFiltered(
		ctx, s.pgClient.Pool(), companyID,
		effectiveLocationIDs,
		nil,  // no department narrowing server-side; frontend filters by role
		true, // include universal positions (location_id IS NULL)
		500, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch positions: %v", appErrors.ErrInternal, err)
	}

	// --- 5. Work centers — same filter -----------------------
	workCenters, err := s.companyRepo.GetWorkCentersFiltered(
		ctx, s.pgClient.Pool(), companyID,
		effectiveLocationIDs,
		true, // include universal work centers
	)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch work centers: %v", appErrors.ErrInternal, err)
	}

	return &models.EmployeeFormOptions{
		PrimaryLocationID: primaryPtr,
		LocationScope:     myLocs.LocationScope,
		AllowedLocations:  myLocs.Locations,
		Roles:             rolesWithDeps,
		Positions:         positions,
		WorkCenters:       workCenters,
		IncludeUniversal:  true,
	}, nil
}
