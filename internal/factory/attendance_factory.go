package factory

import (
	"context"
	"errors"
	"time"

	biometricRepoPkg "auth-service/internal/attendance/biometric/repository"
	biometricPostgres "auth-service/internal/attendance/biometric/repository/postgres"
	biometricSvc "auth-service/internal/attendance/biometric/service"
	"auth-service/internal/attendance/consumer"
	"auth-service/internal/attendance/handler"
	"auth-service/internal/attendance/middleware"
	attendanceRepo "auth-service/internal/attendance/repository"
	attendancePostgres "auth-service/internal/attendance/repository/postgres"
	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/batch"
	"auth-service/internal/attendance/service/device"
	"auth-service/internal/attendance/service/enrollment"
	"auth-service/internal/attendance/service/exemption"
	"auth-service/internal/attendance/service/ingest"
	"auth-service/internal/attendance/service/query"
	"auth-service/internal/attendance/service/report"
	"auth-service/internal/attendance/service/resolution"
	"auth-service/internal/attendance/service/resolver"
	"auth-service/internal/attendance/service/scheduling"
	"auth-service/internal/attendance/service/source"
	"auth-service/internal/attendance/service/usage_integration"
	"auth-service/internal/attendance/service/workcenter"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/encryption"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	infraOutbox "auth-service/internal/infrastructure/outbox"

	academicsRepo "auth-service/internal/academics/repository"
	leaverepo "auth-service/internal/hr/leave/repository"
	hrleavesvc "auth-service/internal/hr/leave/service"
	hrpostgres "auth-service/internal/hr/repository"
	salesRepo "auth-service/internal/sales/repository"
	subRepo "auth-service/internal/subscription/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// errScheduleAdapterNoLeaveRepo is returned by the schedule subject resolver
// adapter when its leave-repository dependency is missing. Without the
// leave repo we cannot enumerate active employees, so any call that needs
// the fan-out list fails explicitly rather than silently returning an
// empty slice (which would look like "no employees exist" downstream).
var errScheduleAdapterNoLeaveRepo = errors.New("schedule subject resolver adapter: leave repository not wired")

// AttendanceFactory centralizes creation and wiring of all attendance components.
//
// Schedule generation has been removed: schedules are derived on read from
// the rule chain (WC → shift → template → calendar → override). There is no
// worker, no queue, no schedule_instances table. The only per-day, per-user
// data we still write is schedule_overrides — the manual override log.
type AttendanceFactory struct {
	// external dependencies
	postgresClient    *client.PostgresClient
	redisClient       *client.RedisClient
	kafkaProducer     *client.KafkaProducer
	outboxRepo        infraOutbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
	cfg               *config.Config
	encryptionManager *encryption.EncryptionManager

	// configuration
	deviceTokenPrefix   string
	deviceTokenSecret   string
	deviceTokenValidity time.Duration

	// repositories (attendance)
	eventRepo          attendanceRepo.EventRepository
	deviceRepo         attendanceRepo.DeviceRepository
	enrollmentRepo     attendanceRepo.DeviceEnrollmentRepository
	tokenRepo          attendanceRepo.TokenRepository
	heartbeatRepo      attendanceRepo.DeviceHeartbeatRepository
	batchRepo          attendanceRepo.AttendanceBatchRepository
	policyRepo         attendanceRepo.PolicyRepository
	ruleRepo           attendanceRepo.RuleRepository
	sourceRepo         attendanceRepo.SourceRepository
	scheduleRepo       attendanceRepo.ScheduleRepository
	summaryRepo        attendanceRepo.SummaryRepository
	exemptionRepo      attendanceRepo.AttendanceExemptionRepository
	sessionSummaryRepo attendanceRepo.AttendanceSessionSummaryRepository
	workCenterRepo     attendanceRepo.WorkCenterRepository
	geofenceRepo       attendanceRepo.GeofenceRepository
	calendarRepo       attendanceRepo.CalendarRepository

	// HR employee repository (cached, used by both SubjectResolver and LocationResolver)
	hrEmployeeRepo hrpostgres.EmployeeRepository

	// data providers (for resolvers)
	employeeDataProvider resolver.EmployeeDataProvider
	leaveDataProvider    resolver.LeaveDataProvider

	// biometric repositories
	faceEmbeddingRepo biometricRepoPkg.FaceEmbeddingRepository
	deviceSyncRepo    biometricRepoPkg.DeviceEmbeddingSyncRepository

	// academic repositories (cached)
	academicStudentRepo    academicsRepo.StudentRepository
	academicEnrollmentRepo academicsRepo.EnrollmentRepository
	academicTimetableRepo  academicsRepo.TimetableRepository
	academicSessionRepo    academicsRepo.AcademicSessionRepository

	// customer resolver dependencies
	customerRepo     salesRepo.CustomerRepository
	subscriptionRepo subRepo.SubscriptionRepository
	trialRepo        subRepo.TrialRepository

	// usage integration service
	usageIntegrationService *usage_integration.UsageIntegrationService

	// canonical timezone resolver (position → location → work center → company)
	tzProvider resolver.TimezoneProvider

	// resolvers
	subjectResolver         resolver.SubjectResolver
	scheduleSubjectResolver resolver.ScheduleSubjectResolver
	studentResolver         resolver.SubjectResolver // external override (optional)

	// subject location resolver (write-side location stamping + scope checks)
	locationResolver resolver.SubjectLocationResolver

	// services
	ingestService          ingest.IngestService
	adminService           admin.AdminService
	queryService           query.QueryService
	resolutionService      resolution.ResolutionService
	correctionService      admin.CorrectionService
	enrollmentService      enrollment.EnrollmentService
	deviceService          device.DeviceService
	tokenService           device.TokenService
	heartbeatService       device.HeartbeatService
	batchIngestService     batch.BatchIngestService
	batchFailureService    batch.BatchFailureService
	sourceAdminService     source.SourceAdminService
	sourceResolver         source.SourceResolver
	schedulingService      scheduling.SchedulingService
	schedulingQueryService scheduling.SchedulingQueryService
	workCenterService      workcenter.Service
	workCenterQueryService workcenter.QueryService
	reportService          report.ReportService
	biometricEnrollmentSvc biometricSvc.BiometricEnrollmentService
	biometricSyncSvc       biometricSvc.BiometricSyncService
	omService              ingest.OMService
	exemptionService       exemption.ExemptionService

	// outbox & consumer
	resolutionConsumer *consumer.AttendanceResolutionConsumer

	// handlers
	ingestHandler              *handler.AttendanceIngestHandler
	adminHandler               *handler.AttendanceAdminHandler
	queryHandler               *handler.AttendanceQueryHandler
	resolutionHandler          *handler.AttendanceResolutionHandler
	correctionHandler          *handler.AttendanceCorrectionHandler
	deviceHandler              *handler.DeviceHandler
	enrollmentHandler          *handler.AttendanceDeviceEnrollmentHandler
	tokenAdminHandler          *handler.DeviceTokenAdminHandler
	heartbeatHandler           *handler.DeviceHeartbeatHandler
	batchHandler               *handler.BatchHandler
	sourceAdminHandler         *handler.AttendanceSourceAdminHandler
	workCenterHandler          *handler.WorkCenterHandler
	schedulingHandler          *handler.SchedulingHandler
	biometricEnrollmentHandler *handler.BiometricEnrollmentHandler
	biometricSyncHandler       *handler.BiometricSyncHandler
	reportHandler              *handler.AttendanceReportHandler
	exemptionHandler           *handler.AttendanceExemptionHandler

	// middleware
	deviceAuthMiddleware *middleware.DeviceAuthMiddleware

	// cancellations
	resolutionCancel context.CancelFunc
}

// AttendanceFactoryConfig holds configuration for the attendance factory.
type AttendanceFactoryConfig struct {
	DeviceTokenPrefix   string
	DeviceTokenSecret   string
	DeviceTokenValidity time.Duration
}

// NewAttendanceFactory creates a new AttendanceFactory.
func NewAttendanceFactory(
	postgresClient *client.PostgresClient,
	redisClient *client.RedisClient,
	kafkaProducer *client.KafkaProducer,
	outboxRepo infraOutbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	cfg *config.Config,
	logger *zap.Logger,
	config AttendanceFactoryConfig,
	encryptionManager *encryption.EncryptionManager,
) *AttendanceFactory {
	return &AttendanceFactory{
		postgresClient:      postgresClient,
		redisClient:         redisClient,
		kafkaProducer:       kafkaProducer,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		cfg:                 cfg,
		logger:              logger.Named("attendance_factory"),
		encryptionManager:   encryptionManager,
		deviceTokenPrefix:   config.DeviceTokenPrefix,
		deviceTokenSecret:   config.DeviceTokenSecret,
		deviceTokenValidity: config.DeviceTokenValidity,
	}
}

// ---------- Setter for customer resolver dependencies ----------
func (f *AttendanceFactory) SetCustomerResolverDependencies(
	customerRepo salesRepo.CustomerRepository,
	subscriptionRepo subRepo.SubscriptionRepository,
	trialRepo subRepo.TrialRepository,
) {
	f.customerRepo = customerRepo
	f.subscriptionRepo = subscriptionRepo
	f.trialRepo = trialRepo
	f.logger.Info("Customer resolver dependencies set")
}

// ---------- Setter for usage integration service ----------
func (f *AttendanceFactory) SetUsageIntegrationService(svc *usage_integration.UsageIntegrationService) {
	f.usageIntegrationService = svc
	f.logger.Info("Usage integration service set")
}

// SetScheduleNotifier is retained as a no-op for backward compatibility.
//
// Schedule generation has been removed, so there are no per-user warnings
// to dispatch. The method accepts any argument so the outer factory can
// keep calling it without knowing that the notifier is gone. Remove the
// call from the outer factory when convenient.
func (f *AttendanceFactory) SetScheduleNotifier(_ interface{}) {
	f.logger.Debug("SetScheduleNotifier called (no-op: schedule generation removed)")
}

// ---------- Repositories ----------

func (f *AttendanceFactory) EventRepository() attendanceRepo.EventRepository {
	if f.eventRepo == nil {
		f.eventRepo = attendancePostgres.NewEventRepository(f.postgresClient, f.logger)
	}
	return f.eventRepo
}

func (f *AttendanceFactory) DeviceRepository() attendanceRepo.DeviceRepository {
	if f.deviceRepo == nil {
		f.deviceRepo = attendancePostgres.NewDeviceRepository(f.postgresClient, f.logger)
	}
	return f.deviceRepo
}

func (f *AttendanceFactory) DeviceEnrollmentRepository() attendanceRepo.DeviceEnrollmentRepository {
	if f.enrollmentRepo == nil {
		f.enrollmentRepo = attendancePostgres.NewDeviceEnrollmentRepository(f.postgresClient, f.logger)
	}
	return f.enrollmentRepo
}

func (f *AttendanceFactory) TokenRepository() attendanceRepo.TokenRepository {
	if f.tokenRepo == nil {
		f.tokenRepo = attendancePostgres.NewTokenRepository(f.postgresClient, f.logger)
	}
	return f.tokenRepo
}

func (f *AttendanceFactory) HeartbeatRepository() attendanceRepo.DeviceHeartbeatRepository {
	if f.heartbeatRepo == nil {
		f.heartbeatRepo = attendancePostgres.NewDeviceHeartbeatRepository(f.postgresClient, f.logger)
	}
	return f.heartbeatRepo
}

func (f *AttendanceFactory) BatchRepository() attendanceRepo.AttendanceBatchRepository {
	if f.batchRepo == nil {
		f.batchRepo = attendancePostgres.NewAttendanceBatchRepository(f.postgresClient, f.logger)
	}
	return f.batchRepo
}

func (f *AttendanceFactory) PolicyRepository() attendanceRepo.PolicyRepository {
	if f.policyRepo == nil {
		f.policyRepo = attendancePostgres.NewPolicyRepository(f.postgresClient, f.logger)
	}
	return f.policyRepo
}

func (f *AttendanceFactory) RuleRepository() attendanceRepo.RuleRepository {
	if f.ruleRepo == nil {
		f.ruleRepo = attendancePostgres.NewRuleRepository(f.postgresClient, f.logger)
	}
	return f.ruleRepo
}

func (f *AttendanceFactory) SourceRepository() attendanceRepo.SourceRepository {
	if f.sourceRepo == nil {
		f.sourceRepo = attendancePostgres.NewSourceRepository(f.postgresClient, f.logger)
	}
	return f.sourceRepo
}

func (f *AttendanceFactory) ScheduleRepository() attendanceRepo.ScheduleRepository {
	if f.scheduleRepo == nil {
		f.scheduleRepo = attendancePostgres.NewScheduleRepository(f.postgresClient, f.logger)
	}
	return f.scheduleRepo
}

func (f *AttendanceFactory) SummaryRepository() attendanceRepo.SummaryRepository {
	if f.summaryRepo == nil {
		f.summaryRepo = attendancePostgres.NewSummaryRepository(f.postgresClient, f.logger)
	}
	return f.summaryRepo
}

func (f *AttendanceFactory) ExemptionRepository() attendanceRepo.AttendanceExemptionRepository {
	if f.exemptionRepo == nil {
		f.exemptionRepo = attendancePostgres.NewAttendanceExemptionRepository(f.postgresClient, f.logger)
	}
	return f.exemptionRepo
}

func (f *AttendanceFactory) SessionSummaryRepository() attendanceRepo.AttendanceSessionSummaryRepository {
	if f.sessionSummaryRepo == nil {
		f.sessionSummaryRepo = attendancePostgres.NewAttendanceSessionSummaryRepository(f.postgresClient, f.logger)
	}
	return f.sessionSummaryRepo
}

func (f *AttendanceFactory) WorkCenterRepository() attendanceRepo.WorkCenterRepository {
	if f.workCenterRepo == nil {
		f.workCenterRepo = attendancePostgres.NewWorkCenterRepository(f.postgresClient, f.logger)
	}
	return f.workCenterRepo
}

// GeofenceRepository returns the attendance geofence repository.
func (f *AttendanceFactory) GeofenceRepository() attendanceRepo.GeofenceRepository {
	if f.geofenceRepo == nil {
		f.geofenceRepo = attendancePostgres.NewGeofenceRepository(f.postgresClient, f.logger)
	}
	return f.geofenceRepo
}

func (f *AttendanceFactory) CalendarRepository() attendanceRepo.CalendarRepository {
	if f.calendarRepo == nil {
		f.calendarRepo = attendancePostgres.NewCalendarRepository(f.postgresClient, f.logger)
	}
	return f.calendarRepo
}

func (f *AttendanceFactory) FaceEmbeddingRepository() biometricRepoPkg.FaceEmbeddingRepository {
	if f.faceEmbeddingRepo == nil {
		f.faceEmbeddingRepo = biometricPostgres.NewFaceEmbeddingRepository(f.postgresClient, f.logger)
	}
	return f.faceEmbeddingRepo
}

func (f *AttendanceFactory) DeviceEmbeddingSyncRepository() biometricRepoPkg.DeviceEmbeddingSyncRepository {
	if f.deviceSyncRepo == nil {
		f.deviceSyncRepo = biometricPostgres.NewDeviceEmbeddingSyncRepository(f.postgresClient, f.logger)
	}
	return f.deviceSyncRepo
}

// HREmployeeRepository returns a cached HR employee repository.
func (f *AttendanceFactory) HREmployeeRepository() hrpostgres.EmployeeRepository {
	if f.hrEmployeeRepo == nil {
		f.hrEmployeeRepo = hrpostgres.NewEmployeeRepository(f.postgresClient)
	}
	return f.hrEmployeeRepo
}

// ---------- Academic Repositories ----------
func (f *AttendanceFactory) StudentRepository() academicsRepo.StudentRepository {
	if f.academicStudentRepo == nil {
		f.academicStudentRepo = academicsRepo.NewStudentRepository(f.logger, f.encryptionManager)
	}
	return f.academicStudentRepo
}

func (f *AttendanceFactory) AcademicsEnrollmentRepository() academicsRepo.EnrollmentRepository {
	if f.academicEnrollmentRepo == nil {
		f.academicEnrollmentRepo = academicsRepo.NewEnrollmentRepository(f.logger)
	}
	return f.academicEnrollmentRepo
}

func (f *AttendanceFactory) TimetableRepository() academicsRepo.TimetableRepository {
	if f.academicTimetableRepo == nil {
		f.academicTimetableRepo = academicsRepo.NewTimetableRepository(f.logger)
	}
	return f.academicTimetableRepo
}

func (f *AttendanceFactory) AcademicSessionRepository() academicsRepo.AcademicSessionRepository {
	if f.academicSessionRepo == nil {
		f.academicSessionRepo = academicsRepo.NewAcademicSessionRepository(f.logger)
	}
	return f.academicSessionRepo
}

// ---------- Data Providers for Student Resolver ----------
func (f *AttendanceFactory) StudentDataProvider() resolver.StudentDataProvider {
	return resolver.NewStudentDataProvider(
		f.postgresClient.DB,
		f.StudentRepository(),
		f.logger,
	)
}

func (f *AttendanceFactory) EnrollmentDataProvider() resolver.EnrollmentDataProvider {
	return resolver.NewEnrollmentDataProvider(
		f.postgresClient.DB,
		f.AcademicsEnrollmentRepository(),
		f.logger,
	)
}

func (f *AttendanceFactory) TimetableDataProvider() resolver.TimetableDataProvider {
	return resolver.NewTimetableDataProvider(
		f.postgresClient.DB,
		f.TimetableRepository(),
		f.logger,
	)
}

func (f *AttendanceFactory) SessionDataProvider() resolver.SessionDataProvider {
	return resolver.NewSessionDataProvider(
		f.postgresClient.DB,
		f.AcademicSessionRepository(),
		f.logger,
	)
}

// ---------- Timezone Provider ----------
//
// TimezoneProvider is the single source of truth for the effective tz of
// any subject. Every resolver, writer, and scheduler calls this. It walks:
//
//	position.location_id → locations.timezone
//	position.work_center_code → work_centers.timezone
//	work_centers.location_id → locations.timezone
//	companies.default_timezone
//	"UTC" (last resort, logged)
func (f *AttendanceFactory) TimezoneProvider() resolver.TimezoneProvider {
	if f.tzProvider == nil {
		f.tzProvider = resolver.NewTimezoneProvider(f.postgresClient, f.logger)
		f.logger.Info("Timezone provider initialized")
	}
	return f.tzProvider
}

// ---------- Subject Location Resolver ----------
func (f *AttendanceFactory) LocationResolver() resolver.SubjectLocationResolver {
	if f.locationResolver == nil {
		employeeLocResolver := resolver.NewEmployeeLocationResolver(f.HREmployeeRepository())
		studentLocResolver := resolver.NewStudentLocationResolver(f.postgresClient, f.logger)
		customerLocResolver := resolver.NewCustomerLocationResolver()

		f.locationResolver = resolver.NewCompositeLocationResolver(
			employeeLocResolver,
			studentLocResolver,
			customerLocResolver,
		)
		f.logger.Info("Subject location resolver initialized")
	}
	return f.locationResolver
}

// ---------- Resolvers ----------
func (f *AttendanceFactory) SetStudentResolver(studentResolver resolver.SubjectResolver) {
	f.studentResolver = studentResolver
}

// SubjectResolver builds the composite resolver.
func (f *AttendanceFactory) SubjectResolver() resolver.SubjectResolver {
	if f.subjectResolver == nil {
		tzProvider := f.TimezoneProvider()

		hrEmployeeRepo := f.HREmployeeRepository()
		employeeProvider := resolver.NewEmployeeDataProvider(
			hrEmployeeRepo,
			f.ScheduleRepository(),
			f.logger,
		)
		f.employeeDataProvider = employeeProvider

		leaveRepo := leaverepo.NewLeaveRepository(f.postgresClient)
		leaveQuerySvc := hrleavesvc.NewLeaveQueryService(
			leaveRepo,
			hrEmployeeRepo,
			f.auditService,
		)
		leaveProvider := resolver.NewLeaveDataProvider(leaveQuerySvc, f.logger)
		f.leaveDataProvider = leaveProvider

		employeeResolver := resolver.NewEmployeeResolver(
			f.WorkCenterRepository(),
			f.ScheduleRepository(),
			f.PolicyRepository(),
			employeeProvider,
			leaveProvider,
			tzProvider,
			f.logger,
		)

		studentResolver := resolver.NewStudentResolver(
			f.StudentDataProvider(),
			f.EnrollmentDataProvider(),
			f.TimetableDataProvider(),
			f.SessionDataProvider(),
			f.WorkCenterRepository(),
			tzProvider,
			f.logger,
		)

		resolvers := map[string]resolver.SubjectResolver{
			"employee": employeeResolver,
			"student":  studentResolver,
		}

		if f.studentResolver != nil {
			resolvers["student"] = f.studentResolver
			f.logger.Info("Using externally provided student resolver")
		}

		if f.customerRepo != nil && f.subscriptionRepo != nil && f.trialRepo != nil {
			customerResolver := resolver.NewCustomerResolverWithSubscription(
				f.postgresClient.DB,
				f.customerRepo,
				f.subscriptionRepo,
				f.trialRepo,
				tzProvider,
				f.logger,
			)
			resolvers["customer"] = customerResolver
			f.logger.Info("Customer resolver with subscription checks enabled")
		} else {
			customerResolver := resolver.NewCustomerResolver(
				tzProvider,
				f.logger,
			)
			resolvers["customer"] = customerResolver
			f.logger.Info("Using fallback customer resolver (no subscription checks)")
		}

		f.subjectResolver = resolver.NewCompositeResolver(resolvers)
	}
	return f.subjectResolver
}

// scheduleSubjectResolverAdapter adapts SubjectResolver to ScheduleSubjectResolver.
//
// It also serves as the bridge to the leave repository for the two "fan-out"
// queries the resolver interface exposes:
//
//	GetActiveSubjectsByCompany → ListActiveEmployeeUserIDs
//	GetUsersByPosition         → ListActiveEmployeeUserIDsByPosition
//
// Those two methods used to be stubs returning empty slices. They now
// delegate to the leave repository, which owns the correct SQL for "active
// employee" and already handles the company scoping.
type scheduleSubjectResolverAdapter struct {
	subjectResolver resolver.SubjectResolver
	tzProvider      resolver.TimezoneProvider
	leaveRepo       leaverepo.LeaveRepository
	logger          *zap.Logger
}

func (a *scheduleSubjectResolverAdapter) ResolveSubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*resolver.ScheduleSubjectInfo, error) {
	resolved, err := a.subjectResolver.Resolve(ctx, companyID, subjectType, subjectID, date)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, err
	}

	companyTz := ""
	if a.tzProvider != nil {
		if tz, err := a.tzProvider.ResolveTimezone(ctx, companyID, nil, nil, nil); err == nil {
			companyTz = tz
		}
	}

	info := &resolver.ScheduleSubjectInfo{
		SubjectID:          subjectID,
		SubjectType:        subjectType,
		IsActive:           resolved.IsActive,
		PositionID:         resolved.PositionID,
		PositionTitle:      "",
		IsSchedulable:      resolved.ScheduleStatus == "working" || resolved.ScheduleStatus == "scheduled",
		AttendanceRequired: true,
		OvertimeAllowed:    false,
		DepartmentID:       resolved.DepartmentID,
		WorkCenterCode:     resolved.WorkCenterCode,
		WorkCenterName:     "",
		WorkCenterTimezone: resolved.Timezone,
		CompanyTimezone:    companyTz,
		CompanyID:          companyID,
	}
	return info, nil
}

func (a *scheduleSubjectResolverAdapter) ResolveOverride(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*resolver.ScheduleOverrideInfo, error) {
	resolved, err := a.subjectResolver.Resolve(ctx, companyID, subjectType, subjectID, date)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return &resolver.ScheduleOverrideInfo{IsOverride: false}, nil
	}
	var overrideType string
	if resolved.OverrideType != nil {
		overrideType = *resolved.OverrideType
	}
	return &resolver.ScheduleOverrideInfo{
		IsOverride:     resolved.IsOverride,
		OverrideType:   overrideType,
		IsOnLeave:      resolved.IsOnLeave,
		LeaveTypeID:    resolved.LeaveTypeID,
		IsLeavePaid:    resolved.IsLeavePaid,
		LeaveRequestID: resolved.LeaveRequestID,
	}, nil
}

// GetUsersByPosition — delegates to the leave repo, which owns the SQL for
// "active employees currently in a position". Company-scoped because
// position IDs are only unique per tenant.
func (a *scheduleSubjectResolverAdapter) GetUsersByPosition(
	ctx context.Context,
	companyID, positionID uuid.UUID,
) ([]uuid.UUID, error) {
	if a.leaveRepo == nil {
		return nil, errScheduleAdapterNoLeaveRepo
	}
	return a.leaveRepo.ListActiveEmployeeUserIDsByPosition(ctx, companyID, positionID)
}

// GetActiveSubjectsByCompany — delegates to the leave repo's
// ListActiveEmployeeUserIDs.
func (a *scheduleSubjectResolverAdapter) GetActiveSubjectsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
) ([]uuid.UUID, error) {
	if a.leaveRepo == nil {
		return nil, errScheduleAdapterNoLeaveRepo
	}
	return a.leaveRepo.ListActiveEmployeeUserIDs(ctx, companyID)
}

func (f *AttendanceFactory) ScheduleSubjectResolver() resolver.ScheduleSubjectResolver {
	if f.scheduleSubjectResolver == nil {
		subjectResolver := f.SubjectResolver()
		f.scheduleSubjectResolver = &scheduleSubjectResolverAdapter{
			subjectResolver: subjectResolver,
			tzProvider:      f.TimezoneProvider(),
			leaveRepo:       leaverepo.NewLeaveRepository(f.postgresClient),
			logger:          f.logger,
		}
	}
	return f.scheduleSubjectResolver
}

// ---------- Services ----------

type omServiceStub struct{}

func (s *omServiceStub) CanPunchAttendance(ctx context.Context, companyID uuid.UUID, actorID *uuid.UUID, subjectType string, subjectID uuid.UUID, sourceType string, workCenterCode *string) (bool, string) {
	return true, ""
}

func (f *AttendanceFactory) OMService() ingest.OMService {
	if f.omService == nil {
		f.omService = &omServiceStub{}
	}
	return f.omService
}

func (f *AttendanceFactory) AdminService() admin.AdminService {
	if f.adminService == nil {
		f.adminService = admin.NewAdminService(
			f.EventRepository(),
			f.PolicyRepository(),
			f.RuleRepository(),
			f.SourceRepository(),
			f.ScheduleRepository(),
			f.SubjectResolver(),
			f.logger,
			f.auditService,
		)
	}
	return f.adminService
}

func (f *AttendanceFactory) QueryService() query.QueryService {
	if f.queryService == nil {
		f.queryService = query.NewQueryService(
			f.EventRepository(),
			f.SummaryRepository(),
			f.SourceRepository(),
			f.PolicyRepository(),
			f.SessionSummaryRepository(),
			f.ExemptionRepository(),
			f.logger,
		)
	}
	return f.queryService
}

func (f *AttendanceFactory) IngestService() ingest.IngestService {
	if f.ingestService == nil {
		f.ingestService = ingest.NewIngestService(
			f.EventRepository(),
			f.DeviceRepository(),
			f.SourceRepository(),
			f.EnrollmentService(),
			f.SourceResolver(),
			f.AdminService(),
			f.OMService(),
			f.auditService,
			f.logger,
			f.SessionSummaryRepository(),
			f.usageIntegrationService,
			f.LocationResolver(),
			f.TimezoneProvider(),
		)
	}
	return f.ingestService
}

func (f *AttendanceFactory) CorrectionService() admin.CorrectionService {
	if f.correctionService == nil {
		f.correctionService = admin.NewCorrectionService(
			f.EventRepository(),
			f.SummaryRepository(),
			f.AdminService(),
			f.SubjectResolver(),
			f.LocationResolver(),
			f.ResolutionService(),
			f.logger,
			f.auditService,
			f.TimezoneProvider(),
		)
	}
	return f.correctionService
}

func (f *AttendanceFactory) ResolutionService() resolution.ResolutionService {
	if f.resolutionService == nil {
		f.resolutionService = resolution.NewResolutionService(
			f.EventRepository(),
			f.SummaryRepository(),
			f.ScheduleRepository(),
			f.PolicyRepository(),
			f.SubjectResolver(),
			f.LocationResolver(),
			f.AdminService(),
			f.ExemptionRepository(),
			f.logger,
			f.auditService,
			f.TimezoneProvider(),
		)
	}
	return f.resolutionService
}

func (f *AttendanceFactory) EnrollmentService() enrollment.EnrollmentService {
	if f.enrollmentService == nil {
		f.enrollmentService = enrollment.NewEnrollmentService(
			f.DeviceEnrollmentRepository(),
			f.DeviceRepository(),
			f.SourceRepository(),
			f.auditService,
			f.logger,
		)
	}
	return f.enrollmentService
}

func (f *AttendanceFactory) DeviceService() device.DeviceService {
	if f.deviceService == nil {
		f.deviceService = device.NewDeviceService(
			f.DeviceRepository(),
			f.logger,
		)
	}
	return f.deviceService
}

func (f *AttendanceFactory) TokenService() device.TokenService {
	if f.tokenService == nil {
		f.tokenService = device.NewTokenService(
			f.TokenRepository(),
			f.DeviceRepository(),
			f.postgresClient,
			f.logger,
			device.TokenServiceConfig{
				TokenPrefix:   f.deviceTokenPrefix,
				TokenSecret:   f.deviceTokenSecret,
				TokenValidity: f.deviceTokenValidity,
			},
		)
	}
	return f.tokenService
}

func (f *AttendanceFactory) HeartbeatService() device.HeartbeatService {
	if f.heartbeatService == nil {
		f.heartbeatService = device.NewHeartbeatService(
			f.HeartbeatRepository(),
			f.DeviceRepository(),
			f.logger,
		)
	}
	return f.heartbeatService
}

func (f *AttendanceFactory) BatchIngestService() batch.BatchIngestService {
	if f.batchIngestService == nil {
		f.batchIngestService = batch.NewBatchIngestService(
			f.BatchRepository(),
			f.outboxRepo,
			f.DeviceRepository(),
			f.IngestService(),
			f.EnrollmentService(),
			f.SubjectResolver(),
			f.logger,
		)
	}
	return f.batchIngestService
}

func (f *AttendanceFactory) BatchFailureService() batch.BatchFailureService {
	if f.batchFailureService == nil {
		f.batchFailureService = batch.NewBatchFailureService(
			f.BatchRepository(),
			f.logger,
		)
	}
	return f.batchFailureService
}

func (f *AttendanceFactory) SourceAdminService() source.SourceAdminService {
	if f.sourceAdminService == nil {
		f.sourceAdminService = source.NewSourceAdminService(
			f.SourceRepository(),
			f.auditService,
			f.logger,
		)
	}
	return f.sourceAdminService
}

func (f *AttendanceFactory) SourceResolver() source.SourceResolver {
	if f.sourceResolver == nil {
		f.sourceResolver = source.NewSourceResolver(f.logger)
	}
	return f.sourceResolver
}

// SchedulingService — no job repo, no generation. Reads + overrides only.
func (f *AttendanceFactory) SchedulingService() scheduling.SchedulingService {
	if f.schedulingService == nil {
		f.schedulingService = scheduling.NewSchedulingService(
			f.ScheduleRepository(),
			f.ScheduleSubjectResolver(),
			f.auditService,
			f.logger,
		)
	}
	return f.schedulingService
}

// SchedulingQueryService — the query side now takes the scheduling service
// so PreviewSchedule can reuse ResolveUserDay (single derivation path).
func (f *AttendanceFactory) SchedulingQueryService() scheduling.SchedulingQueryService {
	if f.schedulingQueryService == nil {
		f.schedulingQueryService = scheduling.NewSchedulingQueryService(
			f.ScheduleRepository(),
			f.ScheduleSubjectResolver(),
			f.TimezoneProvider(),
			f.SchedulingService(),
			f.logger,
		)
	}
	return f.schedulingQueryService
}

func (f *AttendanceFactory) WorkCenterService() workcenter.Service {
	if f.workCenterService == nil {
		f.workCenterService = workcenter.NewService(
			f.WorkCenterRepository(),
			f.auditService,
			f.logger,
		)
	}
	return f.workCenterService
}

func (f *AttendanceFactory) WorkCenterQueryService() workcenter.QueryService {
	if f.workCenterQueryService == nil {
		f.workCenterQueryService = workcenter.NewQueryService(
			f.WorkCenterRepository(),
		)
	}
	return f.workCenterQueryService
}

func (f *AttendanceFactory) ReportService() report.ReportService {
	if f.reportService == nil {
		f.reportService = report.NewReportService(
			f.QueryService(),
			f.logger,
		)
	}
	return f.reportService
}

func (f *AttendanceFactory) BiometricEnrollmentService() biometricSvc.BiometricEnrollmentService {
	if f.biometricEnrollmentSvc == nil {
		f.biometricEnrollmentSvc = biometricSvc.NewBiometricEnrollmentService(
			f.FaceEmbeddingRepository(),
			f.SubjectResolver(),
			f.auditService,
			f.logger,
		)
	}
	return f.biometricEnrollmentSvc
}

func (f *AttendanceFactory) BiometricSyncService() biometricSvc.BiometricSyncService {
	if f.biometricSyncSvc == nil {
		f.biometricSyncSvc = biometricSvc.NewBiometricSyncService(
			f.FaceEmbeddingRepository(),
			f.DeviceEmbeddingSyncRepository(),
			f.auditService,
			f.logger,
		)
	}
	return f.biometricSyncSvc
}

func (f *AttendanceFactory) ExemptionService() exemption.ExemptionService {
	if f.exemptionService == nil {
		f.exemptionService = exemption.NewExemptionService(
			f.ExemptionRepository(),
			f.LocationResolver(),
			f.auditService,
			f.logger,
		)
	}
	return f.exemptionService
}

// ---------- Outbox & Consumer ----------

func (f *AttendanceFactory) ResolutionConsumer() *consumer.AttendanceResolutionConsumer {
	if f.resolutionConsumer == nil && f.kafkaProducer != nil {
		kafkaConsumer, err := client.NewKafkaConsumer(
			f.cfg,
			"attendance.events",
			"attendance-resolution-consumer-group",
			f.logger,
		)
		if err != nil {
			f.logger.Error("Failed to create attendance resolution consumer", zap.Error(err))
			return nil
		}
		f.resolutionConsumer = consumer.NewAttendanceResolutionConsumer(
			kafkaConsumer,
			f.ResolutionService(),
			f.logger,
		)
	}
	return f.resolutionConsumer
}

// ---------- Handlers ----------

func (f *AttendanceFactory) IngestHandler() *handler.AttendanceIngestHandler {
	if f.ingestHandler == nil {
		f.ingestHandler = handler.NewAttendanceIngestHandler(
			f.IngestService(),
			f.logger,
		)
	}
	return f.ingestHandler
}

func (f *AttendanceFactory) AdminHandler() *handler.AttendanceAdminHandler {
	if f.adminHandler == nil {
		f.adminHandler = handler.NewAttendanceAdminHandler(
			f.AdminService(),
			f.QueryService(),
			f.auditService,
			f.logger,
		)
	}
	return f.adminHandler
}

func (f *AttendanceFactory) QueryHandler() *handler.AttendanceQueryHandler {
	if f.queryHandler == nil {
		f.queryHandler = handler.NewAttendanceQueryHandler(
			f.QueryService(),
			f.logger,
		)
	}
	return f.queryHandler
}

func (f *AttendanceFactory) ResolutionHandler() *handler.AttendanceResolutionHandler {
	if f.resolutionHandler == nil {
		f.resolutionHandler = handler.NewAttendanceResolutionHandler(
			f.ResolutionService(),
			f.logger,
		)
	}
	return f.resolutionHandler
}

func (f *AttendanceFactory) CorrectionHandler() *handler.AttendanceCorrectionHandler {
	if f.correctionHandler == nil {
		f.correctionHandler = handler.NewAttendanceCorrectionHandler(
			f.CorrectionService(),
			f.logger,
		)
	}
	return f.correctionHandler
}

func (f *AttendanceFactory) DeviceHandler() *handler.DeviceHandler {
	if f.deviceHandler == nil {
		f.deviceHandler = handler.NewDeviceHandler(
			f.DeviceService(),
			f.SourceAdminService(),
			f.auditService,
			f.logger,
		)
	}
	return f.deviceHandler
}

func (f *AttendanceFactory) EnrollmentHandler() *handler.AttendanceDeviceEnrollmentHandler {
	if f.enrollmentHandler == nil {
		f.enrollmentHandler = handler.NewAttendanceDeviceEnrollmentHandler(
			f.EnrollmentService(),
			f.logger,
		)
	}
	return f.enrollmentHandler
}

func (f *AttendanceFactory) TokenAdminHandler() *handler.DeviceTokenAdminHandler {
	if f.tokenAdminHandler == nil {
		f.tokenAdminHandler = handler.NewDeviceTokenAdminHandler(
			f.TokenService(),
			f.logger,
		)
	}
	return f.tokenAdminHandler
}

func (f *AttendanceFactory) HeartbeatHandler() *handler.DeviceHeartbeatHandler {
	if f.heartbeatHandler == nil {
		f.heartbeatHandler = handler.NewDeviceHeartbeatHandler(
			f.HeartbeatService(),
			f.logger,
		)
	}
	return f.heartbeatHandler
}

func (f *AttendanceFactory) BatchHandler() *handler.BatchHandler {
	if f.batchHandler == nil {
		f.batchHandler = handler.NewBatchHandler(
			f.BatchIngestService(),
			f.logger,
		)
	}
	return f.batchHandler
}

func (f *AttendanceFactory) SourceAdminHandler() *handler.AttendanceSourceAdminHandler {
	if f.sourceAdminHandler == nil {
		f.sourceAdminHandler = handler.NewAttendanceSourceAdminHandler(
			f.SourceAdminService(),
			f.logger,
		)
	}
	return f.sourceAdminHandler
}

func (f *AttendanceFactory) WorkCenterHandler() *handler.WorkCenterHandler {
	if f.workCenterHandler == nil {
		f.workCenterHandler = handler.NewWorkCenterHandler(
			f.WorkCenterService(),
			f.WorkCenterQueryService(),
			f.auditService,
			f.logger,
		)
	}
	return f.workCenterHandler
}

// SchedulingHandler — no longer takes the generation job repository.
func (f *AttendanceFactory) SchedulingHandler() *handler.SchedulingHandler {
	if f.schedulingHandler == nil {
		f.schedulingHandler = handler.NewSchedulingHandler(
			f.SchedulingService(),
			f.SchedulingQueryService(),
			f.logger,
		)
	}
	return f.schedulingHandler
}

func (f *AttendanceFactory) BiometricEnrollmentHandler() *handler.BiometricEnrollmentHandler {
	if f.biometricEnrollmentHandler == nil {
		f.biometricEnrollmentHandler = handler.NewBiometricEnrollmentHandler(
			f.BiometricEnrollmentService(),
			f.logger,
		)
	}
	return f.biometricEnrollmentHandler
}

func (f *AttendanceFactory) BiometricSyncHandler() *handler.BiometricSyncHandler {
	if f.biometricSyncHandler == nil {
		f.biometricSyncHandler = handler.NewBiometricSyncHandler(
			f.BiometricSyncService(),
			f.logger,
		)
	}
	return f.biometricSyncHandler
}

func (f *AttendanceFactory) ReportHandler() *handler.AttendanceReportHandler {
	if f.reportHandler == nil {
		f.reportHandler = handler.NewAttendanceReportHandler(
			f.ReportService(),
			f.QueryService(),
			f.logger,
		)
	}
	return f.reportHandler
}

func (f *AttendanceFactory) ExemptionHandler() *handler.AttendanceExemptionHandler {
	if f.exemptionHandler == nil {
		f.exemptionHandler = handler.NewAttendanceExemptionHandler(
			f.ExemptionService(),
			f.logger,
		)
	}
	return f.exemptionHandler
}

// ---------- Middleware ----------
func (f *AttendanceFactory) DeviceAuthMiddleware() *middleware.DeviceAuthMiddleware {
	if f.deviceAuthMiddleware == nil {
		f.deviceAuthMiddleware = middleware.NewDeviceAuthMiddleware(
			f.TokenService(),
			f.logger,
		)
	}
	return f.deviceAuthMiddleware
}

// ---------- Lifecycle ----------

// StartBackgroundServices brings up the attendance background consumers.
//
// The schedule-generation worker pool that used to start here has been
// removed. Schedules are derived on read, so there is nothing to generate
// in the background. The remaining consumer is the attendance-resolution
// consumer, which is Kafka-gated.
func (f *AttendanceFactory) StartBackgroundServices(ctx context.Context) {
	if f.kafkaProducer != nil {
		if consumer := f.ResolutionConsumer(); consumer != nil {
			consumerCtx, cancel := context.WithCancel(ctx)
			f.resolutionCancel = cancel
			go func() {
				if err := consumer.Start(consumerCtx); err != nil && err != context.Canceled {
					f.logger.Error("Attendance resolution consumer stopped with error", zap.Error(err))
				}
			}()
			f.logger.Info("Attendance resolution consumer started")
		}
	} else {
		f.logger.Warn("Kafka producer not available; Kafka-backed background services disabled")
	}
}

// StopBackgroundServices cancels the resolution consumer. There is no
// schedule-generation worker to stop anymore.
func (f *AttendanceFactory) StopBackgroundServices() {
	if f.resolutionCancel != nil {
		f.resolutionCancel()
		f.logger.Info("Stopped attendance resolution consumer")
	}
}
