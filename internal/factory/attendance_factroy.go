package factory

import (
	"context"
	"fmt"
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
	"auth-service/internal/attendance/service/ingest"
	"auth-service/internal/attendance/service/outbox"
	"auth-service/internal/attendance/service/query"
	"auth-service/internal/attendance/service/report"
	"auth-service/internal/attendance/service/resolution"
	"auth-service/internal/attendance/service/resolver"
	"auth-service/internal/attendance/service/scheduling"
	"auth-service/internal/attendance/service/source"
	"auth-service/internal/attendance/service/usage_integration" // added
	"auth-service/internal/attendance/service/workcenter"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/encryption"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	infraOutbox "auth-service/internal/infrastructure/outbox"

	// Academics imports – use the repository package, not postgres subpackage
	academicsRepo "auth-service/internal/academics/repository"

	// HR imports
	leaverepo "auth-service/internal/hr/leave/repository"
	hrleavesvc "auth-service/internal/hr/leave/service"
	hrpostgres "auth-service/internal/hr/repository"

	// Sales & Subscription imports (for customer resolver)
	salesRepo "auth-service/internal/sales/repository"
	subRepo "auth-service/internal/subscription/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AttendanceFactory centralizes creation and wiring of all attendance components.
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
	locationRepo       attendanceRepo.LocationRepository
	calendarRepo       attendanceRepo.CalendarRepository
	outboxRepoAtt      attendanceRepo.OutboxRepository

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

	// ---------- customer resolver dependencies ----------
	customerRepo     salesRepo.CustomerRepository
	subscriptionRepo subRepo.SubscriptionRepository
	trialRepo        subRepo.TrialRepository

	// ---------- usage integration service ----------
	usageIntegrationService *usage_integration.UsageIntegrationService // added

	// resolvers
	subjectResolver         resolver.SubjectResolver
	scheduleSubjectResolver resolver.ScheduleSubjectResolver
	studentResolver         resolver.SubjectResolver // external override (optional)

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

	// outbox & consumer
	outboxService        *outbox.OutboxService
	resolutionConsumer   *consumer.AttendanceResolutionConsumer
	batchOutboxProcessor *outbox.BatchOutboxProcessor

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
	outboxCancel      context.CancelFunc
	resolutionCancel  context.CancelFunc
	batchOutboxCancel context.CancelFunc
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
// SetCustomerResolverDependencies injects the repositories needed for customer resolution.
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
// SetUsageIntegrationService injects the usage integration service.
func (f *AttendanceFactory) SetUsageIntegrationService(svc *usage_integration.UsageIntegrationService) {
	f.usageIntegrationService = svc
	f.logger.Info("Usage integration service set")
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

func (f *AttendanceFactory) LocationRepository() attendanceRepo.LocationRepository {
	if f.locationRepo == nil {
		f.locationRepo = attendancePostgres.NewLocationRepository(f.postgresClient, f.logger)
	}
	return f.locationRepo
}

func (f *AttendanceFactory) CalendarRepository() attendanceRepo.CalendarRepository {
	if f.calendarRepo == nil {
		f.calendarRepo = attendancePostgres.NewCalendarRepository(f.postgresClient, f.logger)
	}
	return f.calendarRepo
}

func (f *AttendanceFactory) AttendanceOutboxRepository() attendanceRepo.OutboxRepository {
	if f.outboxRepoAtt == nil {
		f.outboxRepoAtt = attendancePostgres.NewOutboxRepository(f.postgresClient, f.logger)
	}
	return f.outboxRepoAtt
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

// ---------- Academic Repositories ----------
// These now use the encryption manager passed in.

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
		f.postgresClient.DB, // *sql.DB
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

// ---------- Resolvers ----------

// SetStudentResolver injects a student resolver into the factory.
// This is optional; if not set, the factory will create its own.
func (f *AttendanceFactory) SetStudentResolver(studentResolver resolver.SubjectResolver) {
	f.studentResolver = studentResolver
}

// SubjectResolver builds the composite resolver with all registered resolvers.
func (f *AttendanceFactory) SubjectResolver() resolver.SubjectResolver {
	if f.subjectResolver == nil {
		// 1. Employee resolver
		hrEmployeeRepo := hrpostgres.NewEmployeeRepository(f.postgresClient, f.logger)
		employeeProvider := resolver.NewEmployeeDataProvider(
			hrEmployeeRepo,
			f.ScheduleRepository(),
			f.logger,
		)
		f.employeeDataProvider = employeeProvider

		leaveRepo := leaverepo.NewLeaveRepository(f.postgresClient, f.logger)
		leaveQuerySvc := hrleavesvc.NewLeaveQueryService(leaveRepo, f.logger)
		leaveProvider := resolver.NewLeaveDataProvider(leaveQuerySvc, f.logger)
		f.leaveDataProvider = leaveProvider

		employeeResolver := resolver.NewEmployeeResolver(
			f.WorkCenterRepository(),
			f.ScheduleRepository(),
			f.PolicyRepository(),
			employeeProvider,
			leaveProvider,
			f.logger,
		)

		// 2. Student resolver (built internally)
		studentResolver := resolver.NewStudentResolver(
			f.StudentDataProvider(),
			f.EnrollmentDataProvider(),
			f.TimetableDataProvider(),
			f.SessionDataProvider(),
			f.WorkCenterRepository(),
			f.logger,
		)

		// 3. Build composite resolver
		resolvers := map[string]resolver.SubjectResolver{
			"employee": employeeResolver,
			"student":  studentResolver,
		}

		// If an external student resolver was set, override the built one
		if f.studentResolver != nil {
			resolvers["student"] = f.studentResolver
			f.logger.Info("Using externally provided student resolver")
		}

		// 4. Customer resolver (if dependencies are set)
		if f.customerRepo != nil && f.subscriptionRepo != nil && f.trialRepo != nil {
			customerResolver := resolver.NewCustomerResolverWithSubscription(
				f.postgresClient.DB,
				f.customerRepo,
				f.subscriptionRepo,
				f.trialRepo,
				f.logger,
			)
			resolvers["customer"] = customerResolver
			f.logger.Info("Customer resolver with subscription checks enabled")
		} else {
			// Fallback: use a simple stub that always returns active
			customerResolver := resolver.NewCustomerResolver(f.logger)
			resolvers["customer"] = customerResolver
			f.logger.Info("Using fallback customer resolver (no subscription checks)")
		}

		f.subjectResolver = resolver.NewCompositeResolver(resolvers)
	}
	return f.subjectResolver
}

// scheduleSubjectResolverAdapter adapts SubjectResolver to ScheduleSubjectResolver.
type scheduleSubjectResolverAdapter struct {
	subjectResolver resolver.SubjectResolver
	logger          *zap.Logger
}

func (a *scheduleSubjectResolverAdapter) ResolveSubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*resolver.ScheduleSubjectInfo, error) {
	a.logger.Info("ResolveSubject (adapter)",
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.String("date", date.Format("2006-01-02")),
	)
	resolved, err := a.subjectResolver.Resolve(ctx, companyID, subjectType, subjectID, date)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return nil, fmt.Errorf("resolve returned nil")
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
		CompanyID:          companyID,
	}
	a.logger.Info("Adapter result",
		zap.String("position_id", func() string {
			if info.PositionID != nil {
				return info.PositionID.String()
			}
			return "<nil>"
		}()),
		zap.String("work_center", func() string {
			if info.WorkCenterCode != nil {
				return *info.WorkCenterCode
			}
			return "<nil>"
		}()),
		zap.Bool("is_schedulable", info.IsSchedulable),
	)
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

func (a *scheduleSubjectResolverAdapter) GetUsersByPosition(ctx context.Context, positionID uuid.UUID) ([]uuid.UUID, error) {
	return []uuid.UUID{}, nil
}

func (a *scheduleSubjectResolverAdapter) GetActiveSubjectsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}) ([]uuid.UUID, error) {
	return []uuid.UUID{}, nil
}

// ScheduleSubjectResolver returns the adapter that uses the composite SubjectResolver.
func (f *AttendanceFactory) ScheduleSubjectResolver() resolver.ScheduleSubjectResolver {
	if f.scheduleSubjectResolver == nil {
		subjectResolver := f.SubjectResolver()
		f.scheduleSubjectResolver = &scheduleSubjectResolverAdapter{
			subjectResolver: subjectResolver,
			logger:          f.logger,
		}
	}
	return f.scheduleSubjectResolver
}

// ---------- Services ----------

// omServiceStub implements ingest.OMService.
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
			f.usageIntegrationService, // pass the usage integration service (may be nil)
		)
	}
	return f.ingestService
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

func (f *AttendanceFactory) ResolutionService() resolution.ResolutionService {
	if f.resolutionService == nil {
		f.resolutionService = resolution.NewResolutionService(
			f.EventRepository(),
			f.SummaryRepository(),
			f.ScheduleRepository(),
			f.PolicyRepository(),
			f.SubjectResolver(),
			f.AdminService(),
			f.ExemptionRepository(),
			f.logger,
			f.auditService,
		)
	}
	return f.resolutionService
}

func (f *AttendanceFactory) CorrectionService() admin.CorrectionService {
	if f.correctionService == nil {
		f.correctionService = admin.NewCorrectionService(
			f.EventRepository(),
			f.SummaryRepository(),
			f.AdminService(),
			f.SubjectResolver(),
			f.ResolutionService(),
			f.logger,
			f.auditService,
		)
	}
	return f.correctionService
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
			f.AttendanceOutboxRepository(),
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

func (f *AttendanceFactory) SchedulingQueryService() scheduling.SchedulingQueryService {
	if f.schedulingQueryService == nil {
		f.schedulingQueryService = scheduling.NewSchedulingQueryService(
			f.ScheduleRepository(),
			f.ScheduleSubjectResolver(),
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

// ---------- Outbox & Consumer ----------

func (f *AttendanceFactory) OutboxService() *outbox.OutboxService {
	if f.outboxService == nil && f.kafkaProducer != nil {
		f.outboxService = outbox.NewOutboxService(
			f.AttendanceOutboxRepository(),
			f.kafkaProducer,
			f.logger,
			100,
			5*time.Second,
			"attendance.events",
		)
	}
	return f.outboxService
}

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

func (f *AttendanceFactory) BatchOutboxProcessor() *outbox.BatchOutboxProcessor {
	if f.batchOutboxProcessor == nil && f.kafkaProducer != nil {
		f.batchOutboxProcessor = outbox.NewBatchOutboxProcessor(
			f.AttendanceOutboxRepository(),
			f.kafkaProducer,
			f.logger,
			100,
			2*time.Second,
		)
	}
	return f.batchOutboxProcessor
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
			f.ExemptionRepository(),
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

// StartBackgroundServices starts outbox, resolution consumer, and batch outbox processor.
func (f *AttendanceFactory) StartBackgroundServices(ctx context.Context) {
	if f.kafkaProducer != nil {
		if svc := f.OutboxService(); svc != nil {
			ctx, cancel := context.WithCancel(ctx)
			f.outboxCancel = cancel
			go func() {
				if err := svc.Start(ctx); err != nil && err != context.Canceled {
					f.logger.Error("Attendance outbox service stopped with error", zap.Error(err))
				}
			}()
			f.logger.Info("Attendance outbox service started")
		}

		if consumer := f.ResolutionConsumer(); consumer != nil {
			ctx, cancel := context.WithCancel(ctx)
			f.resolutionCancel = cancel
			go func() {
				if err := consumer.Start(ctx); err != nil && err != context.Canceled {
					f.logger.Error("Attendance resolution consumer stopped with error", zap.Error(err))
				}
			}()
			f.logger.Info("Attendance resolution consumer started")
		}

		if processor := f.BatchOutboxProcessor(); processor != nil {
			ctx, cancel := context.WithCancel(ctx)
			f.batchOutboxCancel = cancel
			go func() {
				processor.Start(ctx)
				f.logger.Info("Attendance batch outbox processor stopped")
			}()
			f.logger.Info("Attendance batch outbox processor started")
		}
	} else {
		f.logger.Warn("Kafka producer not available; background services disabled")
	}
}

// StopBackgroundServices cancels all background goroutines.
func (f *AttendanceFactory) StopBackgroundServices() {
	if f.outboxCancel != nil {
		f.outboxCancel()
		f.logger.Info("Stopped attendance outbox service")
	}
	if f.resolutionCancel != nil {
		f.resolutionCancel()
		f.logger.Info("Stopped attendance resolution consumer")
	}
	if f.batchOutboxCancel != nil {
		f.batchOutboxCancel()
		f.logger.Info("Stopped attendance batch outbox processor")
	}
}
