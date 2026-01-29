package factory

import (
	"auth-service/internal/bucketing"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/consumer"
	"auth-service/internal/encryption"
	"auth-service/internal/handler"
	"auth-service/internal/hashing"
	"auth-service/internal/hashing/pepperstore"
	b "auth-service/internal/hr/consumer"
	hrhandler "auth-service/internal/hr/handler"
	orgunithandler "auth-service/internal/hr/handler"
	hrpostgres "auth-service/internal/hr/repository"
	a "auth-service/internal/hr/service"
	orgunitservice "auth-service/internal/hr/service"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service"
	"auth-service/internal/sms"
	"auth-service/internal/tls"
	"auth-service/internal/util"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// ============================================================================
// FACTORY STRUCT
// ============================================================================

type Factory struct {
	config            *config.Config
	tlsManager        *tls.TLSManager
	redisClient       *client.RedisClient
	scyllaClient      *scylla.ScyllaClient
	kafkaProducer     *client.KafkaProducer
	esClient          *client.ESClient
	clickhouseClient  *client.ClickHouseClient
	hasher            *hashing.Hasher
	encryptionManager *encryption.EncryptionManager
	bucketingManager  *bucketing.BucketingManager
	pairingRepo       redis.PairingRepository
	pairingService    *service.PairingService
	wsService         *service.WebSocketService
	pairingHandler    *handler.PairingHandler
	wsHandler         *handler.WebSocketHandler
	qrUtil            *util.QRUtil
	hmacUtil          *util.HMACUtil

	// HR Repositories
	hrEmployeeRepository         hrpostgres.EmployeeRepository
	attendanceRepository         hrpostgres.AttendanceRepository
	leaveRepository              hrpostgres.LeaveRepository
	schedulingRepository         hrpostgres.SchedulingRepository
	compensationRepository       hrpostgres.CompensationRepository
	auditRepository              hrpostgres.AuditRepository
	workCenterRepository         hrpostgres.WorkCenterRepository
	orgUnitRepository            hrpostgres.OrgUnitRepository
	attendanceIdentityRepository hrpostgres.AttendanceIdentityRepository
	attendanceDeviceRepository   hrpostgres.AttendanceDeviceRepository
	// Attendance / Device Handlers
	attendanceDeviceHandler     *hrhandler.DeviceHandler
	attendanceAdminHandler      *hrhandler.AttendanceAdminHandler
	attendanceQueryHandler      *hrhandler.AttendanceQueryHandler
	attendanceResolutionHandler *hrhandler.AttendanceResolutionHandler
	attendanceCorrectionHandler *hrhandler.AttendanceCorrectionHandler

	// HR Services
	workCenterService        *a.WorkCenterService
	workCenterQueryService   *a.WorkCenterQueryService
	orgUnitService           *orgunitservice.OrgUnitService
	orgUnitQueryService      *orgunitservice.OrgUnitQueryService
	auditService             *a.AuditService
	auditQueryService        *a.AuditQueryService
	employeeQueryService     *a.EmployeeQueryService
	employeeService          *a.EmployeeService
	leaveService             a.LeaveService
	leaveQueryService        a.LeaveQueryService
	schedulingService        a.SchedulingService
	schedulingQueryService   a.SchedulingQueryService
	compensationService      a.CompensationService
	compensationQueryService a.CompensationQueryService

	// NEW ATTENDANCE SERVICES
	attendanceIngestService     a.AttendanceIngestService
	attendanceSourceResolver    a.AttendanceSourceResolver
	attendanceAdminService      a.AttendanceAdminService
	attendanceQueryService      a.AttendanceQueryService
	attendanceDeviceService     a.AttendanceDeviceService
	attendanceResolutionService a.AttendanceResolutionService

	// Attendance Pipeline
	attendanceOutboxService      *a.AttendanceOutboxService
	attendanceOutboxCancel       context.CancelFunc
	attendanceResolutionConsumer *b.AttendanceResolutionConsumer
	attendanceResolutionCancel   context.CancelFunc

	// Document Storage
	documentStorage a.DocumentStorage

	// Handlers
	attendanceIngestHandler *hrhandler.AttendanceIngestHandler
	workCenterHandler       *hrhandler.WorkCenterHandler
	orgUnitHandler          *orgunithandler.OrgUnitHandler
	hrAuditHandler          *hrhandler.AuditHandler
	hrEmployeeHandler       *hrhandler.EmployeeHandler
	hrCompensationHandler   *hrhandler.CompensationHandler
	hrLeaveHandler          *hrhandler.LeaveHandler
	hrSchedulingHandler     *hrhandler.SchedulingHandler

	// Core Services
	postgresClient            *client.PostgresClient
	postgresUserRepository    postgres.UserRepository
	postgresCompanyRepository postgres.CompanyRepository
	smsManager                *sms.SMSManager
	serviceFactory            *service.ServiceFactory
	adminDeviceRepo           *scylla.AdminDeviceRepositoryImpl
	adminDeviceTrustRepo      scylla.AdminDeviceTrustRepository
	adminMPINRepo             *scylla.AdminMPINRepositoryImpl
	adminDeviceHistoryRepo    *scylla.AdminDeviceHistoryRepositoryImpl
	userOTPService            *service.UserOTPService
	companyService            *service.CompanyService
	adminDeviceService        *service.AdminDeviceService
	adminMPINService          *service.AdminMPINService
	userService               *service.UserService
	mpinRepository            scylla.MPINRepository
	mpinService               *service.MPINService
	pepperStoreRepo           pepperstore.PepperStore
	deviceTrustRepo           scylla.DeviceTrustRepository
	otpRepository             scylla.OTPRepository
	otpService                *service.OTPService
	sessionRepo               redis.SessionRepository
	sessionService            *service.SessionService
	deviceRepository          scylla.DeviceRepository
	deviceService             *service.DeviceService
	deviceHistoryRepo         *scylla.DeviceHistoryRepositoryImpl
	kafkaLoggingMgr           *KafkaLoggingManager
	adminRepository           postgres.AdminRepository
	adminService              *service.AdminService
	jwtService                *service.JWTService
	rbacInitService           *service.RBACInitService
	authHandler               *handler.AuthHandler
	router                    chi.Router
	logger                    *zap.Logger

	// Audit Outbox
	auditOutboxService *service.AuditOutboxService
	auditOutboxCancel  context.CancelFunc

	once      sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

// ============================================================================
// KAFKA LOGGING MANAGER
// ============================================================================

type KafkaLoggingManager struct {
	producer   *service.LogProducerService
	esConsumer *consumer.ESConsumer
	chConsumer *consumer.ClickHouseConsumer
	cancelCtx  context.CancelFunc
	wg         sync.WaitGroup
	logger     *zap.Logger
}

func (m *KafkaLoggingManager) Shutdown() error {
	if m == nil {
		return nil
	}

	m.logger.Info("Shutting down Kafka logging manager...")

	if m.cancelCtx != nil {
		m.cancelCtx()
	}

	m.wg.Wait()

	if m.producer != nil {
		if err := m.producer.Close(); err != nil {
			m.logger.Error("Failed to close log producer", zap.Error(err))
		}
	}

	m.logger.Info("Kafka logging manager shut down successfully")
	return nil
}

func (m *KafkaLoggingManager) GetLogProducerService() *service.LogProducerService {
	return m.producer
}

func (m *KafkaLoggingManager) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	if m == nil {
		errs["kafka_logging_manager"] = fmt.Errorf("kafka logging manager not initialized")
		return errs
	}

	if m.producer == nil {
		errs["kafka_producer"] = fmt.Errorf("kafka producer not initialized")
	}

	if m.esConsumer != nil {
		if err := m.esConsumer.Health(ctx); err != nil {
			errs["es_consumer"] = err
		}
	}

	if m.chConsumer != nil {
		if err := m.chConsumer.Health(ctx); err != nil {
			errs["clickhouse_consumer"] = err
		}
	}

	return errs
}

// ============================================================================
// FACTORY INITIALIZATION
// ============================================================================

func NewFactory() (*Factory, error) {
	cfg := config.LoadConfig()
	util.Init(cfg.Environment, cfg.Logging.Level, cfg.Logging.Format)
	logger := util.Get()

	f := &Factory{
		config: cfg,
		closed: make(chan struct{}),
		logger: logger,
	}

	// Initialize TLS if enabled
	if cfg.Server.EnableTLS {
		tlsConfig := &tls.TLSConfig{
			EnableTLS: cfg.Server.EnableTLS,
			CertFile:  cfg.Server.CertFile,
			KeyFile:   cfg.Server.KeyFile,
		}
		f.tlsManager = tls.NewTLSManager(tlsConfig)
	}

	// Initialize clients
	if err := f.initializeClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}

	// Initialize managers
	f.initializeManagers()

	// Initialize Kafka logging
	kafkaLoggingMgr, err := f.InitializeKafkaLogging()
	if err != nil {
		logger.Error("failed to initialize Kafka logging", zap.Error(err))
	}
	f.kafkaLoggingMgr = kafkaLoggingMgr

	// Initialize RBAC permission registry
	ctx := context.Background()
	if err := f.InitializeRBAC(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}

	// Initialize document storage
	if err := f.initializeDocumentStorage(); err != nil {
		return nil, err
	}

	// Start audit outbox service
	if outbox := f.GetAuditOutboxService(); outbox != nil {
		ctx, cancel := context.WithCancel(context.Background())
		f.auditOutboxCancel = cancel

		go func() {
			if err := outbox.Start(ctx); err != nil {
				f.logger.Error(
					"Audit outbox service stopped with error",
					zap.Error(err),
				)
			}
		}()

		f.logger.Info("Audit outbox service started")
	}

	// Initialize attendance outbox
	if err := f.initializeAttendanceOutbox(); err != nil {
		f.logger.Error("Failed to initialize attendance outbox", zap.Error(err))
	}

	util.Info("Factory initialized successfully",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.Bool("kms_enabled", cfg.KMS.Enabled),
		util.Bool("kafka_logging_enabled", f.kafkaLoggingMgr != nil),
		util.Bool("rbac_initialized", true),
	)

	return f, nil
}

// ============================================================================
// ATTENDANCE SERVICES
// ============================================================================

// GetAttendanceIngestService returns the attendance ingest service
func (f *Factory) GetAttendanceIngestService() a.AttendanceIngestService {
	if f.attendanceIngestService == nil {
		f.attendanceIngestService = a.NewAttendanceIngestService(
			f.AttendanceRepository(),
			f.AttendanceDeviceRepository(),
			f.AttendanceIdentityRepository(),
			f.GetAttendanceSourceResolver(),
			f.logger,
		)
	}
	return f.attendanceIngestService
}

// GetAttendanceSourceResolver returns the attendance source resolver
func (f *Factory) GetAttendanceSourceResolver() a.AttendanceSourceResolver {
	if f.attendanceSourceResolver == nil {
		f.attendanceSourceResolver = a.NewAttendanceSourceResolver(
			f.AttendanceRepository(),
			f.logger,
		)
	}
	return f.attendanceSourceResolver
}

// GetAttendanceAdminService returns the attendance admin service
func (f *Factory) GetAttendanceAdminService() a.AttendanceAdminService {
	if f.attendanceAdminService == nil {
		f.attendanceAdminService = a.NewAttendanceAdminService(
			f.AttendanceRepository(),
			f.GetSchedulingRepository(),
			f.GetAttendanceResolutionService(), // 🔥 REQUIRED
			f.logger,
			f.GetAuditService(),
		)
	}
	return f.attendanceAdminService
}

// GetAttendanceQueryService returns the attendance query service
func (f *Factory) GetAttendanceQueryService() a.AttendanceQueryService {
	if f.attendanceQueryService == nil {
		f.attendanceQueryService = a.NewAttendanceQueryService(
			f.AttendanceRepository(),
			f.logger,
		)
	}
	return f.attendanceQueryService
}

// GetAttendanceDeviceService returns the attendance device service
func (f *Factory) GetAttendanceDeviceService() a.AttendanceDeviceService {
	if f.attendanceDeviceService == nil {
		f.attendanceDeviceService = a.NewAttendanceDeviceService(
			f.AttendanceDeviceRepository(),
			f.AttendanceRepository(),
			f.logger,
		)
	}
	return f.attendanceDeviceService
}

// GetAttendanceResolutionService returns the attendance resolution service
func (f *Factory) GetAttendanceResolutionService() a.AttendanceResolutionService {
	if f.attendanceResolutionService == nil {
		f.attendanceResolutionService = a.NewAttendanceResolutionService(
			f.AttendanceRepository(),
			f.GetSchedulingQueryService(),
			f.GetSchedulingService(),
			f.logger,
		)
	}
	return f.attendanceResolutionService
}

// ============================================================================
// ATTENDANCE REPOSITORIES
// ============================================================================

func (f *Factory) AttendanceRepository() hrpostgres.AttendanceRepository {
	if f.attendanceRepository == nil {
		f.attendanceRepository = hrpostgres.NewAttendanceRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.attendanceRepository
}

func (f *Factory) AttendanceDeviceRepository() hrpostgres.AttendanceDeviceRepository {
	if f.attendanceDeviceRepository == nil {
		f.attendanceDeviceRepository = hrpostgres.NewAttendanceDeviceRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.attendanceDeviceRepository
}

func (f *Factory) AttendanceIdentityRepository() hrpostgres.AttendanceIdentityRepository {
	if f.attendanceIdentityRepository == nil {
		f.attendanceIdentityRepository = hrpostgres.NewAttendanceIdentityRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.attendanceIdentityRepository
}

// ============================================================================
// ATTENDANCE OUTBOX INITIALIZATION
// ============================================================================

func (f *Factory) initializeAttendanceOutbox() error {
	if f.kafkaProducer == nil {
		f.logger.Warn("Kafka producer not available, attendance outbox disabled")
		return nil
	}

	// Create attendance outbox service
	f.attendanceOutboxService = a.NewAttendanceOutboxService(
		f.PostgresClient(),
		f.kafkaProducer,
		500,                 // batch size
		2*time.Second,       // poll interval
		"attendance.events", // topic name
	)

	// Start attendance outbox service
	ctx, cancel := context.WithCancel(context.Background())
	f.attendanceOutboxCancel = cancel
	go func() {
		if err := f.attendanceOutboxService.Start(ctx); err != nil {
			f.logger.Error("Attendance outbox service stopped with error",
				zap.Error(err),
			)
		}
	}()
	f.logger.Info("Attendance outbox service started")

	// Create Kafka consumer for attendance resolution
	kafkaConsumer, err := client.NewKafkaConsumer(
		f.config,
		"attendance.events",
		"attendance-resolution-consumer-group",
		f.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create attendance kafka consumer: %w", err)
	}

	// Create attendance resolution consumer
	resolutionService := f.GetAttendanceResolutionService()
	f.attendanceResolutionConsumer = b.NewAttendanceResolutionConsumer(
		kafkaConsumer,
		resolutionService,
		f.logger,
	)

	// Start attendance resolution consumer
	ctx2, cancel2 := context.WithCancel(context.Background())
	f.attendanceResolutionCancel = cancel2
	go func() {
		if err := f.attendanceResolutionConsumer.Start(ctx2); err != nil {
			f.logger.Error("Attendance resolution consumer stopped with error",
				zap.Error(err),
			)
		}
	}()
	f.logger.Info("Attendance resolution consumer started")

	return nil
}

// ============================================================================
// ATTENDANCE HANDLERS
// ============================================================================

func (f *Factory) GetAttendanceIngestHandler() *hrhandler.AttendanceIngestHandler {
	if f.attendanceIngestHandler == nil {
		f.attendanceIngestHandler = hrhandler.NewAttendanceIngestHandler(
			f.GetAttendanceIngestService(),
			f.logger,
		)
	}
	return f.attendanceIngestHandler
}

// ============================================================================
// HR REPOSITORIES
// ============================================================================

func (f *Factory) HREmployeeRepository() hrpostgres.EmployeeRepository {
	if f.hrEmployeeRepository == nil {
		f.hrEmployeeRepository = hrpostgres.NewEmployeeRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.hrEmployeeRepository
}

func (f *Factory) LeaveRepository() hrpostgres.LeaveRepository {
	if f.leaveRepository == nil {
		f.leaveRepository = hrpostgres.NewLeaveRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.leaveRepository
}

func (f *Factory) GetSchedulingRepository() hrpostgres.SchedulingRepository {
	if f.schedulingRepository == nil {
		f.schedulingRepository = hrpostgres.NewSchedulingRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.schedulingRepository
}

func (f *Factory) CompensationRepository() hrpostgres.CompensationRepository {
	if f.compensationRepository == nil {
		f.compensationRepository = hrpostgres.NewCompensationRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.compensationRepository
}

func (f *Factory) AuditRepository() hrpostgres.AuditRepository {
	if f.auditRepository == nil {
		f.auditRepository = hrpostgres.NewAuditRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.auditRepository
}

func (f *Factory) WorkCenterRepository() hrpostgres.WorkCenterRepository {
	if f.workCenterRepository == nil {
		f.workCenterRepository = hrpostgres.NewWorkCenterRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.workCenterRepository
}

func (f *Factory) GetAttendanceDeviceHandler() *hrhandler.DeviceHandler {
	if f.attendanceDeviceHandler == nil {
		f.attendanceDeviceHandler = hrhandler.NewDeviceHandler(
			f.GetAttendanceDeviceService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.attendanceDeviceHandler
}
func (f *Factory) GetAttendanceAdminHandler() *hrhandler.AttendanceAdminHandler {
	if f.attendanceAdminHandler == nil {
		f.attendanceAdminHandler = hrhandler.NewAttendanceAdminHandler(
			f.GetAttendanceAdminService(),
			f.GetAttendanceQueryService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.attendanceAdminHandler
}
func (f *Factory) GetAttendanceQueryHandler() *hrhandler.AttendanceQueryHandler {
	if f.attendanceQueryHandler == nil {
		f.attendanceQueryHandler = hrhandler.NewAttendanceQueryHandler(
			f.GetAttendanceQueryService(),
			f.logger,
		)
	}
	return f.attendanceQueryHandler
}
func (f *Factory) GetAttendanceResolutionHandler() *hrhandler.AttendanceResolutionHandler {
	if f.attendanceResolutionHandler == nil {
		f.attendanceResolutionHandler = hrhandler.NewAttendanceResolutionHandler(
			f.GetAttendanceResolutionService(),
			f.logger,
		)
	}
	return f.attendanceResolutionHandler
}

func (f *Factory) OrgUnitRepository() hrpostgres.OrgUnitRepository {
	if f.orgUnitRepository == nil {
		f.orgUnitRepository = hrpostgres.NewOrgUnitRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.orgUnitRepository
}

// ============================================================================
// HR SERVICES
// ============================================================================

func (f *Factory) GetEmployeeService() *a.EmployeeService {
	if f.employeeService == nil {
		f.employeeService = a.NewEmployeeService(
			f.HREmployeeRepository(),
			f.GetAuditService(),
			a.EmployeeServiceConfig{
				MaxDocumentSizeMB: f.config.HR.Documents.MaxSizeMB,
				DocumentStorage:   f.DocumentStorage(),
			},
			f.logger,
		)
	}
	return f.employeeService
}

func (f *Factory) GetEmployeeQueryService() *a.EmployeeQueryService {
	if f.employeeQueryService == nil {
		f.employeeQueryService = a.NewEmployeeQueryService(
			f.HREmployeeRepository(),
			f.DocumentStorage(),
			f.logger,
		)
	}
	return f.employeeQueryService
}

func (f *Factory) GetLeaveService() a.LeaveService {
	if f.leaveService == nil {
		f.leaveService = a.NewLeaveService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveService
}

func (f *Factory) GetLeaveQueryService() a.LeaveQueryService {
	if f.leaveQueryService == nil {
		f.leaveQueryService = a.NewLeaveQueryService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveQueryService
}

func (f *Factory) GetSchedulingService() a.SchedulingService {
	if f.schedulingService == nil {
		f.schedulingService = a.NewSchedulingService(
			f.GetSchedulingRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.schedulingService
}

func (f *Factory) GetSchedulingQueryService() a.SchedulingQueryService {
	if f.schedulingQueryService == nil {
		f.schedulingQueryService = a.NewSchedulingQueryService(
			f.GetSchedulingRepository(),
			f.logger,
		)
	}
	return f.schedulingQueryService
}

func (f *Factory) GetCompensationService() a.CompensationService {
	if f.compensationService == nil {
		f.compensationService = a.NewCompensationService(
			f.CompensationRepository(),
			f.AuditRepository(),
			f.logger,
		)
	}
	return f.compensationService
}

func (f *Factory) GetCompensationQueryService() a.CompensationQueryService {
	if f.compensationQueryService == nil {
		f.compensationQueryService = a.NewCompensationQueryService(
			f.CompensationRepository(),
			f.logger,
		)
	}
	return f.compensationQueryService
}

func (f *Factory) GetWorkCenterService() *a.WorkCenterService {
	if f.workCenterService == nil {
		f.workCenterService = a.NewWorkCenterService(
			f.WorkCenterRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.workCenterService
}

func (f *Factory) GetWorkCenterQueryService() *a.WorkCenterQueryService {
	if f.workCenterQueryService == nil {
		f.workCenterQueryService = a.NewWorkCenterQueryService(
			f.WorkCenterRepository(),
			f.logger,
		)
	}
	return f.workCenterQueryService
}

func (f *Factory) GetOrgUnitService() *orgunitservice.OrgUnitService {
	if f.orgUnitService == nil {
		f.orgUnitService = orgunitservice.NewOrgUnitService(
			f.OrgUnitRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.orgUnitService
}

func (f *Factory) GetOrgUnitQueryService() *orgunitservice.OrgUnitQueryService {
	if f.orgUnitQueryService == nil {
		f.orgUnitQueryService = orgunitservice.NewOrgUnitQueryService(
			f.OrgUnitRepository(),
			f.logger,
		)
	}
	return f.orgUnitQueryService
}

func (f *Factory) GetAuditService() *a.AuditService {
	if f.auditService == nil {
		f.auditService = a.NewAuditService(
			f.AuditRepository(),
			f.logger,
		)
	}
	return f.auditService
}

func (f *Factory) GetAuditQueryService() *a.AuditQueryService {
	if f.auditQueryService == nil {
		f.auditQueryService = a.NewAuditQueryService(
			f.AuditRepository(),
			f.logger,
		)
	}
	return f.auditQueryService
}

// ============================================================================
// HR HANDLERS
// ============================================================================

func (f *Factory) GetWorkCenterHandler() *hrhandler.WorkCenterHandler {
	if f.workCenterHandler == nil {
		f.workCenterHandler = hrhandler.NewWorkCenterHandler(
			f.GetWorkCenterService(),
			f.GetWorkCenterQueryService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.workCenterHandler
}

func (f *Factory) GetOrgUnitHandler() *orgunithandler.OrgUnitHandler {
	if f.orgUnitHandler == nil {
		f.orgUnitHandler = orgunithandler.NewOrgUnitHandler(
			f.GetOrgUnitService(),
			f.GetOrgUnitQueryService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.orgUnitHandler
}

func (f *Factory) GetHRAuditHandler() *hrhandler.AuditHandler {
	if f.hrAuditHandler == nil {
		f.hrAuditHandler = hrhandler.NewAuditHandler(
			f.GetAuditQueryService(),
			f.logger,
		)
	}
	return f.hrAuditHandler
}

func (f *Factory) GetHREmployeeHandler() *hrhandler.EmployeeHandler {
	if f.hrEmployeeHandler == nil {
		f.hrEmployeeHandler = hrhandler.NewEmployeeHandler(
			f.GetEmployeeService(),
			f.GetEmployeeQueryService(),
			f.GetAuditService(),
			f.logger,
			f.config.HR.Documents.MaxSizeMB,
		)
	}
	return f.hrEmployeeHandler
}

func (f *Factory) GetHRCompensationHandler() *hrhandler.CompensationHandler {
	if f.hrCompensationHandler == nil {
		f.hrCompensationHandler = hrhandler.NewCompensationHandler(
			f.GetCompensationService(),
			f.GetCompensationQueryService(),
			f.logger,
		)
	}
	return f.hrCompensationHandler
}

func (f *Factory) GetHRLeaveHandler() *hrhandler.LeaveHandler {
	if f.hrLeaveHandler == nil {
		f.hrLeaveHandler = hrhandler.NewLeaveHandler(
			f.GetLeaveService(),
			f.GetLeaveQueryService(),
			f.logger,
		)
	}
	return f.hrLeaveHandler
}

func (f *Factory) GetHRSchedulingHandler() *hrhandler.SchedulingHandler {
	if f.hrSchedulingHandler == nil {
		f.hrSchedulingHandler = hrhandler.NewSchedulingHandler(
			f.GetSchedulingService(),
			f.GetSchedulingQueryService(),
			f.logger,
		)
	}
	return f.hrSchedulingHandler
}
func (f *Factory) GetAttendanceCorrectionHandler() *hrhandler.AttendanceCorrectionHandler {
	if f.attendanceCorrectionHandler == nil {
		f.attendanceCorrectionHandler = hrhandler.NewAttendanceCorrectionHandler(
			f.GetAttendanceAdminService(),
			f.logger,
		)
	}
	return f.attendanceCorrectionHandler
}

// ============================================================================
// DOCUMENT STORAGE
// ============================================================================

func (f *Factory) initializeDocumentStorage() error {
	cfg := f.config

	basePath := cfg.HR.Documents.BasePath
	maxSizeMB := cfg.HR.Documents.MaxSizeMB

	ds, err := a.NewLocalDocumentStorage(
		basePath,
		maxSizeMB,
		f.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize document storage: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ds.HealthCheck(ctx); err != nil {
		return fmt.Errorf("document storage health check failed: %w", err)
	}

	f.documentStorage = ds
	util.Info("Document storage initialized",
		util.String("base_path", basePath),
		util.Int("max_size_mb", maxSizeMB),
	)

	return nil
}

func (f *Factory) DocumentStorage() a.DocumentStorage {
	if f.documentStorage == nil {
		f.logger.Fatal("Document storage not initialized")
	}
	return f.documentStorage
}

// ============================================================================
// KAFKA LOGGING INITIALIZATION
// ============================================================================

func (f *Factory) InitializeKafkaLogging() (*KafkaLoggingManager, error) {
	logger := util.Get()

	if len(f.config.Kafka.Brokers) == 0 {
		logger.Warn("Kafka brokers not configured, logging to stdout only")
		return nil, nil
	}

	kafkaProducer, err := client.NewKafkaProducer(f.config, logger)
	if err != nil {
		logger.Error("failed to initialize Kafka producer", zap.Error(err))
		return nil, err
	}
	f.kafkaProducer = kafkaProducer

	logProducer := service.NewLogProducerService(
		kafkaProducer,
		f.config.Environment,
		"v1.0.0",
	)

	consumerCtx, cancel := context.WithCancel(context.Background())

	mgr := &KafkaLoggingManager{
		producer:  logProducer,
		cancelCtx: cancel,
		logger:    logger,
	}

	// Elasticsearch consumer
	if f.config.Elasticsearch.URL != "" && f.esClient != nil {
		esTopics := []string{
			"admin-events",
			"user-events",
			"security-events",
			"session-events",
		}

		esConsumers := make(map[string]*client.KafkaConsumer)

		for _, topic := range esTopics {
			kafkaConsumer, err := client.NewKafkaConsumer(
				f.config,
				topic,
				"es-consumer-group",
				logger,
			)
			if err != nil {
				logger.Error("failed to create Elasticsearch Kafka consumer",
					zap.String("topic", topic),
					zap.Error(err))
				continue
			}
			esConsumers[topic] = kafkaConsumer
		}

		if len(esConsumers) > 0 {
			esConsumer, err := consumer.NewESConsumer(
				esConsumers,
				f.esClient.Client,
			)
			if err != nil {
				logger.Error("failed to create Elasticsearch consumer", zap.Error(err))
			} else {
				mgr.esConsumer = esConsumer
				mgr.wg.Add(1)
				go func() {
					defer mgr.wg.Done()
					if err := esConsumer.Start(consumerCtx); err != nil {
						logger.Error("ES consumer error", zap.Error(err))
					}
				}()
				logger.Info("Elasticsearch multi-topic consumer started for search events",
					zap.Int("topic_count", len(esConsumers)),
					zap.Strings("topics", esTopics))
			}
		}
	}

	// ClickHouse consumer
	if f.config.Clickhouse.URL != "" && f.clickhouseClient != nil {
		chTopics := []string{
			"device-events",
			"mpin-events",
			"otp-events",
			"security-events",
		}

		chConsumers := make(map[string]*client.KafkaConsumer)

		for _, topic := range chTopics {
			kafkaConsumer, err := client.NewKafkaConsumer(
				f.config,
				topic,
				"clickhouse-consumer-group",
				logger,
			)
			if err != nil {
				logger.Error("failed to create ClickHouse Kafka consumer",
					zap.String("topic", topic),
					zap.Error(err))
				continue
			}
			chConsumers[topic] = kafkaConsumer
		}

		if len(chConsumers) > 0 {
			chConsumer := consumer.NewClickHouseConsumer(
				chConsumers,
				f.clickhouseClient,
				1000,
				5*time.Second,
			)
			mgr.chConsumer = chConsumer
			mgr.wg.Add(1)
			go func() {
				defer mgr.wg.Done()
				if err := chConsumer.Start(consumerCtx); err != nil {
					logger.Error("ClickHouse consumer error", zap.Error(err))
				}
			}()
			logger.Info("ClickHouse multi-topic consumer started for time-series events",
				zap.Int("topic_count", len(chConsumers)),
				zap.Strings("topics", chTopics))
		}
	}

	logger.Info("Kafka logging system initialized with optimized event distribution",
		zap.Bool("es_enabled", mgr.esConsumer != nil),
		zap.Bool("ch_enabled", mgr.chConsumer != nil),
	)

	return mgr, nil
}

// ============================================================================
// AUDIT OUTBOX SERVICE
// ============================================================================

func (f *Factory) GetAuditOutboxService() *service.AuditOutboxService {
	if f.auditOutboxService == nil {
		if f.kafkaProducer == nil {
			f.logger.Warn("Kafka producer not available, audit outbox disabled")
			return nil
		}

		f.auditOutboxService = service.NewAuditOutboxService(
			f.PostgresClient(),
			f.kafkaProducer,
			500,
			5*time.Second,
			"audit-logs",
		)
	}
	return f.auditOutboxService
}

// ============================================================================
// ADMIN REPOSITORIES
// ============================================================================

func (f *Factory) AdminDeviceRepository() *scylla.AdminDeviceRepositoryImpl {
	if f.adminDeviceRepo == nil {
		f.adminDeviceRepo = scylla.NewAdminDeviceRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminDeviceRepo
}

func (f *Factory) AdminDeviceTrustRepository() scylla.AdminDeviceTrustRepository {
	if f.adminDeviceTrustRepo == nil {
		f.adminDeviceTrustRepo = scylla.NewAdminDeviceTrustRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminDeviceTrustRepo
}

func (f *Factory) AdminMPINRepository() *scylla.AdminMPINRepositoryImpl {
	if f.adminMPINRepo == nil {
		f.adminMPINRepo = scylla.NewAdminMPINRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminMPINRepo
}

func (f *Factory) AdminDeviceHistoryRepository() *scylla.AdminDeviceHistoryRepositoryImpl {
	if f.adminDeviceHistoryRepo == nil {
		f.adminDeviceHistoryRepo = scylla.NewAdminDeviceHistoryRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminDeviceHistoryRepo
}

// ============================================================================
// CORE REPOSITORIES
// ============================================================================

func (f *Factory) PostgresClient() *client.PostgresClient {
	if f.postgresClient == nil {
		client, err := client.NewPostgresClient(f.config, f.logger)
		if err != nil {
			f.logger.Fatal("Failed to initialize PostgreSQL client", zap.Error(err))
		}
		f.postgresClient = client
	}
	return f.postgresClient
}

func (f *Factory) UserRepository() postgres.UserRepository {
	if f.postgresUserRepository == nil {
		f.postgresUserRepository = postgres.NewUserRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresUserRepository
}

func (f *Factory) CompanyRepository() postgres.CompanyRepository {
	if f.postgresCompanyRepository == nil {
		f.postgresCompanyRepository = postgres.NewCompanyRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresCompanyRepository
}

func (f *Factory) PepperStoreRepository() pepperstore.PepperStore {
	if f.pepperStoreRepo == nil {
		f.pepperStoreRepo = scylla.NewPepperStoreRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.pepperStoreRepo
}

func (f *Factory) OTPRepository() scylla.OTPRepository {
	if f.otpRepository == nil {
		f.otpRepository = scylla.NewOTPRepository(
			f.ScyllaClient(),
			f.Hasher(),
			f.BucketingManager(),
			f.logger,
		)
	}
	return f.otpRepository
}

func (f *Factory) MPINRepository() scylla.MPINRepository {
	if f.mpinRepository == nil {
		f.mpinRepository = scylla.NewMPINRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.mpinRepository
}

func (f *Factory) GetDeviceTrustRepository() scylla.DeviceTrustRepository {
	if f.deviceTrustRepo == nil {
		f.deviceTrustRepo = scylla.NewDeviceTrustRepository(f.scyllaClient, f.logger)
	}
	return f.deviceTrustRepo
}

func (f *Factory) SessionRepository() redis.SessionRepository {
	if f.sessionRepo == nil {
		f.sessionRepo = redis.NewSessionRepository(
			f.redisClient.Client(),
			f.logger,
		)
	}
	return f.sessionRepo
}

func (f *Factory) DeviceRepository() scylla.DeviceRepository {
	if f.deviceRepository == nil {
		f.deviceRepository = scylla.NewDeviceRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.deviceRepository
}

func (f *Factory) GetDeviceHistoryRepository() *scylla.DeviceHistoryRepositoryImpl {
	if f.deviceHistoryRepo == nil {
		f.deviceHistoryRepo = scylla.NewDeviceHistoryRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.deviceHistoryRepo
}

func (f *Factory) AdminRepository() postgres.AdminRepository {
	if f.adminRepository == nil {
		f.adminRepository = postgres.NewAdminRepositoryPostgres(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.adminRepository
}

// ============================================================================
// CORE SERVICES
// ============================================================================

func (f *Factory) GetJWTService() *service.JWTService {
	if f.jwtService == nil {
		f.jwtService = service.NewJWTService(
			f.Config(),
			f.CompanyRepository(),
			f.AdminRepository(),
			f.logger,
		)
	}
	return f.jwtService
}

func (f *Factory) GetRBACInitService() *service.RBACInitService {
	if f.rbacInitService == nil {
		f.rbacInitService = service.NewRBACInitService(
			f.CompanyRepository(),
			f.logger,
		)
	}
	return f.rbacInitService
}

func (f *Factory) ServiceFactory() *service.ServiceFactory {
	if f.serviceFactory == nil {
		f.serviceFactory = service.NewServiceFactory(
			f.UserRepository(),
			f.Hasher(),
			f.EncryptionManager(),
			f.logger,
		)
	}
	return f.serviceFactory
}

func (f *Factory) GetUserService() *service.UserService {
	f.once.Do(func() {
		repo := f.UserRepository()
		hasher := f.Hasher()
		encMgr := f.EncryptionManager()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.userService = service.NewUserServiceWithCache(
			repo, hasher, encMgr, distCache, logger,
		)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.userService.SetLogProducerService(logProducer)
		}
	})
	return f.userService
}

func (f *Factory) GetPhoneValidator() *service.PhoneValidatorImpl {
	phoneValidator := service.NewPhoneValidator(
		f.GetUserService(),
		nil,
		f.logger,
	)
	return phoneValidator
}

func (f *Factory) GetOTPService() *service.OTPService {
	if f.otpService == nil {
		repo := f.OTPRepository()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		logProducer := f.GetLogProducerService()
		phoneValidator := f.GetPhoneValidator()

		f.otpService = service.NewOTPService(
			repo,
			hasher,
			cfg,
			distCache,
			logger,
			logProducer,
			phoneValidator,
			f.AdminDeviceTrustRepository(),
			f.smsManager,
		)

		if phoneValidator != nil {
			phoneValidator.SetAdminService(f.GetAdminService())
		}
	}
	return f.otpService
}

func (f *Factory) GetAdminService() *service.AdminService {
	if f.adminService == nil {
		f.adminService = service.NewAdminService(
			f.AdminRepository(),
			f.CompanyRepository(),
			f.GetSessionService(),
			f.GetOTPService(),
			f.GetMPINService(),
			f.GetDeviceService(),
			f.Hasher(),
			f.EncryptionManager(),
			f.logger,
		)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.adminService.SetLogProducerService(logProducer)
		}
	}
	return f.adminService
}

func (f *Factory) GetMPINService() *service.MPINService {
	if f.mpinService == nil {
		mpinRepo := f.MPINRepository()
		userRepo := f.UserRepository()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		userOTPService := f.GetUserOTPService()
		encryptionMgr := f.EncryptionManager()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		logProducer := f.GetLogProducerService()
		f.mpinService = service.NewMPINService(
			mpinRepo,
			userRepo,
			deviceTrustRepo,
			userOTPService,
			encryptionMgr,
			hasher,
			cfg,
			logger,
			logProducer,
		)

		if distCache != nil {
			f.mpinService.SetDistributedCache(distCache)
		}
	}
	return f.mpinService
}

func (f *Factory) GetSessionService() *service.SessionService {
	if f.sessionService == nil {
		sessionRepo := f.SessionRepository()
		cfg := f.Config()
		jwtService := f.GetJWTService()
		logger := f.logger
		logProducer := f.GetLogProducerService()
		companyRepo := f.CompanyRepository()

		f.sessionService = service.NewSessionService(
			sessionRepo,
			cfg,
			jwtService,
			logger,
			logProducer,
			companyRepo,
		)
	}
	return f.sessionService
}

func (f *Factory) GetDeviceService() *service.DeviceService {
	if f.deviceService == nil {
		deviceRepo := f.DeviceRepository()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		adminDeviceTrustRepo := f.AdminDeviceTrustRepository()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.deviceService = service.NewDeviceService(
			deviceRepo,
			deviceTrustRepo,
			adminDeviceTrustRepo,
			distCache,
			*cfg,
			logger,
		)

		historyRepo := f.GetDeviceHistoryRepository()
		f.deviceService.SetHistoryRepository(historyRepo)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.deviceService.SetLogProducerService(logProducer)
		}
	}
	return f.deviceService
}

func (f *Factory) GetCompanyService() *service.CompanyService {
	if f.companyService == nil {
		f.companyService = service.NewCompanyService(
			f.CompanyRepository(),
			f.GetUserService(),
			f.logger,
		)
	}
	return f.companyService
}

func (f *Factory) GetAdminDeviceService() *service.AdminDeviceService {
	if f.adminDeviceService == nil {
		deviceRepo := f.AdminDeviceRepository()
		trustRepo := f.AdminDeviceTrustRepository()
		mpinRepo := f.AdminMPINRepository()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.adminDeviceService = service.NewAdminDeviceService(
			deviceRepo,
			trustRepo,
			mpinRepo,
			distCache,
			*cfg,
			logger,
		)

		historyRepo := f.AdminDeviceHistoryRepository()
		f.adminDeviceService.SetHistoryRepository(historyRepo)

		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.adminDeviceService.SetLogProducerService(logProducer)
		}
	}
	return f.adminDeviceService
}

func (f *Factory) GetAdminMPINService() *service.AdminMPINService {
	if f.adminMPINService == nil {
		mpinRepo := f.AdminMPINRepository()
		adminRepo := f.AdminRepository()
		deviceTrustRepo := f.AdminDeviceTrustRepository()
		otpService := f.GetOTPService()
		encryptionMgr := f.EncryptionManager()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		logProducer := f.GetLogProducerService()

		f.adminMPINService = service.NewAdminMPINService(
			mpinRepo,
			adminRepo,
			deviceTrustRepo,
			otpService,
			encryptionMgr,
			hasher,
			cfg,
			logger,
			logProducer,
		)

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
			f.adminMPINService.SetDistributedCache(distCache)
		}
	}
	return f.adminMPINService
}

func (f *Factory) GetUserOTPService() *service.UserOTPService {
	if f.userOTPService == nil {
		repo := f.OTPRepository()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		logProducer := f.GetLogProducerService()
		phoneValidator := f.GetPhoneValidator()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		smsManager := f.GetSMSManager()

		f.userOTPService = service.NewUserOTPService(
			repo,
			hasher,
			cfg,
			distCache,
			logger,
			logProducer,
			phoneValidator,
			deviceTrustRepo,
			smsManager,
		)

		if phoneValidator != nil {
			phoneValidator.SetAdminService(f.GetAdminService())
		}
	}
	return f.userOTPService
}

// ============================================================================
// WEB LOGIN & PAIRING SERVICES
// ============================================================================

func (f *Factory) GetPairingRepository() redis.PairingRepository {
	if f.pairingRepo == nil {
		f.pairingRepo = redis.NewPairingRepository(
			f.redisClient.Client(),
			f.logger,
		)
	}
	return f.pairingRepo
}

func (f *Factory) GetHMACUtil() *util.HMACUtil {
	if f.hmacUtil == nil {
		secret := f.config.Security.JWTSecret
		if secret == "" {
			secret = "default-qr-hmac-secret-change-in-production"
		}
		f.hmacUtil = util.NewHMACUtil(secret)
	}
	return f.hmacUtil
}

func (f *Factory) GetQRUtil() *util.QRUtil {
	if f.qrUtil == nil {
		f.qrUtil = util.NewQRUtil(f.config.Security.JWTSecret)
	}
	return f.qrUtil
}

func (f *Factory) GetPairingService() *service.PairingService {
	if f.pairingService == nil {
		f.pairingService = service.NewPairingService(
			f.GetPairingRepository(),
			f.GetSessionService(),
			f.GetQRUtil(),
			f.config,
			f.logger,
		)
	}
	return f.pairingService
}

func (f *Factory) GetWebSocketService() *service.WebSocketService {
	if f.wsService == nil {
		f.wsService = service.NewWebSocketService(f.logger)

		go f.wsService.Run()

		f.logger.Info("WebSocket service started")
	}
	return f.wsService
}

func (f *Factory) GetPairingHandler() *handler.PairingHandler {
	if f.pairingHandler == nil {
		f.pairingHandler = handler.NewPairingHandler(
			f.GetPairingService(),
			f.GetWebSocketService(),
			f.logger,
		)
	}
	return f.pairingHandler
}

func (f *Factory) GetWebSocketHandler() *handler.WebSocketHandler {
	if f.wsHandler == nil {
		f.wsHandler = handler.NewWebSocketHandler(
			f.GetWebSocketService(),
			f.logger,
		)
	}
	return f.wsHandler
}

// ============================================================================
// CLIENT INITIALIZATION
// ============================================================================

func (f *Factory) initializeClients() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var initErrors []error

	// Redis
	if rc, err := client.NewRedisClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("redis: %w", err))
	} else {
		f.redisClient = rc
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("redis health check: %w", err))
		} else {
			util.Info("Redis client initialized and healthy")
		}
	}

	// PostgreSQL
	if pgc, err := client.NewPostgresClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("postgres: %w", err))
	} else {
		f.postgresClient = pgc
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("postgres health check: %w", err))
		} else {
			util.Info("PostgreSQL client initialized and healthy")
		}
	}

	// ScyllaDB
	if sc, err := scylla.NewScyllaClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = sc
		if err := f.scyllaClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("scylla health check: %w", err))
		} else {
			util.Info("ScyllaDB client initialized and healthy")
		}
	}

	// Elasticsearch
	if ec, err := client.NewElasticsearchClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("elasticsearch: %w", err))
	} else {
		f.esClient = ec
		if err := f.esClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("elasticsearch health check: %w", err))
		} else {
			util.Info("Elasticsearch client initialized and healthy")
		}
	}

	// ClickHouse
	if chc, err := client.NewClickHouseClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("clickhouse: %w", err))
	} else {
		f.clickhouseClient = chc
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("clickhouse health check: %w", err))
		} else {
			util.Info("ClickHouse client initialized and healthy")
		}
	}

	if len(initErrors) > 0 {
		for _, e := range initErrors {
			util.Warn("Service initialization warning", util.ErrorField(e))
		}
	}

	return nil
}

func (f *Factory) initializeManagers() {
	pepperStore := f.PepperStoreRepository()

	hasher, err := hashing.NewHasher(f.config, pepperStore)
	if err != nil {
		f.logger.Error("CRITICAL: Failed to initialize hasher",
			zap.Error(err),
			zap.String("impact", "MPIN operations will fail"))

		if f.config.IsProduction() {
			panic(fmt.Sprintf("CRITICAL: Failed to initialize hasher: %v", err))
		}

		f.hasher = nil
	} else {
		f.hasher = hasher
		util.Info("Hasher initialized with pepper persistence",
			util.Int("current_pepper_version", hasher.GetCurrentPepperVersion()))
	}

	var kmsClient *kms.Client
	if f.config.KMS.Enabled {
		kmsClient = nil
	}

	f.encryptionManager = encryption.NewEncryptionManager(f.config, kmsClient)
	f.bucketingManager = bucketing.NewBucketingManager(f.config)

	f.smsManager = sms.NewSMSManager(f.logger)
	util.Info("SMS manager initialized")

	if f.hasher != nil && f.config.IsProduction() {
		f.hasher.StartPepperRotation()
		util.Info("Pepper rotation started")
	}

	util.Info("Managers initialized successfully",
		util.Bool("hashing_initialized", f.hasher != nil),
		util.Bool("encryption_initialized", f.encryptionManager != nil),
		util.Bool("bucketing_initialized", f.bucketingManager != nil),
		util.Bool("sms_manager_initialized", f.smsManager != nil),
		util.Bool("pepper_persistence_enabled", f.hasher != nil),
	)
}

// ============================================================================
// HANDLER INITIALIZATION
// ============================================================================
func (f *Factory) InitializeHandlers() error {
	logger := f.logger

	userService := f.GetUserService()
	otpService := f.GetOTPService()
	mpinService := f.GetMPINService()
	adminMPINService := f.GetAdminMPINService()
	adminDeviceService := f.GetAdminDeviceService()
	sessionService := f.GetSessionService()
	deviceService := f.GetDeviceService()
	adminService := f.GetAdminService()
	companyService := f.GetCompanyService()
	jwtService := f.GetJWTService()
	userOTPService := f.GetUserOTPService()

	_ = f.GetPairingService()
	_ = f.GetWebSocketService()

	otpHandler := handler.NewOTPHandler(
		otpService,
		sessionService,
		logger,
	)

	adminHandler := handler.NewAdminHandler(
		adminService,
		companyService,
		userService,
		otpService,
		adminMPINService,
		adminDeviceService,
		sessionService,
		jwtService,
		logger,
	)

	rbacHandler := handler.NewRBACHandler(companyService, logger)

	authHandler := handler.NewAuthHandler(
		userOTPService,
		mpinService,
		sessionService,
		userService,
		companyService,
		deviceService,
		jwtService,
		logger,
	)
	f.authHandler = authHandler

	pairingHandler := f.GetPairingHandler()
	wsHandler := f.GetWebSocketHandler()
	workCenterHandler := f.GetWorkCenterHandler()

	f.router = handler.NewRouter(
		otpHandler,
		adminHandler,
		authHandler,
		rbacHandler,
		f.GetHRAuditHandler(),
		f.GetHRCompensationHandler(),
		f.GetHREmployeeHandler(),
		f.GetHRLeaveHandler(),
		f.GetHRSchedulingHandler(),
		f.GetAttendanceIngestHandler(),
		pairingHandler,
		workCenterHandler,
		wsHandler,
		sessionService,
		jwtService,
		logger,
		f.GetOrgUnitHandler(),
		// New attendance handlers
		f.GetAttendanceDeviceHandler(),
		f.GetAttendanceAdminHandler(),
		f.GetAttendanceQueryHandler(),
		f.GetAttendanceResolutionHandler(),
		f.GetAttendanceCorrectionHandler(), // 👈 NEW
	)

	logger.Info("Handlers and router initialized with JWT, bitmask, QR web login, and new attendance system")
	return nil
}
func (f *Factory) GetRouter() chi.Router {
	if f.router == nil {
		if err := f.InitializeHandlers(); err != nil {
			f.logger.Fatal("Failed to initialize handlers", util.ErrorField(err))
		}
	}
	return f.router
}

// ============================================================================
// RBAC INITIALIZATION
// ============================================================================

func (f *Factory) InitializeRBAC(ctx context.Context) error {
	rbacInitService := f.GetRBACInitService()
	if err := rbacInitService.InitializePermissionRegistry(ctx); err != nil {
		return fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}
	f.logger.Info("RBAC permission registry initialized successfully")
	return nil
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	// PostgreSQL health checks
	if f.postgresClient != nil {
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			errs["postgres"] = err
		}
	} else {
		errs["postgres"] = fmt.Errorf("postgres client not initialized")
	}

	if f.employeeQueryService != nil {
		if err := f.employeeQueryService.HealthCheck(ctx); err != nil {
			errs["employee_query_service"] = err
		}
	} else {
		errs["employee_query_service"] = fmt.Errorf("employee query service not initialized")
	}

	if f.employeeService != nil {
		if err := f.employeeService.HealthCheck(ctx); err != nil {
			errs["employee_service"] = err
		}
	} else {
		errs["employee_service"] = fmt.Errorf("employee service not initialized")
	}

	// Attendance services health checks
	if f.attendanceIngestService != nil {
		// AttendanceIngestService doesn't have HealthCheck method
		// We'll check the underlying repositories instead
	} else {
		errs["attendance_ingest_service"] = fmt.Errorf("attendance ingest service not initialized")
	}

	if f.attendanceAdminService != nil {
		if err := f.attendanceAdminService.HealthCheck(ctx); err != nil {
			errs["attendance_admin_service"] = err
		}
	} else {
		errs["attendance_admin_service"] = fmt.Errorf("attendance admin service not initialized")
	}

	if f.attendanceQueryService != nil {
		if err := f.attendanceQueryService.HealthCheck(ctx); err != nil {
			errs["attendance_query_service"] = err
		}
	} else {
		errs["attendance_query_service"] = fmt.Errorf("attendance query service not initialized")
	}

	// Other services
	if f.leaveService != nil {
		// LeaveService doesn't have HealthCheck method
	} else {
		errs["leave_service"] = fmt.Errorf("leave service not initialized")
	}

	if f.schedulingService != nil {
		// SchedulingService doesn't have HealthCheck method
	} else {
		errs["scheduling_service"] = fmt.Errorf("scheduling service not initialized")
	}

	if f.compensationService != nil {
		// CompensationService doesn't have HealthCheck method
	} else {
		errs["compensation_service"] = fmt.Errorf("compensation service not initialized")
	}

	// Core repositories health checks
	if f.postgresUserRepository != nil {
		if err := f.postgresUserRepository.HealthCheck(ctx); err != nil {
			errs["postgres_user_repository"] = err
		}
	} else {
		errs["postgres_user_repository"] = fmt.Errorf("postgres user repository not initialized")
	}

	if f.hrEmployeeRepository != nil {
		if err := f.hrEmployeeRepository.HealthCheck(ctx); err != nil {
			errs["hr_employee_repository"] = err
		}
	} else {
		errs["hr_employee_repository"] = fmt.Errorf("HR employee repository not initialized")
	}

	if f.postgresCompanyRepository != nil {
		if err := f.postgresCompanyRepository.HealthCheck(ctx); err != nil {
			errs["postgres_company_repository"] = err
		}
	} else {
		errs["postgres_company_repository"] = fmt.Errorf("postgres company repository not initialized")
	}

	// Other clients and repositories...
	if f.redisClient != nil {
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			errs["redis"] = err
		}
	} else {
		errs["redis"] = fmt.Errorf("redis client not initialized")
	}

	if f.mpinRepository != nil {
		if err := f.mpinRepository.HealthCheck(ctx); err != nil {
			errs["mpin_repository"] = err
		}
	} else {
		errs["mpin_repository"] = fmt.Errorf("mpin repository not initialized")
	}

	if f.scyllaClient != nil {
		if err := f.scyllaClient.HealthCheck(); err != nil {
			errs["scylla"] = err
		}
	} else {
		errs["scylla"] = fmt.Errorf("scylla client not initialized")
	}

	if f.esClient != nil {
		if err := f.esClient.HealthCheck(); err != nil {
			errs["elasticsearch"] = err
		}
	} else {
		errs["elasticsearch"] = fmt.Errorf("elasticsearch client not initialized")
	}

	if f.clickhouseClient != nil {
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			errs["clickhouse"] = err
		}
	} else {
		errs["clickhouse"] = fmt.Errorf("clickhouse client not initialized")
	}

	if f.kafkaProducer != nil {
		if err := f.kafkaProducer.HealthCheck(ctx); err != nil {
			errs["kafka"] = err
		}
	}

	if f.encryptionManager == nil {
		errs["encryption"] = fmt.Errorf("encryption manager not initialized")
	}

	if f.bucketingManager == nil {
		errs["bucketing"] = fmt.Errorf("bucketing manager not initialized")
	}

	if f.sessionRepo != nil {
		if err := f.sessionRepo.HealthCheck(ctx); err != nil {
			errs["session_repository"] = err
		}
	} else {
		errs["session_repository"] = fmt.Errorf("session repository not initialized")
	}

	if f.deviceRepository != nil {
		if err := f.deviceRepository.HealthCheck(ctx); err != nil {
			errs["device_repository"] = err
		}
	} else {
		errs["device_repository"] = fmt.Errorf("device repository not initialized")
	}

	if f.deviceHistoryRepo != nil {
		if err := f.deviceHistoryRepo.HealthCheck(ctx); err != nil {
			errs["device_history_repository"] = err
		}
	} else {
		errs["device_history_repository"] = fmt.Errorf("device history repository not initialized")
	}

	if f.adminRepository != nil {
		if err := f.adminRepository.HealthCheck(ctx); err != nil {
			errs["admin_repository"] = err
		}
	} else {
		errs["admin_repository"] = fmt.Errorf("admin repository not initialized")
	}

	// JWT + RBAC
	if f.jwtService == nil {
		errs["jwt_service"] = fmt.Errorf("JWT service not initialized")
	}
	if f.rbacInitService == nil {
		errs["rbac_init_service"] = fmt.Errorf("RBAC init service not initialized")
	}

	// Company service
	if f.companyService != nil {
		if err := f.companyService.HealthCheck(ctx); err != nil {
			errs["company_service"] = err
		}
	} else {
		errs["company_service"] = fmt.Errorf("company service not initialized")
	}

	// Kafka logging health check
	if f.kafkaLoggingMgr != nil {
		kafkaErrs := f.kafkaLoggingMgr.HealthCheck(ctx)
		for k, v := range kafkaErrs {
			errs[k] = v
		}
	} else {
		errs["kafka_logging"] = fmt.Errorf("kafka logging manager not initialized")
	}

	// Pepper store
	if f.pepperStoreRepo != nil {
		_, _, err := f.pepperStoreRepo.GetCurrentPepper(ctx)
		if err != nil {
			errs["pepper_store"] = fmt.Errorf("pepper store health check failed: %w", err)
		}
	} else {
		errs["pepper_store"] = fmt.Errorf("pepper store repository not initialized")
	}

	// Hasher
	if f.hasher != nil {
		if err := f.hasher.HealthCheck(ctx); err != nil {
			errs["hasher"] = err
		}
	} else {
		errs["hasher"] = fmt.Errorf("hasher not initialized")
	}

	// Admin repositories
	if f.adminDeviceRepo != nil {
		if err := f.adminDeviceRepo.HealthCheck(ctx); err != nil {
			errs["admin_device_repository"] = err
		}
	} else {
		errs["admin_device_repository"] = fmt.Errorf("admin device repository not initialized")
	}

	if f.adminMPINRepo != nil {
		if err := f.adminMPINRepo.HealthCheck(ctx); err != nil {
			errs["admin_mpin_repository"] = err
		}
	} else {
		errs["admin_mpin_repository"] = fmt.Errorf("admin MPIN repository not initialized")
	}

	// Admin services
	if f.adminDeviceService != nil {
		if err := f.adminDeviceService.HealthCheck(ctx); err != nil {
			errs["admin_device_service"] = err
		}
	} else {
		errs["admin_device_service"] = fmt.Errorf("admin device service not initialized")
	}

	if f.adminMPINService != nil {
		if err := f.adminMPINService.HealthCheck(ctx); err != nil {
			errs["admin_mpin_service"] = err
		}
	} else {
		errs["admin_mpin_service"] = fmt.Errorf("admin MPIN service not initialized")
	}

	// QR WEB LOGIN HEALTH CHECKS
	if f.pairingRepo != nil {
		testSession := &models.PairingSession{
			SessionID: "health-check",
			Status:    "pending",
			Nonce:     "test-nonce",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Minute),
		}

		if err := f.pairingRepo.CreatePairingSession(ctx, testSession); err != nil {
			errs["pairing_repository"] = fmt.Errorf("pairing repository health check failed: %w", err)
		} else {
			_ = f.pairingRepo.DeletePairingSession(ctx, "health-check")
		}
	} else {
		errs["pairing_repository"] = fmt.Errorf("pairing repository not initialized")
	}

	if f.pairingService == nil {
		errs["pairing_service"] = fmt.Errorf("pairing service not initialized")
	}

	if f.wsService == nil {
		errs["websocket_service"] = fmt.Errorf("WebSocket service not initialized")
	}

	if f.qrUtil == nil {
		errs["qr_util"] = fmt.Errorf("QR utility not initialized")
	}

	return errs
}

// ============================================================================
// CLEANUP
// ============================================================================

func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		util.Info("Shutting down factory...")

		// 1️⃣ SHUTDOWN KAFKA LOGGING MANAGER
		if f.kafkaLoggingMgr != nil {
			util.Info("Shutting down Kafka logging manager...")

			if f.kafkaLoggingMgr.cancelCtx != nil {
				f.kafkaLoggingMgr.cancelCtx()
			}

			f.kafkaLoggingMgr.wg.Wait()

			if f.kafkaLoggingMgr.producer != nil {
				if err := f.kafkaLoggingMgr.producer.Close(); err != nil {
					util.Error("Failed to close log producer", util.ErrorField(err))
				}
			}

			if f.kafkaLoggingMgr.esConsumer != nil {
				util.Info("Elasticsearch Kafka consumer stopped")
			}
			if f.kafkaLoggingMgr.chConsumer != nil {
				util.Info("ClickHouse Kafka consumer stopped")
			}

			util.Info("Kafka logging system fully shut down")
		}

		// 2️⃣ SHUTDOWN KAFKA PRODUCER (GLOBAL)
		if f.kafkaProducer != nil {
			if err := f.kafkaProducer.Close(); err != nil {
				util.Error("Failed to close Kafka producer", util.ErrorField(err))
			} else {
				util.Info("Kafka producer closed")
			}
		}

		// 3️⃣ STOP ATTENDANCE OUTBOX SERVICE
		if f.attendanceOutboxCancel != nil {
			f.logger.Info("Stopping attendance outbox service...")
			f.attendanceOutboxCancel()
		}

		// 4️⃣ STOP ATTENDANCE RESOLUTION CONSUMER
		if f.attendanceResolutionCancel != nil {
			f.logger.Info("Stopping attendance resolution consumer...")
			f.attendanceResolutionCancel()
		}

		// 5️⃣ STOP AUDIT OUTBOX SERVICE
		if f.auditOutboxCancel != nil {
			f.logger.Info("Stopping audit outbox service...")
			f.auditOutboxCancel()
		}

		// 6️⃣ CLOSE DATABASES
		if f.postgresClient != nil {
			f.postgresClient.Close()
			util.Info("PostgreSQL client closed")
		}

		if f.clickhouseClient != nil {
			f.clickhouseClient.Close()
			util.Info("ClickHouse client closed")
		}

		if f.esClient != nil {
			f.esClient.Close()
			util.Info("Elasticsearch client closed")
		}

		// 7️⃣ SERVICE FACTORY CLEANUP
		if f.serviceFactory != nil {
			f.serviceFactory.Cleanup()
			util.Info("Service factory cleaned up")
		}

		// 8️⃣ CLOSE SCYLLA + REDIS
		if f.scyllaClient != nil {
			f.scyllaClient.Close()
			util.Info("ScyllaDB client closed")
		}

		if f.redisClient != nil {
			f.redisClient.Close()
			util.Info("Redis client closed")
		}

		// 9️⃣ SECURITY MANAGERS
		if f.hasher != nil {
			util.Info("Hasher shut down")
		}

		if f.encryptionManager != nil {
			f.encryptionManager.ClearCache()
			util.Info("Encryption manager cache cleared")
		}

		// 🔟 WEBSOCKET SERVICE
		if f.wsService != nil {
			if closer, ok := interface{}(f.wsService).(interface{ Close() error }); ok {
				_ = closer.Close()
			}
			util.Info("WebSocket service shut down")
		}

		// 1️⃣1️⃣ FINAL LOGGING SYNC
		util.Sync()
		util.Info("Factory shutdown completed")
	})

	return nil
}

// ============================================================================
// SIMPLE GETTERS
// ============================================================================

func (f *Factory) Config() *config.Config                           { return f.config }
func (f *Factory) TLSManager() *tls.TLSManager                      { return f.tlsManager }
func (f *Factory) ScyllaClient() *scylla.ScyllaClient               { return f.scyllaClient }
func (f *Factory) Hasher() *hashing.Hasher                          { return f.hasher }
func (f *Factory) EncryptionManager() *encryption.EncryptionManager { return f.encryptionManager }
func (f *Factory) BucketingManager() *bucketing.BucketingManager    { return f.bucketingManager }
func (f *Factory) GetLogProducerService() *service.LogProducerService {
	if f.kafkaLoggingMgr == nil {
		return nil
	}
	return f.kafkaLoggingMgr.GetLogProducerService()
}

func (f *Factory) GetSMSManager() *sms.SMSManager {
	return f.smsManager
}

func (f *Factory) PostgresUserRepository() postgres.UserRepository {
	if f.postgresUserRepository == nil {
		f.postgresUserRepository = postgres.NewUserRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresUserRepository
}

func (f *Factory) PostgresCompanyRepository() postgres.CompanyRepository {
	if f.postgresCompanyRepository == nil {
		f.postgresCompanyRepository = postgres.NewCompanyRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.postgresCompanyRepository
}
