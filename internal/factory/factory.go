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
	hrhandler "auth-service/internal/hr/handler" // ✅ ADD
	hrpostgres "auth-service/internal/hr/repository"
	a "auth-service/internal/hr/service"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service"
	"auth-service/internal/sms" // ADD THIS: SMS package import
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

type Factory struct {
	config                 *config.Config
	tlsManager             *tls.TLSManager
	redisClient            *client.RedisClient
	scyllaClient           *scylla.ScyllaClient
	kafkaProducer          *client.KafkaProducer
	esClient               *client.ESClient
	clickhouseClient       *client.ClickHouseClient
	hasher                 *hashing.Hasher
	encryptionManager      *encryption.EncryptionManager
	bucketingManager       *bucketing.BucketingManager
	pairingRepo            redis.PairingRepository
	pairingService         *service.PairingService
	wsService              *service.WebSocketService
	pairingHandler         *handler.PairingHandler
	wsHandler              *handler.WebSocketHandler
	qrUtil                 *util.QRUtil
	hmacUtil               *util.HMACUtil
	hrEmployeeRepository   hrpostgres.EmployeeRepository
	attendanceRepository   hrpostgres.AttendanceRepository
	leaveRepository        hrpostgres.LeaveRepository
	schedulingRepository   hrpostgres.SchedulingRepository // Combined repository
	compensationRepository hrpostgres.CompensationRepository
	// ================= AUDIT =================
	auditRepository        hrpostgres.AuditRepository
	auditService           *a.AuditService
	auditQueryService      *a.AuditQueryService
	documentStorage        a.DocumentStorage
	auditOutboxService     *service.AuditOutboxService
	auditOutboxCancel      context.CancelFunc
	employeeQueryService   *a.EmployeeQueryService
	employeeService        *a.EmployeeService
	attendanceQueryService a.AttendanceQueryService
	attendanceService      a.AttendanceService
	leaveService           a.LeaveService
	leaveQueryService      a.LeaveQueryService
	schedulingService      a.SchedulingService
	schedulingQueryService a.SchedulingQueryService
	compensationService    a.CompensationService // ✅ ADD THIS
	hrAuditHandler         *hrhandler.AuditHandler
	hrEmployeeHandler      *hrhandler.EmployeeHandler
	hrCompensationHandler  *hrhandler.CompensationHandler
	hrLeaveHandler         *hrhandler.LeaveHandler
	hrSchedulingHandler    *hrhandler.SchedulingHandler

	// ✅ UPDATED: PostgreSQL repositories for User and Company
	postgresClient            *client.PostgresClient
	postgresUserRepository    postgres.UserRepository
	postgresCompanyRepository postgres.CompanyRepository
	smsManager                *sms.SMSManager // ADD THIS: SMS Manager field
	serviceFactory            *service.ServiceFactory
	// ✅ FIXED: Use concrete types for repositories that need type assertions
	adminDeviceRepo          *scylla.AdminDeviceRepositoryImpl
	adminDeviceTrustRepo     scylla.AdminDeviceTrustRepository
	adminMPINRepo            *scylla.AdminMPINRepositoryImpl
	adminDeviceHistoryRepo   *scylla.AdminDeviceHistoryRepositoryImpl
	userOTPService           *service.UserOTPService
	companyService           *service.CompanyService
	adminDeviceService       *service.AdminDeviceService
	adminMPINService         *service.AdminMPINService
	userService              *service.UserService
	once                     sync.Once
	closeOnce                sync.Once
	closed                   chan struct{}
	mpinRepository           scylla.MPINRepository
	mpinService              *service.MPINService
	pepperStoreRepo          pepperstore.PepperStore
	deviceTrustRepo          scylla.DeviceTrustRepository
	otpRepository            scylla.OTPRepository
	otpService               *service.OTPService
	sessionRepo              redis.SessionRepository
	sessionService           *service.SessionService
	deviceRepository         scylla.DeviceRepository
	deviceService            *service.DeviceService
	deviceHistoryRepo        *scylla.DeviceHistoryRepositoryImpl
	kafkaLoggingMgr          *KafkaLoggingManager
	adminRepository          postgres.AdminRepository
	adminService             *service.AdminService
	compensationQueryService a.CompensationQueryService
	hrAttendanceHandler      *hrhandler.AttendanceHandler

	// ✅ NEW: JWT and RBAC services
	jwtService      *service.JWTService
	rbacInitService *service.RBACInitService
	authHandler     *handler.AuthHandler
	router          chi.Router

	logger *zap.Logger
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
	if cfg.Server.EnableTLS {
		tlsConfig := &tls.TLSConfig{
			EnableTLS: cfg.Server.EnableTLS,
			CertFile:  cfg.Server.CertFile,
			KeyFile:   cfg.Server.KeyFile,
		}
		f.tlsManager = tls.NewTLSManager(tlsConfig)
	}

	if err := f.initializeClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}
	f.initializeManagers()

	kafkaLoggingMgr, err := f.InitializeKafkaLogging()
	if err != nil {
		logger.Error("failed to initialize Kafka logging", zap.Error(err))
	}
	f.kafkaLoggingMgr = kafkaLoggingMgr

	// ✅ ADD THIS: Initialize RBAC permission registry
	ctx := context.Background()
	if err := f.InitializeRBAC(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}
	f.initializeManagers()

	if err := f.initializeDocumentStorage(); err != nil {
		return nil, err
	}

	// =====================================================================
	// ✅ START AUDIT OUTBOX SERVICE
	// =====================================================================
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

	util.Info("Factory initialized successfully",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.Bool("kms_enabled", cfg.KMS.Enabled),
		util.Bool("kafka_logging_enabled", f.kafkaLoggingMgr != nil),
		util.Bool("rbac_initialized", true), // ✅ ADD THIS
	)

	return f, nil
}

// ============================================================================
// KAFKA LOGGING INITIALIZATION - OPTIMIZED EVENT DISTRIBUTION
// ============================================================================
func (f *Factory) initializeDocumentStorage() error {
	cfg := f.config

	// You can move these to config later
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

	// Health check on startup
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

func (f *Factory) GetCompensationService() a.CompensationService {
	if f.compensationService == nil {
		f.compensationService = a.NewCompensationService(
			f.CompensationRepository(),
			f.AuditRepository(), // uses auditRepo + logAudit internally
			f.logger,
		)
	}
	return f.compensationService
}

func (f *Factory) GetEmployeeQueryService() *a.EmployeeQueryService {
	if f.employeeQueryService == nil {
		f.employeeQueryService = a.NewEmployeeQueryService(
			f.HREmployeeRepository(),
			f.DocumentStorage(), // ✅ from earlier step
			f.logger,
		)
	}
	return f.employeeQueryService
}

func (f *Factory) GetAttendanceQueryService() a.AttendanceQueryService {
	if f.attendanceQueryService == nil {
		f.attendanceQueryService = a.NewAttendanceQueryService(
			f.AttendanceRepository(),
			f.logger,
		)
	}
	return f.attendanceQueryService
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

func (f *Factory) GetHRAuditHandler() *hrhandler.AuditHandler {
	if f.hrAuditHandler == nil {
		f.hrAuditHandler = hrhandler.NewAuditHandler(
			f.GetAuditQueryService(), // HR audit query service
			f.logger,
		)
	}
	return f.hrAuditHandler
}

// GetLeaveQueryService returns the leave query service
func (f *Factory) GetLeaveQueryService() a.LeaveQueryService {
	if f.leaveQueryService == nil {
		f.leaveQueryService = a.NewLeaveQueryService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveQueryService
}
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

	// ✅ ELASTICSEARCH CONSUMER - Search & Analytics Events (MULTI-TOPIC)
	if f.config.Elasticsearch.URL != "" && f.esClient != nil {
		esTopics := []string{
			"admin-events",    // Audit trails, role searches
			"user-events",     // User behavior analysis
			"security-events", // Fraud investigation (dual-purpose)
			"session-events",  // Session analytics
		}

		// Create multiple Kafka consumers for ES (one per topic)
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

	// ✅ CLICKHOUSE CONSUMER - Time-Series & Metrics Events (MULTI-TOPIC)
	if f.config.Clickhouse.URL != "" && f.clickhouseClient != nil {
		chTopics := []string{
			"device-events",   // Device metrics, binding trends
			"mpin-events",     // Authentication patterns
			"otp-events",      // Delivery metrics
			"security-events", // Real-time fraud detection (dual-purpose)
		}

		// Create multiple Kafka consumers for ClickHouse (one per topic)
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
				f.clickhouseClient, // ✅ PASS THE FULL CLIENT
				1000,               // batch size
				5*time.Second,      // flush interval
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
// ADMIN REPOSITORY GETTERS - FIXED
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

func (f *Factory) GetHREmployeeHandler() *hrhandler.EmployeeHandler {
	if f.hrEmployeeHandler == nil {
		f.hrEmployeeHandler = hrhandler.NewEmployeeHandler(
			f.GetEmployeeService(),      // write service
			f.GetEmployeeQueryService(), // read service
			f.GetAuditService(),         // audit service
			f.logger,
			f.config.HR.Documents.MaxSizeMB, // ✅ FIXED
		)
	}
	return f.hrEmployeeHandler
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

func (f *Factory) GetCompensationQueryService() a.CompensationQueryService {
	if f.compensationQueryService == nil {
		f.compensationQueryService = a.NewCompensationQueryService(
			f.CompensationRepository(),
			f.logger,
		)
	}
	return f.compensationQueryService
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

// GetSchedulingQueryService returns the scheduling query service
func (f *Factory) GetSchedulingQueryService() a.SchedulingQueryService {
	if f.schedulingQueryService == nil {
		f.schedulingQueryService = a.NewSchedulingQueryService(
			f.GetSchedulingRepository(),
			f.logger,
		)
	}
	return f.schedulingQueryService
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
func (f *Factory) GetHRAttendanceHandler() *hrhandler.AttendanceHandler {
	if f.hrAttendanceHandler == nil {
		f.hrAttendanceHandler = hrhandler.NewAttendanceHandler(
			f.GetAttendanceService(),
			f.GetAttendanceQueryService(),
			f.logger,
		)
	}
	return f.hrAttendanceHandler
}

// ============================================================================
// ✅ AUDIT REPOSITORY
// ============================================================================

func (f *Factory) AuditRepository() hrpostgres.AuditRepository {
	if f.auditRepository == nil {
		f.auditRepository = hrpostgres.NewAuditRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.auditRepository
}

// ============================================================================
// ✅ AUDIT SERVICE
// ============================================================================
func (f *Factory) GetAuditQueryService() *a.AuditQueryService {
	if f.auditQueryService == nil {
		f.auditQueryService = a.NewAuditQueryService(
			f.AuditRepository(),
			f.logger,
		)
	}
	return f.auditQueryService
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

// ============================================================================
// ✅ AUDIT OUTBOX SERVICE
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

func (f *Factory) GetAuditOutboxService() *service.AuditOutboxService {
	if f.auditOutboxService == nil {

		// Kafka is optional – if not present, outbox should not start
		if f.kafkaProducer == nil {
			f.logger.Warn("Kafka producer not available, audit outbox disabled")
			return nil
		}

		f.auditOutboxService = service.NewAuditOutboxService(
			f.PostgresClient(),
			f.kafkaProducer,
			500,           // batch size
			5*time.Second, // poll interval
			"audit-logs",  // Changed from "audit-events" to "audit-logs"
		)
	}
	return f.auditOutboxService
}

// ============================================================================
// ✅ HR EMPLOYEE REPOSITORY GETTER
// ============================================================================

func (f *Factory) DocumentStorage() a.DocumentStorage {
	if f.documentStorage == nil {
		f.logger.Fatal("Document storage not initialized")
	}
	return f.documentStorage
}

func (f *Factory) HREmployeeRepository() hrpostgres.EmployeeRepository {
	if f.hrEmployeeRepository == nil {
		f.hrEmployeeRepository = hrpostgres.NewEmployeeRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.hrEmployeeRepository
}

// ============================================================================
// ATTENDANCE SERVICE (WRITE / COMMAND)
// ============================================================================

func (f *Factory) GetAttendanceService() a.AttendanceService {
	if f.attendanceService == nil {
		f.attendanceService = a.NewAttendanceService(
			f.AttendanceRepository(),
			f.logger,
		)
	}
	return f.attendanceService
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
// ✅ UPDATED REPOSITORY GETTERS - POSTGRESQL MIGRATION
// ============================================================================

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

// Add getter methods
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
func (f *Factory) WorkCalendarRepository() hrpostgres.SchedulingRepository {
	return f.GetSchedulingRepository()
}

func (f *Factory) ScheduleTemplateRepository() hrpostgres.SchedulingRepository {
	return f.GetSchedulingRepository()
}

func (f *Factory) ScheduleAssignmentRepository() hrpostgres.SchedulingRepository {
	return f.GetSchedulingRepository()
}

func (f *Factory) ScheduleInstanceRepository() hrpostgres.SchedulingRepository {
	return f.GetSchedulingRepository()
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

func (f *Factory) AttendanceRepository() hrpostgres.AttendanceRepository {
	// Create attendance repository if not exists
	if f.attendanceRepository == nil {
		f.attendanceRepository = hrpostgres.NewAttendanceRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.attendanceRepository
}

// ============================================================================
// ✅ USER OTP SERVICE GETTERS
// ============================================================================

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

		// Set admin service after UserOTPService is created to break circular dependency
		if phoneValidator != nil {
			phoneValidator.SetAdminService(f.GetAdminService())
		}
	}
	return f.userOTPService
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

func (f *Factory) LeaveRepository() hrpostgres.LeaveRepository {
	if f.leaveRepository == nil {
		f.leaveRepository = hrpostgres.NewLeaveRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.leaveRepository
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
// ✅ JWT AND RBAC SERVICES
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

// ============================================================================
// ✅ SERVICE GETTERS - UPDATED WITH JWT AND BITMASK SUPPORT
// ============================================================================

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
	// Create phone validator without admin service initially to break circular dependency
	phoneValidator := service.NewPhoneValidator(
		f.GetUserService(),
		nil, // Don't pass admin service yet
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

		// Create phone validator without triggering admin service creation
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
			f.smsManager, // ADD THIS: Pass SMS Manager
		)

		// Set admin service after OTPService is created to break circular dependency
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
			f.CompanyRepository(), // ✅ NEW: companyRepo
			f.GetSessionService(),
			f.GetOTPService(), // This is now safe
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

// func (f *Factory) GetPhoneValidator() *service.PhoneValidatorImpl {
// 	return service.NewPhoneValidator(
// 		f.GetUserService(),
// 		nil,
// 		f.logger,
// 	)
// }

// func (f *Factory) GetOTPService() *service.OTPService {
// 	if f.otpService == nil {
// 		repo := f.OTPRepository()
// 		hasher := f.Hasher()
// 		cfg := f.Config()
// 		logger := f.logger

// 		var distCache *service.DistributedCache
// 		if f.redisClient != nil {
// 			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
// 		}

// 		logProducer := f.GetLogProducerService()
// 		phoneValidator := f.GetPhoneValidator()

//			f.otpService = service.NewOTPService(
//				repo,
//				hasher,
//				cfg,
//				distCache,
//				logger,
//				logProducer,
//				phoneValidator,
//			)
//		}
//		return f.otpService
//	}
func (f *Factory) GetMPINService() *service.MPINService {
	if f.mpinService == nil {
		mpinRepo := f.MPINRepository()
		userRepo := f.UserRepository()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		userOTPService := f.GetUserOTPService() // ✅ NEW: for users
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
		deviceTrustRepo := f.GetDeviceTrustRepository()        // NEW
		adminDeviceTrustRepo := f.AdminDeviceTrustRepository() // NEW
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.deviceService = service.NewDeviceService(
			deviceRepo,
			deviceTrustRepo,      // NEW ARG
			adminDeviceTrustRepo, // NEW ARG
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

// ============================================================================
// ✅ ADMIN SERVICE GETTERS
// ============================================================================

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

// func (f *Factory) GetAdminService() *service.AdminService {
// 	if f.adminService == nil {
// 		f.adminService = service.NewAdminService(
// 			f.AdminRepository(),
// 			f.UserRepository(),
// 			f.GetSessionService(),
// 			f.GetOTPService(),
// 			f.GetMPINService(),
// 			f.GetDeviceService(),
// 			f.Hasher(),
// 			f.EncryptionManager(),
// 			f.logger,
// 		)

// 		logProducer := f.GetLogProducerService()
// 		if logProducer != nil {
// 			f.adminService.SetLogProducerService(logProducer)
// 		}
// 	}
// 	return f.adminService
// }

// ============================================================================
// ✅ CLIENT INITIALIZATION
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

	// ADD THIS: Initialize SMS Manager
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
		util.Bool("sms_manager_initialized", f.smsManager != nil), // ADD THIS
		util.Bool("pepper_persistence_enabled", f.hasher != nil),
	)
}

// ============================================================================
// ✅ HANDLER INITIALIZATION - UPDATED WITH JWT AND RBAC
// ============================================================================
// ============================================================================
// ✅ HANDLER INITIALIZATION - UPDATED WITH QR WEB LOGIN
// ============================================================================

func (f *Factory) InitializeHandlers() error {
	logger := f.logger

	// Get all services
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
	userOTPService := f.GetUserOTPService() // ✅ NEW: for users

	// ✅ NEW: QR Web Login services
	_ = f.GetPairingService()
	_ = f.GetWebSocketService()

	// Initialize handlers
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

	// ✅ FIXED: Auth handler with all required services
	authHandler := handler.NewAuthHandler(
		userOTPService, // ✅ NEW: Add UserOTPService
		mpinService,
		sessionService,
		userService,
		companyService,
		deviceService,
		jwtService,
		logger,
	)
	f.authHandler = authHandler

	// ✅ NEW: QR Web Login handlers
	pairingHandler := f.GetPairingHandler()
	wsHandler := f.GetWebSocketHandler()

	// ✅ UPDATED: Router with QR Web Login handlers
	f.router = handler.NewRouter(
		otpHandler,
		adminHandler,
		authHandler,
		rbacHandler,

		f.GetHRAttendanceHandler(),
		f.GetHRAuditHandler(),
		f.GetHRCompensationHandler(),
		f.GetHREmployeeHandler(),
		f.GetHRLeaveHandler(),
		f.GetHRSchedulingHandler(),

		pairingHandler,
		wsHandler,

		sessionService,
		jwtService,
		logger,
	)

	logger.Info("Handlers and router initialized with JWT, bitmask, and QR web login support")
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
// ✅ RBAC INITIALIZATION
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
// ✅ HEALTH CHECK - UPDATED FOR JWT AND RBAC
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
	if f.attendanceService != nil {
		if err := f.attendanceService.HealthCheck(ctx); err != nil {
			errs["attendance_service"] = err
		}
	} else {
		errs["attendance_service"] = fmt.Errorf("attendance service not initialized")
	}

	if f.attendanceQueryService != nil {
		if err := f.attendanceQueryService.HealthCheck(ctx); err != nil {
			errs["attendance_query_service"] = err
		}
	} else {
		errs["attendance_query_service"] = fmt.Errorf("attendance query service not initialized")
	}

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

	// ======================================================================
	// ✅ NEW — QR WEB LOGIN HEALTH CHECKS
	// ======================================================================
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
			// cleanup
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
// ✅ CLEANUP
// ============================================================================
// ============================================================================
// ✅ CLEANUP (UPDATED — NO INVALID Close() CALLS ON KAFKA CONSUMERS)
// ============================================================================
// ============================================================================
// ✅ CLEANUP (FINAL — WITH ES & CLICKHOUSE CONSUMER STOP + KAFKA PRODUCER CLOSE)
// ============================================================================
func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		util.Info("Shutting down factory...")

		// ============================================================================
		// 1️⃣ SHUTDOWN KAFKA LOGGING MANAGER
		//    - Cancels consumer contexts
		//    - Waits for goroutines to exit
		// ============================================================================
		if f.kafkaLoggingMgr != nil {
			util.Info("Shutting down Kafka logging manager...")

			// Stop all consumer goroutines
			if f.kafkaLoggingMgr.cancelCtx != nil {
				f.kafkaLoggingMgr.cancelCtx()
			}

			// Wait for ES/ClickHouse consumers to exit
			f.kafkaLoggingMgr.wg.Wait()

			// Close log producer (this wraps KafkaProducer)
			if f.kafkaLoggingMgr.producer != nil {
				if err := f.kafkaLoggingMgr.producer.Close(); err != nil {
					util.Error("Failed to close log producer", util.ErrorField(err))
				}
			}

			// Explicit status logs
			if f.kafkaLoggingMgr.esConsumer != nil {
				util.Info("Elasticsearch Kafka consumer stopped")
			}
			if f.kafkaLoggingMgr.chConsumer != nil {
				util.Info("ClickHouse Kafka consumer stopped")
			}

			util.Info("Kafka logging system fully shut down")
		}

		// ============================================================================
		// 2️⃣ SHUTDOWN KAFKA PRODUCER (GLOBAL)
		//    Note: LogProducerService already closed its producer, but we still
		//    close the factory-level one as safety.
		// ============================================================================
		if f.kafkaProducer != nil {
			if err := f.kafkaProducer.Close(); err != nil {
				util.Error("Failed to close Kafka producer", util.ErrorField(err))
			} else {
				util.Info("Kafka producer closed")
			}
		}

		// ============================================================================
		// 3️⃣ CLOSE DATABASES
		// ============================================================================
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

		// ============================================================================
		// 4️⃣ SERVICE FACTORY CLEANUP
		// ============================================================================
		if f.serviceFactory != nil {
			f.serviceFactory.Cleanup()
			util.Info("Service factory cleaned up")
		}

		// ============================================================================
		// 5️⃣ CLOSE SCYLLA + REDIS
		// ============================================================================
		if f.scyllaClient != nil {
			f.scyllaClient.Close()
			util.Info("ScyllaDB client closed")
		}

		if f.redisClient != nil {
			f.redisClient.Close()
			util.Info("Redis client closed")
		}

		// ============================================================================
		// 6️⃣ SECURITY MANAGERS
		// ============================================================================
		if f.hasher != nil {
			util.Info("Hasher shut down")
		}

		if f.encryptionManager != nil {
			f.encryptionManager.ClearCache()
			util.Info("Encryption manager cache cleared")
		}
		// =========================================================================
		// ✅ STOP AUDIT OUTBOX SERVICE
		// =========================================================================
		if f.auditOutboxCancel != nil {
			f.logger.Info("Stopping audit outbox service...")
			f.auditOutboxCancel()
		}

		// ============================================================================
		// 7️⃣ WEBSOCKET SERVICE
		// ============================================================================
		if f.wsService != nil {
			if closer, ok := interface{}(f.wsService).(interface{ Close() error }); ok {
				_ = closer.Close()
			}
			util.Info("WebSocket service shut down")
		}

		// ============================================================================
		// 8️⃣ FINAL LOGGING SYNC
		// ============================================================================
		util.Sync()
		util.Info("Factory shutdown completed")
	})

	return nil
}

// ============================================================================
// ✅ SIMPLE GETTERS
// ============================================================================

func (f *Factory) Config() *config.Config                           { return f.config }
func (f *Factory) TLSManager() *tls.TLSManager                      { return f.tlsManager }
func (f *Factory) ScyllaClient() *scylla.ScyllaClient               { return f.scyllaClient }
func (f *Factory) Hasher() *hashing.Hasher                          { return f.hasher }
func (f *Factory) EncryptionManager() *encryption.EncryptionManager { return f.encryptionManager }
func (f *Factory) BucketingManager() *bucketing.BucketingManager    { return f.bucketingManager }
func (f *Factory) PostgresClient() *client.PostgresClient           { return f.postgresClient }
func (f *Factory) GetLogProducerService() *service.LogProducerService {
	if f.kafkaLoggingMgr == nil {
		return nil
	}
	return f.kafkaLoggingMgr.GetLogProducerService()
}

// ✅ UPDATED: PostgreSQL repository getters
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

// GetPairingRepository returns the pairing repository
func (f *Factory) GetPairingRepository() redis.PairingRepository {
	if f.pairingRepo == nil {
		f.pairingRepo = redis.NewPairingRepository(
			f.redisClient.Client(),
			f.logger,
		)
	}
	return f.pairingRepo
}

// GetHMACUtil returns HMAC utility
func (f *Factory) GetHMACUtil() *util.HMACUtil {
	if f.hmacUtil == nil {
		secret := f.config.Security.JWTSecret // Use JWT secret or separate config
		if secret == "" {
			secret = "default-qr-hmac-secret-change-in-production"
		}
		f.hmacUtil = util.NewHMACUtil(secret)
	}
	return f.hmacUtil
}

// GetQRUtil returns QR utility
func (f *Factory) GetQRUtil() *util.QRUtil {
	if f.qrUtil == nil {
		f.qrUtil = util.NewQRUtil(f.config.Security.JWTSecret)
	}
	return f.qrUtil
}

// GetPairingService returns the pairing service
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

// GetWebSocketService returns the WebSocket service
func (f *Factory) GetWebSocketService() *service.WebSocketService {
	if f.wsService == nil {
		f.wsService = service.NewWebSocketService(f.logger)

		// Start the WebSocket service in background
		go f.wsService.Run()

		f.logger.Info("WebSocket service started")
	}
	return f.wsService
}

// GetPairingHandler returns the pairing handler
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

// GetWebSocketHandler returns the WebSocket handler
func (f *Factory) GetWebSocketHandler() *handler.WebSocketHandler {
	if f.wsHandler == nil {
		f.wsHandler = handler.NewWebSocketHandler(
			f.GetWebSocketService(),
			f.logger,
		)
	}
	return f.wsHandler
}

// GetSMSManager returns the SMS manager instance
func (f *Factory) GetSMSManager() *sms.SMSManager {
	return f.smsManager
}
