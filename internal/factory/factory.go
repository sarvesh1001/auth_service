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
	leaverepo "auth-service/internal/hr/leave/repository"
	payrollrepo "auth-service/internal/hr/payroll/repository"
	hrpostgres "auth-service/internal/hr/repository"
	a "auth-service/internal/hr/service"
	orgunitservice "auth-service/internal/hr/service"
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

	leavehandler "auth-service/internal/hr/leave/handler"
	leavesvc "auth-service/internal/hr/leave/service"
	payrollhandler "auth-service/internal/hr/payroll/handler"
	payrollsvc "auth-service/internal/hr/payroll/service"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

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
	schedulingRepository         hrpostgres.SchedulingRepository
	auditRepository              hrpostgres.AuditRepository
	workCenterRepository         hrpostgres.WorkCenterRepository
	orgUnitRepository            hrpostgres.OrgUnitRepository
	attendanceIdentityRepository hrpostgres.AttendanceIdentityRepository
	attendanceDeviceRepository   hrpostgres.AttendanceDeviceRepository

	// Leave Repository
	leaveRepository leaverepo.LeaveRepository

	// Payroll Repository
	payrollRepository payrollrepo.PayrollRepository

	// Handlers
	attendanceDeviceHandler     *hrhandler.DeviceHandler
	attendanceAdminHandler      *hrhandler.AttendanceAdminHandler
	attendanceQueryHandler      *hrhandler.AttendanceQueryHandler
	attendanceResolutionHandler *hrhandler.AttendanceResolutionHandler
	attendanceCorrectionHandler *hrhandler.AttendanceCorrectionHandler
	workCenterHandler           *hrhandler.WorkCenterHandler
	orgUnitHandler              *orgunithandler.OrgUnitHandler
	hrAuditHandler              *hrhandler.AuditHandler
	hrEmployeeHandler           *hrhandler.EmployeeHandler
	hrSchedulingHandler         *hrhandler.SchedulingHandler

	// Leave Handlers
	leaveAdminHandler   *leavehandler.LeaveAdminHandler
	leaveQueryHandler   *leavehandler.LeaveQueryHandler
	leaveRequestHandler *leavehandler.LeaveRequestHandler
	// Attendance – Class & OM
	attendanceClassService a.ClassAttendanceService
	attendanceClassHandler *hrhandler.AttendanceClassHandler
	attendanceOMHandler    *hrhandler.AttendanceOMHandler

	// Payroll Handlers
	payrollAdminHandler    *payrollhandler.PayrollAdminHandler
	payrollRunHandler      *payrollhandler.PayrollRunHandler
	attendanceBulkService  a.AttendanceBulkService
	attendanceBatchService a.AttendanceBatchService

	// Services
	workCenterService            *a.WorkCenterService
	workCenterQueryService       *a.WorkCenterQueryService
	orgUnitService               *orgunitservice.OrgUnitService
	orgUnitQueryService          *orgunitservice.OrgUnitQueryService
	auditService                 *a.AuditService
	auditQueryService            *a.AuditQueryService
	employeeQueryService         *a.EmployeeQueryService
	employeeService              *a.EmployeeService
	schedulingService            a.SchedulingService
	schedulingQueryService       a.SchedulingQueryService
	attendanceIngestService      a.AttendanceIngestService
	attendanceSourceResolver     a.AttendanceSourceResolver
	attendanceAdminService       a.AttendanceAdminService
	attendanceQueryService       a.AttendanceQueryService
	attendanceDeviceService      a.AttendanceDeviceService
	attendanceResolutionService  a.AttendanceResolutionService
	attendanceOMService          a.AttendanceOMService
	attendanceOutboxService      *a.AttendanceOutboxService
	attendanceOutboxCancel       context.CancelFunc
	attendanceResolutionConsumer *b.AttendanceResolutionConsumer
	attendanceResolutionCancel   context.CancelFunc

	// Leave Services
	leaveBalanceService leavesvc.LeaveBalanceService
	leavePolicyService  leavesvc.LeavePolicyService
	leaveAccrualService leavesvc.LeaveAccrualService
	leaveQueryService   leavesvc.LeaveQueryService
	leaveRequestService leavesvc.LeaveRequestService

	// Payroll Services
	payrollRunService         payrollsvc.PayrollRunService
	payrollCalculationService payrollsvc.PayrollCalculationService
	payrollLockService        payrollsvc.PayrollLockService
	compensationResolver      payrollsvc.CompensationResolver
	taxEngine                 payrollsvc.TaxEngine
	payslipService            payrollsvc.PayslipService // 👈 ADD THIS
	documentStorage           a.DocumentStorage

	attendanceIngestHandler *hrhandler.AttendanceIngestHandler

	postgresClient            *client.PostgresClient
	postgresUserRepository    postgres.UserRepository
	postgresCompanyRepository postgres.CompanyRepository
	smsManager                *sms.SMSManager
	serviceFactory            *service.ServiceFactory

	adminDeviceRepo        *scylla.AdminDeviceRepositoryImpl
	adminDeviceTrustRepo   scylla.AdminDeviceTrustRepository
	adminMPINRepo          *scylla.AdminMPINRepositoryImpl
	adminDeviceHistoryRepo *scylla.AdminDeviceHistoryRepositoryImpl

	userOTPService     *service.UserOTPService
	companyService     *service.CompanyService
	adminDeviceService *service.AdminDeviceService
	adminMPINService   *service.AdminMPINService
	userService        *service.UserService
	mpinRepository     scylla.MPINRepository
	mpinService        *service.MPINService
	pepperStoreRepo    pepperstore.PepperStore
	deviceTrustRepo    scylla.DeviceTrustRepository
	otpRepository      scylla.OTPRepository
	otpService         *service.OTPService
	sessionRepo        redis.SessionRepository
	sessionService     *service.SessionService
	deviceRepository   scylla.DeviceRepository
	deviceService      *service.DeviceService
	deviceHistoryRepo  *scylla.DeviceHistoryRepositoryImpl

	kafkaLoggingMgr *KafkaLoggingManager
	payslipHandler  *payrollhandler.PayslipHandler // 👈 ADD
	adminRepository postgres.AdminRepository
	adminService    *service.AdminService
	jwtService      *service.JWTService
	rbacInitService *service.RBACInitService
	authHandler     *handler.AuthHandler
	router          chi.Router
	logger          *zap.Logger

	auditOutboxService *service.AuditOutboxService
	auditOutboxCancel  context.CancelFunc

	once      sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

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

func NewFactory() (*Factory, error) {
	cfg := config.LoadConfig()
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

	ctx := context.Background()
	if err := f.InitializeRBAC(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}

	if err := f.initializeDocumentStorage(); err != nil {
		return nil, err
	}

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

	if err := f.initializeAttendanceOutbox(); err != nil {
		f.logger.Error("Failed to initialize attendance outbox", zap.Error(err))
	}

	return f, nil
}

// Payroll Repository
func (f *Factory) PayrollRepository() payrollrepo.PayrollRepository {
	if f.payrollRepository == nil {
		f.payrollRepository = payrollrepo.NewPayrollRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.payrollRepository
}

// Payroll Services
func (f *Factory) CompensationResolver() payrollsvc.CompensationResolver {
	if f.compensationResolver == nil {
		f.compensationResolver = payrollsvc.NewCompensationResolver(
			f.PayrollRepository(),
			f.logger,
		)
	}
	return f.compensationResolver
}

func (f *Factory) TaxEngine() payrollsvc.TaxEngine {
	if f.taxEngine == nil {
		f.taxEngine = payrollsvc.NewTaxEngine(
			f.PayrollRepository(),
			f.logger,
		)
	}
	return f.taxEngine
}

func (f *Factory) PayrollCalculationService() payrollsvc.PayrollCalculationService {
	if f.payrollCalculationService == nil {
		f.payrollCalculationService = payrollsvc.NewPayrollCalculationService(
			f.PayrollRepository(),
			f.CompensationResolver(),
			f.TaxEngine(),
			f.logger,
		)
	}
	return f.payrollCalculationService
}

func (f *Factory) PayrollLockService() payrollsvc.PayrollLockService {
	if f.payrollLockService == nil {
		f.payrollLockService = payrollsvc.NewPayrollLockService(
			f.PayrollRepository(),
			f.logger,
		)
	}
	return f.payrollLockService
}

func (f *Factory) PayrollRunService() payrollsvc.PayrollRunService {
	if f.payrollRunService == nil {
		f.payrollRunService = payrollsvc.NewPayrollRunService(
			f.PayrollRepository(),
			f.PayrollCalculationService(),
			f.PayrollLockService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.payrollRunService
}

// Payroll Handlers
func (f *Factory) PayrollAdminHandler() *payrollhandler.PayrollAdminHandler {
	if f.payrollAdminHandler == nil {
		f.payrollAdminHandler = payrollhandler.NewPayrollAdminHandler(
			f.PayrollLockService(),
			f.PayrollCalculationService(),
			f.logger,
		)
	}
	return f.payrollAdminHandler
}

func (f *Factory) PayrollRunHandler() *payrollhandler.PayrollRunHandler {
	if f.payrollRunHandler == nil {
		f.payrollRunHandler = payrollhandler.NewPayrollRunHandler(
			f.PayrollRunService(),
			f.logger,
		)
	}
	return f.payrollRunHandler
}

// Leave Services (already existing but kept for completeness)
func (f *Factory) LeaveRepository() leaverepo.LeaveRepository {
	if f.leaveRepository == nil {
		f.leaveRepository = leaverepo.NewLeaveRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.leaveRepository
}

func (f *Factory) LeavePolicyService() leavesvc.LeavePolicyService {
	if f.leavePolicyService == nil {
		f.leavePolicyService = leavesvc.NewLeavePolicyService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leavePolicyService
}

func (f *Factory) LeaveAccrualService() leavesvc.LeaveAccrualService {
	if f.leaveAccrualService == nil {
		f.leaveAccrualService = leavesvc.NewLeaveAccrualService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveAccrualService
}

func (f *Factory) LeaveQueryService() leavesvc.LeaveQueryService {
	if f.leaveQueryService == nil {
		f.leaveQueryService = leavesvc.NewLeaveQueryService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveQueryService
}
func (f *Factory) PayslipHandler() *payrollhandler.PayslipHandler {
	if f.payslipHandler == nil {
		f.payslipHandler = payrollhandler.NewPayslipHandler(
			f.PayslipService(),
		)
	}
	return f.payslipHandler
}

func (f *Factory) LeaveBalanceService() leavesvc.LeaveBalanceService {
	if f.leaveBalanceService == nil {
		f.leaveBalanceService = leavesvc.NewLeaveBalanceService(
			f.LeaveRepository(),
			f.logger,
		)
	}
	return f.leaveBalanceService
}

func (f *Factory) LeaveRequestService() leavesvc.LeaveRequestService {
	if f.leaveRequestService == nil {
		f.leaveRequestService = leavesvc.NewLeaveRequestService(
			f.LeaveRepository(),
			f.LeaveBalanceService(),
			f.logger,
		)
	}
	return f.leaveRequestService
}

// Leave Handlers
func (f *Factory) LeaveAdminHandler() *leavehandler.LeaveAdminHandler {
	if f.leaveAdminHandler == nil {
		f.leaveAdminHandler = leavehandler.NewLeaveAdminHandler(
			f.LeavePolicyService(),
			f.LeaveAccrualService(),
			f.logger,
		)
	}
	return f.leaveAdminHandler
}

func (f *Factory) LeaveQueryHandler() *leavehandler.LeaveQueryHandler {
	if f.leaveQueryHandler == nil {
		f.leaveQueryHandler = leavehandler.NewLeaveQueryHandler(
			f.LeaveQueryService(),
			f.logger,
		)
	}
	return f.leaveQueryHandler
}

func (f *Factory) LeaveRequestHandler() *leavehandler.LeaveRequestHandler {
	if f.leaveRequestHandler == nil {
		f.leaveRequestHandler = leavehandler.NewLeaveRequestHandler(
			f.LeaveRequestService(),
			f.LeaveQueryService(),
			f.GetSchedulingService(),
			f.logger,
		)
	}
	return f.leaveRequestHandler
}

func (f *Factory) GetAttendanceBatchService() a.AttendanceBatchService {
	if f.attendanceBatchService == nil {
		f.attendanceBatchService = a.NewAttendanceBatchService(
			f.GetAttendanceAdminService(),
			f.GetAttendanceOMService(),
			f.GetAttendanceResolutionService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.attendanceBatchService
}

// Existing HR Services (kept for reference)
func (f *Factory) GetAttendanceOMService() a.AttendanceOMService {
	if f.attendanceOMService == nil {
		f.attendanceOMService = a.NewAttendanceOMService(
			f.OrgUnitRepository(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.attendanceOMService
}

func (f *Factory) PayslipService() payrollsvc.PayslipService {
	if f.payslipService == nil {
		f.payslipService = payrollsvc.NewPayslipService(
			f.PayrollRepository(),
		)
	}
	return f.payslipService
}

func (f *Factory) GetAttendanceIngestService() a.AttendanceIngestService {
	if f.attendanceIngestService == nil {
		f.attendanceIngestService = a.NewAttendanceIngestService(
			f.AttendanceRepository(),
			f.AttendanceDeviceRepository(),
			f.AttendanceIdentityRepository(),
			f.GetAttendanceSourceResolver(),
			f.GetAttendanceAdminService(), // ✅ ADD THIS
			f.GetAttendanceOMService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.attendanceIngestService
}

func (f *Factory) GetAttendanceSourceResolver() a.AttendanceSourceResolver {
	if f.attendanceSourceResolver == nil {
		f.attendanceSourceResolver = a.NewAttendanceSourceResolver(
			f.logger,
		)
	}
	return f.attendanceSourceResolver
}

func (f *Factory) GetAttendanceAdminService() a.AttendanceAdminService {
	if f.attendanceAdminService == nil {
		f.attendanceAdminService = a.NewAttendanceAdminService(
			f.AttendanceRepository(),
			f.GetSchedulingRepository(),
			f.GetAttendanceResolutionService(),
			f.GetAttendanceOMService(),
			f.logger,
			f.GetAuditService(),
		)
	}
	return f.attendanceAdminService
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

func (f *Factory) GetAttendanceClassService() a.ClassAttendanceService {
	if f.attendanceClassService == nil {
		f.attendanceClassService = a.NewClassAttendanceService(
			f.OrgUnitRepository(),
			f.GetAttendanceBatchService(),
			f.logger,
		)
	}
	return f.attendanceClassService
}

func (f *Factory) GetAttendanceClassHandler() *hrhandler.AttendanceClassHandler {
	if f.attendanceClassHandler == nil {
		f.attendanceClassHandler = hrhandler.NewAttendanceClassHandler(
			f.GetAttendanceClassService(),
			f.logger,
		)
	}
	return f.attendanceClassHandler
}
func (f *Factory) GetAttendanceOMHandler() *hrhandler.AttendanceOMHandler {
	if f.attendanceOMHandler == nil {
		f.attendanceOMHandler = hrhandler.NewAttendanceOMHandler(
			f.GetAttendanceOMService(),
			f.logger,
		)
	}
	return f.attendanceOMHandler
}

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

func (f *Factory) GetAttendanceResolutionService() a.AttendanceResolutionService {
	if f.attendanceResolutionService == nil {
		f.attendanceResolutionService = a.NewAttendanceResolutionService(
			f.AttendanceRepository(),
			f.GetSchedulingQueryService(),
			f.GetSchedulingService(),
			f.GetAuditService(),
			f.logger,
		)
	}
	return f.attendanceResolutionService
}

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

func (f *Factory) initializeAttendanceOutbox() error {
	if f.kafkaProducer == nil {
		f.logger.Warn("Kafka producer not available, attendance outbox disabled")
		return nil
	}

	f.attendanceOutboxService = a.NewAttendanceOutboxService(
		f.PostgresClient(),
		f.kafkaProducer,
		500,
		2*time.Second,
		"attendance.events",
	)

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

	kafkaConsumer, err := client.NewKafkaConsumer(
		f.config,
		"attendance.events",
		"attendance-resolution-consumer-group",
		f.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create attendance kafka consumer: %w", err)
	}

	resolutionService := f.GetAttendanceResolutionService()
	f.attendanceResolutionConsumer = b.NewAttendanceResolutionConsumer(
		kafkaConsumer,
		resolutionService,
		f.logger,
	)

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

func (f *Factory) GetAttendanceIngestHandler() *hrhandler.AttendanceIngestHandler {
	if f.attendanceIngestHandler == nil {
		f.attendanceIngestHandler = hrhandler.NewAttendanceIngestHandler(
			f.GetAttendanceIngestService(),
			f.logger,
		)
	}
	return f.attendanceIngestHandler
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

func (f *Factory) GetSchedulingRepository() hrpostgres.SchedulingRepository {
	if f.schedulingRepository == nil {
		f.schedulingRepository = hrpostgres.NewSchedulingRepository(
			f.PostgresClient(),
			f.logger,
		)
	}
	return f.schedulingRepository
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

func (f *Factory) GetSchedulingService() a.SchedulingService {
	if f.schedulingService == nil {
		f.schedulingService = a.NewSchedulingService(
			f.GetSchedulingRepository(),
			f.LeaveQueryService(),
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
func (f *Factory) GetAttendanceBulkService() a.AttendanceBulkService {
	if f.attendanceBulkService == nil {
		f.attendanceBulkService = a.NewAttendanceBulkService(
			f.GetAttendanceBatchService(), // 🔥 delegate
			f.logger,
		)
	}
	return f.attendanceBulkService
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

	return nil
}

func (f *Factory) DocumentStorage() a.DocumentStorage {
	if f.documentStorage == nil {
		f.logger.Fatal("Document storage not initialized")
	}
	return f.documentStorage
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

func (f *Factory) initializeClients() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var initErrors []error

	if rc, err := client.NewRedisClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("redis: %w", err))
	} else {
		f.redisClient = rc
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("redis health check: %w", err))
		}
	}

	if pgc, err := client.NewPostgresClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("postgres: %w", err))
	} else {
		f.postgresClient = pgc
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("postgres health check: %w", err))
		}
	}

	if sc, err := scylla.NewScyllaClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = sc
		if err := f.scyllaClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("scylla health check: %w", err))
		}
	}

	if ec, err := client.NewElasticsearchClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("elasticsearch: %w", err))
	} else {
		f.esClient = ec
		if err := f.esClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("elasticsearch health check: %w", err))
		}
	}

	if chc, err := client.NewClickHouseClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("clickhouse: %w", err))
	} else {
		f.clickhouseClient = chc
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("clickhouse health check: %w", err))
		}
	}

	if len(initErrors) > 0 {
		for _, e := range initErrors {
			f.logger.Error("Client initialization failed", zap.Error(e))
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
	}

	var kmsClient *kms.Client
	if f.config.KMS.Enabled {
		kmsClient = nil
	}
	f.encryptionManager = encryption.NewEncryptionManager(f.config, kmsClient)
	f.bucketingManager = bucketing.NewBucketingManager(f.config)
	f.smsManager = sms.NewSMSManager(f.logger)

	if f.hasher != nil && f.config.IsProduction() {
		f.hasher.StartPepperRotation()
	}
}

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

	f.router = handler.NewRouter(
		otpHandler,
		adminHandler,
		authHandler,
		rbacHandler,
		f.GetHRAuditHandler(),
		f.GetHREmployeeHandler(),
		f.GetHRSchedulingHandler(),
		f.GetAttendanceIngestHandler(),
		pairingHandler,
		f.GetWorkCenterHandler(),
		wsHandler,
		sessionService,
		jwtService,
		logger,
		f.GetOrgUnitHandler(),
		f.LeaveAdminHandler(),
		f.LeaveRequestHandler(),
		f.LeaveQueryHandler(),
		f.PayrollAdminHandler(),
		f.PayrollRunHandler(),
		f.GetAttendanceDeviceHandler(),
		f.GetAttendanceAdminHandler(),
		f.GetAttendanceQueryHandler(),
		f.GetAttendanceResolutionHandler(),
		f.GetAttendanceCorrectionHandler(),
	)

	logger.Info("Handlers and router initialized with JWT, bitmask, QR web login, attendance, leave, and payroll systems")
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

func (f *Factory) InitializeRBAC(ctx context.Context) error {
	rbacInitService := f.GetRBACInitService()
	if err := rbacInitService.InitializePermissionRegistry(ctx); err != nil {
		return fmt.Errorf("failed to initialize RBAC permission registry: %w", err)
	}
	f.logger.Info("RBAC permission registry initialized successfully")
	return nil
}

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	if f.postgresClient != nil {
		if err := f.postgresClient.HealthCheck(ctx); err != nil {
			errs["postgres"] = err
		}
	} else {
		errs["postgres"] = fmt.Errorf("postgres client not initialized")
	}

	// Check payroll services
	if f.payrollRepository != nil {
		if err := f.payrollRepository.HealthCheck(ctx); err != nil {
			errs["payroll_repository"] = err
		}
	} else {
		errs["payroll_repository"] = fmt.Errorf("payroll repository not initialized")
	}

	if f.leaveRepository != nil {
		if err := f.leaveRepository.HealthCheck(ctx); err != nil {
			errs["leave_repository"] = err
		}
	} else {
		errs["leave_repository"] = fmt.Errorf("leave repository not initialized")
	}

	// Existing health checks remain...
	// [Previous health check code remains the same, just showing payroll addition]

	return errs
}

func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)

		if f.kafkaLoggingMgr != nil {
			if f.kafkaLoggingMgr.cancelCtx != nil {
				f.kafkaLoggingMgr.cancelCtx()
			}
			f.kafkaLoggingMgr.wg.Wait()
			if f.kafkaLoggingMgr.producer != nil {
				if err := f.kafkaLoggingMgr.producer.Close(); err != nil {
					f.logger.Error("Failed to close Kafka producer", zap.Error(err))
				}
			}
		}

		if f.kafkaProducer != nil {
			if err := f.kafkaProducer.Close(); err != nil {
				f.logger.Error("Failed to close Kafka producer", zap.Error(err))
			} else {
				f.logger.Info("Kafka producer closed successfully")
			}
		}

		if f.attendanceOutboxCancel != nil {
			f.logger.Info("Stopping attendance outbox service...")
			f.attendanceOutboxCancel()
		}

		if f.attendanceResolutionCancel != nil {
			f.logger.Info("Stopping attendance resolution consumer...")
			f.attendanceResolutionCancel()
		}

		if f.auditOutboxCancel != nil {
			f.logger.Info("Stopping audit outbox service...")
			f.auditOutboxCancel()
		}

		if f.postgresClient != nil {
			f.postgresClient.Close()
		}

		if f.clickhouseClient != nil {
			f.clickhouseClient.Close()
		}

		if f.esClient != nil {
			f.esClient.Close()
		}

		if f.serviceFactory != nil {
			f.serviceFactory.Cleanup()
		}

		if f.scyllaClient != nil {
			f.scyllaClient.Close()
		}

		if f.redisClient != nil {
			f.redisClient.Close()
		}

		if f.encryptionManager != nil {
			f.encryptionManager.ClearCache()
		}

		if f.wsService != nil {
			if closer, ok := interface{}(f.wsService).(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
	})
	return nil
}

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
