package factory

import (
	"time"

	"auth-service/internal/accounting"
	"auth-service/internal/accounting/handler"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	mainservice "auth-service/internal/service"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// AccountingInfraFactory initializes all accounting module dependencies.
type AccountingInfraFactory struct {
	log              *zap.Logger
	postgresClient   *client.PostgresClient
	eventPublisher   EventPublisher
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	outboxRepo       outbox.Repository // ✅ shared outbox repository (no local processor)

	// Repositories
	accountRepo        repository.AccountRepository
	analyticsRepo      repository.AnalyticsRepository
	complianceRepo     repository.ComplianceRepository
	journalRepo        repository.JournalRepository
	ledgerRepo         repository.LedgerRepository
	periodLockRepo     repository.PeriodLockRepository
	reconciliationRepo repository.ReconciliationRepository
	settingsRepo       repository.AccountingSettingsRepository
	taxProfileRepo     repository.TaxProfileRepository
	taxRateRepo        repository.TaxRateRepository
	taxRuleRepo        repository.TaxRuleRepository
	taxTransactionRepo repository.TaxTransactionRepository
	analyticsHandler   *handler.AnalyticsHandler
	periodLockService  service.PeriodLockService
	periodLockHandler  *handler.PeriodLockHandler

	// Services
	accountingSvc              service.AccountingService
	accountingAnalyticsSvc     service.AccountingAnalyticsService
	accountingQuerySvc         *service.AccountingQueryService
	accountSvc                 service.AccountService
	complianceSvc              service.ComplianceService
	complianceAnalyticsSvc     service.ComplianceAnalyticsService
	journalSvc                 service.JournalService
	ledgerSvc                  service.LedgerService
	ruleEngineSvc              service.AccountingRuleEngine
	reconciliationSvc          service.ReconciliationService
	reconciliationAnalyticsSvc service.ReconciliationAnalyticsService
	taxAnalyticsSvc            service.TaxAnalyticsService
	taxEngineSvc               service.TaxEngineService

	// Handlers
	accountHandler            *handler.AccountHandler
	accountingSettingsHandler *handler.AccountingSettingsHandler
	complianceHandler         *handler.ComplianceHandler
	journalHandler            *handler.JournalHandler
	ledgerHandler             *handler.LedgerHandler
	reconciliationHandler     *handler.ReconciliationHandler
	reportHandler             *handler.ReportHandler
	taxHandler                *handler.TaxHandler
}

// NewAccountingInfraFactory creates a new accounting infrastructure factory.
// It now receives the shared outbox repository from the main factory.
func NewAccountingInfraFactory(
	postgresClient *client.PostgresClient,
	redisClient *client.RedisClient,
	sharedOutboxRepo outbox.Repository, // ✅ shared outbox repository
	eventPublisher EventPublisher,
	auditService *audit.AuditService,
	sessionService *mainservice.SessionService,
	logger *zap.Logger,
) (*AccountingInfraFactory, error) {
	af := &AccountingInfraFactory{
		log:            logger.Named("accounting_infra"),
		postgresClient: postgresClient,
		eventPublisher: eventPublisher,
		auditService:   auditService,
		outboxRepo:     sharedOutboxRepo, // ✅ use the shared repository
	}

	// Idempotency store (hybrid)
	pgStore := idempotency.NewPostgresStore(postgresClient.DB)
	redisCache := idempotency.NewRedisCache(redisClient, 24*time.Hour)
	af.idempotencyStore = idempotency.NewHybridStore(pgStore, redisCache)

	// ❌ Outbox processor creation removed – the central processor handles it

	// Initialize repositories
	af.accountRepo = repository.NewAccountRepository(af.log)
	af.analyticsRepo = repository.NewAnalyticsRepository(af.log)
	af.complianceRepo = repository.NewComplianceRepository(af.log)
	af.journalRepo = repository.NewJournalRepository(af.log)
	af.ledgerRepo = repository.NewLedgerRepository(af.log)
	af.periodLockRepo = repository.NewPeriodLockRepository(af.log)
	af.periodLockService = service.NewPeriodLockService(
		af.periodLockRepo,
		af.postgresClient,
		af.auditService,
		af.log,
		af.idempotencyStore,
	)
	af.periodLockHandler = handler.NewPeriodLockHandler(af.periodLockService, af.log)
	af.reconciliationRepo = repository.NewReconciliationRepository(af.log)
	af.settingsRepo = repository.NewAccountingSettingsRepository(af.log)
	af.taxProfileRepo = repository.NewTaxProfileRepository(af.log)
	af.taxRateRepo = repository.NewTaxRateRepository(af.log)
	af.taxRuleRepo = repository.NewTaxRuleRepository(af.log)
	af.taxTransactionRepo = repository.NewTaxTransactionRepository(af.log)

	// 👇 Services that are independent first
	// LedgerService now requires periodLockRepo
	af.ledgerSvc = service.NewLedgerService(
		af.ledgerRepo,
		af.journalRepo,
		af.settingsRepo,
		af.periodLockRepo,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	// 👇 Rule engine (needs periodLockRepo, ledgerRepo, journalRepo, settingsRepo)
	af.ruleEngineSvc = service.NewRuleEngine(
		af.ledgerRepo,
		af.journalRepo,
		af.settingsRepo,
		af.periodLockRepo,
		af.auditService,
		af.log,
	)

	// JournalService now requires ruleEngine
	af.journalSvc = service.NewJournalService(
		af.journalRepo,
		af.ledgerSvc,
		af.ruleEngineSvc,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	// Remaining services
	af.taxEngineSvc = service.NewTaxEngineService(
		af.taxProfileRepo,
		af.taxRateRepo,
		af.taxRuleRepo,
		af.taxTransactionRepo,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	af.complianceSvc = service.NewComplianceService(
		af.complianceRepo,
		af.taxEngineSvc,
		af.journalSvc,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	af.accountingSvc = service.NewAccountingService(
		af.journalSvc,
		af.ledgerSvc,
		af.taxEngineSvc,
		af.complianceSvc,
		af.settingsRepo,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	af.accountingQuerySvc = service.NewAccountingQueryService(
		af.accountRepo,
		af.journalRepo,
		af.ledgerRepo,
		af.taxTransactionRepo,
		af.complianceRepo,
		af.analyticsRepo,
		af.postgresClient,
		af.log,
	)

	af.accountingAnalyticsSvc = service.NewAccountingAnalyticsService(
		af.analyticsRepo,
		af.postgresClient,
		af.log,
	)

	af.complianceAnalyticsSvc = service.NewComplianceAnalyticsService(
		af.analyticsRepo,
		af.postgresClient,
		af.log,
	)

	af.reconciliationSvc = service.NewReconciliationService(
		af.reconciliationRepo,
		af.analyticsRepo,
		af.journalSvc,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	af.reconciliationAnalyticsSvc = service.NewReconciliationAnalyticsService(
		af.analyticsRepo,
		af.postgresClient,
		af.log,
	)

	af.taxAnalyticsSvc = service.NewTaxAnalyticsService(
		af.analyticsRepo,
		af.postgresClient.DB,
		af.log,
	)

	// Account Service
	af.accountSvc = service.NewAccountService(
		af.accountRepo,
		af.postgresClient,
		af.log,
		af.outboxRepo,
		af.idempotencyStore,
		af.auditService,
	)

	af.analyticsHandler = handler.NewAnalyticsHandler(
		af.accountingAnalyticsSvc,
		af.taxAnalyticsSvc,
		af.complianceAnalyticsSvc,
		af.reconciliationAnalyticsSvc,
		af.log,
	)

	// Handlers
	af.accountHandler = handler.NewAccountHandler(af.accountSvc, af.log)
	af.accountingSettingsHandler = handler.NewAccountingSettingsHandler(af.accountingSvc, af.log)
	af.complianceHandler = handler.NewComplianceHandler(af.complianceSvc, af.log)
	af.journalHandler = handler.NewJournalHandler(af.journalSvc, af.log)
	af.ledgerHandler = handler.NewLedgerHandler(af.ledgerSvc, af.log)
	af.reconciliationHandler = handler.NewReconciliationHandler(af.reconciliationSvc, af.log)
	af.reportHandler = handler.NewReportHandler(af.accountingQuerySvc, af.log)
	af.taxHandler = handler.NewTaxHandler(af.taxEngineSvc, af.log)

	return af, nil
}

// Getters for repositories
func (af *AccountingInfraFactory) AccountRepo() repository.AccountRepository { return af.accountRepo }
func (af *AccountingInfraFactory) AnalyticsRepo() repository.AnalyticsRepository {
	return af.analyticsRepo
}
func (af *AccountingInfraFactory) ComplianceRepo() repository.ComplianceRepository {
	return af.complianceRepo
}
func (af *AccountingInfraFactory) JournalRepo() repository.JournalRepository { return af.journalRepo }
func (af *AccountingInfraFactory) LedgerRepo() repository.LedgerRepository   { return af.ledgerRepo }
func (af *AccountingInfraFactory) PeriodLockRepo() repository.PeriodLockRepository {
	return af.periodLockRepo
}
func (af *AccountingInfraFactory) ReconciliationRepo() repository.ReconciliationRepository {
	return af.reconciliationRepo
}
func (af *AccountingInfraFactory) SettingsRepo() repository.AccountingSettingsRepository {
	return af.settingsRepo
}
func (af *AccountingInfraFactory) TaxProfileRepo() repository.TaxProfileRepository {
	return af.taxProfileRepo
}
func (af *AccountingInfraFactory) TaxRateRepo() repository.TaxRateRepository { return af.taxRateRepo }
func (af *AccountingInfraFactory) TaxRuleRepo() repository.TaxRuleRepository { return af.taxRuleRepo }
func (af *AccountingInfraFactory) TaxTransactionRepo() repository.TaxTransactionRepository {
	return af.taxTransactionRepo
}

// Getters for services
func (af *AccountingInfraFactory) AccountService() service.AccountService {
	return af.accountSvc
}
func (af *AccountingInfraFactory) AccountingService() service.AccountingService {
	return af.accountingSvc
}
func (af *AccountingInfraFactory) AccountingAnalyticsService() service.AccountingAnalyticsService {
	return af.accountingAnalyticsSvc
}
func (af *AccountingInfraFactory) AccountingQueryService() *service.AccountingQueryService {
	return af.accountingQuerySvc
}
func (af *AccountingInfraFactory) ComplianceService() service.ComplianceService {
	return af.complianceSvc
}
func (af *AccountingInfraFactory) ComplianceAnalyticsService() service.ComplianceAnalyticsService {
	return af.complianceAnalyticsSvc
}
func (af *AccountingInfraFactory) JournalService() service.JournalService { return af.journalSvc }
func (af *AccountingInfraFactory) LedgerService() service.LedgerService   { return af.ledgerSvc }
func (af *AccountingInfraFactory) RuleEngine() service.AccountingRuleEngine {
	return af.ruleEngineSvc
}
func (af *AccountingInfraFactory) ReconciliationService() service.ReconciliationService {
	return af.reconciliationSvc
}
func (af *AccountingInfraFactory) ReconciliationAnalyticsService() service.ReconciliationAnalyticsService {
	return af.reconciliationAnalyticsSvc
}
func (af *AccountingInfraFactory) TaxAnalyticsService() service.TaxAnalyticsService {
	return af.taxAnalyticsSvc
}
func (af *AccountingInfraFactory) TaxEngineService() service.TaxEngineService { return af.taxEngineSvc }

// Getters for handlers
func (af *AccountingInfraFactory) AccountHandler() *handler.AccountHandler {
	return af.accountHandler
}
func (af *AccountingInfraFactory) AccountingSettingsHandler() *handler.AccountingSettingsHandler {
	return af.accountingSettingsHandler
}
func (af *AccountingInfraFactory) ComplianceHandler() *handler.ComplianceHandler {
	return af.complianceHandler
}
func (af *AccountingInfraFactory) AnalyticsHandler() *handler.AnalyticsHandler {
	return af.analyticsHandler
}
func (af *AccountingInfraFactory) PeriodLockHandler() *handler.PeriodLockHandler {
	return af.periodLockHandler
}
func (af *AccountingInfraFactory) JournalHandler() *handler.JournalHandler { return af.journalHandler }
func (af *AccountingInfraFactory) LedgerHandler() *handler.LedgerHandler   { return af.ledgerHandler }
func (af *AccountingInfraFactory) ReconciliationHandler() *handler.ReconciliationHandler {
	return af.reconciliationHandler
}
func (af *AccountingInfraFactory) ReportHandler() *handler.ReportHandler { return af.reportHandler }
func (af *AccountingInfraFactory) TaxHandler() *handler.TaxHandler       { return af.taxHandler }

// RegisterRoutes mounts accounting routes on the given router.
func (af *AccountingInfraFactory) RegisterRoutes(r chi.Router, jwtService *mainservice.JWTService, logger *zap.Logger) {
	accountingHandlers := &accounting.AccountingHandlers{
		AccountHandler:            af.accountHandler,
		LedgerHandler:             af.ledgerHandler,
		ReconciliationHandler:     af.reconciliationHandler,
		ReportHandler:             af.reportHandler,
		ComplianceHandler:         af.complianceHandler,
		JournalHandler:            af.journalHandler,
		TaxHandler:                af.taxHandler,
		AccountingSettingsHandler: af.accountingSettingsHandler,
	}
	accounting.RegisterAccountingRoutes(r, accountingHandlers, logger, jwtService)
}

// Close is a no-op because the outbox processor is managed centrally.
func (af *AccountingInfraFactory) Close() {
	// No longer needed – central outbox handles shutdown
}
