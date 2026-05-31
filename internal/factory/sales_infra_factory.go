package factory

import (
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/encryption"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/sales"
	"auth-service/internal/sales/handler"
	"auth-service/internal/sales/repository"
	"auth-service/internal/sales/service"
	mainservice "auth-service/internal/service"

	accountingService "auth-service/internal/accounting/service"
)

// SalesInfraFactory encapsulates all sales components (repos, services, handlers)
// and provides lazy initialisation to handle circular dependencies.
type SalesInfraFactory struct {
	logger              *zap.Logger
	pgClient            *client.PostgresClient
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	encryptionMgr       *encryption.EncryptionManager
	accountingTaxEngine accountingService.TaxEngineService

	// repositories (lazy)
	analyticsRepo          repository.AnalyticsRepository
	autoDiscountRepo       repository.AutomaticDiscountRepository
	commissionPlanRepo     repository.CommissionPlanRepository
	commissionRuleRepo     repository.CommissionRuleRepository
	couponRepo             repository.CouponRepository
	creditCheckHistoryRepo repository.CreditCheckHistoryRepository
	creditNoteAppRepo      repository.CreditNoteApplicationRepository
	creditNoteRepo         repository.CreditNoteRepository
	customerRepo           repository.CustomerRepository
	discountExclusionRepo  repository.DiscountExclusionRepository
	discountPriorityRepo   repository.DiscountPriorityRepository
	discountUsageRepo      repository.DiscountUsageRepository
	invoiceRepo            repository.InvoiceRepository
	orderRepo              repository.OrderRepository
	paymentRefundRepo      repository.PaymentRefundRepository
	paymentRepo            repository.PaymentRepository
	paymentTermRepo        repository.PaymentTermRepository
	pricingRepo            repository.PricingRepository
	productRepo            repository.ProductRepository
	promotionRepo          repository.PromotionRepository
	quoteRepo              repository.QuoteRepository
	returnRepo             repository.ReturnRepository
	salesCommissionRepo    repository.SalesCommissionRepository
	salesRepCommissionRepo repository.SalesRepCommissionRepository
	salesRepRepo           repository.SalesRepRepository
	salesTargetRepo        repository.SalesTargetRepository
	stackingRuleRepo       repository.StackingRuleRepository
	taxSnapshotRepo        repository.TaxSnapshotRepository

	// services (lazy)
	couponService             service.CouponService
	creditCheckService        service.CreditCheckService
	creditNoteService         service.CreditNoteService
	customerService           service.CustomerService
	discountEngineService     service.DiscountEngineService
	invoiceService            service.InvoiceService
	orderService              service.OrderService
	paymentService            service.PaymentService
	paymentTermService        service.PaymentTermService
	pricingService            service.PricingService
	productService            service.ProductService
	promotionService          service.PromotionService
	quoteService              service.QuoteService
	returnService             service.ReturnService
	salesAnalyticsService     service.SalesAnalyticsService
	salesQueryService         service.SalesQueryService
	salesRepCommissionService service.SalesRepCommissionService
	salesRepService           service.SalesRepService
	taxIntegrationService     service.TaxIntegrationService

	// handlers (lazy)
	commissionHandler  *handler.CommissionHandler
	couponHandler      *handler.CouponHandler
	creditCheckHandler *handler.CreditCheckHandler
	creditNoteHandler  *handler.CreditNoteHandler
	customerHandler    *handler.CustomerHandler
	discountHandler    *handler.DiscountHandler
	invoiceHandler     *handler.InvoiceHandler
	orderHandler       *handler.OrderHandler
	paymentHandler     *handler.PaymentHandler
	paymentTermHandler *handler.PaymentTermHandler
	pricingHandler     *handler.PricingHandler
	productHandler     *handler.ProductHandler
	promotionHandler   *handler.PromotionHandler
	quoteHandler       *handler.QuoteHandler
	reportHandler      *handler.ReportHandler
	returnHandler      *handler.ReturnHandler
	salesRepHandler    *handler.SalesRepHandler
	taxHandler         *handler.TaxHandler
}

// NewSalesInfraFactory creates a new sales infrastructure factory.
func NewSalesInfraFactory(
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	encryptionMgr *encryption.EncryptionManager,
	accountingTaxEngine accountingService.TaxEngineService,
	logger *zap.Logger,
) *SalesInfraFactory {
	return &SalesInfraFactory{
		logger:              logger.Named("sales_infra"),
		pgClient:            pgClient,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		encryptionMgr:       encryptionMgr,
		accountingTaxEngine: accountingTaxEngine,
	}
}

// ----------------------------------------------------------------------------
// Repository getters (lazy initialisation)
// ----------------------------------------------------------------------------

func (f *SalesInfraFactory) AnalyticsRepo() repository.AnalyticsRepository {
	if f.analyticsRepo == nil {
		f.analyticsRepo = repository.NewAnalyticsRepository(f.logger)
	}
	return f.analyticsRepo
}

func (f *SalesInfraFactory) AutomaticDiscountRepo() repository.AutomaticDiscountRepository {
	if f.autoDiscountRepo == nil {
		f.autoDiscountRepo = repository.NewAutomaticDiscountRepository(f.logger)
	}
	return f.autoDiscountRepo
}

func (f *SalesInfraFactory) CommissionPlanRepo() repository.CommissionPlanRepository {
	if f.commissionPlanRepo == nil {
		f.commissionPlanRepo = repository.NewCommissionPlanRepository(f.logger)
	}
	return f.commissionPlanRepo
}

func (f *SalesInfraFactory) CommissionRuleRepo() repository.CommissionRuleRepository {
	if f.commissionRuleRepo == nil {
		f.commissionRuleRepo = repository.NewCommissionRuleRepository(f.logger)
	}
	return f.commissionRuleRepo
}

func (f *SalesInfraFactory) CouponRepo() repository.CouponRepository {
	if f.couponRepo == nil {
		f.couponRepo = repository.NewCouponRepository(f.logger)
	}
	return f.couponRepo
}

func (f *SalesInfraFactory) CreditCheckHistoryRepo() repository.CreditCheckHistoryRepository {
	if f.creditCheckHistoryRepo == nil {
		f.creditCheckHistoryRepo = repository.NewCreditCheckHistoryRepository(f.logger)
	}
	return f.creditCheckHistoryRepo
}

func (f *SalesInfraFactory) CreditNoteApplicationRepo() repository.CreditNoteApplicationRepository {
	if f.creditNoteAppRepo == nil {
		f.creditNoteAppRepo = repository.NewCreditNoteApplicationRepository(f.logger)
	}
	return f.creditNoteAppRepo
}

func (f *SalesInfraFactory) CreditNoteRepo() repository.CreditNoteRepository {
	if f.creditNoteRepo == nil {
		f.creditNoteRepo = repository.NewCreditNoteRepository(f.logger)
	}
	return f.creditNoteRepo
}

func (f *SalesInfraFactory) CustomerRepo() repository.CustomerRepository {
	if f.customerRepo == nil {
		f.customerRepo = repository.NewCustomerRepository(f.logger)
	}
	return f.customerRepo
}

func (f *SalesInfraFactory) DiscountExclusionRepo() repository.DiscountExclusionRepository {
	if f.discountExclusionRepo == nil {
		f.discountExclusionRepo = repository.NewDiscountExclusionRepository(f.logger)
	}
	return f.discountExclusionRepo
}

func (f *SalesInfraFactory) DiscountPriorityRepo() repository.DiscountPriorityRepository {
	if f.discountPriorityRepo == nil {
		f.discountPriorityRepo = repository.NewDiscountPriorityRepository(f.logger)
	}
	return f.discountPriorityRepo
}

func (f *SalesInfraFactory) DiscountUsageRepo() repository.DiscountUsageRepository {
	if f.discountUsageRepo == nil {
		f.discountUsageRepo = repository.NewDiscountUsageRepository(f.logger)
	}
	return f.discountUsageRepo
}

func (f *SalesInfraFactory) InvoiceRepo() repository.InvoiceRepository {
	if f.invoiceRepo == nil {
		f.invoiceRepo = repository.NewInvoiceRepository(f.logger)
	}
	return f.invoiceRepo
}

func (f *SalesInfraFactory) OrderRepo() repository.OrderRepository {
	if f.orderRepo == nil {
		f.orderRepo = repository.NewOrderRepository(f.logger)
	}
	return f.orderRepo
}

func (f *SalesInfraFactory) PaymentRefundRepo() repository.PaymentRefundRepository {
	if f.paymentRefundRepo == nil {
		f.paymentRefundRepo = repository.NewPaymentRefundRepository(f.logger)
	}
	return f.paymentRefundRepo
}

func (f *SalesInfraFactory) PaymentRepo() repository.PaymentRepository {
	if f.paymentRepo == nil {
		f.paymentRepo = repository.NewPaymentRepository(f.logger)
	}
	return f.paymentRepo
}

func (f *SalesInfraFactory) PaymentTermRepo() repository.PaymentTermRepository {
	if f.paymentTermRepo == nil {
		f.paymentTermRepo = repository.NewPaymentTermRepository(f.logger)
	}
	return f.paymentTermRepo
}

func (f *SalesInfraFactory) PricingRepo() repository.PricingRepository {
	if f.pricingRepo == nil {
		f.pricingRepo = repository.NewPricingRepository(f.logger)
	}
	return f.pricingRepo
}

func (f *SalesInfraFactory) ProductRepo() repository.ProductRepository {
	if f.productRepo == nil {
		f.productRepo = repository.NewProductRepository(f.logger)
	}
	return f.productRepo
}

func (f *SalesInfraFactory) PromotionRepo() repository.PromotionRepository {
	if f.promotionRepo == nil {
		f.promotionRepo = repository.NewPromotionRepository(f.logger)
	}
	return f.promotionRepo
}

func (f *SalesInfraFactory) QuoteRepo() repository.QuoteRepository {
	if f.quoteRepo == nil {
		f.quoteRepo = repository.NewQuoteRepository(f.logger)
	}
	return f.quoteRepo
}

func (f *SalesInfraFactory) ReturnRepo() repository.ReturnRepository {
	if f.returnRepo == nil {
		f.returnRepo = repository.NewReturnRepository(f.logger)
	}
	return f.returnRepo
}

func (f *SalesInfraFactory) SalesCommissionRepo() repository.SalesCommissionRepository {
	if f.salesCommissionRepo == nil {
		f.salesCommissionRepo = repository.NewSalesCommissionRepository(f.logger)
	}
	return f.salesCommissionRepo
}

func (f *SalesInfraFactory) SalesRepCommissionRepo() repository.SalesRepCommissionRepository {
	if f.salesRepCommissionRepo == nil {
		f.salesRepCommissionRepo = repository.NewSalesRepCommissionRepository(f.logger)
	}
	return f.salesRepCommissionRepo
}

func (f *SalesInfraFactory) SalesRepRepo() repository.SalesRepRepository {
	if f.salesRepRepo == nil {
		f.salesRepRepo = repository.NewSalesRepRepository(f.logger)
	}
	return f.salesRepRepo
}

func (f *SalesInfraFactory) SalesTargetRepo() repository.SalesTargetRepository {
	if f.salesTargetRepo == nil {
		f.salesTargetRepo = repository.NewSalesTargetRepository(f.logger)
	}
	return f.salesTargetRepo
}

func (f *SalesInfraFactory) StackingRuleRepo() repository.StackingRuleRepository {
	if f.stackingRuleRepo == nil {
		f.stackingRuleRepo = repository.NewStackingRuleRepository(f.logger)
	}
	return f.stackingRuleRepo
}

func (f *SalesInfraFactory) TaxSnapshotRepo() repository.TaxSnapshotRepository {
	if f.taxSnapshotRepo == nil {
		f.taxSnapshotRepo = repository.NewTaxSnapshotRepository(f.logger)
	}
	return f.taxSnapshotRepo
}

// ----------------------------------------------------------------------------
// Service getters (lazy initialisation – handles circular dependencies)
// ----------------------------------------------------------------------------

func (f *SalesInfraFactory) CouponService() service.CouponService {
	if f.couponService == nil {
		f.couponService = service.NewCouponService(
			f.CouponRepo(),
			f.DiscountUsageRepo(),
			f.OrderRepo(),
			f.QuoteRepo(),
			f.InvoiceRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.couponService
}

func (f *SalesInfraFactory) CreditCheckService() service.CreditCheckService {
	if f.creditCheckService == nil {
		f.creditCheckService = service.NewCreditCheckService(
			f.CustomerRepo(),
			f.OrderRepo(),
			f.InvoiceRepo(),
			f.CreditCheckHistoryRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.creditCheckService
}

func (f *SalesInfraFactory) CreditNoteService() service.CreditNoteService {
	if f.creditNoteService == nil {
		f.creditNoteService = service.NewCreditNoteService(
			f.CreditNoteRepo(),
			f.CreditNoteApplicationRepo(),
			f.InvoiceRepo(),
			f.InvoiceService(),
			f.PaymentService(),
			f.ReturnRepo(),
			f.OrderRepo(),
			f.ProductRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.creditNoteService
}

func (f *SalesInfraFactory) CustomerService() service.CustomerService {
	if f.customerService == nil {
		f.customerService = service.NewCustomerService(
			f.CustomerRepo(),
			f.CreditCheckHistoryRepo(),
			f.PaymentTermRepo(),
			f.SalesRepRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.encryptionMgr,
			f.logger,
		)
	}
	return f.customerService
}

func (f *SalesInfraFactory) DiscountEngineService() service.DiscountEngineService {
	if f.discountEngineService == nil {
		f.discountEngineService = service.NewDiscountEngineService(
			f.CouponRepo(),
			f.PromotionRepo(),
			f.AutomaticDiscountRepo(),
			f.StackingRuleRepo(),
			f.DiscountExclusionRepo(),
			f.DiscountPriorityRepo(),
			f.DiscountUsageRepo(),
			f.PricingRepo(),
			f.OrderRepo(),
			f.InvoiceRepo(),
			f.QuoteRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.discountEngineService
}

func (f *SalesInfraFactory) InvoiceService() service.InvoiceService {
	if f.invoiceService == nil {
		f.invoiceService = service.NewInvoiceService(
			f.InvoiceRepo(),
			f.OrderRepo(),
			f.ProductRepo(),
			f.CustomerService(),
			f.PricingRepo(),
			f.DiscountEngineService(),
			f.TaxSnapshotRepo(),
			f.PaymentRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.invoiceService
}

func (f *SalesInfraFactory) OrderService() service.OrderService {
	if f.orderService == nil {
		f.orderService = service.NewOrderService(
			f.OrderRepo(),
			f.ProductRepo(),
			f.CustomerService(),
			f.PricingRepo(),
			f.CouponRepo(),
			f.PromotionRepo(),
			f.DiscountUsageRepo(),
			f.TaxSnapshotRepo(),
			f.DiscountEngineService(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.orderService
}

func (f *SalesInfraFactory) PaymentService() service.PaymentService {
	if f.paymentService == nil {
		f.paymentService = service.NewPaymentService(
			f.PaymentRepo(),
			f.InvoiceRepo(),
			f.PaymentRefundRepo(),
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.pgClient,
			f.logger,
		)
	}
	return f.paymentService
}

func (f *SalesInfraFactory) PaymentTermService() service.PaymentTermService {
	if f.paymentTermService == nil {
		f.paymentTermService = service.NewPaymentTermService(
			f.PaymentTermRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.paymentTermService
}

func (f *SalesInfraFactory) PricingService() service.PricingService {
	if f.pricingService == nil {
		f.pricingService = service.NewPricingService(
			f.PricingRepo(),
			f.ProductRepo(),
			f.CouponRepo(),
			f.PromotionRepo(),
			f.OrderRepo(),
			f.QuoteRepo(),
			f.InvoiceRepo(),
			f.CustomerService(),
			f.logger,
		)
	}
	return f.pricingService
}

func (f *SalesInfraFactory) ProductService() service.ProductService {
	if f.productService == nil {
		f.productService = service.NewProductService(
			f.ProductRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.productService
}

func (f *SalesInfraFactory) PromotionService() service.PromotionService {
	if f.promotionService == nil {
		f.promotionService = service.NewPromotionService(
			f.PromotionRepo(),
			f.DiscountUsageRepo(),
			f.StackingRuleRepo(),
			f.OrderRepo(),
			f.QuoteRepo(),
			f.InvoiceRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.promotionService
}

func (f *SalesInfraFactory) QuoteService() service.QuoteService {
	if f.quoteService == nil {
		f.quoteService = service.NewQuoteService(
			f.QuoteRepo(),
			f.OrderService(),
			f.ProductRepo(),
			f.CustomerService(),
			f.PricingRepo(),
			f.CouponRepo(),
			f.PromotionRepo(),
			f.DiscountUsageRepo(),
			f.TaxSnapshotRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.quoteService
}

func (f *SalesInfraFactory) ReturnService() service.ReturnService {
	if f.returnService == nil {
		f.returnService = service.NewReturnService(
			f.ReturnRepo(),
			f.PaymentRefundRepo(),
			f.InvoiceRepo(),
			f.OrderRepo(),
			f.ProductRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.returnService
}

func (f *SalesInfraFactory) SalesAnalyticsService() service.SalesAnalyticsService {
	if f.salesAnalyticsService == nil {
		f.salesAnalyticsService = service.NewSalesAnalyticsService(
			f.AnalyticsRepo(),
			f.OrderRepo(),
			f.InvoiceRepo(),
			f.SalesRepCommissionRepo(),
			f.ReturnRepo(),
			f.ProductRepo(),
			f.pgClient,
			f.logger,
		)
	}
	return f.salesAnalyticsService
}

func (f *SalesInfraFactory) SalesQueryService() service.SalesQueryService {
	if f.salesQueryService == nil {
		f.salesQueryService = service.NewSalesQueryService(
			f.AnalyticsRepo(),
			f.OrderRepo(),
			f.InvoiceRepo(),
			f.PaymentRepo(),
			f.ReturnRepo(),
			f.CustomerRepo(),
			f.ProductRepo(),
			f.SalesRepRepo(),
			f.QuoteRepo(),
			f.DiscountUsageRepo(),
			f.TaxSnapshotRepo(),
			f.CreditNoteRepo(),
			f.pgClient,
			f.logger,
		)
	}
	return f.salesQueryService
}

func (f *SalesInfraFactory) SalesRepCommissionService() service.SalesRepCommissionService {
	if f.salesRepCommissionService == nil {
		f.salesRepCommissionService = service.NewSalesRepCommissionService(
			f.CommissionPlanRepo(),
			f.CommissionRuleRepo(),
			f.SalesCommissionRepo(),
			f.SalesRepRepo(),
			f.OrderRepo(),
			f.InvoiceRepo(),
			f.PaymentRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.salesRepCommissionService
}

func (f *SalesInfraFactory) SalesRepService() service.SalesRepService {
	if f.salesRepService == nil {
		f.salesRepService = service.NewSalesRepService(
			f.SalesRepRepo(),
			f.OrderRepo(),
			f.QuoteRepo(),
			f.InvoiceRepo(),
			f.SalesRepCommissionRepo(),
			f.SalesTargetRepo(),
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.encryptionMgr, // <-- ADDED
			f.logger,
		)
	}
	return f.salesRepService
}
func (f *SalesInfraFactory) TaxIntegrationService() service.TaxIntegrationService {
	if f.taxIntegrationService == nil {
		f.taxIntegrationService = service.NewTaxIntegrationService(
			f.TaxSnapshotRepo(),
			f.OrderRepo(),
			f.QuoteRepo(),
			f.InvoiceRepo(),
			f.ProductRepo(),
			f.CustomerRepo(),
			f.accountingTaxEngine,
			f.pgClient,
			f.outboxRepo,
			f.idempotencyStore,
			f.auditService,
			f.logger,
		)
	}
	return f.taxIntegrationService
}

// ----------------------------------------------------------------------------
// Handler getters (lazy initialisation)
// ----------------------------------------------------------------------------

func (f *SalesInfraFactory) CommissionHandler() *handler.CommissionHandler {
	if f.commissionHandler == nil {
		f.commissionHandler = handler.NewCommissionHandler(f.SalesRepCommissionService(), f.logger)
	}
	return f.commissionHandler
}

func (f *SalesInfraFactory) CouponHandler() *handler.CouponHandler {
	if f.couponHandler == nil {
		f.couponHandler = handler.NewCouponHandler(f.CouponService(), f.logger)
	}
	return f.couponHandler
}

func (f *SalesInfraFactory) CreditCheckHandler() *handler.CreditCheckHandler {
	if f.creditCheckHandler == nil {
		f.creditCheckHandler = handler.NewCreditCheckHandler(f.CreditCheckService(), f.logger)
	}
	return f.creditCheckHandler
}

func (f *SalesInfraFactory) CreditNoteHandler() *handler.CreditNoteHandler {
	if f.creditNoteHandler == nil {
		f.creditNoteHandler = handler.NewCreditNoteHandler(f.CreditNoteService(), f.logger)
	}
	return f.creditNoteHandler
}

func (f *SalesInfraFactory) CustomerHandler() *handler.CustomerHandler {
	if f.customerHandler == nil {
		f.customerHandler = handler.NewCustomerHandler(f.CustomerService(), f.logger)
	}
	return f.customerHandler
}

func (f *SalesInfraFactory) DiscountHandler() *handler.DiscountHandler {
	if f.discountHandler == nil {
		f.discountHandler = handler.NewDiscountHandler(f.DiscountEngineService(), f.logger)
	}
	return f.discountHandler
}

func (f *SalesInfraFactory) InvoiceHandler() *handler.InvoiceHandler {
	if f.invoiceHandler == nil {
		f.invoiceHandler = handler.NewInvoiceHandler(f.InvoiceService(), f.logger)
	}
	return f.invoiceHandler
}

func (f *SalesInfraFactory) OrderHandler() *handler.OrderHandler {
	if f.orderHandler == nil {
		f.orderHandler = handler.NewOrderHandler(f.OrderService(), f.logger)
	}
	return f.orderHandler
}

func (f *SalesInfraFactory) PaymentHandler() *handler.PaymentHandler {
	if f.paymentHandler == nil {
		f.paymentHandler = handler.NewPaymentHandler(f.PaymentService(), f.logger)
	}
	return f.paymentHandler
}

func (f *SalesInfraFactory) PaymentTermHandler() *handler.PaymentTermHandler {
	if f.paymentTermHandler == nil {
		f.paymentTermHandler = handler.NewPaymentTermHandler(f.PaymentTermService(), f.logger)
	}
	return f.paymentTermHandler
}

func (f *SalesInfraFactory) PricingHandler() *handler.PricingHandler {
	if f.pricingHandler == nil {
		f.pricingHandler = handler.NewPricingHandler(f.PricingService(), f.logger)
	}
	return f.pricingHandler
}

func (f *SalesInfraFactory) ProductHandler() *handler.ProductHandler {
	if f.productHandler == nil {
		f.productHandler = handler.NewProductHandler(f.ProductService(), f.logger)
	}
	return f.productHandler
}

func (f *SalesInfraFactory) PromotionHandler() *handler.PromotionHandler {
	if f.promotionHandler == nil {
		f.promotionHandler = handler.NewPromotionHandler(f.PromotionService(), f.logger)
	}
	return f.promotionHandler
}

func (f *SalesInfraFactory) QuoteHandler() *handler.QuoteHandler {
	if f.quoteHandler == nil {
		f.quoteHandler = handler.NewQuoteHandler(f.QuoteService(), f.logger)
	}
	return f.quoteHandler
}

func (f *SalesInfraFactory) ReportHandler() *handler.ReportHandler {
	if f.reportHandler == nil {
		f.reportHandler = handler.NewReportHandler(f.SalesQueryService(), f.logger)
	}
	return f.reportHandler
}

func (f *SalesInfraFactory) ReturnHandler() *handler.ReturnHandler {
	if f.returnHandler == nil {
		f.returnHandler = handler.NewReturnHandler(f.ReturnService(), f.logger)
	}
	return f.returnHandler
}

func (f *SalesInfraFactory) SalesRepHandler() *handler.SalesRepHandler {
	if f.salesRepHandler == nil {
		f.salesRepHandler = handler.NewSalesRepHandler(f.SalesRepService(), f.logger)
	}
	return f.salesRepHandler
}

func (f *SalesInfraFactory) TaxHandler() *handler.TaxHandler {
	if f.taxHandler == nil {
		f.taxHandler = handler.NewTaxHandler(f.TaxIntegrationService(), f.logger)
	}
	return f.taxHandler
}

// ----------------------------------------------------------------------------
// Route registration
// ----------------------------------------------------------------------------

// RegisterRoutes mounts all sales routes on the given router.
func (f *SalesInfraFactory) RegisterRoutes(r chi.Router, jwtService *mainservice.JWTService) {
	handlers := &sales.SalesHandlers{
		CommissionHandler:  f.CommissionHandler(),
		CouponHandler:      f.CouponHandler(),
		CreditCheckHandler: f.CreditCheckHandler(),
		CreditNoteHandler:  f.CreditNoteHandler(),
		CustomerHandler:    f.CustomerHandler(),
		DiscountHandler:    f.DiscountHandler(),
		InvoiceHandler:     f.InvoiceHandler(),
		OrderHandler:       f.OrderHandler(),
		PaymentHandler:     f.PaymentHandler(),
		PaymentTermHandler: f.PaymentTermHandler(),
		PricingHandler:     f.PricingHandler(),
		ProductHandler:     f.ProductHandler(),
		PromotionHandler:   f.PromotionHandler(),
		QuoteHandler:       f.QuoteHandler(),
		ReportHandler:      f.ReportHandler(),
		ReturnHandler:      f.ReturnHandler(),
		SalesRepHandler:    f.SalesRepHandler(),
		TaxHandler:         f.TaxHandler(),
	}
	sales.RegisterSalesRoutes(r, handlers, f.logger, jwtService)
}

// Close performs any necessary cleanup (placeholder for future use).
func (f *SalesInfraFactory) Close() {
	// No background tasks to shut down yet.
}
