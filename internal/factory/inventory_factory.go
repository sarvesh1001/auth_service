package factory

import (
	"context"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/inventory"
	"auth-service/internal/inventory/handler"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"

	"go.uber.org/zap"
)

type InventoryInfraFactory struct {
	log            *zap.Logger
	postgresClient *client.PostgresClient
	redisClient    *client.RedisClient
	eventPublisher EventPublisher
	auditService   *audit.AuditService

	idempotencyStore idempotency.Store
	outboxRepo       outbox.Repository
	outboxProcessor  *outbox.Processor
	outboxCancel     context.CancelFunc

	// Repositories
	itemRepo            repository.ItemRepository
	stockLedgerRepo     repository.StockLedgerRepository
	stockBalanceRepo    repository.StockBalanceRepository
	batchRepo           repository.BatchRepository
	bomRepo             repository.BOMRepository
	movementRepo        repository.MovementRepository
	analysisRepo        repository.InventoryAnalysisRepository
	reorderRepo         repository.ReorderOrderRepository
	warehouseRepo       repository.WarehouseRepository
	reservationRepo     repository.ReservationRepository
	prodOrderRepo       repository.ProductionOrderRepository
	locationRepo        repository.InventoryLocationRepository
	fulfillmentRepo     repository.FulfillmentRepository
	shipmentRepo        repository.ShipmentRepository
	transferRepo        repository.TransferOrderRepository
	serialRepo          repository.SerialRepository
	shipmentItemRepo    repository.ShipmentItemRepository
	serialNumberTxnRepo repository.SerialNumberTransactionRepository
	cycleCountRepo      repository.InventoryCycleCountRepository
	pickingListRepo     repository.PickingListRepository
	pickingListItemRepo repository.PickingListItemRepository
	packingListRepo     repository.PackingListRepository
	packingListItemRepo repository.PackingListItemRepository

	// Services
	inventorySvc       service.InventoryService
	valuationSvc       service.ValuationService
	stockSvc           service.StockService
	movementSvc        service.MovementService
	warehouseSvc       service.WarehouseService
	productionSvc      service.ProductionService
	inventoryQuerySvc  service.InventoryQueryService
	reorderSvc         service.ReorderService
	reservationSvc     service.ReservationService
	analyticsSvc       service.InventoryAnalyticsService
	locationSvc        service.InventoryLocationService
	fulfillmentSvc     service.FulfillmentService
	shipmentSvc        service.ShipmentService
	transferOrderSvc   service.TransferOrderService
	serialNumberSvc    service.SerialNumberService
	shipmentItemSvc    service.ShipmentItemService
	serialNumberTxnSvc service.SerialNumberTransactionService
	cycleCountSvc      service.CycleCountService
	pickingSvc         service.PickingService
	packingSvc         service.PackingService

	// App services
	itemAppSvc        service.ItemApplicationService
	bomAppSvc         service.BOMService
	analyticsQuerySvc service.AnalyticsQueryService

	// Handlers (existing)
	stockHandler          *handler.StockHandler
	valuationHandler      *handler.ValuationHandler
	itemHandler           *handler.ItemHandler
	bomHandler            *handler.BOMHandler
	productionHandler     *handler.ProductionHandler
	warehouseHandler      *handler.WarehouseHandler
	movementHandler       *handler.MovementHandler
	reportHandler         *handler.ReportHandler
	reorderHandler        *handler.ReorderHandler
	batchHandler          *handler.BatchHandler
	inventoryQueryHandler *handler.InventoryQueryHandler
	adjustmentHandler     *handler.AdjustmentHandler
	reservationHandler    *handler.ReservationHandler
	analyticsHandler      *handler.AnalyticsHandler
	locationHandler       *handler.InventoryLocationHandler
	fulfillmentHandler    *handler.FulfillmentOrderHandler
	shipmentHandler       *handler.ShipmentHandler
	transferOrderHandler  *handler.TransferOrderHandler
	serialNumberHandler   *handler.SerialNumberHandler

	// NEW handlers
	shipmentItemHandler            *handler.ShipmentItemHandler
	serialNumberTransactionHandler *handler.SerialNumberTransactionHandler
	cycleCountHandler              *handler.CycleCountHandler
	pickingHandler                 *handler.PickingHandler
	packingHandler                 *handler.PackingHandler
}

func NewInventoryInfraFactory(
	postgresClient *client.PostgresClient,
	redisClient *client.RedisClient,
	kafkaProducer *client.KafkaProducer,
	eventPublisher EventPublisher,
	auditService *audit.AuditService,
	logger *zap.Logger,
) (*InventoryInfraFactory, error) {
	infra := &InventoryInfraFactory{
		log:            logger.Named("inventory_infra"),
		postgresClient: postgresClient,
		redisClient:    redisClient,
		eventPublisher: eventPublisher,
		auditService:   auditService,
	}

	// Idempotency store
	pgStore := idempotency.NewPostgresStore(postgresClient.DB)
	redisCache := idempotency.NewRedisCache(redisClient, 24*time.Hour)
	infra.idempotencyStore = idempotency.NewHybridStore(pgStore, redisCache)

	// Outbox
	if kafkaProducer != nil {
		infra.outboxRepo = outbox.NewPostgresRepository(postgresClient.DB)
		infra.outboxProcessor = outbox.NewProcessor(infra.outboxRepo, kafkaProducer, infra.log)
		ctx, cancel := context.WithCancel(context.Background())
		infra.outboxCancel = cancel
		go infra.outboxProcessor.Start(ctx)
		infra.log.Info("Inventory outbox processor started")
	} else {
		infra.log.Warn("Kafka producer not available – inventory outbox disabled")
	}

	// ========== Repositories ==========
	infra.itemRepo = repository.NewItemRepository(infra.log)
	infra.stockLedgerRepo = repository.NewStockLedgerRepository(infra.log)
	infra.stockBalanceRepo = repository.NewStockBalanceRepository(infra.log)
	infra.batchRepo = repository.NewBatchRepository(infra.log)
	infra.bomRepo = repository.NewBOMRepository(infra.log)
	infra.movementRepo = repository.NewMovementRepository(infra.log)
	infra.analysisRepo = repository.NewInventoryAnalysisRepository(infra.log)
	infra.reorderRepo = repository.NewReorderOrderRepository(infra.log)
	infra.warehouseRepo = repository.NewWarehouseRepository(infra.log)
	infra.reservationRepo = repository.NewReservationRepository(infra.log)
	infra.prodOrderRepo = repository.NewProductionOrderRepository(infra.log)
	infra.locationRepo = repository.NewInventoryLocationRepository(infra.log)
	infra.fulfillmentRepo = repository.NewFulfillmentRepository(infra.log)
	infra.shipmentRepo = repository.NewShipmentRepository(infra.log)
	infra.transferRepo = repository.NewTransferOrderRepository(infra.log)
	infra.serialRepo = repository.NewSerialRepository(infra.log)
	infra.shipmentItemRepo = repository.NewShipmentItemRepository(infra.log)
	infra.serialNumberTxnRepo = repository.NewSerialNumberTransactionRepository(infra.log)
	infra.cycleCountRepo = repository.NewInventoryCycleCountRepository(infra.log)
	infra.pickingListRepo = repository.NewPickingListRepository(infra.log)
	infra.pickingListItemRepo = repository.NewPickingListItemRepository(infra.log)
	infra.packingListRepo = repository.NewPackingListRepository(infra.log)
	infra.packingListItemRepo = repository.NewPackingListItemRepository(infra.log)

	// ========== Core Services ==========
	infra.inventorySvc = service.NewInventoryService(
		infra.itemRepo, infra.movementRepo, infra.stockBalanceRepo,
		infra.stockLedgerRepo, infra.batchRepo, infra.warehouseRepo,
		infra.postgresClient, infra.outboxRepo, infra.idempotencyStore,
		infra.auditService, infra.log,
	)

	infra.reservationSvc = service.NewReservationService(
		infra.reservationRepo, infra.stockBalanceRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	infra.valuationSvc = service.NewValuationService(
		infra.itemRepo, infra.stockBalanceRepo, infra.stockLedgerRepo,
		infra.movementRepo, infra.batchRepo, infra.postgresClient, infra.log,
	)

	infra.stockSvc = service.NewStockService(
		infra.stockBalanceRepo, infra.stockLedgerRepo, infra.batchRepo,
		infra.movementRepo, infra.itemRepo, infra.warehouseRepo, infra.inventorySvc,
		infra.postgresClient, infra.outboxRepo, infra.idempotencyStore,
		infra.auditService, infra.log,
	)

	infra.movementSvc = service.NewMovementService(
		infra.movementRepo, infra.stockBalanceRepo, infra.stockLedgerRepo,
		infra.reservationRepo, infra.reservationSvc, infra.batchRepo,
		infra.itemRepo, infra.warehouseRepo,
		infra.postgresClient, infra.outboxRepo, infra.idempotencyStore,
		infra.auditService, infra.log,
	)

	infra.warehouseSvc = service.NewWarehouseService(
		infra.warehouseRepo, infra.locationRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	infra.productionSvc = service.NewProductionService(
		infra.prodOrderRepo,
		infra.bomRepo,
		infra.itemRepo,
		infra.batchRepo, // ✅ new
		infra.stockSvc,  // ✅ new
		infra.inventorySvc,
		infra.outboxRepo,
		infra.idempotencyStore,
		infra.auditService,
		infra.postgresClient,
		infra.log,
	)
	infra.inventoryQuerySvc = service.NewInventoryQueryService(
		infra.postgresClient.DB, infra.stockBalanceRepo, infra.movementRepo,
		infra.itemRepo, infra.batchRepo, infra.warehouseRepo, infra.reservationRepo,
		infra.log,
	)

	infra.reorderSvc = service.NewReorderService(
		infra.itemRepo, infra.warehouseRepo, infra.reorderRepo,
		infra.stockBalanceRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	infra.analyticsSvc = service.NewInventoryAnalyticsService(
		infra.analysisRepo, infra.movementRepo, infra.stockBalanceRepo,
		infra.stockLedgerRepo, infra.reorderSvc, infra.postgresClient, infra.log,
	)

	infra.locationSvc = service.NewInventoryLocationService(
		infra.locationRepo, infra.warehouseRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	// NEW: ShipmentItemService
	infra.shipmentItemSvc = service.NewShipmentItemService(
		infra.shipmentItemRepo, infra.fulfillmentRepo, infra.shipmentRepo,
		infra.itemRepo, infra.postgresClient, infra.outboxRepo,
		infra.idempotencyStore, infra.auditService, infra.log,
	)

	// NEW: SerialNumberTransactionService
	infra.serialNumberTxnSvc = service.NewSerialNumberTransactionService(
		infra.serialNumberTxnRepo, infra.serialRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	infra.fulfillmentSvc = service.NewFulfillmentService(
		infra.fulfillmentRepo,
		infra.shipmentRepo,
		infra.reservationSvc,
		infra.inventorySvc,
		infra.productionSvc,
		infra.stockSvc, // <-- added
		infra.itemRepo,
		infra.warehouseRepo,
		infra.stockBalanceRepo,
		infra.postgresClient,
		infra.outboxRepo,
		infra.idempotencyStore,
		infra.auditService,
		infra.log,
	)
	infra.shipmentSvc = service.NewShipmentService(
		infra.shipmentRepo, infra.postgresClient, infra.outboxRepo,
		infra.idempotencyStore, infra.auditService, infra.log,
	)

	infra.transferOrderSvc = service.NewTransferOrderService(
		infra.transferRepo, infra.itemRepo, infra.warehouseRepo, infra.stockBalanceRepo,
		infra.inventorySvc, infra.stockLedgerRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	// UPDATED: SerialNumberService now includes SerialNumberTransactionService
	infra.serialNumberSvc = service.NewSerialNumberService(
		infra.serialRepo, infra.itemRepo, infra.warehouseRepo, infra.batchRepo,
		infra.serialNumberTxnSvc, // new dependency
		infra.postgresClient, infra.outboxRepo, infra.idempotencyStore,
		infra.auditService, infra.log,
	)

	// NEW: CycleCountService
	infra.cycleCountSvc = service.NewCycleCountService(
		infra.cycleCountRepo, infra.stockSvc, infra.itemRepo,
		infra.warehouseRepo, infra.stockBalanceRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	// NEW: PickingService
	infra.pickingSvc = service.NewPickingService(
		infra.pickingListRepo, infra.pickingListItemRepo, infra.fulfillmentRepo,
		infra.warehouseRepo, infra.postgresClient, infra.outboxRepo,
		infra.idempotencyStore, infra.auditService, infra.log,
	)

	// NEW: PackingService
	infra.packingSvc = service.NewPackingService(
		infra.packingListRepo, infra.packingListItemRepo, infra.shipmentItemRepo,
		infra.shipmentRepo, infra.warehouseRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	// ========== App Services ==========
	infra.itemAppSvc = service.NewItemApplicationService(
		infra.inventorySvc, infra.itemRepo, infra.inventoryQuerySvc,
		infra.postgresClient.DB, infra.log,
	)

	infra.bomAppSvc = service.NewBOMService(
		infra.bomRepo, infra.itemRepo, infra.postgresClient,
		infra.outboxRepo, infra.idempotencyStore, infra.auditService, infra.log,
	)

	infra.analyticsQuerySvc = service.NewAnalyticsQueryService(
		infra.analysisRepo, infra.postgresClient.DB, infra.log,
	)

	// ========== Handlers (existing) ==========
	infra.stockHandler = handler.NewStockHandler(
		infra.stockSvc, infra.inventoryQuerySvc, infra.movementSvc, infra.log,
	)
	infra.valuationHandler = handler.NewValuationHandler(infra.valuationSvc, infra.log)
	infra.itemHandler = handler.NewItemHandler(infra.itemAppSvc, infra.log)
	infra.bomHandler = handler.NewBOMHandler(infra.bomAppSvc, infra.log)
	infra.productionHandler = handler.NewProductionHandler(infra.productionSvc, infra.log)
	infra.warehouseHandler = handler.NewWarehouseHandler(infra.warehouseSvc, infra.log)
	infra.movementHandler = handler.NewMovementHandler(infra.movementSvc, infra.log)
	infra.reportHandler = handler.NewReportHandler(
		infra.inventoryQuerySvc, infra.valuationSvc, infra.analyticsSvc, infra.log,
	)
	infra.reorderHandler = handler.NewReorderHandler(
		infra.reorderSvc, infra.reorderRepo, infra.postgresClient.DB, infra.log,
	)
	infra.batchHandler = handler.NewBatchHandler(
		infra.inventorySvc, infra.batchRepo, infra.postgresClient, infra.log,
	)
	infra.inventoryQueryHandler = handler.NewInventoryQueryHandler(infra.inventoryQuerySvc, infra.log)
	infra.adjustmentHandler = handler.NewAdjustmentHandler(infra.stockSvc, infra.movementSvc, infra.log)
	infra.reservationHandler = handler.NewReservationHandler(
		infra.reservationSvc, infra.reservationRepo, infra.postgresClient, infra.log,
	)
	infra.analyticsHandler = handler.NewAnalyticsHandler(infra.analyticsQuerySvc, infra.log)
	infra.locationHandler = handler.NewInventoryLocationHandler(infra.locationSvc, infra.log)
	infra.fulfillmentHandler = handler.NewFulfillmentOrderHandler(infra.fulfillmentSvc, infra.warehouseRepo, infra.log)
	infra.shipmentHandler = handler.NewShipmentHandler(infra.shipmentSvc, infra.fulfillmentSvc, infra.log)
	infra.transferOrderHandler = handler.NewTransferOrderHandler(infra.transferOrderSvc, infra.log)
	infra.serialNumberHandler = handler.NewSerialNumberHandler(infra.serialNumberSvc, infra.log)

	// ========== NEW Handlers ==========
	infra.shipmentItemHandler = handler.NewShipmentItemHandler(infra.shipmentItemSvc, infra.log)
	infra.serialNumberTransactionHandler = handler.NewSerialNumberTransactionHandler(
		infra.serialNumberTxnSvc, infra.postgresClient.DB, infra.log,
	)
	infra.cycleCountHandler = handler.NewCycleCountHandler(infra.cycleCountSvc, infra.log)
	infra.pickingHandler = handler.NewPickingHandler(infra.pickingSvc, infra.log)
	infra.packingHandler = handler.NewPackingHandler(infra.packingSvc, infra.log)

	return infra, nil
}

// InventoryHandlers returns all handlers grouped for routing.
func (i *InventoryInfraFactory) InventoryHandlers() *inventory.InventoryHandlers {
	return &inventory.InventoryHandlers{
		// Existing handlers
		ItemHandler:           i.itemHandler,
		StockHandler:          i.stockHandler,
		ValuationHandler:      i.valuationHandler,
		BOMHandler:            i.bomHandler,
		ProductionHandler:     i.productionHandler,
		WarehouseHandler:      i.warehouseHandler,
		MovementHandler:       i.movementHandler,
		ReportHandler:         i.reportHandler,
		ReorderHandler:        i.reorderHandler,
		BatchHandler:          i.batchHandler,
		InventoryQueryHandler: i.inventoryQueryHandler,
		AdjustmentHandler:     i.adjustmentHandler,
		ReservationHandler:    i.reservationHandler,
		AnalyticsHandler:      i.analyticsHandler,
		FulfillmentHandler:    i.fulfillmentHandler,
		ShipmentHandler:       i.shipmentHandler,
		TransferOrderHandler:  i.transferOrderHandler,
		SerialNumberHandler:   i.serialNumberHandler,
		LocationHandler:       i.locationHandler,

		// NEW handlers
		ShipmentItemHandler:            i.shipmentItemHandler,
		SerialNumberTransactionHandler: i.serialNumberTransactionHandler,
		PickingHandler:                 i.pickingHandler, // ✅ ADD THIS
		PackingHandler:                 i.packingHandler,
	}
}

// Close shuts down background processes.
func (i *InventoryInfraFactory) Close() {
	if i.outboxCancel != nil {
		i.outboxCancel()
	}
}
