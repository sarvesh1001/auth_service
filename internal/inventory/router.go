package inventory

import (
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"auth-service/internal/inventory/handler"
	authMiddleware "auth-service/internal/middleware"
	"auth-service/internal/service"
)

// InventoryHandlers aggregates all inventory-related handlers.
type InventoryHandlers struct {
	ItemHandler           *handler.ItemHandler
	StockHandler          *handler.StockHandler
	ValuationHandler      *handler.ValuationHandler
	BOMHandler            *handler.BOMHandler
	ProductionHandler     *handler.ProductionHandler
	WarehouseHandler      *handler.WarehouseHandler
	MovementHandler       *handler.MovementHandler
	ReportHandler         *handler.ReportHandler
	ReorderHandler        *handler.ReorderHandler
	BatchHandler          *handler.BatchHandler
	InventoryQueryHandler *handler.InventoryQueryHandler
	AdjustmentHandler     *handler.AdjustmentHandler
	ReservationHandler    *handler.ReservationHandler
	AnalyticsHandler      *handler.AnalyticsHandler
	FulfillmentHandler    *handler.FulfillmentOrderHandler
	ShipmentHandler       *handler.ShipmentHandler
	TransferOrderHandler  *handler.TransferOrderHandler
	SerialNumberHandler   *handler.SerialNumberHandler
	LocationHandler       *handler.InventoryLocationHandler

	// NEW handlers
	ShipmentItemHandler            *handler.ShipmentItemHandler
	SerialNumberTransactionHandler *handler.SerialNumberTransactionHandler
	CycleCountHandler              *handler.CycleCountHandler
	PackingHandler                 *handler.PackingHandler
	PickingHandler                 *handler.PickingHandler
}

// RegisterInventoryRoutes mounts all inventory routes under /api/v1/companies/{companyID}/inventory.
func RegisterInventoryRoutes(
	r chi.Router,
	handlers *InventoryHandlers,
	logger *zap.Logger,
	jwtService *service.JWTService,
) {
	r.Route("/inventory", func(r chi.Router) {
		// -------------------------------
		// 1. Items
		// -------------------------------
		r.Route("/items", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.create", logger)).
				Post("/", handlers.ItemHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/", handlers.ItemHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/low-stock", handlers.ItemHandler.GetLowStock)
			r.Route("/{itemID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
					Get("/", handlers.ItemHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update", logger)).
					Put("/", handlers.ItemHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.delete", logger)).
					Delete("/", handlers.ItemHandler.Delete)
			})
		})

		// -------------------------------
		// 2. Stock (available, levels, adjust, batch picking)
		// -------------------------------
		r.Route("/stock", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Post("/available", handlers.StockHandler.GetAvailableStock)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/levels", handlers.StockHandler.GetStockLevels)
			// Transfer handled by /transfer-orders
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/adjust", handlers.StockHandler.AdjustStock)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Post("/batch-picking", handlers.StockHandler.GetBatchPicking)
		})

		// -------------------------------
		// 3. Valuations & COGS
		// -------------------------------
		r.Route("/valuation", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/", handlers.ValuationHandler.GetCompanyValuation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Post("/snapshots", handlers.ValuationHandler.CreateValuationSnapshot)
			r.Route("/items/{itemId}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
					Get("/", handlers.ValuationHandler.GetItemValuation)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
					Get("/cogs", handlers.ValuationHandler.GetCOGS)
			})
		})

		// -------------------------------
		// 4. BOMs
		// -------------------------------
		r.Route("/boms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.create", logger)).
				Post("/", handlers.BOMHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view", logger)).
				Get("/", handlers.BOMHandler.List)
			r.Route("/{bomID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view", logger)).
					Get("/", handlers.BOMHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.update", logger)).
					Put("/", handlers.BOMHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.delete", logger)).
					Delete("/", handlers.BOMHandler.Delete)
				r.Route("/items", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.update", logger)).
						Post("/", handlers.BOMHandler.AddBOMItem)
					r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view", logger)).
						Get("/", handlers.BOMHandler.GetBOMItems)
				})
			})
			r.Route("/items/{bomItemID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.update", logger)).
					Put("/", handlers.BOMHandler.UpdateBOMItem)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.delete", logger)).
					Delete("/", handlers.BOMHandler.RemoveBOMItem)
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view", logger)).
				Get("/products/{productItemID}", handlers.BOMHandler.GetByProductItemID)
		})

		// -------------------------------
		// 5. Production Orders
		// -------------------------------
		r.Route("/production-orders", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.create", logger)).
				Post("/", handlers.ProductionHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.view", logger)).
				Get("/", handlers.ProductionHandler.List)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.view", logger)).
					Get("/", handlers.ProductionHandler.Get)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.update", logger)).
					Post("/release", handlers.ProductionHandler.Release)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.start", logger)).
					Post("/start", handlers.ProductionHandler.Start)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.finish", logger)).
					Post("/complete", handlers.ProductionHandler.Complete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.cancel", logger)).
					Post("/cancel", handlers.ProductionHandler.Cancel)
			})
		})

		// -------------------------------
		// 6. Warehouses
		// -------------------------------
		r.Route("/warehouses", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.create", logger)).
				Post("/", handlers.WarehouseHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.create", logger)).
				Post("/bulk", handlers.WarehouseHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view", logger)).
				Get("/", handlers.WarehouseHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view", logger)).
				Get("/by-code/{code}", handlers.WarehouseHandler.GetByCode)
			r.Route("/{warehouseID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view", logger)).
					Get("/", handlers.WarehouseHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update", logger)).
					Put("/", handlers.WarehouseHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.delete", logger)).
					Delete("/", handlers.WarehouseHandler.Delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update", logger)).
					Patch("/status", handlers.WarehouseHandler.SetStatus)
			})
		})

		// -------------------------------
		// 7. Stock Movements (in/out)
		// -------------------------------
		r.Route("/movements", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.in", logger)).
				Post("/", handlers.MovementHandler.CreateMovement)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/", handlers.MovementHandler.ListMovements)
			r.Route("/{movementID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
					Get("/", handlers.MovementHandler.GetMovement)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
					Post("/cancel", handlers.MovementHandler.CancelMovement)
			})
		})

		// -------------------------------
		// 8. Adjustments (dedicated)
		// -------------------------------
		r.Route("/adjustments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/", handlers.AdjustmentHandler.CreateAdjustment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/", handlers.AdjustmentHandler.ListAdjustments)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
					Get("/", handlers.AdjustmentHandler.GetAdjustment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
					Post("/cancel", handlers.AdjustmentHandler.CancelAdjustment)
			})
		})

		// -------------------------------
		// 9. Reservations
		// -------------------------------
		r.Route("/reservations", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Post("/", handlers.ReservationHandler.CreateReservation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/", handlers.ReservationHandler.ListReservations)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/expire", handlers.ReservationHandler.ExpireReservations)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
					Post("/fulfill", handlers.ReservationHandler.FulfillReservation)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
					Post("/cancel", handlers.ReservationHandler.CancelReservation)
			})
		})

		// -------------------------------
		// 10. Batches
		// -------------------------------
		r.Route("/batches", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.create", logger)).
				Post("/", handlers.BatchHandler.CreateBatch)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/", handlers.BatchHandler.ListBatches)
			r.Route("/{batchId}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
					Get("/", handlers.BatchHandler.GetBatch)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.update", logger)).
					Patch("/adjust", handlers.BatchHandler.AdjustBatch)
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/items/{itemId}", handlers.BatchHandler.ListBatchesByItem)
		})

		// -------------------------------
		// 11. Inventory Query (detailed read views)
		// -------------------------------
		r.Route("/query", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/stock/current", handlers.InventoryQueryHandler.GetCurrentStock)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/warehouses/{warehouseId}/stock", handlers.InventoryQueryHandler.GetAllStockByWarehouse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/items/{itemId}/stock", handlers.InventoryQueryHandler.GetAllStockByItem)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/batches/{batchId}/stock", handlers.InventoryQueryHandler.GetAllStockByBatch)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/movements", handlers.InventoryQueryHandler.GetMovements)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/low-stock", handlers.InventoryQueryHandler.GetLowStockItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/expiring-batches", handlers.InventoryQueryHandler.GetExpiringBatches)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/reservations", handlers.InventoryQueryHandler.GetReservationsByReference)
		})

		// -------------------------------
		// 12. Reports
		// -------------------------------
		r.Route("/reports", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Post("/valuation/item", handlers.ReportHandler.GetItemValuation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/valuation/company", handlers.ReportHandler.GetCompanyValuation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Post("/valuation/snapshot", handlers.ReportHandler.GenerateValuationSnapshot)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/low-stock", handlers.ReportHandler.GetLowStockReport)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/expiring-batches", handlers.ReportHandler.GetExpiringBatches)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/stock-levels", handlers.ReportHandler.GetStockLevelsReport)
		})

		// -------------------------------
		// 13. Reorder Management
		// -------------------------------
		r.Route("/reorder", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Post("/trigger", handlers.ReorderHandler.TriggerReorder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update", logger)).
				Post("/process", handlers.ReorderHandler.ProcessPending)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
				Get("/orders", handlers.ReorderHandler.ListReorderOrders)
			r.Route("/orders/{reorderOrderId}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view", logger)).
					Get("/", handlers.ReorderHandler.GetReorderOrder)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update", logger)).
					Put("/status", handlers.ReorderHandler.UpdateReorderStatus)
			})
		})

		// -------------------------------
		// 14. Analytics
		// -------------------------------
		r.Route("/analytics", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/daily-snapshots", handlers.AnalyticsHandler.GetDailySnapshots)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/turnover-metrics", handlers.AnalyticsHandler.GetTurnoverMetrics)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/abc-classifications", handlers.AnalyticsHandler.GetABCClassifications)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/inventory-aging", handlers.AnalyticsHandler.GetInventoryAging)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/demand-history", handlers.AnalyticsHandler.GetDemandHistory)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/movement-summary", handlers.AnalyticsHandler.GetMovementDailySummary)
		})

		// -------------------------------
		// 15. Fulfillment Orders
		// -------------------------------
		r.Route("/fulfillment", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/orders", handlers.FulfillmentHandler.CreateFulfillmentOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/orders/{fulfillmentOrderID}/items", handlers.FulfillmentHandler.AddFulfillmentItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/orders/{fulfillmentOrderID}/process", handlers.FulfillmentHandler.ProcessFulfillmentOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/orders/{fulfillmentOrderID}/allocate", handlers.FulfillmentHandler.AllocateStockToFulfillment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/orders/{fulfillmentOrderID}", handlers.FulfillmentHandler.GetFulfillmentOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/orders/{fulfillmentOrderID}/items", handlers.FulfillmentHandler.GetFulfillmentOrderItems)
		})

		// -------------------------------
		// 16. Shipments
		// -------------------------------
		// -------------------------------
		// 16. Shipments
		// -------------------------------
		r.Route("/shipments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
				Post("/", handlers.ShipmentHandler.CreateShipment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
				Post("/{id}/ship", handlers.ShipmentHandler.Ship)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
				Post("/{id}/deliver", handlers.ShipmentHandler.Deliver)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/{id}", handlers.ShipmentHandler.GetShipment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/", handlers.ShipmentHandler.ListShipments)

			// ========== NEW: Shipment Items under shipment ==========
			r.Route("/{shipmentID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
					Post("/", handlers.ShipmentItemHandler.CreateShipmentItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
					Get("/", handlers.ShipmentItemHandler.GetShipmentItems)
			})
		})
		// -------------------------------
		// 17. Transfer Orders
		// -------------------------------
		r.Route("/transfer-orders", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Post("/", handlers.TransferOrderHandler.CreateTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Post("/{transferOrderId}/dispatch", handlers.TransferOrderHandler.DispatchTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Post("/{transferOrderId}/receive", handlers.TransferOrderHandler.ReceiveTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Post("/{transferOrderId}/cancel", handlers.TransferOrderHandler.CancelTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Get("/{transferOrderId}", handlers.TransferOrderHandler.GetTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Get("/{transferOrderId}/items", handlers.TransferOrderHandler.GetTransferOrderItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer", logger)).
				Get("/", handlers.TransferOrderHandler.ListTransferOrders)
		})

		// -------------------------------
		// 18. Serial Numbers
		// -------------------------------
		r.Route("/serials", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update", logger)).
				Post("/register", handlers.SerialNumberHandler.RegisterSerialNumbers)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update", logger)).
				Post("/{id}/assign-warehouse", handlers.SerialNumberHandler.AssignToWarehouse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.update", logger)).
				Post("/{id}/assign-batch", handlers.SerialNumberHandler.AssignToBatch)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update", logger)).
				Patch("/{id}/status", handlers.SerialNumberHandler.UpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/{id}", handlers.SerialNumberHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/by-number", handlers.SerialNumberHandler.GetByNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/", handlers.SerialNumberHandler.List)
		})

		// -------------------------------
		// 19. Inventory Locations (hierarchical)
		// -------------------------------
		r.Route("/locations", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.create", logger)).
				Post("/", handlers.LocationHandler.CreateLocation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update", logger)).
				Put("/{locationId}", handlers.LocationHandler.UpdateLocation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.delete", logger)).
				Delete("/{locationId}", handlers.LocationHandler.DeleteLocation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view", logger)).
				Get("/{locationId}", handlers.LocationHandler.GetLocation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view", logger)).
				Get("/", handlers.LocationHandler.ListLocations)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view", logger)).
				Get("/tree", handlers.LocationHandler.GetLocationTree)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update", logger)).
				Post("/warehouses/{warehouseId}/assign", handlers.LocationHandler.AssignWarehouseToLocation)
		})

		// ========== NEW: Shipment Items ==========
		r.Route("/shipment-items", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
				Post("/", handlers.ShipmentItemHandler.CreateShipmentItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/shipments/{shipmentID}", handlers.ShipmentItemHandler.GetShipmentItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/{shipmentItemID}", handlers.ShipmentItemHandler.GetShipmentItemByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
				Put("/{shipmentItemID}", handlers.ShipmentItemHandler.UpdateShippedQuantity)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out", logger)).
				Delete("/{shipmentItemID}", handlers.ShipmentItemHandler.DeleteShipmentItem)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/", handlers.ShipmentItemHandler.ListShipmentItems)
		})

		// ========== NEW: Serial Number Transactions ==========
		r.Route("/serial-transactions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/serials/{serialID}", handlers.SerialNumberTransactionHandler.GetTransactionHistory)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view", logger)).
				Get("/", handlers.SerialNumberTransactionHandler.ListTransactions)
		})

		// ========== NEW: Cycle Counts ==========
		r.Route("/cycle-counts", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/", handlers.CycleCountHandler.CreateCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/{cycleCountID}/start", handlers.CycleCountHandler.StartCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/{cycleCountID}/complete", handlers.CycleCountHandler.CompleteCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/{cycleCountID}/cancel", handlers.CycleCountHandler.CancelCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/{cycleCountID}", handlers.CycleCountHandler.GetCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/", handlers.CycleCountHandler.ListCycleCounts)
		})

		// ========== NEW: Picking Lists ==========
		r.Route("/picking", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/lists", handlers.PickingHandler.GeneratePickingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/lists/{listID}/assign", handlers.PickingHandler.AssignPicker)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/items/{itemID}/pick", handlers.PickingHandler.PickItem)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/lists/{listID}/complete", handlers.PickingHandler.CompletePicking)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/lists/{listID}", handlers.PickingHandler.GetPickingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/lists", handlers.PickingHandler.ListPickingLists)
		})

		// ========== NEW: Packing Lists ==========
		// ========== NEW: Packing Lists ==========
		r.Route("/packing", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/lists", handlers.PackingHandler.GeneratePackingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/lists/{listID}/verify", handlers.PackingHandler.VerifyPacking)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
				Post("/lists/{listID}/complete", handlers.PackingHandler.CompletePacking)

			// Item operations now under the specific list
			r.Route("/lists/{listID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
					Post("/", handlers.PackingHandler.PackItem) // single item
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust", logger)).
					Post("/bulk", handlers.PackingHandler.BulkPackItems) // bulk pack
			})

			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/lists/{listID}", handlers.PackingHandler.GetPackingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/lists", handlers.PackingHandler.ListPackingLists)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view", logger)).
				Get("/lists/{listID}/items", handlers.PackingHandler.GetPackingListItems)
		})
	})
}
