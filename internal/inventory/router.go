package inventory

import (
	"github.com/go-chi/chi/v5"

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

	// New handlers
	ShipmentItemHandler            *handler.ShipmentItemHandler
	SerialNumberTransactionHandler *handler.SerialNumberTransactionHandler
	CycleCountHandler              *handler.CycleCountHandler
	PackingHandler                 *handler.PackingHandler
	PickingHandler                 *handler.PickingHandler
	PurchaseOrderHandler           *handler.PurchaseOrderHandler // <-- NEW: vendors & purchase orders
}

// RegisterInventoryRoutes mounts all inventory routes under /api/v1/companies/{companyID}/inventory.
func RegisterInventoryRoutes(
	r chi.Router,
	handlers *InventoryHandlers,
	jwtService *service.JWTService,
) {
	r.Route("/inventory", func(r chi.Router) {
		// -------------------------------
		// 1. Items
		// -------------------------------
		r.Route("/items", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.create")).
				Post("/", handlers.ItemHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/", handlers.ItemHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/low-stock", handlers.ItemHandler.GetLowStock)
			r.Route("/{itemID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
					Get("/", handlers.ItemHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
					Put("/", handlers.ItemHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.delete")).
					Delete("/", handlers.ItemHandler.Delete)
			})
		})

		// -------------------------------
		// 2. Stock (available, levels, adjust, batch picking)
		// -------------------------------
		r.Route("/stock", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Post("/available", handlers.StockHandler.GetAvailableStock)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/levels", handlers.StockHandler.GetStockLevels)
			// Transfer handled by /transfer-orders
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/adjust", handlers.StockHandler.AdjustStock)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Post("/batch-picking", handlers.StockHandler.GetBatchPicking)
		})

		// -------------------------------
		// 3. Valuations & COGS
		// -------------------------------
		r.Route("/valuation", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/", handlers.ValuationHandler.GetCompanyValuation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Post("/snapshots", handlers.ValuationHandler.CreateValuationSnapshot)
			r.Route("/items/{itemId}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
					Get("/", handlers.ValuationHandler.GetItemValuation)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
					Get("/cogs", handlers.ValuationHandler.GetCOGS)
			})
		})

		// -------------------------------
		// 4. BOMs
		// -------------------------------
		r.Route("/boms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.create")).
				Post("/", handlers.BOMHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view")).
				Get("/", handlers.BOMHandler.List)
			r.Route("/{bomID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view")).
					Get("/", handlers.BOMHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.update")).
					Put("/", handlers.BOMHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.delete")).
					Delete("/", handlers.BOMHandler.Delete)
				r.Route("/items", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.update")).
						Post("/", handlers.BOMHandler.AddBOMItem)
					r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view")).
						Get("/", handlers.BOMHandler.GetBOMItems)
				})
			})
			r.Route("/items/{bomItemID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.update")).
					Put("/", handlers.BOMHandler.UpdateBOMItem)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.delete")).
					Delete("/", handlers.BOMHandler.RemoveBOMItem)
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.bom.view")).
				Get("/products/{productItemID}", handlers.BOMHandler.GetByProductItemID)
		})

		// -------------------------------
		// 5. Production Orders
		// -------------------------------
		r.Route("/production-orders", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.create")).
				Post("/", handlers.ProductionHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.view")).
				Get("/", handlers.ProductionHandler.List)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.view")).
					Get("/", handlers.ProductionHandler.Get)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.update")).
					Post("/release", handlers.ProductionHandler.Release)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.start")).
					Post("/start", handlers.ProductionHandler.Start)

				// NEW: partial consumption and scrap recording
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.update")).
					Post("/consume", handlers.ProductionHandler.ConsumeComponent)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.update")).
					Post("/scrap", handlers.ProductionHandler.RecordScrap)

				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.finish")).
					Post("/complete", handlers.ProductionHandler.Complete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("production.order.cancel")).
					Post("/cancel", handlers.ProductionHandler.Cancel)
			})
		})

		// -------------------------------
		// 6. Warehouses
		// -------------------------------
		r.Route("/warehouses", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.create")).
				Post("/", handlers.WarehouseHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.create")).
				Post("/bulk", handlers.WarehouseHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view")).
				Get("/", handlers.WarehouseHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view")).
				Get("/by-code/{code}", handlers.WarehouseHandler.GetByCode)
			r.Route("/{warehouseID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view")).
					Get("/", handlers.WarehouseHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update")).
					Put("/", handlers.WarehouseHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.delete")).
					Delete("/", handlers.WarehouseHandler.Delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update")).
					Patch("/status", handlers.WarehouseHandler.SetStatus)
			})
		})

		// -------------------------------
		// 7. Stock Movements (in/out)
		// -------------------------------
		r.Route("/movements", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.in")).
				Post("/", handlers.MovementHandler.CreateMovement)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/", handlers.MovementHandler.ListMovements)
			r.Route("/{movementID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
					Get("/", handlers.MovementHandler.GetMovement)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
					Post("/cancel", handlers.MovementHandler.CancelMovement)
			})
		})

		// -------------------------------
		// 8. Adjustments (dedicated)
		// -------------------------------
		r.Route("/adjustments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/", handlers.AdjustmentHandler.CreateAdjustment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/", handlers.AdjustmentHandler.ListAdjustments)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
					Get("/", handlers.AdjustmentHandler.GetAdjustment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
					Post("/cancel", handlers.AdjustmentHandler.CancelAdjustment)
			})
		})

		// -------------------------------
		// 9. Reservations
		// -------------------------------
		r.Route("/reservations", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Post("/", handlers.ReservationHandler.CreateReservation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/", handlers.ReservationHandler.ListReservations)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/expire", handlers.ReservationHandler.ExpireReservations)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
					Post("/fulfill", handlers.ReservationHandler.FulfillReservation)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
					Post("/cancel", handlers.ReservationHandler.CancelReservation)
			})
		})

		// -------------------------------
		// 10. Batches
		// -------------------------------
		r.Route("/batches", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.create")).
				Post("/", handlers.BatchHandler.CreateBatch)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/", handlers.BatchHandler.ListBatches)
			r.Route("/{batchId}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
					Get("/", handlers.BatchHandler.GetBatch)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.update")).
					Patch("/adjust", handlers.BatchHandler.AdjustBatch)
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/items/{itemId}", handlers.BatchHandler.ListBatchesByItem)
		})

		// -------------------------------
		// 11. Inventory Query (detailed read views)
		// -------------------------------
		r.Route("/query", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/stock/current", handlers.InventoryQueryHandler.GetCurrentStock)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/warehouses/{warehouseId}/stock", handlers.InventoryQueryHandler.GetAllStockByWarehouse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/items/{itemId}/stock", handlers.InventoryQueryHandler.GetAllStockByItem)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/batches/{batchId}/stock", handlers.InventoryQueryHandler.GetAllStockByBatch)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/movements", handlers.InventoryQueryHandler.GetMovements)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/low-stock", handlers.InventoryQueryHandler.GetLowStockItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/expiring-batches", handlers.InventoryQueryHandler.GetExpiringBatches)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/reservations", handlers.InventoryQueryHandler.GetReservationsByReference)
		})

		// -------------------------------
		// 12. Reports
		// -------------------------------
		r.Route("/reports", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Post("/valuation/item", handlers.ReportHandler.GetItemValuation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/valuation/company", handlers.ReportHandler.GetCompanyValuation)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Post("/valuation/snapshot", handlers.ReportHandler.GenerateValuationSnapshot)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/low-stock", handlers.ReportHandler.GetLowStockReport)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/expiring-batches", handlers.ReportHandler.GetExpiringBatches)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/stock-levels", handlers.ReportHandler.GetStockLevelsReport)
		})

		// -------------------------------
		// 13. Reorder Management
		// -------------------------------
		r.Route("/reorder", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Post("/trigger", handlers.ReorderHandler.TriggerReorder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
				Post("/process", handlers.ReorderHandler.ProcessPending)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/orders", handlers.ReorderHandler.ListReorderOrders)
			r.Route("/orders/{reorderOrderId}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
					Get("/", handlers.ReorderHandler.GetReorderOrder)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
					Put("/status", handlers.ReorderHandler.UpdateReorderStatus)
			})
		})

		// -------------------------------
		// 14. Analytics
		// -------------------------------
		r.Route("/analytics", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/daily-snapshots", handlers.AnalyticsHandler.GetDailySnapshots)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/turnover-metrics", handlers.AnalyticsHandler.GetTurnoverMetrics)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/abc-classifications", handlers.AnalyticsHandler.GetABCClassifications)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/inventory-aging", handlers.AnalyticsHandler.GetInventoryAging)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/demand-history", handlers.AnalyticsHandler.GetDemandHistory)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/movement-summary", handlers.AnalyticsHandler.GetMovementDailySummary)
		})

		// -------------------------------
		// 15. Fulfillment Orders
		// -------------------------------
		r.Route("/fulfillment", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/orders", handlers.FulfillmentHandler.CreateFulfillmentOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/orders/{fulfillmentOrderID}/items", handlers.FulfillmentHandler.AddFulfillmentItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/orders/{fulfillmentOrderID}/process", handlers.FulfillmentHandler.ProcessFulfillmentOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/orders/{fulfillmentOrderID}/allocate", handlers.FulfillmentHandler.AllocateStockToFulfillment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/orders/{fulfillmentOrderID}", handlers.FulfillmentHandler.GetFulfillmentOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/orders/{fulfillmentOrderID}/items", handlers.FulfillmentHandler.GetFulfillmentOrderItems)
		})

		// -------------------------------
		// 16. Shipments
		// -------------------------------
		r.Route("/shipments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
				Post("/", handlers.ShipmentHandler.CreateShipment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
				Post("/{id}/ship", handlers.ShipmentHandler.Ship)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
				Post("/{id}/deliver", handlers.ShipmentHandler.Deliver)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/{id}", handlers.ShipmentHandler.GetShipment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/", handlers.ShipmentHandler.ListShipments)

			// Shipment Items under shipment
			r.Route("/{shipmentID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
					Post("/", handlers.ShipmentItemHandler.CreateShipmentItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
					Get("/", handlers.ShipmentItemHandler.GetShipmentItems)
			})
		})

		// -------------------------------
		// 17. Transfer Orders
		// -------------------------------
		r.Route("/transfer-orders", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Post("/", handlers.TransferOrderHandler.CreateTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Post("/{transferOrderId}/dispatch", handlers.TransferOrderHandler.DispatchTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Post("/{transferOrderId}/receive", handlers.TransferOrderHandler.ReceiveTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Post("/{transferOrderId}/cancel", handlers.TransferOrderHandler.CancelTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Get("/{transferOrderId}", handlers.TransferOrderHandler.GetTransferOrder)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Get("/{transferOrderId}/items", handlers.TransferOrderHandler.GetTransferOrderItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.transfer")).
				Get("/", handlers.TransferOrderHandler.ListTransferOrders)
		})

		// -------------------------------
		// 18. Serial Numbers
		// -------------------------------
		r.Route("/serials", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
				Post("/register", handlers.SerialNumberHandler.RegisterSerialNumbers)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
				Post("/{id}/assign-warehouse", handlers.SerialNumberHandler.AssignToWarehouse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.update")).
				Post("/{id}/assign-batch", handlers.SerialNumberHandler.AssignToBatch)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
				Patch("/{id}/status", handlers.SerialNumberHandler.UpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/{id}", handlers.SerialNumberHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/by-number", handlers.SerialNumberHandler.GetByNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/", handlers.SerialNumberHandler.List)

			// Transaction history for a specific serial number
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/{serialID}/transactions", handlers.SerialNumberTransactionHandler.GetTransactionHistory)
		})

		// -------------------------------
		// 19. Inventory Locations (hierarchical)
		// -------------------------------
		r.Route("/locations", func(r chi.Router) {
			// Create location (requires warehouse_id in body)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.create")).
				Post("/", handlers.LocationHandler.CreateLocation)

			// Update location (can change warehouse, name, etc.)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.update")).
				Put("/{locationId}", handlers.LocationHandler.UpdateLocation)

			// Soft delete location
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.delete")).
				Delete("/{locationId}", handlers.LocationHandler.DeleteLocation)

			// Get single location by ID
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view")).
				Get("/{locationId}", handlers.LocationHandler.GetLocation)

			// List locations for a specific warehouse (requires ?warehouse_id=...)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view")).
				Get("/", handlers.LocationHandler.ListLocations)

			// Get hierarchical tree for a specific warehouse (requires ?warehouse_id=...)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.warehouse.view")).
				Get("/tree", handlers.LocationHandler.GetLocationTree)
		})

		// -------------------------------
		// Shipment Items (standalone)
		// -------------------------------
		r.Route("/shipment-items", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
				Post("/", handlers.ShipmentItemHandler.CreateShipmentItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/shipments/{shipmentID}", handlers.ShipmentItemHandler.GetShipmentItems)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/{shipmentItemID}", handlers.ShipmentItemHandler.GetShipmentItemByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
				Put("/{shipmentItemID}", handlers.ShipmentItemHandler.UpdateShippedQuantity)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.out")).
				Delete("/{shipmentItemID}", handlers.ShipmentItemHandler.DeleteShipmentItem)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/", handlers.ShipmentItemHandler.ListShipmentItems)
		})

		// -------------------------------
		// Serial Number Transactions (global)
		// -------------------------------
		r.Route("/serial-transactions", func(r chi.Router) {
			// This endpoint already exists in /serials/{serialID}/transactions,
			// but we keep for global listing
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.batch.view")).
				Get("/", handlers.SerialNumberTransactionHandler.ListTransactions)
		})

		// -------------------------------
		// Cycle Counts
		// -------------------------------
		r.Route("/cycle-counts", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/", handlers.CycleCountHandler.CreateCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/{cycleCountID}/start", handlers.CycleCountHandler.StartCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/{cycleCountID}/complete", handlers.CycleCountHandler.CompleteCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/{cycleCountID}/cancel", handlers.CycleCountHandler.CancelCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/{cycleCountID}", handlers.CycleCountHandler.GetCycleCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/", handlers.CycleCountHandler.ListCycleCounts)
		})

		// -------------------------------
		// Picking Lists
		// -------------------------------
		r.Route("/picking", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/lists", handlers.PickingHandler.GeneratePickingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/lists/{listID}/assign", handlers.PickingHandler.AssignPicker)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/items/{itemID}/pick", handlers.PickingHandler.PickItem)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/lists/{listID}/complete", handlers.PickingHandler.CompletePicking)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/lists/{listID}", handlers.PickingHandler.GetPickingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/lists", handlers.PickingHandler.ListPickingLists)
		})

		// -------------------------------
		// Packing Lists
		// -------------------------------
		r.Route("/packing", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/lists", handlers.PackingHandler.GeneratePackingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/lists/{listID}/verify", handlers.PackingHandler.VerifyPacking)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/lists/{listID}/complete", handlers.PackingHandler.CompletePacking)

			// Item operations under the specific list
			r.Route("/lists/{listID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
					Post("/", handlers.PackingHandler.PackItem) // single item
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
					Post("/bulk", handlers.PackingHandler.BulkPackItems) // bulk pack
			})

			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/lists/{listID}", handlers.PackingHandler.GetPackingList)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/lists", handlers.PackingHandler.ListPackingLists)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.view")).
				Get("/lists/{listID}/items", handlers.PackingHandler.GetPackingListItems)
		})

		// -------------------------------
		// 20. Vendors & Purchase Orders (NEW)
		// -------------------------------
		// Vendors CRUD
		r.Route("/vendors", func(r chi.Router) {
			// Create vendor (requires inventory.item.create permission – reuses existing)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.create")).
				Post("/", handlers.PurchaseOrderHandler.CreateVendor)
			// List vendors (inventory.item.view)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/", handlers.PurchaseOrderHandler.ListVendors)
			r.Route("/{vendorId}", func(r chi.Router) {
				// Get vendor by ID (view)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
					Get("/", handlers.PurchaseOrderHandler.GetVendor)
				// Update vendor (item.update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
					Put("/", handlers.PurchaseOrderHandler.UpdateVendor)
				// Delete vendor (item.delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.delete")).
					Delete("/", handlers.PurchaseOrderHandler.DeleteVendor)
			})
		})

		// Purchase Orders CRUD + Items + Receiving
		r.Route("/purchase-orders", func(r chi.Router) {
			// Create purchase order (requires inventory.item.create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.create")).
				Post("/", handlers.PurchaseOrderHandler.CreatePurchaseOrder)
			// List purchase orders (view)
			r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
				Get("/", handlers.PurchaseOrderHandler.ListPurchaseOrders)

			r.Route("/{purchaseOrderId}", func(r chi.Router) {
				// Get PO (view)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
					Get("/", handlers.PurchaseOrderHandler.GetPurchaseOrder)
				// Update status (update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
					Put("/status", handlers.PurchaseOrderHandler.UpdatePurchaseOrderStatus)

				// Items under PO
				r.Route("/items", func(r chi.Router) {
					// Add items to PO (update)
					r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.update")).
						Post("/", handlers.PurchaseOrderHandler.AddPurchaseOrderItems)
					// List items (view)
					r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.item.view")).
						Get("/", handlers.PurchaseOrderHandler.GetPurchaseOrderItems)
				})

				// Receiving endpoint (stock adjust permission – because it creates stock movements)
				r.With(authMiddleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
					Post("/receive", handlers.PurchaseOrderHandler.ReceivePurchaseOrder)
			})
		})
	})
}
