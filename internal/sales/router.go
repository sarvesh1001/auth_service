package sales

import (
	"github.com/go-chi/chi/v5"

	"auth-service/internal/middleware"
	"auth-service/internal/sales/handler"
	"auth-service/internal/service"
)

// SalesHandlers groups all sales sub‑module handlers.
type SalesHandlers struct {
	CommissionHandler  *handler.CommissionHandler
	CouponHandler      *handler.CouponHandler
	CreditCheckHandler *handler.CreditCheckHandler
	CreditNoteHandler  *handler.CreditNoteHandler
	CustomerHandler    *handler.CustomerHandler
	DiscountHandler    *handler.DiscountHandler
	InvoiceHandler     *handler.InvoiceHandler
	OrderHandler       *handler.OrderHandler
	PaymentHandler     *handler.PaymentHandler
	PaymentTermHandler *handler.PaymentTermHandler
	PricingHandler     *handler.PricingHandler
	ProductHandler     *handler.ProductHandler
	PromotionHandler   *handler.PromotionHandler
	QuoteHandler       *handler.QuoteHandler
	TaxHandler         *handler.TaxHandler
	ReportHandler      *handler.ReportHandler
	ReturnHandler      *handler.ReturnHandler
	SalesRepHandler    *handler.SalesRepHandler
}

// RegisterSalesRoutes registers all sales HTTP endpoints under /sales.
func RegisterSalesRoutes(
	r chi.Router,
	handlers *SalesHandlers,
	jwtService *service.JWTService,
) {
	// ---------------------------------------------------------------------
	// Commission routes (mapped to sales.deal permissions)
	// ---------------------------------------------------------------------
	r.Route("/sales/commissions", func(r chi.Router) {
		// Commission Plan endpoints
		r.Route("/plans", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/", handlers.CommissionHandler.CreateCommissionPlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.CommissionHandler.ListCommissionPlans)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/active", handlers.CommissionHandler.GetActiveCommissionPlans)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/by-code", handlers.CommissionHandler.GetCommissionPlanByCode)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/{id}/exists", handlers.CommissionHandler.CommissionPlanExists)

			r.Route("/{id}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/", handlers.CommissionHandler.GetCommissionPlanByID)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Put("/", handlers.CommissionHandler.UpdateCommissionPlan)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Delete("/", handlers.CommissionHandler.DeleteCommissionPlan)
			})
		})

		// Commission Rule endpoints
		r.Route("/rules", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/", handlers.CommissionHandler.CreateCommissionRule)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.CommissionHandler.GetCommissionRules)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/{id}/exists", handlers.CommissionHandler.CommissionRuleExists)

			r.Route("/{id}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/", handlers.CommissionHandler.GetCommissionRuleByID)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Put("/", handlers.CommissionHandler.UpdateCommissionRule)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Delete("/", handlers.CommissionHandler.DeleteCommissionRule)
			})
		})

		// Sales Rep – Commission Plan Assignment
		r.Route("/sales-reps/{salesRepId}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/plan", handlers.CommissionHandler.AssignCommissionPlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/plan", handlers.CommissionHandler.RemoveCommissionPlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/plan", handlers.CommissionHandler.GetSalesRepCommissionPlan)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/commissions", handlers.CommissionHandler.GetSalesRepCommissions)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/commission-summary", handlers.CommissionHandler.GetCommissionSummaryBySalesRep)
		})

		// Commission Calculation
		r.Route("/calculate", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/order", handlers.CommissionHandler.CalculateOrderCommission)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/invoice", handlers.CommissionHandler.CalculateInvoiceCommission)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/payment", handlers.CommissionHandler.CalculatePaymentCommission)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/period", handlers.CommissionHandler.CalculateCommissionForPeriod)
		})

		// Preview Commission
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/preview", handlers.CommissionHandler.PreviewCommission)

		// Process Commissions from events
		r.Route("/process", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/order", handlers.CommissionHandler.ProcessOrderCompletedCommission)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/invoice", handlers.CommissionHandler.ProcessInvoicePaidCommission)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/payment", handlers.CommissionHandler.ProcessPaymentReceivedCommission)
		})

		// Commission Records
		r.Route("/records", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/", handlers.CommissionHandler.CreateCommissionRecord)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.CommissionHandler.ListCommissions)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/by-reference", handlers.CommissionHandler.GetCommissionByReference)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/already-generated", handlers.CommissionHandler.CommissionAlreadyGenerated)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/pending", handlers.CommissionHandler.GetPendingCommissions)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/approved", handlers.CommissionHandler.GetApprovedCommissions)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/unpaid", handlers.CommissionHandler.GetUnpaidCommissions)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/total", handlers.CommissionHandler.GetTotalCommissionAmount)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/total-paid", handlers.CommissionHandler.GetTotalPaidCommission)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/outstanding-liability", handlers.CommissionHandler.GetOutstandingCommissionLiability)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/top-sales-reps", handlers.CommissionHandler.GetTopSalesRepCommissions)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/trend", handlers.CommissionHandler.GetCommissionTrend)

			r.Route("/{id}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/", handlers.CommissionHandler.GetCommissionByID)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Put("/", handlers.CommissionHandler.UpdateCommissionRecord)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/exists", handlers.CommissionHandler.CommissionRecordExists)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/pending", handlers.CommissionHandler.MarkCommissionPending)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/approve", handlers.CommissionHandler.ApproveCommission)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/reject", handlers.CommissionHandler.RejectCommission)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/paid", handlers.CommissionHandler.MarkCommissionPaid)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/recalculate", handlers.CommissionHandler.RecalculateCommission)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/reverse", handlers.CommissionHandler.ReverseCommission)
			})
		})
	})

	// ---------------------------------------------------------------------
	// Coupon routes (mapped to marketing.campaign permissions)
	// ---------------------------------------------------------------------
	r.Route("/sales/coupons", func(r chi.Router) {
		// Create / Update / Delete
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.create")).
			Post("/", handlers.CouponHandler.CreateCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Put("/{id}", handlers.CouponHandler.UpdateCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.delete")).
			Delete("/{id}", handlers.CouponHandler.DeleteCoupon)

		// Read operations
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}", handlers.CouponHandler.GetCouponByID)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/by-code", handlers.CouponHandler.GetCouponByCode)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/", handlers.CouponHandler.ListCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/search", handlers.CouponHandler.SearchCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/active", handlers.CouponHandler.GetActiveCoupons)

		// Activation / Deactivation / Expiration
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/{id}/activate", handlers.CouponHandler.ActivateCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/{id}/deactivate", handlers.CouponHandler.DeactivateCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/{id}/expire", handlers.CouponHandler.ExpireCoupon)

		// Validation & calculation
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/validate", handlers.CouponHandler.ValidateCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/{id}/calculate", handlers.CouponHandler.CalculateDiscount)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/{id}/calculate-products", handlers.CouponHandler.CalculateDiscountForProducts)

		// Apply / Remove coupon on orders, quotes, invoices
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply/order", handlers.CouponHandler.ApplyCouponToOrder)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply/quote", handlers.CouponHandler.ApplyCouponToQuote)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
			Post("/apply/invoice", handlers.CouponHandler.ApplyCouponToInvoice)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/remove/order", handlers.CouponHandler.RemoveCouponFromOrder)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/remove/quote", handlers.CouponHandler.RemoveCouponFromQuote)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
			Delete("/remove/invoice", handlers.CouponHandler.RemoveCouponFromInvoice)

		// Usage tracking
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/usage", handlers.CouponHandler.RecordCouponUsage)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/usage-count", handlers.CouponHandler.GetCouponUsageCount)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/customer-usage", handlers.CouponHandler.GetCustomerCouponUsageCount)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/usage-history", handlers.CouponHandler.GetCouponUsageHistory)

		// Analytics
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/top", handlers.CouponHandler.GetTopCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/most-used", handlers.CouponHandler.GetMostUsedCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/highest-discount", handlers.CouponHandler.GetHighestDiscountCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/total-discount", handlers.CouponHandler.GetTotalCouponDiscountAmount)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/redemption-rate", handlers.CouponHandler.GetCouponRedemptionRate)

		// Existence & status checks
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/exists", handlers.CouponHandler.CouponCodeExists)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/exists", handlers.CouponHandler.CouponExists)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/expired", handlers.CouponHandler.IsCouponExpired)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/usage-limit-reached", handlers.CouponHandler.IsCouponUsageLimitReached)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/customer-limit-reached", handlers.CouponHandler.IsCustomerUsageLimitReached)
	})

	// ---------------------------------------------------------------------
	// Credit Check routes (mapped to sales.deal permissions)
	// ---------------------------------------------------------------------
	r.Route("/sales/credit", func(r chi.Router) {
		// --- Credit check operations (read-like) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/check/customer", handlers.CreditCheckHandler.CheckCustomerCreditLimit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/check/order", handlers.CreditCheckHandler.CheckOrderCreditEligibility)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/check/invoice", handlers.CreditCheckHandler.CheckInvoiceCreditEligibility)

		// --- Customer credit info (read) ---
		r.Route("/customers/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/available-credit", handlers.CreditCheckHandler.GetCustomerAvailableCredit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/outstanding-balance", handlers.CreditCheckHandler.GetCustomerOutstandingBalance)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/credit-exposure", handlers.CreditCheckHandler.GetCustomerCreditExposure)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/can-place-order", handlers.CreditCheckHandler.CanCustomerPlaceOrder)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/credit-limit", handlers.CreditCheckHandler.GetCustomerCreditLimit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/credit-suspended", handlers.CreditCheckHandler.IsCustomerCreditSuspended)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/credit-history", handlers.CreditCheckHandler.GetCustomerCreditHistory)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/avg-payment-delay", handlers.CreditCheckHandler.GetAveragePaymentDelay)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/collection-score", handlers.CreditCheckHandler.GetCustomerCollectionScore)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/credit-utilization", handlers.CreditCheckHandler.GetCustomerCreditUtilization)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/exceeded-limit", handlers.CreditCheckHandler.CustomerExceededCreditLimit)

			// --- Customer credit modifications (write) ---
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/credit-limit", handlers.CreditCheckHandler.SetCustomerCreditLimit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/credit-limit/increase", handlers.CreditCheckHandler.IncreaseCustomerCreditLimit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/credit-limit/decrease", handlers.CreditCheckHandler.DecreaseCustomerCreditLimit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/credit-suspend", handlers.CreditCheckHandler.SuspendCustomerCredit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/credit-restore", handlers.CreditCheckHandler.RestoreCustomerCredit)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/auto-review", handlers.CreditCheckHandler.RunAutomaticCreditReview)
		})

		// --- Order credit operations ---
		r.Route("/orders", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/on-hold", handlers.CreditCheckHandler.GetOrdersOnCreditHold)

			r.Route("/{id}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/hold", handlers.CreditCheckHandler.HoldOrderForCredit)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Post("/release-hold", handlers.CreditCheckHandler.ReleaseOrderCreditHold)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/on-hold", handlers.CreditCheckHandler.IsOrderOnCreditHold)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
					Put("/credit-status", handlers.CreditCheckHandler.UpdateOrderCreditStatus)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/credit-history", handlers.CreditCheckHandler.GetOrderCreditHistory)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/has-credit-issues", handlers.CreditCheckHandler.OrderHasCreditIssues)
			})
		})

		// --- Credit history logs ---
		r.Route("/history", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/", handlers.CreditCheckHandler.LogCreditCheck)

			r.Route("/{id}", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/", handlers.CreditCheckHandler.GetCreditCheckHistoryByID)

				r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
					Get("/exists", handlers.CreditCheckHandler.CreditHistoryExists)
			})
		})

		// --- Analytics and reports ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/failed-checks", handlers.CreditCheckHandler.GetFailedCreditChecks)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/exceeding-limit", handlers.CreditCheckHandler.GetCustomersExceedingCreditLimit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/near-limit", handlers.CreditCheckHandler.GetCustomersNearCreditLimit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/high-risk", handlers.CreditCheckHandler.GetHighRiskCustomers)

		// --- Global totals / metrics ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/totals/outstanding", handlers.CreditCheckHandler.GetTotalOutstandingCredit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/totals/credit-exposure", handlers.CreditCheckHandler.GetTotalCreditExposure)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/totals/average-utilization", handlers.CreditCheckHandler.GetAverageCreditUtilization)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/totals/credit-hold-rate", handlers.CreditCheckHandler.GetCreditHoldRate)
	})

	// ---------------------------------------------------------------------
	// Credit Notes routes (mapped to finance.invoice permissions)
	// ---------------------------------------------------------------------
	r.Route("/sales/credit-notes", func(r chi.Router) {
		// Create operations
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.create")).
			Post("/", handlers.CreditNoteHandler.CreateDraftCreditNote)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.create")).
			Post("/from-invoice", handlers.CreditNoteHandler.CreateFromInvoice)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.create")).
			Post("/from-return", handlers.CreditNoteHandler.CreateFromReturn)

		// Read operations (list, search, get by number)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/", handlers.CreditNoteHandler.ListCreditNotes)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/search", handlers.CreditNoteHandler.SearchCreditNotes)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/by-number", handlers.CreditNoteHandler.GetCreditNoteByNumber)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/exists/number", handlers.CreditNoteHandler.CreditNoteNumberExists)

		// Analytics endpoints
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/total-issued", handlers.CreditNoteHandler.GetTotalCreditIssued)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/total-applied", handlers.CreditNoteHandler.GetTotalCreditApplied)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/outstanding", handlers.CreditNoteHandler.GetOutstandingCredits)

		// Customer-specific credit note operations
		r.Route("/customers/{customerId}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/credit-balance", handlers.CreditNoteHandler.GetCustomerCreditBalance)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/unused", handlers.CreditNoteHandler.GetUnusedCreditNotes)
		})

		// Preview totals (no persistence)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Post("/preview", handlers.CreditNoteHandler.PreviewTotals)

		// Single credit note operations (by ID)
		r.Route("/{id}", func(r chi.Router) {
			// Basic CRUD
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/", handlers.CreditNoteHandler.GetCreditNoteByID)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Put("/", handlers.CreditNoteHandler.UpdateCreditNote)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.delete")).
				Delete("/", handlers.CreditNoteHandler.DeleteCreditNote)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/exists", handlers.CreditNoteHandler.CreditNoteExists)

			// Items
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/items", handlers.CreditNoteHandler.AddItems)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Put("/items", handlers.CreditNoteHandler.ReplaceItems)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/items/{itemId}", handlers.CreditNoteHandler.RemoveItem)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/items", handlers.CreditNoteHandler.GetCreditNoteItems)

			// Totals
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/calculate", handlers.CreditNoteHandler.CalculateTotals)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/totals", handlers.CreditNoteHandler.GetCreditNoteTotals)

			// Status changes
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/issue", handlers.CreditNoteHandler.IssueCreditNote)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/void", handlers.CreditNoteHandler.VoidCreditNote)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/mark-fully-applied", handlers.CreditNoteHandler.MarkFullyApplied)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Put("/status", handlers.CreditNoteHandler.UpdateStatus)

			// Applications
			r.Route("/applications", func(r chi.Router) {
				r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
					Post("/invoice", handlers.CreditNoteHandler.ApplyToInvoice)

				r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
					Post("/invoices", handlers.CreditNoteHandler.ApplyToInvoices)

				r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
					Post("/auto", handlers.CreditNoteHandler.AutoApplyToOutstandingInvoices)

				r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
					Get("/", handlers.CreditNoteHandler.GetApplications)

				r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
					Delete("/{appId}", handlers.CreditNoteHandler.RemoveApplication)
			})

			// Remaining balance & full application check
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/remaining-balance", handlers.CreditNoteHandler.GetRemainingBalance)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/fully-applied", handlers.CreditNoteHandler.IsFullyApplied)

			// Convert to refund
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/convert-to-refund", handlers.CreditNoteHandler.ConvertToRefund)
		})
	})

	// ---------------------------------------------------------------------
	// Customer routes (using sales.deal permissions)
	// ---------------------------------------------------------------------
	r.Route("/sales/customers", func(r chi.Router) {
		// Create (uses write permission)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.CustomerHandler.CreateCustomer)

		// List / Search (read)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.CustomerHandler.ListCustomers)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.CustomerHandler.SearchCustomers)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-code", handlers.CustomerHandler.GetCustomerByCode)

		// Special collections (read)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/with-outstanding-invoices", handlers.CustomerHandler.GetCustomersWithOutstandingInvoices)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-by-revenue", handlers.CustomerHandler.GetTopCustomersByRevenue)

		// Customer ID scoped routes
		r.Route("/{id}", func(r chi.Router) {
			// Read operations
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.CustomerHandler.GetCustomerByID)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/exists", handlers.CustomerHandler.CustomerExists)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/active", handlers.CustomerHandler.IsCustomerActive)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/credit-limit", handlers.CustomerHandler.GetCreditLimit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/outstanding-balance", handlers.CustomerHandler.GetOutstandingBalance)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/can-purchase", handlers.CustomerHandler.CanCustomerPurchaseAmount)

			// Write operations (create/update/delete)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Put("/", handlers.CustomerHandler.UpdateCustomer)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Delete("/", handlers.CustomerHandler.DeleteCustomer)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/activate", handlers.CustomerHandler.ActivateCustomer)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/deactivate", handlers.CustomerHandler.DeactivateCustomer)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Put("/credit-limit", handlers.CustomerHandler.UpdateCreditLimit)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/payment-term", handlers.CustomerHandler.AssignPaymentTerm)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Delete("/payment-term", handlers.CustomerHandler.RemovePaymentTerm)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Post("/sales-rep", handlers.CustomerHandler.AssignSalesRep)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
				Delete("/sales-rep", handlers.CustomerHandler.RemoveSalesRep)
		})
	})

	// ---------------------------------------------------------------------
	// Discount Handler routes (using sales.deal permissions)
	// ---------------------------------------------------------------------
	r.Route("/sales/discounts", func(r chi.Router) {
		// --- Evaluate discounts on existing entities (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/evaluate/order", handlers.DiscountHandler.EvaluateOrderDiscounts)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/evaluate/quote", handlers.DiscountHandler.EvaluateQuoteDiscounts)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/evaluate/invoice", handlers.DiscountHandler.EvaluateInvoiceDiscounts)

		// --- Retrieve applicable discounts (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/applicable-coupons", handlers.DiscountHandler.GetApplicableCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/applicable-promotions", handlers.DiscountHandler.GetApplicablePromotions)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/applicable-automatic", handlers.DiscountHandler.GetApplicableAutomaticDiscounts)

		// --- Best discount (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/best-coupon", handlers.DiscountHandler.GetBestCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/best-promotion", handlers.DiscountHandler.GetBestPromotion)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/best-combination", handlers.DiscountHandler.GetBestDiscountCombination)

		// --- Stacking rules (read/write) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/validate-stacking", handlers.DiscountHandler.ValidateStackingRules)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/can-stack", handlers.DiscountHandler.CanStackDiscounts)

		// --- Discount calculation utilities (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/calculate/coupon", handlers.DiscountHandler.CalculateCouponDiscount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/calculate/promotion", handlers.DiscountHandler.CalculatePromotionDiscount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/calculate/automatic", handlers.DiscountHandler.CalculateAutomaticDiscount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/calculate/combined", handlers.DiscountHandler.CalculateCombinedDiscount)

		// --- Apply / remove discounts (write) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply/coupon", handlers.DiscountHandler.ApplyCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/remove/coupon", handlers.DiscountHandler.RemoveCoupon)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply/promotion", handlers.DiscountHandler.ApplyPromotion)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/remove/promotion", handlers.DiscountHandler.RemovePromotion)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply-best", handlers.DiscountHandler.ApplyBestDiscounts)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/clear", handlers.DiscountHandler.ClearDiscounts)

		// --- Usage tracking (write) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/track/coupon", handlers.DiscountHandler.TrackCouponUsage)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/track/promotion", handlers.DiscountHandler.TrackPromotionUsage)

		// --- Analytics & existence (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/coupon-usage-count", handlers.DiscountHandler.GetCouponUsageCount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/promotion-usage-count", handlers.DiscountHandler.GetPromotionUsageCount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-coupons", handlers.DiscountHandler.GetTopCoupons)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top-promotions", handlers.DiscountHandler.GetTopPromotions)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/total-discount", handlers.DiscountHandler.GetTotalDiscountAmount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/total-coupon-discount", handlers.DiscountHandler.GetTotalCouponDiscountAmount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/total-promotion-discount", handlers.DiscountHandler.GetTotalPromotionDiscountAmount)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/average-discount-rate", handlers.DiscountHandler.GetAverageDiscountRate)

		// --- Existence & expiry checks (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/coupon-exists", handlers.DiscountHandler.CouponExists)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/promotion-exists", handlers.DiscountHandler.PromotionExists)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/coupon-expired", handlers.DiscountHandler.IsCouponExpired)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/promotion-expired", handlers.DiscountHandler.IsPromotionExpired)
	})

	// ================================
	// INVOICE ROUTES
	// ================================
	r.Route("/sales/invoices", func(r chi.Router) {
		// Creation
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.create")).
			Post("/", handlers.InvoiceHandler.CreateDraftInvoice)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.create")).
			Post("/from-order", handlers.InvoiceHandler.CreateInvoiceFromOrder)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.create")).
			Post("/from-quote", handlers.InvoiceHandler.CreateInvoiceFromQuote)

		// Listing & search
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/", handlers.InvoiceHandler.ListInvoices)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/search", handlers.InvoiceHandler.SearchInvoices)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/by-number", handlers.InvoiceHandler.GetInvoiceByNumber)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/by-customer", handlers.InvoiceHandler.GetInvoicesByCustomer)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/by-order", handlers.InvoiceHandler.GetInvoicesByOrder)

		// Special lists
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/overdue", handlers.InvoiceHandler.GetOverdueInvoices)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/due-soon", handlers.InvoiceHandler.GetInvoicesDueSoon)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/top-overdue", handlers.InvoiceHandler.GetTopOverdueInvoices)

		// Pricing preview (no existing invoice ID)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Post("/preview-pricing", handlers.InvoiceHandler.PreviewPricing)

		// Metrics
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/metrics/total-revenue", handlers.InvoiceHandler.GetTotalInvoicedRevenue)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/metrics/collected-revenue", handlers.InvoiceHandler.GetCollectedRevenue)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/metrics/outstanding-receivables", handlers.InvoiceHandler.GetOutstandingReceivables)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/metrics/average-payment-time", handlers.InvoiceHandler.GetAveragePaymentTime)

		// Operations on a specific invoice
		r.Route("/{id}", func(r chi.Router) {
			// Read
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/", handlers.InvoiceHandler.GetInvoiceByID)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/exists", handlers.InvoiceHandler.InvoiceExists)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/is-paid", handlers.InvoiceHandler.IsInvoicePaid)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/is-overdue", handlers.InvoiceHandler.IsInvoiceOverdue)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/totals", handlers.InvoiceHandler.GetInvoiceTotals)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/items", handlers.InvoiceHandler.GetInvoiceItems)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/payments", handlers.InvoiceHandler.GetInvoicePayments)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/outstanding", handlers.InvoiceHandler.GetOutstandingAmount)

			// Write/update
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Put("/", handlers.InvoiceHandler.UpdateInvoice)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.delete")).
				Delete("/", handlers.InvoiceHandler.DeleteInvoice)

			// Items
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/items", handlers.InvoiceHandler.AddItems)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Put("/items", handlers.InvoiceHandler.ReplaceItems)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/items/{itemId}", handlers.InvoiceHandler.RemoveItem)

			// Pricing & totals
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/calculate-pricing", handlers.InvoiceHandler.CalculatePricing)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/recalculate-totals", handlers.InvoiceHandler.RecalculateTotals)

			// Discounts
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/manual-discount", handlers.InvoiceHandler.ApplyManualDiscount)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/manual-discount", handlers.InvoiceHandler.RemoveManualDiscount)

			// Status transitions
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Patch("/status", handlers.InvoiceHandler.UpdateStatus)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/issue", handlers.InvoiceHandler.IssueInvoice)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/mark-paid", handlers.InvoiceHandler.MarkAsPaid)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/mark-overdue", handlers.InvoiceHandler.MarkAsOverdue)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/void", handlers.InvoiceHandler.VoidInvoice)

			// Payment operations
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/register-payment", handlers.InvoiceHandler.RegisterPayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/apply-payment", handlers.InvoiceHandler.ApplyPayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/payments/{paymentId}", handlers.InvoiceHandler.RemovePayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/refresh-balances", handlers.InvoiceHandler.RefreshPaymentBalances)

			// Due date
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Patch("/due-date", handlers.InvoiceHandler.UpdateDueDate)

			// Reminders (send permission)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.send")).
				Post("/send-due-reminder", handlers.InvoiceHandler.SendDueReminder)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.send")).
				Post("/send-overdue-reminder", handlers.InvoiceHandler.SendOverdueReminder)
		})
	})

	// ================================
	// ORDER ROUTES
	// ================================
	r.Route("/sales/orders", func(r chi.Router) {
		// --- Create (create permission) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.OrderHandler.CreateDraftOrder)

		// --- Read operations (view permission) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.OrderHandler.ListOrders)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.OrderHandler.SearchOrders)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-number", handlers.OrderHandler.GetOrderByNumber)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-customer", handlers.OrderHandler.GetOrdersByCustomer)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/pending", handlers.OrderHandler.GetPendingOrders)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/ready-for-invoicing", handlers.OrderHandler.GetOrdersReadyForInvoicing)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue", handlers.OrderHandler.GetOrderRevenue)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/average-value", handlers.OrderHandler.GetAverageOrderValue)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/top", handlers.OrderHandler.GetTopOrdersByValue)

		// --- Pricing preview (read) ---
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/preview-pricing", handlers.OrderHandler.PreviewPricing)

		// --- Single order operations ---
		r.Route("/{id}", func(r chi.Router) {
			// Read
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.OrderHandler.GetOrderByID)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/exists", handlers.OrderHandler.OrderExists)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/has-invoices", handlers.OrderHandler.HasInvoices)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/has-returns", handlers.OrderHandler.HasReturns)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/totals", handlers.OrderHandler.GetOrderTotals)

			// Items
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/items", handlers.OrderHandler.GetOrderItems)

			// Write / update (update permission)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.OrderHandler.UpdateOrder)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/", handlers.OrderHandler.DeleteOrder)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/items", handlers.OrderHandler.AddItems)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/items", handlers.OrderHandler.ReplaceItems)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/items/{itemId}", handlers.OrderHandler.RemoveItem)

			// Discounts (update)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/coupons", handlers.OrderHandler.ApplyCoupon)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/coupons/{code}", handlers.OrderHandler.RemoveCoupon)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/best-discounts", handlers.OrderHandler.ApplyBestDiscounts)

			// Recalculation
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/recalculate", handlers.OrderHandler.RecalculateTotals)

			// Status transitions (update)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/status", handlers.OrderHandler.UpdateStatus)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/confirm", handlers.OrderHandler.ConfirmOrder)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/processing", handlers.OrderHandler.MarkProcessing)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/shipped", handlers.OrderHandler.MarkShipped)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/delivered", handlers.OrderHandler.MarkDelivered)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/cancel", handlers.OrderHandler.CancelOrder)

			// Sales rep assignment
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/assign-sales-rep", handlers.OrderHandler.AssignSalesRep)

			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/assign-sales-rep", handlers.OrderHandler.RemoveSalesRep)
		})
	})

	// -------------------- PAYMENT ROUTES --------------------
	r.Route("/sales/payments", func(r chi.Router) {
		// Create payment (requires process permission)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/", handlers.PaymentHandler.CreatePayment)

		// Register various payment methods (all require process)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/cash", handlers.PaymentHandler.RegisterCashPayment)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/card", handlers.PaymentHandler.RegisterCardPayment)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/bank-transfer", handlers.PaymentHandler.RegisterBankTransferPayment)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/cheque", handlers.PaymentHandler.RegisterChequePayment)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/wallet", handlers.PaymentHandler.RegisterWalletPayment)

		// Gateway payment and webhook
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
			Post("/gateway", handlers.PaymentHandler.ProcessGatewayPayment)
		r.Post("/gateway/webhook", handlers.PaymentHandler.ProcessGatewayWebhook) // no permission check (external)

		// Idempotency lookup (view permission)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/idempotent/{key}", handlers.PaymentHandler.GetPaymentByIdempotencyKey)

		// List / search (view)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/", handlers.PaymentHandler.ListPayments)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/search", handlers.PaymentHandler.SearchPayments)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/by-customer", handlers.PaymentHandler.GetPaymentsByCustomer)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/by-invoice", handlers.PaymentHandler.GetPaymentsByInvoice)

		// Lookup by number / gateway ref (view)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/by-number", handlers.PaymentHandler.GetPaymentByNumber)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/by-gateway-ref", handlers.PaymentHandler.GetPaymentByGatewayReference)

		// Metrics / reports (view)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/metrics/total-received", handlers.PaymentHandler.GetTotalPaymentsReceived)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/metrics/total-refunded", handlers.PaymentHandler.GetTotalRefundedAmount)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/metrics/net-collections", handlers.PaymentHandler.GetNetCollections)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/metrics/by-method", handlers.PaymentHandler.GetPaymentsByMethod)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/metrics/failed", handlers.PaymentHandler.GetFailedPayments)

		// Existence checks (view)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/exists/number", handlers.PaymentHandler.PaymentNumberExists)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/exists/gateway-tx", handlers.PaymentHandler.GatewayTransactionExists)

		// Unreconciled payments (view)
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/unreconciled", handlers.PaymentHandler.GetUnreconciledPayments)

		// Payment by ID (view)
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/", handlers.PaymentHandler.GetPaymentByID)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/exists", handlers.PaymentHandler.PaymentExists)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/has-refunds", handlers.PaymentHandler.HasRefunds)

			// Update & Delete (process)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Put("/", handlers.PaymentHandler.UpdatePayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Delete("/", handlers.PaymentHandler.DeletePayment)

			// Status transitions (process)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Patch("/status", handlers.PaymentHandler.UpdateStatus)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/status/pending", handlers.PaymentHandler.MarkPending)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/status/processing", handlers.PaymentHandler.MarkProcessing)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/status/completed", handlers.PaymentHandler.MarkCompleted)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/status/failed", handlers.PaymentHandler.MarkFailed)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/cancel", handlers.PaymentHandler.CancelPayment)

			// Reconciliation (process)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/reconcile", handlers.PaymentHandler.ReconcilePayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/unreconcile", handlers.PaymentHandler.UnreconcilePayment)

			// Allocations (process)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/allocate", handlers.PaymentHandler.AllocatePayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/allocate-multiple", handlers.PaymentHandler.AllocatePaymentToInvoices)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Post("/auto-allocate", handlers.PaymentHandler.AutoAllocatePayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.process")).
				Delete("/allocations/{allocId}", handlers.PaymentHandler.RemoveAllocation)

			// Allocation info (view)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/allocations", handlers.PaymentHandler.GetPaymentAllocations)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/unallocated-amount", handlers.PaymentHandler.GetUnallocatedAmount)

			// Refunds (refund permission)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refunds", handlers.PaymentHandler.CreateRefund)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refunds/full", handlers.PaymentHandler.RefundFullPayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refunds/partial", handlers.PaymentHandler.RefundPartialPayment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refunds/gateway", handlers.PaymentHandler.ProcessGatewayRefund)

			// Refund info (view)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/refunds", handlers.PaymentHandler.GetPaymentRefunds)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/refunded-amount", handlers.PaymentHandler.GetRefundedAmount)
		})

		// Refund by ID (view)
		r.Route("/refunds/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/", handlers.PaymentHandler.GetRefundByID)
		})
	})

	// ==================== NEW: PAYMENT TERM ROUTES ====================
	// Permissions mapping: read → finance.invoice.view, write → finance.invoice.update
	r.Route("/sales/payment-terms", func(r chi.Router) {
		// Create
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
			Post("/", handlers.PaymentTermHandler.CreatePaymentTerm)

		// List / search
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/", handlers.PaymentTermHandler.ListPaymentTerms)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/search", handlers.PaymentTermHandler.SearchPaymentTerms)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/active", handlers.PaymentTermHandler.GetActivePaymentTerms)

		// Lookup by alternate keys
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/by-code", handlers.PaymentTermHandler.GetPaymentTermByCode)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/by-name", handlers.PaymentTermHandler.GetPaymentTermByName)

		// Individual term operations
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/", handlers.PaymentTermHandler.GetPaymentTermByID)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Put("/", handlers.PaymentTermHandler.UpdatePaymentTerm)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/", handlers.PaymentTermHandler.DeletePaymentTerm)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Patch("/status", handlers.PaymentTermHandler.UpdatePaymentTermStatus)

			// Calculations
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Post("/calculate-due-date", handlers.PaymentTermHandler.CalculateDueDate)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Post("/calculate-early-discount", handlers.PaymentTermHandler.CalculateEarlyPaymentDiscount)

			// Customer assignment
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/assign-customer", handlers.PaymentTermHandler.AssignPaymentTermToCustomer)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/assign-customer", handlers.PaymentTermHandler.RemovePaymentTermFromCustomer)
		})
	})

	// ==================== NEW: PRICING ROUTES ====================
	// Permissions: read → sales.deal.view, write → sales.deal.create (or sales.deal.update for validations)
	r.Route("/sales/pricing", func(r chi.Router) {
		// Base prices
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/product-base-price", handlers.PricingHandler.GetProductBasePrice)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/products-base-prices", handlers.PricingHandler.GetProductsBasePrices)
		// Order pricing
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/order/calculate", handlers.PricingHandler.CalculateOrderPricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/order/preview", handlers.PricingHandler.PreviewOrderPricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/order/tax", handlers.PricingHandler.CalculateOrderTax)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/order/discounts", handlers.PricingHandler.CalculateOrderDiscounts)

		// Quote pricing
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/quote/calculate", handlers.PricingHandler.CalculateQuotePricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/quote/preview", handlers.PricingHandler.PreviewQuotePricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/quote/tax", handlers.PricingHandler.CalculateQuoteTax)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/quote/discounts", handlers.PricingHandler.CalculateQuoteDiscounts)

		// Invoice pricing
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/invoice/calculate", handlers.PricingHandler.CalculateInvoicePricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/invoice/preview", handlers.PricingHandler.PreviewInvoicePricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/invoice/tax", handlers.PricingHandler.CalculateInvoiceTax)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/invoice/discounts", handlers.PricingHandler.CalculateInvoiceDiscounts)

		// Low‑level tax calculations
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/line-tax", handlers.PricingHandler.CalculateLineTax)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/tax-amount", handlers.PricingHandler.CalculateTaxAmount)

		// Discount discovery & combination
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/applicable-coupons", handlers.PricingHandler.GetApplicableCoupons)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/best-coupon", handlers.PricingHandler.GetBestCoupon)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/applicable-promotions", handlers.PricingHandler.GetApplicablePromotions)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/best-promotion", handlers.PricingHandler.GetBestPromotion)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/combined-discount", handlers.PricingHandler.CalculateCombinedDiscount)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/validate-combination", handlers.PricingHandler.ValidateDiscountCombination)

		// Customer credit / balance info
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customer-credit-limit", handlers.PricingHandler.GetCustomerCreditLimit)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customer-outstanding-balance", handlers.PricingHandler.GetCustomerOutstandingBalance)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customer-can-purchase", handlers.PricingHandler.CanCustomerPurchaseAmount)

		// Validation endpoints
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/validate", handlers.PricingHandler.ValidatePricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/validate/order", handlers.PricingHandler.ValidateOrderPricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/validate/quote", handlers.PricingHandler.ValidateQuotePricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/validate/invoice", handlers.PricingHandler.ValidateInvoicePricing)

		// Analytics / reporting
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/average-discount-rate", handlers.PricingHandler.GetAverageDiscountRate)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/total-discount-amount", handlers.PricingHandler.GetTotalDiscountAmount)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/effective-revenue", handlers.PricingHandler.GetEffectiveRevenueAfterDiscounts)
	})

	// ==================== PRODUCT ROUTES ====================
	r.Route("/sales/products", func(r chi.Router) {
		// Create
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.ProductHandler.CreateProduct)

		// Update & Delete
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.ProductHandler.UpdateProduct)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.ProductHandler.DeleteProduct)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.ProductHandler.GetProductByID)

			// Status
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/status", handlers.ProductHandler.UpdateProductStatus)

			// Unit price
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/unit-price", handlers.ProductHandler.UpdateUnitPrice)

			// Inventory linking
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/link-inventory", handlers.ProductHandler.LinkInventoryItem)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/unlink-inventory", handlers.ProductHandler.UnlinkInventoryItem)
		})

		// Queries
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-sku", handlers.ProductHandler.GetProductBySKU)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.ProductHandler.ListProducts)
	})

	// ==================== PROMOTION ROUTES ====================
	r.Route("/sales/promotions", func(r chi.Router) {
		// CRUD
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.create")).
			Post("/", handlers.PromotionHandler.CreatePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Put("/{id}", handlers.PromotionHandler.UpdatePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.delete")).
			Delete("/{id}", handlers.PromotionHandler.DeletePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}", handlers.PromotionHandler.GetPromotionByID)

		// Lookups
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/by-code", handlers.PromotionHandler.GetPromotionByCode)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/by-name", handlers.PromotionHandler.GetPromotionByName)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/search", handlers.PromotionHandler.SearchPromotions)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/active", handlers.PromotionHandler.GetActivePromotions)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/", handlers.PromotionHandler.ListPromotions)

		// State changes
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/{id}/activate", handlers.PromotionHandler.ActivatePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/{id}/deactivate", handlers.PromotionHandler.DeactivatePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/{id}/expire", handlers.PromotionHandler.ExpirePromotion)

		// Promotion Rules
		r.Route("/rules", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
				Post("/", handlers.PromotionHandler.CreatePromotionRule)
			r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
				Put("/{ruleId}", handlers.PromotionHandler.UpdatePromotionRule)
			r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
				Delete("/{ruleId}", handlers.PromotionHandler.DeletePromotionRule)
			r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
				Get("/{ruleId}", handlers.PromotionHandler.GetPromotionRuleByID)
			r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
				Get("/{ruleId}/exists", handlers.PromotionHandler.PromotionRuleExists)
		})
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/rules", handlers.PromotionHandler.GetPromotionRules)

		// Validation & evaluation
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/validate", handlers.PromotionHandler.ValidatePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/evaluate", handlers.PromotionHandler.EvaluatePromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/{id}/calculate-discount", handlers.PromotionHandler.CalculatePromotionDiscount)

		// Applying promotions to entities (order, quote, invoice)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply/order", handlers.PromotionHandler.ApplyPromotionToOrder)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply/quote", handlers.PromotionHandler.ApplyPromotionToQuote)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
			Post("/apply/invoice", handlers.PromotionHandler.ApplyPromotionToInvoice)

		// Apply best promotion automatically
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Post("/apply-best", handlers.PromotionHandler.ApplyBestPromotions)

		// Removing promotions
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/remove/order", handlers.PromotionHandler.RemovePromotionFromOrder)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/remove/quote", handlers.PromotionHandler.RemovePromotionFromQuote)
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
			Delete("/remove/invoice", handlers.PromotionHandler.RemovePromotionFromInvoice)

		// Clear all promotions from an entity
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
			Delete("/clear", handlers.PromotionHandler.ClearPromotions)

		// Usage tracking
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.update")).
			Post("/usage", handlers.PromotionHandler.RecordPromotionUsage)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/usage-count", handlers.PromotionHandler.GetPromotionUsageCount)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/customer-usage", handlers.PromotionHandler.GetCustomerPromotionUsageCount)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/usage-history", handlers.PromotionHandler.GetPromotionUsageHistory)

		// Stacking
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/can-stack", handlers.PromotionHandler.CanStackPromotion)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Post("/validate-stacking", handlers.PromotionHandler.ValidatePromotionStacking)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/stackable", handlers.PromotionHandler.GetStackablePromotions)

		// Analytics / reporting
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/top", handlers.PromotionHandler.GetTopPromotions)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/most-used", handlers.PromotionHandler.GetMostUsedPromotions)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/highest-revenue", handlers.PromotionHandler.GetHighestRevenuePromotions)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/total-discount", handlers.PromotionHandler.GetTotalPromotionDiscountAmount)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/conversion-impact", handlers.PromotionHandler.GetPromotionConversionImpact)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/redemption-rate", handlers.PromotionHandler.GetPromotionRedemptionRate)

		// Existence & status helpers
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/exists", handlers.PromotionHandler.PromotionExists)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/code-exists", handlers.PromotionHandler.PromotionCodeExists)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/expired", handlers.PromotionHandler.IsPromotionExpired)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/{id}/usage-limit-reached", handlers.PromotionHandler.IsPromotionUsageLimitReached)
		r.With(middleware.BitmaskPermissionMiddleware("marketing.campaign.view")).
			Get("/customer-limit-reached", handlers.PromotionHandler.IsCustomerPromotionUsageLimitReached)
	})
	// ==================== NEW QUOTE ROUTES ====================
	r.Route("/sales/quotes", func(r chi.Router) {
		// Create & modify
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.create")).
			Post("/", handlers.QuoteHandler.CreateQuote)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Put("/{id}", handlers.QuoteHandler.UpdateQuote)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.delete")).
			Delete("/{id}", handlers.QuoteHandler.DeleteQuote)

		// Read single
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/{id}", handlers.QuoteHandler.GetQuoteByID)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/by-number", handlers.QuoteHandler.GetQuoteByNumber)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/latest-revision", handlers.QuoteHandler.GetLatestRevision)

		// List & search
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/", handlers.QuoteHandler.ListQuotes)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/search", handlers.QuoteHandler.SearchQuotes)

		// Items management
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/items", handlers.QuoteHandler.AddItems)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Put("/{id}/items", handlers.QuoteHandler.ReplaceItems)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Delete("/{id}/items/{itemId}", handlers.QuoteHandler.RemoveItem)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/{id}/items", handlers.QuoteHandler.GetQuoteItems)

		// Discounts & pricing
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/coupons", handlers.QuoteHandler.ApplyCoupon)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Delete("/{id}/coupons/{code}", handlers.QuoteHandler.RemoveCoupon)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/best-discounts", handlers.QuoteHandler.ApplyBestDiscounts)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Post("/preview-pricing", handlers.QuoteHandler.PreviewPricing)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/recalculate", handlers.QuoteHandler.RecalculateTotals)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/{id}/totals", handlers.QuoteHandler.GetQuoteTotals)

		// Status & lifecycle
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Patch("/{id}/status", handlers.QuoteHandler.UpdateStatus)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/mark-sent", handlers.QuoteHandler.MarkSent)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/accept", handlers.QuoteHandler.AcceptQuote)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/reject", handlers.QuoteHandler.RejectQuote)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/expire", handlers.QuoteHandler.ExpireQuote)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/expiring", handlers.QuoteHandler.GetExpiringQuotes)

		// Conversion to order
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/convert", handlers.QuoteHandler.ConvertToOrder)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/{id}/is-converted", handlers.QuoteHandler.IsConverted)

		// Sales rep assignment
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/assign-sales-rep", handlers.QuoteHandler.AssignSalesRep)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Delete("/{id}/assign-sales-rep", handlers.QuoteHandler.RemoveSalesRep)

		// Revisions
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
			Post("/{id}/revisions", handlers.QuoteHandler.CreateRevision)

		// Analytics & existence
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/conversion-rate", handlers.QuoteHandler.GetQuoteConversionRate)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/total-quoted-revenue", handlers.QuoteHandler.GetTotalQuotedRevenue)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/{id}/exists", handlers.QuoteHandler.QuoteExists)
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/{id}/expired", handlers.QuoteHandler.IsExpired)
	})

	// ==================== NEW TAX ROUTES ====================
	r.Route("/sales/tax", func(r chi.Router) {
		// Tax calculations (view permission)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Post("/calculate/order", handlers.TaxHandler.CalculateOrderTaxes)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Post("/calculate/quote", handlers.TaxHandler.CalculateQuoteTaxes)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Post("/calculate/invoice", handlers.TaxHandler.CalculateInvoiceTaxes)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Post("/calculate/return", handlers.TaxHandler.CalculateReturnTaxes)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Post("/calculate/line", handlers.TaxHandler.CalculateLineTax)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Post("/preview", handlers.TaxHandler.PreviewTaxes)

		// Applying taxes to entities (update permission)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.update")).
			Post("/apply/order", handlers.TaxHandler.ApplyTaxesToOrder)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.update")).
			Post("/apply/quote", handlers.TaxHandler.ApplyTaxesToQuote)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.update")).
			Post("/apply/invoice", handlers.TaxHandler.ApplyTaxesToInvoice)

		// Refresh taxes (update)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.update")).
			Post("/refresh/order", handlers.TaxHandler.RefreshOrderTaxes)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.update")).
			Post("/refresh/invoice", handlers.TaxHandler.RefreshInvoiceTaxes)

		// Tax breakdown (view)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/breakdown/order/{orderId}", handlers.TaxHandler.GetOrderTaxBreakdown)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/breakdown/invoice/{invoiceId}", handlers.TaxHandler.GetInvoiceTaxBreakdown)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/breakdown/quote/{quoteId}", handlers.TaxHandler.GetQuoteTaxBreakdown)

		// Tax snapshots
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.create")).
			Post("/snapshots", handlers.TaxHandler.CreateTaxSnapshot)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/snapshots/{id}", handlers.TaxHandler.GetTaxSnapshotByID)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/snapshots/latest", handlers.TaxHandler.GetLatestTaxSnapshot)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/snapshots", handlers.TaxHandler.GetTaxSnapshots)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.update")).
			Post("/snapshots/{id}/recalculate", handlers.TaxHandler.RecalculateTaxSnapshot)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.delete")).
			Delete("/snapshots/{id}", handlers.TaxHandler.ArchiveTaxSnapshot)
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/snapshots/{id}/exists", handlers.TaxHandler.TaxSnapshotExists)
	})

	// ==================== NEW: Reports ====================
	r.Route("/sales/reports", func(r chi.Router) {
		// Dashboard & Summary
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/dashboard", handlers.ReportHandler.GetSalesDashboard)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/{customerId}/overdue-invoices", handlers.ReportHandler.GetCustomerOverdueInvoices)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/today-summary", handlers.ReportHandler.GetTodaySalesSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/realtime-snapshot", handlers.ReportHandler.GetRealtimeSalesSnapshot)

		// Revenue
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/summary", handlers.ReportHandler.GetRevenueSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/trend", handlers.ReportHandler.GetRevenueTrend)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/by-customer", handlers.ReportHandler.GetRevenueByCustomer)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/by-product", handlers.ReportHandler.GetRevenueByProduct)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/by-category", handlers.ReportHandler.GetRevenueByCategory)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/by-sales-rep", handlers.ReportHandler.GetRevenueBySalesRep)

		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/revenue/by-payment-method", handlers.ReportHandler.GetRevenueByPaymentMethod)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/revenue/net-after-returns", handlers.ReportHandler.GetNetRevenueAfterReturns)

		// Customers
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/top", handlers.ReportHandler.GetTopCustomers)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/{customerId}/sales-summary", handlers.ReportHandler.GetCustomerSalesSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/{customerId}/lifetime-value", handlers.ReportHandler.GetCustomerLifetimeValue)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/outstanding-balance", handlers.ReportHandler.GetCustomersWithOutstandingBalance)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/overdue-invoices", handlers.ReportHandler.GetCustomersWithOverdueInvoices)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/inactive", handlers.ReportHandler.GetInactiveCustomers)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/customers/new", handlers.ReportHandler.GetNewCustomers)

		// Orders
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/orders/summary", handlers.ReportHandler.GetOrderSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/orders/by-status", handlers.ReportHandler.GetOrdersByStatus)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/orders/top", handlers.ReportHandler.GetTopOrdersByValue)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/orders/average-value-trend", handlers.ReportHandler.GetAverageOrderValueTrend)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/orders/conversion-funnel", handlers.ReportHandler.GetOrderConversionFunnel)

		// Quotes
		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/quotes/summary", handlers.ReportHandler.GetQuoteSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/quotes/conversion-metrics", handlers.ReportHandler.GetQuoteConversionMetrics)

		r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
			Get("/quotes/expiring-soon", handlers.ReportHandler.GetQuotesExpiringSoon)

		// Invoices & Receivables
		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/invoices/summary", handlers.ReportHandler.GetInvoiceSummary)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/receivables/outstanding-summary", handlers.ReportHandler.GetOutstandingReceivablesSummary)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/invoices/overdue", handlers.ReportHandler.GetOverdueInvoices)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/invoices/overdue-aging", handlers.ReportHandler.GetOverdueInvoiceAging)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/invoices/due-soon", handlers.ReportHandler.GetInvoicesDueSoon)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/invoices/collection-trend", handlers.ReportHandler.GetInvoiceCollectionTrend)

		r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
			Get("/invoices/average-collection-days", handlers.ReportHandler.GetAverageCollectionDays)

		// Payments & Refunds
		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/payments/summary", handlers.ReportHandler.GetPaymentSummary)

		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/payments/method-breakdown", handlers.ReportHandler.GetPaymentMethodBreakdown)

		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/payments/failed-analytics", handlers.ReportHandler.GetFailedPaymentAnalytics)

		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/refunds/summary", handlers.ReportHandler.GetRefundSummary)

		// Products
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/products/top-selling", handlers.ReportHandler.GetTopSellingProducts)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/products/least-selling", handlers.ReportHandler.GetLeastSellingProducts)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/products/{productId}/sales-trend", handlers.ReportHandler.GetProductSalesTrend)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/products/never-sold", handlers.ReportHandler.GetProductsNeverSold)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/products/most-returned", handlers.ReportHandler.GetMostReturnedProducts)

		// Returns & Refunds Liability
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/returns/summary", handlers.ReportHandler.GetReturnSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/returns/rate-trend", handlers.ReportHandler.GetReturnRateTrend)

		r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
			Get("/refunds/liability-summary", handlers.ReportHandler.GetRefundLiabilitySummary)

		// Discounts & Promotions
		r.With(middleware.BitmaskPermissionMiddleware("marketing.analytics.view")).
			Get("/discounts/summary", handlers.ReportHandler.GetDiscountSummary)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.analytics.view")).
			Get("/discounts/coupon-performance", handlers.ReportHandler.GetCouponPerformance)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.analytics.view")).
			Get("/discounts/promotion-performance", handlers.ReportHandler.GetPromotionPerformance)

		r.With(middleware.BitmaskPermissionMiddleware("marketing.analytics.view")).
			Get("/discounts/impact-on-revenue", handlers.ReportHandler.GetDiscountImpactOnRevenue)

		// Tax Reports
		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/tax/summary", handlers.ReportHandler.GetTaxSummary)

		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/tax/breakdown-by-rate", handlers.ReportHandler.GetTaxBreakdownByRate)

		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/tax/breakdown-by-jurisdiction", handlers.ReportHandler.GetTaxBreakdownByJurisdiction)

		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/tax/breakdown-by-product", handlers.ReportHandler.GetTaxBreakdownByProduct)

		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/tax/collected-trend", handlers.ReportHandler.GetCollectedTaxTrend)

		r.With(middleware.BitmaskPermissionMiddleware("finance.tax.view")).
			Get("/tax/audit-report", handlers.ReportHandler.GetTaxAuditReport)

		// Sales Rep Performance & Commission
		r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
			Get("/sales-rep/{salesRepId}/performance", handlers.ReportHandler.GetSalesRepPerformance)

		r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
			Get("/sales-rep/leaderboard", handlers.ReportHandler.GetSalesLeaderboard)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")). // previously sales.commission.read
											Get("/commissions/summary", handlers.ReportHandler.GetCommissionSummary)

		// Credit Risk
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/credit/risk-summary", handlers.ReportHandler.GetCreditRiskSummary)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/credit/customers-near-limit", handlers.ReportHandler.GetCustomersNearCreditLimit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/credit/customers-exceeding-limit", handlers.ReportHandler.GetCustomersExceedingCreditLimit)

		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/credit/orders-on-hold", handlers.ReportHandler.GetOrdersOnCreditHold)

		// Standard Reports (exportable)
		r.With(middleware.BitmaskPermissionMiddleware("accounting.report.export")).
			Get("/sales-report", handlers.ReportHandler.GetSalesReport)

		r.With(middleware.BitmaskPermissionMiddleware("accounting.report.export")).
			Get("/tax-report", handlers.ReportHandler.GetTaxReport)

		r.With(middleware.BitmaskPermissionMiddleware("accounting.report.export")).
			Get("/receivables-report", handlers.ReportHandler.GetReceivablesReport)

		r.With(middleware.BitmaskPermissionMiddleware("accounting.report.export")).
			Get("/customer-statement", handlers.ReportHandler.GetCustomerStatement)

		// Audit Trail
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/audit-trail", handlers.ReportHandler.GetSalesAuditTrail)
	})

	// ==================== SALES REPS ROUTES ====================
	r.Route("/sales/sales-reps", func(r chi.Router) {
		// Create sales rep
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.SalesRepHandler.CreateSalesRep)

		// Update, delete, activate/deactivate, etc.
		r.Route("/{id}", func(r chi.Router) {
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.SalesRepHandler.UpdateSalesRep)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.SalesRepHandler.DeleteSalesRep)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/activate", handlers.SalesRepHandler.ActivateSalesRep)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/deactivate", handlers.SalesRepHandler.DeactivateSalesRep)

			// Targets
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.create")).
				Post("/target", handlers.SalesRepHandler.SetSalesTarget)
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/target", handlers.SalesRepHandler.GetSalesTarget)

			// Commission plan assignment (use sales.deal.update as fallback)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/commission-plan", handlers.SalesRepHandler.SetCommissionPlan)

			// Assignment to orders, quotes, invoices
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/assign-order", handlers.SalesRepHandler.AssignOrder)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/assign-order", handlers.SalesRepHandler.RemoveOrderAssignment)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/assigned-orders", handlers.SalesRepHandler.GetAssignedOrders)

			r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
				Post("/assign-quote", handlers.SalesRepHandler.AssignQuote)
			r.With(middleware.BitmaskPermissionMiddleware("sales.quote.update")).
				Delete("/assign-quote", handlers.SalesRepHandler.RemoveQuoteAssignment)
			r.With(middleware.BitmaskPermissionMiddleware("sales.quote.view")).
				Get("/assigned-quotes", handlers.SalesRepHandler.GetAssignedQuotes)

			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/assign-invoice", handlers.SalesRepHandler.AssignInvoice)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Delete("/assign-invoice", handlers.SalesRepHandler.RemoveInvoiceAssignment)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/assigned-invoices", handlers.SalesRepHandler.GetAssignedInvoices)

			// Performance metrics
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/commission", handlers.SalesRepHandler.CalculateCommission)
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/earned-commission", handlers.SalesRepHandler.GetEarnedCommission)
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/revenue", handlers.SalesRepHandler.GetSalesRevenue)
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/collected-revenue", handlers.SalesRepHandler.GetCollectedRevenue)
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/average-deal-size", handlers.SalesRepHandler.GetAverageDealSize)
			r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
				Get("/conversion-rate", handlers.SalesRepHandler.GetConversionRate)
		})

		// List and search
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.SalesRepHandler.ListSalesReps)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.SalesRepHandler.SearchSalesReps)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/active", handlers.SalesRepHandler.GetActiveSalesReps)

		// Lookup by alternative keys
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-user", handlers.SalesRepHandler.GetSalesRepByUserID)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-code", handlers.SalesRepHandler.GetSalesRepByCode)

		// Existence checks
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/exists", handlers.SalesRepHandler.SalesRepCodeExists)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/{id}/exists", handlers.SalesRepHandler.SalesRepExists)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/user-linked", handlers.SalesRepHandler.UserAlreadyLinked)

		// Leaderboard and top reps
		r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
			Get("/leaderboard", handlers.SalesRepHandler.GetSalesRepLeaderboard)
		r.With(middleware.BitmaskPermissionMiddleware("sales.target.view")).
			Get("/top", handlers.SalesRepHandler.GetTopSalesReps)
	})

	// ==================== NEW ROUTES: RETURNS ====================
	r.Route("/sales/returns", func(r chi.Router) {
		// Create returns
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/", handlers.ReturnHandler.CreateReturnRequest)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/from-order", handlers.ReturnHandler.CreateReturnFromOrder)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.create")).
			Post("/from-invoice", handlers.ReturnHandler.CreateReturnFromInvoice)

		// List, search, and filters
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/", handlers.ReturnHandler.ListReturns)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/search", handlers.ReturnHandler.SearchReturns)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-customer", handlers.ReturnHandler.GetReturnsByCustomer)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-order", handlers.ReturnHandler.GetReturnsByOrder)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-invoice", handlers.ReturnHandler.GetReturnsByInvoice)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/by-number", handlers.ReturnHandler.GetReturnByNumber)

		// Status-specific lists
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/pending", handlers.ReturnHandler.GetPendingReturns)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/approved", handlers.ReturnHandler.GetApprovedReturns)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/rejected", handlers.ReturnHandler.GetRejectedReturns)

		// Preview and calculations
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Post("/preview-refund", handlers.ReturnHandler.PreviewRefund)

		// Single return operations
		r.Route("/{id}", func(r chi.Router) {
			// Read
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/", handlers.ReturnHandler.GetReturnByID)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/exists", handlers.ReturnHandler.ReturnExists)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/is-approved", handlers.ReturnHandler.IsReturnApproved)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/is-completed", handlers.ReturnHandler.IsReturnCompleted)

			// Update & delete
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/", handlers.ReturnHandler.UpdateReturnRequest)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.delete")).
				Delete("/", handlers.ReturnHandler.DeleteReturnRequest)

			// Status transitions
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/approve", handlers.ReturnHandler.ApproveReturn)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/reject", handlers.ReturnHandler.RejectReturn)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/cancel", handlers.ReturnHandler.CancelReturn)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/mark-received", handlers.ReturnHandler.MarkReceived)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/complete", handlers.ReturnHandler.CompleteReturn)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Patch("/status", handlers.ReturnHandler.UpdateStatus)

			// Items
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Post("/items", handlers.ReturnHandler.AddItems)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Put("/items", handlers.ReturnHandler.ReplaceItems)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.update")).
				Delete("/items/{itemId}", handlers.ReturnHandler.RemoveItem)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/items", handlers.ReturnHandler.GetReturnItems)

			// Refund calculations
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Get("/refund-amount", handlers.ReturnHandler.CalculateRefundAmount)
			r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
				Post("/partial-refund-amount", handlers.ReturnHandler.CalculatePartialRefund)

			// Credit note
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.update")).
				Post("/credit-note", handlers.ReturnHandler.GenerateCreditNote)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/credit-note", handlers.ReturnHandler.GetCreditNote)
			r.With(middleware.BitmaskPermissionMiddleware("finance.invoice.view")).
				Get("/has-credit-note", handlers.ReturnHandler.HasCreditNote)

			// Refunds (payment refunds)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refund", handlers.ReturnHandler.ProcessRefund)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refund/full", handlers.ReturnHandler.ProcessFullRefund)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.refund")).
				Post("/refund/partial", handlers.ReturnHandler.ProcessPartialRefund)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/refunds", handlers.ReturnHandler.GetRefunds)
			r.With(middleware.BitmaskPermissionMiddleware("finance.payment.view")).
				Get("/refunded-amount", handlers.ReturnHandler.GetRefundedAmount)

			// Inventory actions
			r.With(middleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/restock", handlers.ReturnHandler.RestockReturnedItems)
			r.With(middleware.BitmaskPermissionMiddleware("inventory.stock.adjust")).
				Post("/mark-damaged", handlers.ReturnHandler.MarkItemsAsDamaged)
		})

		// Analytics endpoints
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/return-rate", handlers.ReturnHandler.GetReturnRate)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/total-refund-amount", handlers.ReturnHandler.GetTotalRefundAmount)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/most-returned-products", handlers.ReturnHandler.GetMostReturnedProducts)
		r.With(middleware.BitmaskPermissionMiddleware("sales.deal.view")).
			Get("/number-exists", handlers.ReturnHandler.ReturnNumberExists)
	})
}
