package accounting

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"auth-service/internal/accounting/handler"
	authMiddleware "auth-service/internal/middleware"
	"auth-service/internal/service"
)

// AccountingHandlers groups all accounting handlers.
type AccountingHandlers struct {
	AccountHandler            *handler.AccountHandler
	LedgerHandler             *handler.LedgerHandler
	ReconciliationHandler     *handler.ReconciliationHandler
	ReportHandler             *handler.ReportHandler
	ComplianceHandler         *handler.ComplianceHandler
	JournalHandler            *handler.JournalHandler
	TaxHandler                *handler.TaxHandler
	AccountingSettingsHandler *handler.AccountingSettingsHandler
	AnalyticsHandler          *handler.AnalyticsHandler
	PeriodLockHandler         *handler.PeriodLockHandler

	// 👇 ADDED
	CostCenterHandler *handler.CostCenterHandler
}

// RegisterAccountingRoutes registers all accounting routes under
// /companies/{companyID}/accounting.
//
// Middleware chain applied inside this function (in order):
//
//	jwt → session → subscription → location → idempotency
//
// The caller must NOT wrap this call in a group that already applies
// those middlewares, otherwise they will run twice.
func RegisterAccountingRoutes(
	r chi.Router,
	handlers *AccountingHandlers,
	jwtService *service.JWTService,

	// auth + platform middleware, provided by the main router
	jwtAuthMiddleware func(http.Handler) http.Handler,
	sessionValidationMiddleware func(http.Handler) http.Handler,
	subscriptionEnforcementMiddleware func(http.Handler) http.Handler,
	locationValidationMiddleware func(http.Handler) http.Handler,
	idempotencyMiddleware func(http.Handler) http.Handler,
) {
	r.Route("/companies/{companyID}/accounting", func(r chi.Router) {
		// ---- Mandatory chain ----
		r.Use(jwtAuthMiddleware)
		r.Use(sessionValidationMiddleware)
		r.Use(subscriptionEnforcementMiddleware)
		r.Use(locationValidationMiddleware)
		r.Use(idempotencyMiddleware)

		// ========== Chart of Accounts ==========
		r.Route("/accounts", func(r chi.Router) {

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create")).
				Post("/", handlers.AccountHandler.CreateAccount)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create")).
				Post("/bulk", handlers.AccountHandler.BulkCreateAccounts)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/tree", handlers.AccountHandler.GetAccountTree)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/by-code", handlers.AccountHandler.GetAccountByCode)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/", handlers.AccountHandler.ListAccounts)

			r.Route("/{accountID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/", handlers.AccountHandler.GetAccount)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Put("/", handlers.AccountHandler.UpdateAccount)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Patch("/status", handlers.AccountHandler.UpdateAccountStatus)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Patch("/move", handlers.AccountHandler.MoveAccount)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.delete")).
					Delete("/", handlers.AccountHandler.DeleteAccount)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/children", handlers.AccountHandler.GetChildren)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/has-children", handlers.AccountHandler.HasChildren)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/usage", handlers.AccountHandler.CheckUsage)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/circular", handlers.AccountHandler.CheckCircularReference)
			})
		})

		// ========== Cost Centers (👇 ADDED) ==========
		r.Route("/cost-centers", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/", handlers.CostCenterHandler.List) // ?include_inactive=true&tree=true&limit=&offset=

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create")).
				Post("/", handlers.CostCenterHandler.Create)

			r.Route("/{costCenterID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/", handlers.CostCenterHandler.GetByID)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Put("/", handlers.CostCenterHandler.Update)

				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.delete")).
					Delete("/", handlers.CostCenterHandler.Deactivate)
			})
		})

		// ========== Accounting Settings ==========
		r.Route("/settings", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
				Get("/", handlers.AccountingSettingsHandler.GetSettings)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Post("/", handlers.AccountingSettingsHandler.CreateSettings)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/", handlers.AccountingSettingsHandler.UpdateSettings)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/upsert", handlers.AccountingSettingsHandler.UpsertSettings)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/fiscal-year", handlers.AccountingSettingsHandler.UpdateFiscalYear)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/currency", handlers.AccountingSettingsHandler.UpdateCurrency)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/tax-scheme", handlers.AccountingSettingsHandler.UpdateTaxScheme)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
				Get("/exists", handlers.AccountingSettingsHandler.ExistsSettings)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
				Get("/fiscal-period", handlers.AccountingSettingsHandler.GetFiscalPeriod)

			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/flags", handlers.AccountingSettingsHandler.UpdateFlags)
		})

		// ========== Ledger ==========
		r.Route("/ledger", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/balance", handlers.LedgerHandler.GetAccountBalance)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
				Post("/recompute", handlers.LedgerHandler.RecomputeBalances)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/trial-balance", handlers.LedgerHandler.TrialBalance)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view")).
				Get("/profit-and-loss", handlers.LedgerHandler.ProfitAndLoss)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view")).
				Get("/balance-sheet", handlers.LedgerHandler.BalanceSheet)
		})

		// ========== Reconciliation ==========
		r.Route("/reconciliation", func(r chi.Router) {
			r.Route("/batches", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/", handlers.ReconciliationHandler.CreateBatch)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/", handlers.ReconciliationHandler.ListBatches)
				r.Route("/{batchID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
						Get("/", handlers.ReconciliationHandler.GetBatch)
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
						Post("/stats", handlers.ReconciliationHandler.UpdateBatchStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
						Post("/complete", handlers.ReconciliationHandler.CompleteBatch)
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
						Delete("/", handlers.ReconciliationHandler.DeleteBatch)
				})
			})

			r.Route("/batches/{batchID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/", handlers.ReconciliationHandler.AddItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/", handlers.ReconciliationHandler.GetItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/unmatched", handlers.ReconciliationHandler.GetUnmatchedItems)
			})

			r.Route("/batches/{batchID}/match", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/auto", handlers.ReconciliationHandler.AutoMatch)
			})
			r.Route("/items/{itemID}/match", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/manual", handlers.ReconciliationHandler.ManualMatch)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Put("/status", handlers.ReconciliationHandler.SetItemMatchStatus)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Delete("/", handlers.ReconciliationHandler.UnmatchItem)
			})

			r.Route("/batches/{batchID}/differences", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/", handlers.ReconciliationHandler.CreateDifference)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/", handlers.ReconciliationHandler.GetDifferences)
			})
			r.Route("/differences/{diffID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/resolve", handlers.ReconciliationHandler.ResolveDifference)
			})

			r.Route("/batches/{batchID}/adjustments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/", handlers.ReconciliationHandler.CreateAdjustment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/", handlers.ReconciliationHandler.GetAdjustments)
			})
			r.Route("/adjustments/{adjID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Delete("/", handlers.ReconciliationHandler.DeleteAdjustment)
			})
		})

		// ========== Reports ==========
		r.Route("/reports", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view")).
				Get("/trial-balance", handlers.ReportHandler.GetTrialBalance)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/general-ledger", handlers.ReportHandler.GetGeneralLedger)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view")).
				Get("/balance-sheet", handlers.ReportHandler.GetBalanceSheet)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view")).
				Get("/income-statement", handlers.ReportHandler.GetIncomeStatement)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.cashflow.view")).
				Get("/cash-flow", handlers.ReportHandler.GetCashFlowStatement)

			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/tax-summary", handlers.ReportHandler.GetTaxSummary)

			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/compliance-returns", handlers.ReportHandler.ListComplianceReturns)

			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/account-balance", handlers.ReportHandler.GetAccountBalance)
		})

		// ========== Compliance ==========
		r.Route("/compliance", func(r chi.Router) {
			r.Route("/returns", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create")).
					Post("/", handlers.ComplianceHandler.CreateReturn)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
					Get("/", handlers.ComplianceHandler.ListReturns)
				r.Route("/{id}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
						Get("/", handlers.ComplianceHandler.GetReturnByID)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Put("/", handlers.ComplianceHandler.UpdateReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete")).
						Delete("/", handlers.ComplianceHandler.DeleteReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Post("/submit", handlers.ComplianceHandler.SubmitReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Post("/file", handlers.ComplianceHandler.FileReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Post("/amend", handlers.ComplianceHandler.AmendReturn)
				})
			})
			r.Route("/filings/{filingID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
					Get("/", handlers.ComplianceHandler.GetFilingByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
					Patch("/status", handlers.ComplianceHandler.UpdateFilingStatus)
			})
		})

		// ========== Journals ==========
		r.Route("/journals", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create")).
				Post("/", handlers.JournalHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.view")).
				Get("/", handlers.JournalHandler.List)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.view")).
					Get("/", handlers.ReportHandler.GetJournal)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Put("/", handlers.JournalHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.delete")).
					Delete("/", handlers.JournalHandler.Delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Post("/post", handlers.JournalHandler.Post)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Post("/reverse", handlers.JournalHandler.Reverse)
			})
		})

		// ========== Tax Engine ==========
		r.Route("/tax", func(r chi.Router) {
			r.Route("/rates", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create")).
					Post("/", handlers.TaxHandler.CreateTaxRate)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
					Get("/", handlers.TaxHandler.ListTaxRates)
				r.Route("/{rateID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Put("/", handlers.TaxHandler.UpdateTaxRate)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete")).
						Delete("/", handlers.TaxHandler.DeleteTaxRate)
				})
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
					Post("/close-open", handlers.TaxHandler.CloseOpenRates)
			})

			r.Route("/rules", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create")).
					Post("/", handlers.TaxHandler.CreateTaxRule)
				r.Route("/{ruleID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Put("/", handlers.TaxHandler.UpdateTaxRule)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete")).
						Delete("/", handlers.TaxHandler.DeleteTaxRule)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
						Get("/", handlers.TaxHandler.GetRuleBundle)
				})
			})

			r.Route("/profiles", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create")).
					Post("/", handlers.TaxHandler.CreateTaxProfile)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
					Get("/", handlers.TaxHandler.ListTaxProfiles)
				r.Route("/{profileID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Put("/", handlers.TaxHandler.UpdateTaxProfile)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete")).
						Delete("/", handlers.TaxHandler.DeleteTaxProfile)
				})
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
					Post("/{profileID}/set-default", handlers.TaxHandler.SetDefaultTaxProfile)
			})

			r.Route("/transactions", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create")).
					Post("/", handlers.TaxHandler.CreateTaxTransaction)
				r.Route("/{transactionType}/{transactionID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
						Get("/", handlers.TaxHandler.GetTransactionTaxBreakdown)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update")).
						Post("/void", handlers.TaxHandler.VoidTaxTransaction)
				})
			})

			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Post("/compute", handlers.TaxHandler.ComputeTax)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Post("/evaluate-rules", handlers.TaxHandler.EvaluateRules)

			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/return", handlers.TaxHandler.GenerateTaxReturn)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/summary", handlers.TaxHandler.GetTaxSummary)
		})

		// ========== Analytics ==========
		r.Route("/analytics", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/daily-summaries", handlers.AnalyticsHandler.ListDailySummaries)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/daily-summaries/{summaryID}", handlers.AnalyticsHandler.GetDailySummary)

			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/snapshots", handlers.AnalyticsHandler.ListSnapshots)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/snapshots/{snapshotID}", handlers.AnalyticsHandler.GetSnapshot)

			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/journal-metrics", handlers.AnalyticsHandler.ListJournalMetrics)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/journal-metrics/{metricID}", handlers.AnalyticsHandler.GetJournalMetric)

			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/cashflow", handlers.AnalyticsHandler.ListCashflows)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/cashflow/{cashflowID}", handlers.AnalyticsHandler.GetCashflow)

			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.tax.read")).
				Get("/tax-summaries", handlers.AnalyticsHandler.ListTaxSummaries)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.tax.read")).
				Get("/tax-summaries/{summaryID}", handlers.AnalyticsHandler.GetTaxSummary)

			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read")).
				Get("/reconciliation/daily-stats", handlers.AnalyticsHandler.ListReconciliationDailyStats)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read")).
				Get("/reconciliation/daily-stats/{reconciliationType}/{date}", handlers.AnalyticsHandler.GetReconciliationDailyStats)

			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read")).
				Get("/reconciliation/diff-trends", handlers.AnalyticsHandler.ListReconciliationDiffTrends)
		})

		// ========== PERIOD LOCKS ==========
		r.Route("/periods", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/locks", handlers.PeriodLockHandler.ListPeriodLocks)

			r.Route("/{fiscalYear}/{period}/lock", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/", handlers.PeriodLockHandler.GetPeriodLock)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
					Post("/", handlers.PeriodLockHandler.LockPeriod)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
					Delete("/", handlers.PeriodLockHandler.UnlockPeriod)
			})
		})
	})
}
