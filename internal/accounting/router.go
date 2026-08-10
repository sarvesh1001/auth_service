package accounting

import (
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
	PeriodLockHandler         *handler.PeriodLockHandler // 👈 NEW
}

// RegisterAccountingRoutes registers all accounting routes under /companies/{companyID}/accounting.
func RegisterAccountingRoutes(
	r chi.Router,
	handlers *AccountingHandlers,
	jwtService *service.JWTService,
) {
	r.Route("/accounting", func(r chi.Router) {

		// ========== Chart of Accounts ==========
		r.Route("/accounts", func(r chi.Router) {

			// Create a single account
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create")).
				Post("/", handlers.AccountHandler.CreateAccount)

			// Bulk create accounts
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create")).
				Post("/bulk", handlers.AccountHandler.BulkCreateAccounts)

			// Get account tree
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/tree", handlers.AccountHandler.GetAccountTree)

			// Get account by code
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/by-code", handlers.AccountHandler.GetAccountByCode)

			// List accounts
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/", handlers.AccountHandler.ListAccounts)

			r.Route("/{accountID}", func(r chi.Router) {

				// Get account details
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/", handlers.AccountHandler.GetAccount)

				// Full update
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Put("/", handlers.AccountHandler.UpdateAccount)

				// Update status
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Patch("/status", handlers.AccountHandler.UpdateAccountStatus)

				// Move account
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update")).
					Patch("/move", handlers.AccountHandler.MoveAccount)

				// Delete
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.delete")).
					Delete("/", handlers.AccountHandler.DeleteAccount)

				// Children
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/children", handlers.AccountHandler.GetChildren)

				// Has children
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/has-children", handlers.AccountHandler.HasChildren)

				// Usage
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/usage", handlers.AccountHandler.CheckUsage)

				// Circular check
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/circular", handlers.AccountHandler.CheckCircularReference)
			})
		})

		// ========== Accounting Settings ==========
		r.Route("/settings", func(r chi.Router) {
			// GET /companies/{companyID}/accounting/settings
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
				Get("/", handlers.AccountingSettingsHandler.GetSettings)

			// POST /companies/{companyID}/accounting/settings
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Post("/", handlers.AccountingSettingsHandler.CreateSettings)

			// PUT /companies/{companyID}/accounting/settings
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/", handlers.AccountingSettingsHandler.UpdateSettings)

			// PUT /companies/{companyID}/accounting/settings/upsert
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/upsert", handlers.AccountingSettingsHandler.UpsertSettings)

			// PUT /companies/{companyID}/accounting/settings/fiscal-year
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/fiscal-year", handlers.AccountingSettingsHandler.UpdateFiscalYear)

			// PUT /companies/{companyID}/accounting/settings/currency
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/currency", handlers.AccountingSettingsHandler.UpdateCurrency)

			// PUT /companies/{companyID}/accounting/settings/tax-scheme
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/tax-scheme", handlers.AccountingSettingsHandler.UpdateTaxScheme)

			// ===== NEW ROUTES =====
			// GET /companies/{companyID}/accounting/settings/exists
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
				Get("/exists", handlers.AccountingSettingsHandler.ExistsSettings)

			// GET /companies/{companyID}/accounting/settings/fiscal-period
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
				Get("/fiscal-period", handlers.AccountingSettingsHandler.GetFiscalPeriod)

			// PUT /companies/{companyID}/accounting/settings/flags
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
				Put("/flags", handlers.AccountingSettingsHandler.UpdateFlags)
		})

		// ========== Ledger ==========
		r.Route("/ledger", func(r chi.Router) {
			// GET /companies/{companyID}/accounting/ledger/balance
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/balance", handlers.LedgerHandler.GetAccountBalance)

			// POST /companies/{companyID}/accounting/ledger/recompute
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
				Post("/recompute", handlers.LedgerHandler.RecomputeBalances)

			// NEW: Trial Balance
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/trial-balance", handlers.LedgerHandler.TrialBalance)

			// NEW: Profit & Loss
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view")).
				Get("/profit-and-loss", handlers.LedgerHandler.ProfitAndLoss)

			// NEW: Balance Sheet
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view")).
				Get("/balance-sheet", handlers.LedgerHandler.BalanceSheet)
		})

		// ========== Reconciliation ==========
		r.Route("/reconciliation", func(r chi.Router) {
			// Batches
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

			// Items
			r.Route("/batches/{batchID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Post("/", handlers.ReconciliationHandler.AddItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/", handlers.ReconciliationHandler.GetItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile")).
					Get("/unmatched", handlers.ReconciliationHandler.GetUnmatchedItems)
			})

			// Matching
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

			// Differences
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

			// Adjustments
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
			// Trial Balance (now GET with query params)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view")).
				Get("/trial-balance", handlers.ReportHandler.GetTrialBalance)

			// General Ledger
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/general-ledger", handlers.ReportHandler.GetGeneralLedger)

			// Balance Sheet
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view")).
				Get("/balance-sheet", handlers.ReportHandler.GetBalanceSheet)

			// Income Statement (now GET with query params)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view")).
				Get("/income-statement", handlers.ReportHandler.GetIncomeStatement)

			// Cash Flow Statement
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.cashflow.view")).
				Get("/cash-flow", handlers.ReportHandler.GetCashFlowStatement)

			// Tax Summary
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/tax-summary", handlers.ReportHandler.GetTaxSummary)

			// Compliance Returns (list)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/compliance-returns", handlers.ReportHandler.ListComplianceReturns)

			// NEW: Account Balance (report-style)
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
				// UPDATED: Use ReportHandler.GetJournal to return journal with lines
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
			// Tax Rates
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

			// Tax Rules
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

			// Tax Profiles
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

			// Tax Transactions
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

			// Tax Computation
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Post("/compute", handlers.TaxHandler.ComputeTax)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Post("/evaluate-rules", handlers.TaxHandler.EvaluateRules)

			// Tax Returns / Summaries
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/return", handlers.TaxHandler.GenerateTaxReturn)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view")).
				Get("/summary", handlers.TaxHandler.GetTaxSummary)
		})

		// ========== Analytics ==========
		r.Route("/analytics", func(r chi.Router) {
			// Daily Account Summaries
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/daily-summaries", handlers.AnalyticsHandler.ListDailySummaries)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/daily-summaries/{summaryID}", handlers.AnalyticsHandler.GetDailySummary)

			// Account Snapshots (balances)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/snapshots", handlers.AnalyticsHandler.ListSnapshots)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/snapshots/{snapshotID}", handlers.AnalyticsHandler.GetSnapshot)

			// Journal Metrics
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/journal-metrics", handlers.AnalyticsHandler.ListJournalMetrics)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/journal-metrics/{metricID}", handlers.AnalyticsHandler.GetJournalMetric)

			// Cashflow
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/cashflow", handlers.AnalyticsHandler.ListCashflows)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read")).
				Get("/cashflow/{cashflowID}", handlers.AnalyticsHandler.GetCashflow)

			// Tax Summaries (uses separate permission)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.tax.read")).
				Get("/tax-summaries", handlers.AnalyticsHandler.ListTaxSummaries)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.tax.read")).
				Get("/tax-summaries/{summaryID}", handlers.AnalyticsHandler.GetTaxSummary)

			// Reconciliation Daily Stats
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read")).
				Get("/reconciliation/daily-stats", handlers.AnalyticsHandler.ListReconciliationDailyStats)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read")).
				Get("/reconciliation/daily-stats/{reconciliationType}/{date}", handlers.AnalyticsHandler.GetReconciliationDailyStats)

			// Reconciliation Difference Trends
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read")).
				Get("/reconciliation/diff-trends", handlers.AnalyticsHandler.ListReconciliationDiffTrends)
		})

		// ========== PERIOD LOCKS (NEW) ==========
		r.Route("/periods", func(r chi.Router) {
			// List all period locks for the company
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
				Get("/locks", handlers.PeriodLockHandler.ListPeriodLocks)

			// Operations on a specific period
			r.Route("/{fiscalYear}/{period}/lock", func(r chi.Router) {
				// Get lock status
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view")).
					Get("/", handlers.PeriodLockHandler.GetPeriodLock)

				// Lock a period (admin action – use company update permission)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
					Post("/", handlers.PeriodLockHandler.LockPeriod)

				// Unlock a period (admin action)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
					Delete("/", handlers.PeriodLockHandler.UnlockPeriod)
			})
		})
	})
}
