package accounting

import (
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

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
	logger *zap.Logger,
	jwtService *service.JWTService,
) {
	r.Route("/accounting", func(r chi.Router) {

		// ========== Chart of Accounts ==========
		r.Route("/accounts", func(r chi.Router) {

			// Create a single account
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create", logger)).
				Post("/", handlers.AccountHandler.CreateAccount)

			// Bulk create accounts
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create", logger)).
				Post("/bulk", handlers.AccountHandler.BulkCreateAccounts)

			// Get account tree
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/tree", handlers.AccountHandler.GetAccountTree)

			// Get account by code
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/by-code", handlers.AccountHandler.GetAccountByCode)

			// List accounts
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/", handlers.AccountHandler.ListAccounts)

			r.Route("/{accountID}", func(r chi.Router) {

				// Get account details
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
					Get("/", handlers.AccountHandler.GetAccount)

				// Full update
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update", logger)).
					Put("/", handlers.AccountHandler.UpdateAccount)

				// Update status
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update", logger)).
					Patch("/status", handlers.AccountHandler.UpdateAccountStatus)

				// Move account
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update", logger)).
					Patch("/move", handlers.AccountHandler.MoveAccount)

				// Delete
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.delete", logger)).
					Delete("/", handlers.AccountHandler.DeleteAccount)

				// Children
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
					Get("/children", handlers.AccountHandler.GetChildren)

				// Has children
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
					Get("/has-children", handlers.AccountHandler.HasChildren)

				// Usage
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
					Get("/usage", handlers.AccountHandler.CheckUsage)

				// Circular check
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
					Get("/circular", handlers.AccountHandler.CheckCircularReference)
			})
		})

		// ========== Accounting Settings ==========
		r.Route("/settings", func(r chi.Router) {
			// GET /companies/{companyID}/accounting/settings
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
				Get("/", handlers.AccountingSettingsHandler.GetSettings)

			// POST /companies/{companyID}/accounting/settings
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Post("/", handlers.AccountingSettingsHandler.CreateSettings)

			// PUT /companies/{companyID}/accounting/settings
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/", handlers.AccountingSettingsHandler.UpdateSettings)

			// PUT /companies/{companyID}/accounting/settings/upsert
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/upsert", handlers.AccountingSettingsHandler.UpsertSettings)

			// PUT /companies/{companyID}/accounting/settings/fiscal-year
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/fiscal-year", handlers.AccountingSettingsHandler.UpdateFiscalYear)

			// PUT /companies/{companyID}/accounting/settings/currency
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/currency", handlers.AccountingSettingsHandler.UpdateCurrency)

			// PUT /companies/{companyID}/accounting/settings/tax-scheme
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/tax-scheme", handlers.AccountingSettingsHandler.UpdateTaxScheme)

			// ===== NEW ROUTES =====
			// GET /companies/{companyID}/accounting/settings/exists
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
				Get("/exists", handlers.AccountingSettingsHandler.ExistsSettings)

			// GET /companies/{companyID}/accounting/settings/fiscal-period
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
				Get("/fiscal-period", handlers.AccountingSettingsHandler.GetFiscalPeriod)

			// PUT /companies/{companyID}/accounting/settings/flags
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/flags", handlers.AccountingSettingsHandler.UpdateFlags)
		})

		// ========== Ledger ==========
		r.Route("/ledger", func(r chi.Router) {
			// GET /companies/{companyID}/accounting/ledger/balance
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/balance", handlers.LedgerHandler.GetAccountBalance)

			// POST /companies/{companyID}/accounting/ledger/recompute
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
				Post("/recompute", handlers.LedgerHandler.RecomputeBalances)

			// NEW: Trial Balance
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/trial-balance", handlers.LedgerHandler.TrialBalance)

			// NEW: Profit & Loss
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view", logger)).
				Get("/profit-and-loss", handlers.LedgerHandler.ProfitAndLoss)

			// NEW: Balance Sheet
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view", logger)).
				Get("/balance-sheet", handlers.LedgerHandler.BalanceSheet)
		})

		// ========== Reconciliation ==========
		r.Route("/reconciliation", func(r chi.Router) {
			// Batches
			r.Route("/batches", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/", handlers.ReconciliationHandler.CreateBatch)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Get("/", handlers.ReconciliationHandler.ListBatches)
				r.Route("/{batchID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
						Get("/", handlers.ReconciliationHandler.GetBatch)
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
						Post("/stats", handlers.ReconciliationHandler.UpdateBatchStats)
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
						Post("/complete", handlers.ReconciliationHandler.CompleteBatch)
					r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
						Delete("/", handlers.ReconciliationHandler.DeleteBatch)
				})
			})

			// Items
			r.Route("/batches/{batchID}/items", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/", handlers.ReconciliationHandler.AddItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Get("/", handlers.ReconciliationHandler.GetItems)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Get("/unmatched", handlers.ReconciliationHandler.GetUnmatchedItems)
			})

			// Matching
			r.Route("/batches/{batchID}/match", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/auto", handlers.ReconciliationHandler.AutoMatch)
			})
			r.Route("/items/{itemID}/match", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/manual", handlers.ReconciliationHandler.ManualMatch)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Put("/status", handlers.ReconciliationHandler.SetItemMatchStatus)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Delete("/", handlers.ReconciliationHandler.UnmatchItem)
			})

			// Differences
			r.Route("/batches/{batchID}/differences", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/", handlers.ReconciliationHandler.CreateDifference)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Get("/", handlers.ReconciliationHandler.GetDifferences)
			})
			r.Route("/differences/{diffID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/resolve", handlers.ReconciliationHandler.ResolveDifference)
			})

			// Adjustments
			r.Route("/batches/{batchID}/adjustments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Post("/", handlers.ReconciliationHandler.CreateAdjustment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Get("/", handlers.ReconciliationHandler.GetAdjustments)
			})
			r.Route("/adjustments/{adjID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
					Delete("/", handlers.ReconciliationHandler.DeleteAdjustment)
			})
		})

		// ========== Reports ==========
		r.Route("/reports", func(r chi.Router) {
			// Trial Balance (now GET with query params)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view", logger)).
				Get("/trial-balance", handlers.ReportHandler.GetTrialBalance)

			// General Ledger
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/general-ledger", handlers.ReportHandler.GetGeneralLedger)

			// Balance Sheet
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view", logger)).
				Get("/balance-sheet", handlers.ReportHandler.GetBalanceSheet)

			// Income Statement (now GET with query params)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view", logger)).
				Get("/income-statement", handlers.ReportHandler.GetIncomeStatement)

			// Cash Flow Statement
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.cashflow.view", logger)).
				Get("/cash-flow", handlers.ReportHandler.GetCashFlowStatement)

			// Tax Summary
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Get("/tax-summary", handlers.ReportHandler.GetTaxSummary)

			// Compliance Returns (list)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Get("/compliance-returns", handlers.ReportHandler.ListComplianceReturns)

			// NEW: Account Balance (report-style)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/account-balance", handlers.ReportHandler.GetAccountBalance)
		})

		// ========== Compliance ==========
		r.Route("/compliance", func(r chi.Router) {
			r.Route("/returns", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create", logger)).
					Post("/", handlers.ComplianceHandler.CreateReturn)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
					Get("/", handlers.ComplianceHandler.ListReturns)
				r.Route("/{id}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
						Get("/", handlers.ComplianceHandler.GetReturnByID)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Put("/", handlers.ComplianceHandler.UpdateReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete", logger)).
						Delete("/", handlers.ComplianceHandler.DeleteReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Post("/submit", handlers.ComplianceHandler.SubmitReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Post("/file", handlers.ComplianceHandler.FileReturn)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Post("/amend", handlers.ComplianceHandler.AmendReturn)
				})
			})
			r.Route("/filings/{filingID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
					Get("/", handlers.ComplianceHandler.GetFilingByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
					Patch("/status", handlers.ComplianceHandler.UpdateFilingStatus)
			})
		})

		// ========== Journals ==========
		r.Route("/journals", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create", logger)).
				Post("/", handlers.JournalHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.view", logger)).
				Get("/", handlers.JournalHandler.List)
			r.Route("/{id}", func(r chi.Router) {
				// UPDATED: Use ReportHandler.GetJournal to return journal with lines
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.view", logger)).
					Get("/", handlers.ReportHandler.GetJournal)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update", logger)).
					Put("/", handlers.JournalHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.delete", logger)).
					Delete("/", handlers.JournalHandler.Delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update", logger)).
					Post("/post", handlers.JournalHandler.Post)
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.update", logger)).
					Post("/reverse", handlers.JournalHandler.Reverse)
			})
		})

		// ========== Tax Engine ==========
		r.Route("/tax", func(r chi.Router) {
			// Tax Rates
			r.Route("/rates", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create", logger)).
					Post("/", handlers.TaxHandler.CreateTaxRate)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
					Get("/", handlers.TaxHandler.ListTaxRates)
				r.Route("/{rateID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Put("/", handlers.TaxHandler.UpdateTaxRate)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete", logger)).
						Delete("/", handlers.TaxHandler.DeleteTaxRate)
				})
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
					Post("/close-open", handlers.TaxHandler.CloseOpenRates)
			})

			// Tax Rules
			r.Route("/rules", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create", logger)).
					Post("/", handlers.TaxHandler.CreateTaxRule)
				r.Route("/{ruleID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Put("/", handlers.TaxHandler.UpdateTaxRule)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete", logger)).
						Delete("/", handlers.TaxHandler.DeleteTaxRule)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
						Get("/", handlers.TaxHandler.GetRuleBundle)
				})
			})

			// Tax Profiles
			r.Route("/profiles", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create", logger)).
					Post("/", handlers.TaxHandler.CreateTaxProfile)
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
					Get("/", handlers.TaxHandler.ListTaxProfiles)
				r.Route("/{profileID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Put("/", handlers.TaxHandler.UpdateTaxProfile)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.delete", logger)).
						Delete("/", handlers.TaxHandler.DeleteTaxProfile)
				})
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
					Post("/{profileID}/set-default", handlers.TaxHandler.SetDefaultTaxProfile)
			})

			// Tax Transactions
			r.Route("/transactions", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.create", logger)).
					Post("/", handlers.TaxHandler.CreateTaxTransaction)
				r.Route("/{transactionType}/{transactionID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
						Get("/", handlers.TaxHandler.GetTransactionTaxBreakdown)
					r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.update", logger)).
						Post("/void", handlers.TaxHandler.VoidTaxTransaction)
				})
			})

			// Tax Computation
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Post("/compute", handlers.TaxHandler.ComputeTax)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Post("/evaluate-rules", handlers.TaxHandler.EvaluateRules)

			// Tax Returns / Summaries
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Get("/return", handlers.TaxHandler.GenerateTaxReturn)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Get("/summary", handlers.TaxHandler.GetTaxSummary)
		})

		// ========== Analytics ==========
		r.Route("/analytics", func(r chi.Router) {
			// Daily Account Summaries
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/daily-summaries", handlers.AnalyticsHandler.ListDailySummaries)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/daily-summaries/{summaryID}", handlers.AnalyticsHandler.GetDailySummary)

			// Account Snapshots (balances)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/snapshots", handlers.AnalyticsHandler.ListSnapshots)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/snapshots/{snapshotID}", handlers.AnalyticsHandler.GetSnapshot)

			// Journal Metrics
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/journal-metrics", handlers.AnalyticsHandler.ListJournalMetrics)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/journal-metrics/{metricID}", handlers.AnalyticsHandler.GetJournalMetric)

			// Cashflow
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/cashflow", handlers.AnalyticsHandler.ListCashflows)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.read", logger)).
				Get("/cashflow/{cashflowID}", handlers.AnalyticsHandler.GetCashflow)

			// Tax Summaries (uses separate permission)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.tax.read", logger)).
				Get("/tax-summaries", handlers.AnalyticsHandler.ListTaxSummaries)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.tax.read", logger)).
				Get("/tax-summaries/{summaryID}", handlers.AnalyticsHandler.GetTaxSummary)

			// Reconciliation Daily Stats
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read", logger)).
				Get("/reconciliation/daily-stats", handlers.AnalyticsHandler.ListReconciliationDailyStats)
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read", logger)).
				Get("/reconciliation/daily-stats/{reconciliationType}/{date}", handlers.AnalyticsHandler.GetReconciliationDailyStats)

			// Reconciliation Difference Trends
			r.With(authMiddleware.BitmaskPermissionMiddleware("analytics.reconciliation.read", logger)).
				Get("/reconciliation/diff-trends", handlers.AnalyticsHandler.ListReconciliationDiffTrends)
		})

		// ========== PERIOD LOCKS (NEW) ==========
		r.Route("/periods", func(r chi.Router) {
			// List all period locks for the company
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/locks", handlers.PeriodLockHandler.ListPeriodLocks)

			// Operations on a specific period
			r.Route("/{fiscalYear}/{period}/lock", func(r chi.Router) {
				// Get lock status
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
					Get("/", handlers.PeriodLockHandler.GetPeriodLock)

				// Lock a period (admin action – use company update permission)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
					Post("/", handlers.PeriodLockHandler.LockPeriod)

				// Unlock a period (admin action)
				r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
					Delete("/", handlers.PeriodLockHandler.UnlockPeriod)
			})
		})
	})
}
