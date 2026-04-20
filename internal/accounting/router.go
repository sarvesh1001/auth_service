// ==================== accounting_routes.go ====================
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
	LedgerHandler             *handler.LedgerHandler
	ReconciliationHandler     *handler.ReconciliationHandler
	ReportHandler             *handler.ReportHandler
	ComplianceHandler         *handler.ComplianceHandler
	JournalHandler            *handler.JournalHandler
	TaxHandler                *handler.TaxHandler
	AccountingSettingsHandler *handler.AccountingSettingsHandler
}

// RegisterAccountingRoutes registers all accounting routes under /companies/{companyID}/accounting.
func RegisterAccountingRoutes(
	r chi.Router,
	handlers *AccountingHandlers,
	logger *zap.Logger,
	jwtService *service.JWTService, // kept for consistency, though not directly used here
) {
	r.Route("/accounting", func(r chi.Router) {

		// ========== Accounting Settings ==========
		r.Route("/settings", func(r chi.Router) {
			// GET /companies/{companyID}/accounting/settings
			// Uses administration.company.view (bit_index 210)
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view", logger)).
				Get("/", handlers.AccountingSettingsHandler.GetSettings)

			// PUT /companies/{companyID}/accounting/settings/fiscal-year
			// Uses administration.company.update (bit_index 211)
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/fiscal-year", handlers.AccountingSettingsHandler.UpdateFiscalYear)

			// PUT /companies/{companyID}/accounting/settings/currency
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/currency", handlers.AccountingSettingsHandler.UpdateCurrency)

			// PUT /companies/{companyID}/accounting/settings/tax-scheme
			r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update", logger)).
				Put("/tax-scheme", handlers.AccountingSettingsHandler.UpdateTaxScheme)
		})

		// ---------- Ledger ----------
		r.Route("/ledger", func(r chi.Router) {
			// GET /companies/{companyID}/accounting/ledger/balance
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/balance", handlers.LedgerHandler.GetAccountBalance)

			// POST /companies/{companyID}/accounting/ledger/recompute
			// Using "accounting.reconcile" as the closest permission for recompute
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.reconcile", logger)).
				Post("/recompute", handlers.LedgerHandler.RecomputeBalances)
		})

		// ---------- Reconciliation ----------
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

		// ---------- Reports ----------
		r.Route("/reports", func(r chi.Router) {
			// Trial Balance
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view", logger)).
				Post("/trial-balance", handlers.ReportHandler.GetTrialBalance)

			// General Ledger
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.ledger.view", logger)).
				Get("/general-ledger", handlers.ReportHandler.GetGeneralLedger)

			// Balance Sheet
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.balance_sheet.view", logger)).
				Get("/balance-sheet", handlers.ReportHandler.GetBalanceSheet)

			// Income Statement
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.pl.view", logger)).
				Post("/income-statement", handlers.ReportHandler.GetIncomeStatement)

			// Cash Flow Statement
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.cashflow.view", logger)).
				Get("/cash-flow", handlers.ReportHandler.GetCashFlowStatement)

			// Tax Summary
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Get("/tax-summary", handlers.ReportHandler.GetTaxSummary)

			// Compliance Returns (list)
			r.With(authMiddleware.BitmaskPermissionMiddleware("finance.tax.view", logger)).
				Get("/compliance-returns", handlers.ReportHandler.ListComplianceReturns)
		})

		// ---------- Compliance ----------
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

		// ---------- Journals ----------
		r.Route("/journals", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.create", logger)).
				Post("/", handlers.JournalHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.view", logger)).
				Get("/", handlers.JournalHandler.List)
			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("accounting.journal.view", logger)).
					Get("/", handlers.JournalHandler.GetByID)
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

		// ---------- Tax Engine ----------
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
	})
}
