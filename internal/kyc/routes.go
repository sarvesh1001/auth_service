package kyc

import (
	"github.com/go-chi/chi/v5"

	"auth-service/internal/kyc/handler"
	authMiddleware "auth-service/internal/middleware"
)

// RegisterKYCRoutes registers all KYC document management routes.
func RegisterKYCRoutes(r chi.Router, h *handler.KYCDocumentHandler) {
	r.Route("/kyc", func(r chi.Router) {
		// All KYC operations require admin session and appropriate permissions

		// Document upload – admin can upload for any user
		r.Route("/documents", func(r chi.Router) {
			// NEW: Generate upload URL and file key
			r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
				Post("/upload-url", h.GetUploadURL)

			// NEW: Upload file to storage
			r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
				Post("/upload", h.UploadFile)

			// Existing: create metadata (idempotent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
				Post("/", h.UploadDocument)

			// List documents – admin can list all or filter by user
			r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
				Get("/", h.ListDocuments)

			// Get pending documents for verification
			r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
				Get("/pending", h.GetPendingDocuments)

			// Single document operations
			r.Route("/{id}", func(r chi.Router) {
				// View document details
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
					Get("/", h.GetDocumentByID)

				// NEW: Download the actual file
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view")).
					Get("/file", h.GetFile)

				// Verify or reject a document
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.update")).
					Patch("/verify", h.VerifyDocument)

				// Delete a document (permanent)
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.delete")).
					Delete("/", h.DeleteDocument)
			})
		})
	})
}
