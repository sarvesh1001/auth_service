package avatar

import (
	"github.com/go-chi/chi/v5"

	"auth-service/internal/avatar/handler"
	authMiddleware "auth-service/internal/middleware"
)

func RegisterAvatarRoutes(r chi.Router, h *handler.AvatarHandler) {
	r.Route("/avatars", func(r chi.Router) {
		// Upload file – requires administration update permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
			Post("/upload", h.UploadFile)

		// Upload flow – requires administration update permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
			Post("/upload-url", h.GetUploadURL)
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
			Post("/confirm", h.ConfirmUpload)

		// Retrieve active avatars – requires administration view permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
			Get("/primary", h.GetPrimaryAvatar)
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
			Get("/", h.ListAvatars)

		// Retrieve soft‑deleted (inactive) avatars – requires administration view permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
			Get("/inactive", h.ListInactiveAvatars)

		// Get a signed URL for a file key – requires administration view permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
			Get("/signed-url", h.GetSignedURL)

		// Get any user's primary avatar – administration view permission (used in admin employee views)
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
			Get("/users/{userId}/primary", h.GetUserPrimaryAvatar)

		// Get single avatar by ID – requires administration view permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.view")).
			Get("/{id}", h.GetAvatar)

		// Update / delete – requires administration update permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
			Put("/{id}/primary", h.SetPrimary)
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
			Delete("/{id}", h.DeleteAvatar)

		// Reactivate a soft‑deleted avatar – requires administration update permission
		r.With(authMiddleware.BitmaskPermissionMiddleware("administration.company.update")).
			Put("/{id}/reactivate", h.ReactivateAvatar)
	})
}
