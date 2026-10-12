package attendance

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"auth-service/internal/attendance/handler"
)

// RegisterAttendanceRoutes mounts all attendance endpoints.
func RegisterAttendanceRoutes(
	r chi.Router,
	// Handlers
	ingestHandler *handler.AttendanceIngestHandler,
	queryHandler *handler.AttendanceQueryHandler,
	exemptionHandler *handler.AttendanceExemptionHandler,
	resolutionHandler *handler.AttendanceResolutionHandler,
	deviceHandler *handler.DeviceHandler,
	enrollmentHandler *handler.AttendanceDeviceEnrollmentHandler,
	tokenAdminHandler *handler.DeviceTokenAdminHandler,
	sourceAdminHandler *handler.AttendanceSourceAdminHandler,
	correctionHandler *handler.AttendanceCorrectionHandler,
	reportHandler *handler.AttendanceReportHandler,
	batchHandler *handler.BatchHandler,
	heartbeatHandler *handler.DeviceHeartbeatHandler,
	biometricEnrollmentHandler *handler.BiometricEnrollmentHandler,
	biometricSyncHandler *handler.BiometricSyncHandler,
	workCenterHandler *handler.WorkCenterHandler,
	schedulingHandler *handler.SchedulingHandler,
	adminHandler *handler.AttendanceAdminHandler,
	// Auth middleware (provided by main router)
	jwtAuthMiddleware func(http.Handler) http.Handler,
	sessionValidationMiddleware func(http.Handler) http.Handler,
	bitmaskPermissionMiddleware func(permission string) func(http.Handler) http.Handler,
	deviceAuthMiddleware func(http.Handler) http.Handler,
	companyAccessMiddleware func(http.Handler) http.Handler,
	subscriptionEnforcementMiddleware func(http.Handler) http.Handler,
	locationValidationMiddleware func(http.Handler) http.Handler,
	idempotencyMiddleware func(http.Handler) http.Handler,
) {
	// ============================================================
	// 1. USER‑AUTHENTICATED ROUTES
	//    Chain: jwt → session → subscription → location → idempotency
	//           → [per-route: bitmask + companyAccess] → handler
	// ============================================================
	r.Route("/companies/{companyID}/attendance", func(r chi.Router) {
		r.Use(jwtAuthMiddleware)
		r.Use(sessionValidationMiddleware)
		r.Use(subscriptionEnforcementMiddleware)
		r.Use(locationValidationMiddleware)
		r.Use(idempotencyMiddleware)

		// ----- Self punches -----
		r.With(
			bitmaskPermissionMiddleware("attendance.self.punch"),
			companyAccessMiddleware,
		).Post("/self/punch", ingestHandler.SelfPunchAttendance)

		// ----- Team/Admin punches -----
		r.With(
			bitmaskPermissionMiddleware("attendance.team.punch"),
			companyAccessMiddleware,
		).Post("/punch", ingestHandler.PunchAttendance)

		// ----- Events -----
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/events/search", queryHandler.SearchEvents)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/events/{eventID}", queryHandler.GetEvent)

		// ----- Daily summaries & stats -----
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/summary/{subjectType}/{subjectID}/{date}", queryHandler.GetDailySummary)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/summaries/{subjectType}/{subjectID}", queryHandler.GetSubjectSummaries)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/stats/company", queryHandler.GetCompanyStats)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/stats/subject/{subjectType}/{subjectID}", queryHandler.GetSubjectStats)

		// ----- Session summaries -----
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/session-summaries", queryHandler.ListSessionSummaries)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/session-summary/{sessionID}", queryHandler.GetSessionSummary)

		// ----- Exemptions -----
		r.With(bitmaskPermissionMiddleware("attendance.manage_exemptions"), companyAccessMiddleware).
			Post("/exemptions", exemptionHandler.CreateExemption)
		r.With(bitmaskPermissionMiddleware("attendance.manage_exemptions"), companyAccessMiddleware).
			Put("/exemptions/{exemptionID}", exemptionHandler.UpdateExemption)
		r.With(bitmaskPermissionMiddleware("attendance.manage_exemptions"), companyAccessMiddleware).
			Delete("/exemptions/{exemptionID}", exemptionHandler.DeleteExemption)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/exemptions", queryHandler.ListExemptions)

		// ----- Corrections -----
		r.With(bitmaskPermissionMiddleware("attendance.correct"), companyAccessMiddleware).
			Post("/corrections", correctionHandler.CreateCorrection)

		// ----- Resolution / Recalculation -----
		r.With(bitmaskPermissionMiddleware("attendance.configure"), companyAccessMiddleware).
			Post("/resolve/event", resolutionHandler.ResolveEvent)
		r.With(bitmaskPermissionMiddleware("attendance.configure"), companyAccessMiddleware).
			Post("/resolve/day", resolutionHandler.ResolveDay)
		r.With(bitmaskPermissionMiddleware("attendance.configure"), companyAccessMiddleware).
			Post("/resolve/batch", resolutionHandler.BatchResolve)
		r.With(bitmaskPermissionMiddleware("attendance.configure"), companyAccessMiddleware).
			Post("/resolve/period", resolutionHandler.BatchResolveByPeriod)
		r.With(bitmaskPermissionMiddleware("attendance.configure"), companyAccessMiddleware).
			Post("/resolve/day/{userID}/{date}", resolutionHandler.ResolveDayByPath)

		// ----- Reports -----
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/reports", reportHandler.GenerateReport)
		r.With(bitmaskPermissionMiddleware("hr.attendance.view"), companyAccessMiddleware).
			Get("/reports/stream", reportHandler.StreamEvents)

		// ----- Admin (policies, rules, sources, biometric) -----
		r.Route("/admin", func(r chi.Router) {
			r.Use(bitmaskPermissionMiddleware("attendance.configure"))
			r.Use(companyAccessMiddleware)

			// ---- Policies ----
			r.Post("/policies", adminHandler.CreatePolicy)
			r.Get("/policies", adminHandler.ListPolicies)
			r.Get("/policies/{policyID}", adminHandler.GetPolicy)
			r.Put("/policies/{policyID}", adminHandler.UpdatePolicy)
			r.Delete("/policies/{policyID}", adminHandler.DeletePolicy)
			r.Post("/assign-policy", adminHandler.AssignPolicyToUser)

			// ---- Company rules ----
			r.Get("/rules/company", adminHandler.GetCompanyRules)
			r.Put("/rules/company", adminHandler.UpdateCompanyRules)
			r.Get("/rules/resolve", adminHandler.GetResolvedRules)

			// ---- Sources ----
			r.Get("/sources", sourceAdminHandler.ListSources)
			r.Post("/sources", sourceAdminHandler.CreateSource)
			r.Put("/sources/{sourceType}", sourceAdminHandler.UpdateSourceStatus)

			// ---- Biometric admin ----
			r.Post("/biometric/enroll", biometricEnrollmentHandler.EnrollFace)
			r.Post("/biometric/re-enroll", biometricEnrollmentHandler.ReEnrollFace)
			r.Post("/biometric/deactivate", biometricEnrollmentHandler.DeactivateFace)
			r.Post("/biometric/activate", biometricEnrollmentHandler.ActivateFace)
			r.Post("/biometric/rotate", biometricEnrollmentHandler.RotateEmbeddingModel)
			r.Get("/biometric/embeddings", biometricEnrollmentHandler.ListActiveFaceEmbeddings)
			r.Get(
				"/biometric/embedding/{subjectType}/{subjectID}",
				biometricEnrollmentHandler.GetFaceEmbedding,
			)
			r.Post(
				"/biometric/force-resync/{deviceID}",
				biometricSyncHandler.ForceDeviceResync,
			)
		})

		// ----- Device management -----
		r.Route("/devices", func(r chi.Router) {
			r.Use(bitmaskPermissionMiddleware("attendance.configure"))
			r.Use(companyAccessMiddleware)

			r.Post("/", deviceHandler.CreateDevice)
			r.Get("/", deviceHandler.ListDevices)
			r.Get("/stats", deviceHandler.GetDeviceStatistics)
			r.Get("/health", deviceHandler.HealthCheck)

			r.Route("/{deviceID}", func(r chi.Router) {
				r.Get("/", deviceHandler.GetDevice)
				r.Put("/", deviceHandler.UpdateDevice)
				r.Delete("/", deviceHandler.DeleteDevice)
				r.Post("/activate", deviceHandler.ActivateDevice)
				r.Post("/deactivate", deviceHandler.DeactivateDevice)
				r.Post("/trust", deviceHandler.MarkAsTrusted)
				r.Post("/revoke-trust", deviceHandler.RevokeTrust)

				r.Post("/enrollments", enrollmentHandler.EnrollUser)
				r.Delete("/enrollments", enrollmentHandler.RevokeEnrollment)
				r.Post("/enrollments/unrevoke", enrollmentHandler.UnrevokeEnrollment)
				r.Get("/enrollments", enrollmentHandler.GetDeviceEnrollments)
				r.Get("/enrollments/revoked", enrollmentHandler.GetRevokedDeviceEnrollments)

				r.Post("/tokens", tokenAdminHandler.IssueDeviceToken)
				r.Get("/tokens/current", tokenAdminHandler.GetCurrentDeviceToken)
				r.Delete("/tokens/{tokenID}", tokenAdminHandler.RevokeDeviceToken)
				r.Post("/tokens/revoke-all", tokenAdminHandler.RevokeAllDeviceTokens)
			})
		})

		// ----- Work Centers -----
		r.Route("/work-centers", func(r chi.Router) {
			r.Use(bitmaskPermissionMiddleware("administration.company.view"))
			r.Use(companyAccessMiddleware)

			r.Get("/", workCenterHandler.ListWorkCenters)
			r.Get("/search", workCenterHandler.SearchWorkCenters)
			r.Get("/active", workCenterHandler.GetActiveWorkCenters)
			r.Get("/health", workCenterHandler.HealthCheck)

			r.With(bitmaskPermissionMiddleware("administration.company.update")).
				Post("/", workCenterHandler.CreateWorkCenter)

			r.Route("/{workCenterCode}", func(r chi.Router) {
				r.Get("/", workCenterHandler.GetWorkCenter)
				r.With(bitmaskPermissionMiddleware("administration.company.update")).
					Put("/", workCenterHandler.UpdateWorkCenter)
				r.With(bitmaskPermissionMiddleware("administration.company.update")).
					Delete("/", workCenterHandler.DeleteWorkCenter)
			})
		})

		// ============================================================
		// SCHEDULING
		//
		// Schedules are derived on read from the rule chain:
		//   user WC (date-scoped) → WC shift mapping → template rules
		//     → location calendar → per-day override
		//
		// There is no materialization, no schedule_instances table, and
		// no generation endpoint. The only per-day write is /overrides.
		//
		//   Reads  → hr.attendance.view       (any HR user)
		//   Writes → attendance.configure     (HR-admin)
		//
		// Mounted with r.Route (not r.Group) so the /scheduling prefix
		// is part of the path.
		// ============================================================
		r.Route("/scheduling", func(r chi.Router) {
			r.Use(companyAccessMiddleware)

			// ---------- READ: hr.attendance.view ----------
			r.With(bitmaskPermissionMiddleware("hr.attendance.view")).Group(func(r chi.Router) {
				r.Get("/health", schedulingHandler.HealthCheck)

				// Work calendars
				r.Get("/calendars", schedulingHandler.ListWorkCalendars)
				r.Get("/calendars/{calendarID}", schedulingHandler.GetWorkCalendar)
				r.Get("/calendars/{calendarID}/availability", schedulingHandler.GetCalendarAvailability)

				// Shift templates
				r.Get("/templates", schedulingHandler.ListScheduleTemplates)
				r.Get("/templates/{templateID}", schedulingHandler.GetScheduleTemplate)

				// Position-based lookups
				r.Get("/position-based/users/{userID}/position", schedulingHandler.GetUserScheduledPosition)
				r.Get("/position-based/users/{userID}/current", schedulingHandler.GetUserCurrentAssignment)
				r.Get("/query/user/{userID}/assignment", schedulingHandler.GetUserCurrentAssignment)

				// Overrides (read)
				r.Get("/overrides", schedulingHandler.GetScheduleOverrides)
				r.Get("/overrides/{overrideID}", schedulingHandler.GetScheduleOverrideByID)

				// Work center shifts (read)
				r.Get("/work-centers/{workCenterCode}/shifts", schedulingHandler.GetWorkCenterShifts)

				// Availability
				r.Get("/availability/check", schedulingHandler.CheckScheduleAvailability)

				// NEW: derived schedule preview. Replaces the old
				// /instances family. Writes nothing.
				r.Get("/schedule/{userID}", schedulingHandler.PreviewUserSchedule)
			})

			// ---------- WRITE: attendance.configure ----------
			r.With(bitmaskPermissionMiddleware("attendance.configure")).Group(func(r chi.Router) {
				// Work calendars
				r.Post("/calendars", schedulingHandler.CreateWorkCalendar)
				r.Put("/calendars/{calendarID}", schedulingHandler.UpdateWorkCalendar)
				r.Delete("/calendars/{calendarID}", schedulingHandler.DeleteWorkCalendar)

				// Holidays
				r.Post("/holidays", schedulingHandler.AddHolidayToCalendar)

				// Shift templates
				r.Post("/templates", schedulingHandler.CreateScheduleTemplate)
				r.Put("/templates/{templateID}", schedulingHandler.UpdateScheduleTemplate)
				r.Delete("/templates/{templateID}", schedulingHandler.DeleteScheduleTemplate)

				// Overrides (write)
				r.Post("/overrides", schedulingHandler.CreateScheduleOverride)
				r.Put("/overrides/{overrideID}", schedulingHandler.UpdateScheduleOverride)
				r.Delete("/overrides/{overrideID}", schedulingHandler.DeleteScheduleOverride)

				// Work center shift mapping (write)
				r.Post("/work-center-shifts", schedulingHandler.CreateWorkCenterShiftMapping)
				r.Put("/work-center-shifts", schedulingHandler.UpdateWorkCenterShiftMapping)
			})
		})
	})

	// ============================================================
	// 2. DEVICE‑AUTHENTICATED ROUTES
	// ============================================================
	r.Route("/companies/{companyID}/attendance-device", func(r chi.Router) {
		r.Use(deviceAuthMiddleware)
		r.Use(subscriptionEnforcementMiddleware)
		r.Use(companyAccessMiddleware)
		r.Use(idempotencyMiddleware)

		r.Post("/events/punch", ingestHandler.DevicePunchAttendance)

		r.Post("/batch/ingest", batchHandler.BatchPunch)
		r.Get("/batch/{batch_ref}/status", batchHandler.GetBatchStatus)
		r.Get("/batch/{batch_ref}/failures", batchHandler.GetBatchFailures)

		r.Post("/device/heartbeat", heartbeatHandler.Heartbeat)

		r.Post("/biometric/sync", biometricSyncHandler.SyncEmbeddings)
		r.Get("/biometric/full/{deviceID}", biometricSyncHandler.FullSync)
		r.Get("/biometric/incremental/{deviceID}", biometricSyncHandler.IncrementalSync)
		r.Post("/biometric/reset/{deviceID}", biometricSyncHandler.ForceDeviceResync)
		r.Get("/biometric/health", biometricSyncHandler.HealthCheck)

		r.Post("/biometric/enroll", biometricEnrollmentHandler.EnrollFace)
		r.Post("/biometric/re-enroll", biometricEnrollmentHandler.ReEnrollFace)
		r.Post("/biometric/deactivate", biometricEnrollmentHandler.DeactivateFace)
		r.Post("/biometric/activate", biometricEnrollmentHandler.ActivateFace)
		r.Get("/biometric/embedding/{subjectType}/{subjectID}", biometricEnrollmentHandler.GetFaceEmbedding)
		r.Get("/biometric/embeddings", biometricEnrollmentHandler.ListActiveFaceEmbeddings)
	})

	// ============================================================
	// 3. ACADEMIC‑SPECIFIC DEVICE ROUTES
	// ============================================================
	r.Route("/companies/{companyID}/academics/biometric-device", func(r chi.Router) {
		r.Use(deviceAuthMiddleware)
		r.Use(subscriptionEnforcementMiddleware)
		r.Use(companyAccessMiddleware)
		r.Use(idempotencyMiddleware)

		r.Post("/sync", biometricSyncHandler.SyncEmbeddings)
		r.Post("/full/{deviceID}", biometricSyncHandler.FullSync)
		r.Post("/reset/{deviceID}", biometricSyncHandler.ForceDeviceResync)
	})
}
