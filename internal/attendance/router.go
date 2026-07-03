package attendance

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"auth-service/internal/attendance/handler"
)

// RegisterAttendanceRoutes mounts all attendance endpoints.
// All permission names used below are taken from the provided permission list.
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
	// Middleware functions (provided by main router)
	jwtAuthMiddleware func(http.Handler) http.Handler,
	sessionValidationMiddleware func(http.Handler) http.Handler,
	bitmaskPermissionMiddleware func(permission string, logger *zap.Logger) func(http.Handler) http.Handler,
	deviceAuthMiddleware func(http.Handler) http.Handler,
	companyAccessMiddleware func(http.Handler) http.Handler,
	logger *zap.Logger,
) {
	// ============================================================
	// 1. USER‑AUTHENTICATED ROUTES (JWT + session + permissions)
	// ============================================================
	r.Route("/companies/{companyID}/attendance", func(r chi.Router) {
		r.Use(jwtAuthMiddleware)
		r.Use(sessionValidationMiddleware)

		// ----- Self punches -----
		r.With(
			bitmaskPermissionMiddleware("attendance.self.punch", logger),
			companyAccessMiddleware,
		).Post("/self/punch", ingestHandler.SelfPunchAttendance)

		// ----- Team/Admin punches -----
		r.With(
			bitmaskPermissionMiddleware("attendance.team.punch", logger),
			companyAccessMiddleware,
		).Post("/punch", ingestHandler.PunchAttendance)

		// ----- Events -----
		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/events/search", queryHandler.SearchEvents)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/events/{eventID}", queryHandler.GetEvent)

		// ----- Daily summaries & stats -----
		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/summary/{subjectType}/{subjectID}/{date}", queryHandler.GetDailySummary)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/summaries/{subjectType}/{subjectID}", queryHandler.GetSubjectSummaries)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/stats/company", queryHandler.GetCompanyStats)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/stats/subject/{subjectType}/{subjectID}", queryHandler.GetSubjectStats)

		// ----- Session summaries -----
		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/session-summaries", queryHandler.ListSessionSummaries)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/session-summary/{sessionID}", queryHandler.GetSessionSummary)

		// ----- Exemptions -----
		r.With(
			bitmaskPermissionMiddleware("attendance.manage_exemptions", logger),
			companyAccessMiddleware,
		).Post("/exemptions", exemptionHandler.CreateExemption)

		r.With(
			bitmaskPermissionMiddleware("attendance.manage_exemptions", logger),
			companyAccessMiddleware,
		).Put("/exemptions/{exemptionID}", exemptionHandler.UpdateExemption)

		r.With(
			bitmaskPermissionMiddleware("attendance.manage_exemptions", logger),
			companyAccessMiddleware,
		).Delete("/exemptions/{exemptionID}", exemptionHandler.DeleteExemption)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/exemptions", queryHandler.ListExemptions)

		// ----- Corrections -----
		r.With(
			bitmaskPermissionMiddleware("attendance.correct", logger),
			companyAccessMiddleware,
		).Post("/corrections", correctionHandler.CreateCorrection)

		// ----- Resolution / Recalculation (now using attendance.configure) -----
		r.With(
			bitmaskPermissionMiddleware("attendance.configure", logger),
			companyAccessMiddleware,
		).Post("/resolve/event", resolutionHandler.ResolveEvent)

		r.With(
			bitmaskPermissionMiddleware("attendance.configure", logger),
			companyAccessMiddleware,
		).Post("/resolve/day", resolutionHandler.ResolveDay)

		r.With(
			bitmaskPermissionMiddleware("attendance.configure", logger),
			companyAccessMiddleware,
		).Post("/resolve/batch", resolutionHandler.BatchResolve)

		r.With(
			bitmaskPermissionMiddleware("attendance.configure", logger),
			companyAccessMiddleware,
		).Post("/resolve/period", resolutionHandler.BatchResolveByPeriod)

		r.With(
			bitmaskPermissionMiddleware("attendance.configure", logger),
			companyAccessMiddleware,
		).Post("/resolve/day/{userID}/{date}", resolutionHandler.ResolveDayByPath)

		// ----- Reports -----
		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/reports", reportHandler.GenerateReport)

		r.With(
			bitmaskPermissionMiddleware("hr.attendance.view", logger),
			companyAccessMiddleware,
		).Get("/reports/stream", reportHandler.StreamEvents)

		// ----- Admin (policies, rules, sources) -----
		r.Route("/admin", func(r chi.Router) {
			r.Use(bitmaskPermissionMiddleware("attendance.configure", logger))
			r.Use(companyAccessMiddleware)

			r.Post("/policies", adminHandler.CreatePolicy)
			r.Get("/policies", adminHandler.ListPolicies)
			r.Get("/policies/{policyID}", adminHandler.GetPolicy)
			r.Put("/policies/{policyID}", adminHandler.UpdatePolicy)
			r.Delete("/policies/{policyID}", adminHandler.DeletePolicy)
			r.Post("/assign-policy", adminHandler.AssignPolicyToUser)

			r.Get("/rules/company", adminHandler.GetCompanyRules)
			r.Put("/rules/company", adminHandler.UpdateCompanyRules)
			r.Get("/rules/resolve", adminHandler.GetResolvedRules)

			r.Get("/sources", sourceAdminHandler.ListSources)
			r.Post("/sources", sourceAdminHandler.CreateSource)
			r.Put("/sources/{sourceType}", sourceAdminHandler.UpdateSourceStatus)
		})

		// ----- Device management -----
		r.Route("/devices", func(r chi.Router) {
			r.Use(bitmaskPermissionMiddleware("attendance.configure", logger))
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
			r.Use(bitmaskPermissionMiddleware("operations.task.view", logger))
			r.Use(companyAccessMiddleware)

			r.Get("/", workCenterHandler.ListWorkCenters)
			r.Get("/search", workCenterHandler.SearchWorkCenters)
			r.Get("/active", workCenterHandler.GetActiveWorkCenters)
			r.Post("/", workCenterHandler.CreateWorkCenter)
			r.Get("/health", workCenterHandler.HealthCheck)

			r.Route("/{workCenterCode}", func(r chi.Router) {
				r.Get("/", workCenterHandler.GetWorkCenter)
				r.Put("/", workCenterHandler.UpdateWorkCenter)
				r.Delete("/", workCenterHandler.DeleteWorkCenter)
			})
		})

		// ----- Scheduling -----
		r.Route("/scheduling", func(r chi.Router) {
			r.Use(bitmaskPermissionMiddleware("operations.shift.view", logger))
			r.Use(companyAccessMiddleware)

			r.Get("/health", schedulingHandler.HealthCheck)

			// Calendars
			r.Get("/calendars", schedulingHandler.ListWorkCalendars)
			r.Post("/calendars", schedulingHandler.CreateWorkCalendar)
			r.Get("/calendars/{calendarID}", schedulingHandler.GetWorkCalendar)
			r.Put("/calendars/{calendarID}", schedulingHandler.UpdateWorkCalendar)
			r.Delete("/calendars/{calendarID}", schedulingHandler.DeleteWorkCalendar)
			r.Get("/calendars/{calendarID}/availability", schedulingHandler.GetCalendarAvailability)

			// Holidays
			r.Post("/holidays", schedulingHandler.AddHolidayToCalendar)
			r.Post("/holidays/process", schedulingHandler.ProcessHolidayForDate)

			// Templates
			r.Get("/templates", schedulingHandler.ListScheduleTemplates)
			r.Post("/templates", schedulingHandler.CreateScheduleTemplate)
			r.Get("/templates/{templateID}", schedulingHandler.GetScheduleTemplate)
			r.Put("/templates/{templateID}", schedulingHandler.UpdateScheduleTemplate)
			r.Delete("/templates/{templateID}", schedulingHandler.DeleteScheduleTemplate)

			// Instances
			r.Get("/instances", schedulingHandler.ListScheduleInstances)
			r.Post("/instances", schedulingHandler.CreateScheduleInstance)
			// Bulk creation not yet implemented in SchedulingHandler – keep commented
			// r.Post("/instances/bulk", schedulingHandler.BulkCreateScheduleInstances)
			// Search uses ListScheduleInstances with query params
			// r.Post("/instances/search", schedulingHandler.SearchScheduleInstances)
			r.Get("/instances/{instanceID}", schedulingHandler.GetScheduleInstance)
			r.Put("/instances/{instanceID}", schedulingHandler.UpdateScheduleInstance)
			r.Delete("/instances/{instanceID}", schedulingHandler.DeleteScheduleInstance)

			// Position‑based resolution
			r.Get("/position-based/users/{userID}/position", schedulingHandler.GetUserScheduledPosition)
			r.Get("/position-based/users/{userID}/current", schedulingHandler.GetUserCurrentAssignment)
			// ResolveUserDay is not a separate handler; use GetUserScheduledPosition
			// r.Get("/position-based/users/{userID}/resolve", schedulingHandler.ResolveUserDay)
			r.Post("/position-based/instances", schedulingHandler.CreateScheduleInstanceFromPosition)

			// Generate schedules
			r.Post("/generate/user/{userID}", schedulingHandler.GenerateScheduleForUser)
			r.Post("/generate/company", schedulingHandler.GenerateScheduleForCompany)

			// Overrides
			r.Post("/overrides", schedulingHandler.CreateScheduleOverride)
			r.Get("/overrides", schedulingHandler.GetScheduleOverrides)
			r.Get("/overrides/{overrideID}", schedulingHandler.GetScheduleOverrideByID)
			r.Put("/overrides/{overrideID}", schedulingHandler.UpdateScheduleOverride)
			r.Delete("/overrides/{overrideID}", schedulingHandler.DeleteScheduleOverride)

			// Work center shifts
			r.Get("/work-centers/{workCenterCode}/shifts", schedulingHandler.GetWorkCenterShifts)
			r.Post("/work-center-shifts", schedulingHandler.CreateWorkCenterShiftMapping)
			r.Put("/work-center-shifts", schedulingHandler.UpdateWorkCenterShiftMapping)

			// Availability & conflict
			r.Get("/availability/check", schedulingHandler.CheckScheduleAvailability)
			r.Get("/availability/conflict-check", schedulingHandler.ValidateScheduleConflict)

			// Reports / stats
			r.Get("/reports/stats", schedulingHandler.GetScheduleStats)

			// Query – use ListScheduleInstances for search
			r.Get("/query/instances", schedulingHandler.ListScheduleInstances)
			r.Get("/query/user/{userID}/assignment", schedulingHandler.GetUserCurrentAssignment)
		})
	})

	// ============================================================
	// 2. DEVICE‑AUTHENTICATED ROUTES (device token + middleware)
	// ============================================================
	r.Route("/companies/{companyID}/attendance-device", func(r chi.Router) {
		r.Use(deviceAuthMiddleware)
		r.Use(companyAccessMiddleware)

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
	// 3. ACADEMIC‑SPECIFIC DEVICE ROUTES (student biometrics)
	// ============================================================
	r.Route("/companies/{companyID}/academics/biometric-device", func(r chi.Router) {
		r.Use(deviceAuthMiddleware)
		r.Use(companyAccessMiddleware)

		r.Post("/sync", biometricSyncHandler.SyncEmbeddings)
		r.Post("/full/{deviceID}", biometricSyncHandler.FullSync)
		r.Post("/reset/{deviceID}", biometricSyncHandler.ForceDeviceResync)
	})
}
