package academics

import (
	"auth-service/internal/academics/handler"
	authMiddleware "auth-service/internal/middleware"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// RegisterAcademicRoutes registers all academic‑domain routes (excluding attendance,
// which is handled by the generic attendance module).
func RegisterAcademicRoutes(
	r chi.Router,
	academicYearHandler *handler.AcademicYearHandler,
	admissionHandler *handler.AdmissionHandler,
	analyticsHandler *handler.AnalyticsHandler,
	assignmentHandler *handler.AssignmentHandler,
	courseHandler *handler.CourseHandler,
	curriculumHandler *handler.CurriculumHandler,
	enrollmentHandler *handler.EnrollmentHandler,
	examHandler *handler.ExamHandler,
	feeHandler *handler.FeeHandler,
	gradingHandler *handler.GradingHandler,
	guardianHandler *handler.GuardianHandler,
	libraryHandler *handler.LibraryHandler,
	notificationHandler *handler.NotificationHandler,
	roomHandler *handler.RoomHandler,
	sectionHandler *handler.SectionHandler,
	studentHandler *handler.StudentHandler,
	subjectHandler *handler.SubjectHandler,
	submissionHandler *handler.SubmissionHandler,
	teacherHandler *handler.TeacherHandler,
	termHandler *handler.TermHandler,
	timetableHandler *handler.TimetableHandler,
	transportHandler *handler.TransportHandler,
	sessionGenerationHandler *handler.SessionGenerationHandler,
	logger *zap.Logger,
) {
	r.Route("/academics", func(r chi.Router) {
		// ========== Academic Years ==========
		r.Route("/academic-years", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Get("/", academicYearHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Get("/count", academicYearHandler.Count)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Get("/exists", academicYearHandler.Exists)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Get("/current", academicYearHandler.GetCurrent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.create", logger)).
				Post("/", academicYearHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.bulk_create", logger)).
				Post("/bulk", academicYearHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.upsert", logger)).
				Post("/upsert", academicYearHandler.Upsert)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Post("/validate-overlap", academicYearHandler.ValidateOverlap)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Get("/by-name", academicYearHandler.GetByName)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
				Get("/all", academicYearHandler.ListByCompany)

			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read", logger)).
					Get("/", academicYearHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.update", logger)).
					Put("/", academicYearHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.update", logger)).
					Patch("/dates", academicYearHandler.UpdateDates)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.set_current", logger)).
					Post("/set-current", academicYearHandler.SetCurrent)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.delete", logger)).
					Delete("/", academicYearHandler.Delete)
			})
		})

		// ========== Admissions ==========
		r.Route("/admissions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read", logger)).
				Get("/", admissionHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.create", logger)).
				Post("/", admissionHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.bulk_create", logger)).
				Post("/bulk", admissionHandler.BulkCreate)
			r.Route("/{admissionID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read", logger)).
					Get("/", admissionHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.update", logger)).
					Put("/", admissionHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.update_status", logger)).
					Patch("/status", admissionHandler.UpdateStatus)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.delete", logger)).
					Delete("/", admissionHandler.Delete)
			})
		})

		r.Route("/students/{studentID}/admissions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read", logger)).
				Get("/", admissionHandler.GetByStudentID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read", logger)).
				Get("/academic-years/{academicYearID}", admissionHandler.GetByStudentAndYear)
		})

		r.Route("/academic-years/{academicYearID}/admissions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read", logger)).
				Get("/", admissionHandler.GetByAcademicYearID)
		})

		// ========== Assignments ==========
		r.Route("/assignments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.read", logger)).
				Get("/", assignmentHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.create", logger)).
				Post("/", assignmentHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.bulk_create", logger)).
				Post("/bulk", assignmentHandler.BulkCreate)
			r.Route("/{assignmentID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.read", logger)).
					Get("/", assignmentHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.update", logger)).
					Put("/", assignmentHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.delete", logger)).
					Delete("/", assignmentHandler.Delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.publish", logger)).
					Patch("/publish", assignmentHandler.Publish)
			})
		})

		// ========== ANALYTICS ==========
		r.Route("/analytics", func(r chi.Router) {
			// Academic Year Metrics
			r.Route("/academic-years", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetAcademicYearMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListAcademicYearMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshAcademicYearMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/refresh-all", analyticsHandler.RefreshAllAcademicYearMetrics)
			})

			// Exam Metrics
			r.Route("/exams", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetExamMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListExamMetrics)
			})

			// Fee Metrics
			r.Route("/fees", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetFeeMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListFeeMetrics)
			})

			// Grading Metrics
			r.Route("/grading", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetGradingMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListGradingMetrics)
			})

			// Guardian Metrics
			r.Route("/guardians", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetGuardianMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListGuardianMetrics)
			})

			// Library Metrics
			r.Route("/library", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetLibraryMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListLibraryMetrics)
			})

			// Room Metrics
			r.Route("/rooms", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetRoomMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListRoomMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshRoomMetrics)
			})

			// Students Metrics
			r.Route("/students", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetStudentMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListStudentMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshStudentMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{studentID}/academic-years/{academicYearID}/session-summary", analyticsHandler.GetStudentSessionSummary)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/session-summaries", analyticsHandler.ListStudentSessionSummaries)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{studentID}/academic-years/{academicYearID}/session-summary/refresh", analyticsHandler.RefreshStudentSessionSummary)
			})

			// Sections Metrics
			r.Route("/sections", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetSectionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListSectionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshSectionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{sectionID}/session-metrics", analyticsHandler.GetSectionSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/session-metrics", analyticsHandler.ListSectionSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{sectionID}/session-metrics/refresh", analyticsHandler.RefreshSectionSessionMetrics)
			})

			// Subject Metrics
			r.Route("/subjects", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetSubjectMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListSubjectMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshSubjectMetrics)
			})

			// Submission Metrics
			r.Route("/submissions", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetSubmissionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListSubmissionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshSubmissionMetrics)
			})

			// Teachers Metrics
			r.Route("/teachers", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetTeacherMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListTeacherMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshTeacherMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{teacherID}/academic-years/{academicYearID}/session-metrics", analyticsHandler.GetTeacherSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/session-metrics", analyticsHandler.ListTeacherSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{teacherID}/academic-years/{academicYearID}/session-metrics/refresh", analyticsHandler.RefreshTeacherSessionMetrics)
			})

			// Timetable Metrics
			r.Route("/timetables", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetTimetableMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListTimetableMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshTimetableMetrics)
			})

			// Transport Metrics
			r.Route("/transport", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/{academicYearID}/metrics", analyticsHandler.GetTransportMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/metrics", analyticsHandler.ListTransportMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshTransportMetrics)
			})

			// Biometric Device Usage Metrics
			r.Route("/biometric-usage", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/", analyticsHandler.GetBiometricUsageMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read", logger)).
					Get("/list", analyticsHandler.ListBiometricUsageMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write", logger)).
					Post("/refresh", analyticsHandler.RefreshBiometricUsageMetrics)
			})
		})

		// ========== Courses ==========
		r.Route("/courses", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.create", logger)).
				Post("/", courseHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.bulk_create", logger)).
				Post("/bulk", courseHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read", logger)).
				Get("/{courseID}", courseHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read", logger)).
				Get("/", courseHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.update", logger)).
				Put("/{courseID}", courseHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.delete", logger)).
				Delete("/{courseID}", courseHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.activate", logger)).
				Post("/{courseID}/activate", courseHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.deactivate", logger)).
				Post("/{courseID}/deactivate", courseHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read", logger)).
				Get("/active", courseHandler.ListActive)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read", logger)).
				Get("/by-code", courseHandler.GetByCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read", logger)).
				Post("/validate-code", courseHandler.ValidateUniqueCode)
		})

		// ========== Curriculum ==========
		r.Route("/curriculum", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.assign", logger)).
				Post("/courses/{courseID}/subjects", curriculumHandler.AssignSubject)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.bulk_assign", logger)).
				Post("/subjects/bulk", curriculumHandler.BulkAssignSubjects)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.read", logger)).
				Get("/courses/{courseID}/subjects", curriculumHandler.GetSubjectsByCourse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.read", logger)).
				Get("/subjects/{subjectID}/courses", curriculumHandler.GetCoursesBySubject)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.remove", logger)).
				Delete("/mappings/{mappingID}", curriculumHandler.RemoveMapping)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.remove_all", logger)).
				Delete("/courses/{courseID}/subjects", curriculumHandler.RemoveAllForCourse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.read", logger)).
				Get("/exists", curriculumHandler.Exists)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.validate", logger)).
				Post("/courses/{courseID}/validate", curriculumHandler.ValidateCurriculum)
		})

		// ========== Enrollments ==========
		r.Route("/enrollments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.create", logger)).
				Post("/", enrollmentHandler.EnrollStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_create", logger)).
				Post("/bulk", enrollmentHandler.BulkEnroll)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.upsert", logger)).
				Post("/upsert", enrollmentHandler.UpsertEnrollment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/{enrollmentID}", enrollmentHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/", enrollmentHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update", logger)).
				Put("/{enrollmentID}", enrollmentHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update", logger)).
				Patch("/{enrollmentID}/roll-number", enrollmentHandler.UpdateRollNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.transfer", logger)).
				Post("/{enrollmentID}/transfer-section", enrollmentHandler.TransferSection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_transfer", logger)).
				Post("/transfer/bulk", enrollmentHandler.BulkTransferSection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.swap", logger)).
				Post("/swap-sections", enrollmentHandler.SwapSections)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.promote", logger)).
				Post("/promote", enrollmentHandler.PromoteStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_promote", logger)).
				Post("/promote/bulk", enrollmentHandler.BulkPromote)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.promote_section", logger)).
				Post("/sections/{sectionID}/promote", enrollmentHandler.PromoteSection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.graduate", logger)).
				Post("/{enrollmentID}/graduate", enrollmentHandler.GraduateStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.mark_alumni", logger)).
				Post("/students/{studentID}/alumni", enrollmentHandler.MarkAlumni)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_update_status", logger)).
				Patch("/status/bulk", enrollmentHandler.BulkUpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_assign_roll_numbers", logger)).
				Post("/roll-numbers/bulk", enrollmentHandler.BulkAssignRollNumbers)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.search", logger)).
				Get("/search", enrollmentHandler.Search)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/sections/{sectionID}/strength", enrollmentHandler.GetSectionStrength)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/academic-years/{academicYearID}/strength", enrollmentHandler.GetAcademicYearStrength)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/academic-years/{academicYearID}/dropouts", enrollmentHandler.GetDropoutCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/academic-years/{academicYearID}/promotion-stats", enrollmentHandler.GetPromotionStats)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update", logger)).
				Post("/{enrollmentID}/activate", enrollmentHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update", logger)).
				Post("/{enrollmentID}/complete", enrollmentHandler.Complete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update", logger)).
				Post("/{enrollmentID}/withdraw", enrollmentHandler.Withdraw)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update_status", logger)).
				Patch("/{enrollmentID}/status", enrollmentHandler.UpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/count", enrollmentHandler.Count)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/students/{studentID}", enrollmentHandler.ListByStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/sections/{sectionID}", enrollmentHandler.ListBySection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/academic-years/{academicYearID}", enrollmentHandler.ListByAcademicYear)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/students/{studentID}/academic-years/{academicYearID}", enrollmentHandler.GetByStudentAndYear)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read", logger)).
				Get("/students/{studentID}/active", enrollmentHandler.GetActiveByStudent)
		})

		// ========== Exams ==========
		r.Route("/exams", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.create", logger)).
				Post("/", examHandler.CreateExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.read", logger)).
				Get("/{examID}", examHandler.GetExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.read", logger)).
				Get("/", examHandler.ListExams)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.update", logger)).
				Put("/{examID}", examHandler.UpdateExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.delete", logger)).
				Delete("/{examID}", examHandler.DeleteExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.create", logger)).
				Post("/{examID}/schedule", examHandler.CreateExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.read", logger)).
				Get("/schedules/{scheduleID}", examHandler.GetExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.read", logger)).
				Get("/{examID}/schedules", examHandler.ListExamSchedules)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.update", logger)).
				Put("/schedules/{scheduleID}", examHandler.UpdateExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.delete", logger)).
				Delete("/schedules/{scheduleID}", examHandler.DeleteExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.create", logger)).
				Post("/results", examHandler.CreateExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.bulk_create", logger)).
				Post("/results/bulk", examHandler.BulkCreateExamResults)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.read", logger)).
				Get("/results/{resultID}", examHandler.GetExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.read", logger)).
				Get("/results", examHandler.ListExamResults)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.update", logger)).
				Put("/results/{resultID}", examHandler.UpdateExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.delete", logger)).
				Delete("/results/{resultID}", examHandler.DeleteExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.create", logger)).
				Post("/{examID}/grades", examHandler.CreateExamGrade)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.read", logger)).
				Get("/grades/{gradeID}", examHandler.GetExamGrade)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.read", logger)).
				Get("/{examID}/grades", examHandler.ListExamGrades)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.update", logger)).
				Put("/grades/{gradeID}", examHandler.UpdateExamGrade)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.delete", logger)).
				Delete("/grades/{gradeID}", examHandler.DeleteExamGrade)
		})

		// ========== Fees ==========
		r.Route("/fees", func(r chi.Router) {
			r.Route("/structures", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.create", logger)).
					Post("/", feeHandler.CreateFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.read", logger)).
					Get("/{feeStructureID}", feeHandler.GetFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.read", logger)).
					Get("/", feeHandler.ListFeeStructures)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update", logger)).
					Put("/{feeStructureID}", feeHandler.UpdateFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.delete", logger)).
					Delete("/{feeStructureID}", feeHandler.DeleteFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update", logger)).
					Post("/{feeStructureID}/items", feeHandler.AddFeeStructureItem)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update", logger)).
					Put("/{feeStructureID}/items/{itemID}", feeHandler.UpdateFeeStructureItem)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update", logger)).
					Delete("/items/{itemID}", feeHandler.DeleteFeeStructureItem)
			})
			r.Route("/invoices", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.create", logger)).
					Post("/", feeHandler.CreateInvoice)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.read", logger)).
					Get("/{invoiceID}", feeHandler.GetInvoice)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.read", logger)).
					Get("/number/{invoiceNo}", feeHandler.GetInvoiceByNumber)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.read", logger)).
					Get("/", feeHandler.ListInvoices)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.update", logger)).
					Patch("/{invoiceID}/status", feeHandler.UpdateInvoiceStatus)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read", logger)).
					Get("/{invoiceID}/payments", feeHandler.GetPaymentsByInvoice)
			})
			r.Route("/payments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.create", logger)).
					Post("/", feeHandler.CreatePayment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read", logger)).
					Get("/{paymentID}", feeHandler.GetPayment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read", logger)).
					Get("/invoices/{invoiceID}/payments", feeHandler.GetPaymentsByInvoice)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read", logger)).
					Get("/", feeHandler.ListPayments)
			})
			r.Route("/discounts", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.discount.create", logger)).
					Post("/", feeHandler.CreateDiscount)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.discount.update", logger)).
					Put("/{discountID}", feeHandler.UpdateDiscount)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.discount.delete", logger)).
					Delete("/{discountID}", feeHandler.DeleteDiscount)
			})
			r.Route("/penalties", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.penalty.create", logger)).
					Post("/", feeHandler.CreatePenalty)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.penalty.update", logger)).
					Put("/{penaltyID}", feeHandler.UpdatePenalty)
			})
			r.Route("/receipts", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.receipt.generate", logger)).
					Post("/payments/{paymentID}", feeHandler.GenerateReceipt)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.receipt.read", logger)).
					Get("/{receiptNo}", feeHandler.GetReceiptByNumber)
			})
		})

		// ========== Grading ==========
		r.Route("/grading", func(r chi.Router) {
			r.Route("/policies", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.create", logger)).
					Post("/", gradingHandler.CreateGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.read", logger)).
					Get("/{policyID}", gradingHandler.GetGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.read", logger)).
					Get("/default", gradingHandler.GetDefaultGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.read", logger)).
					Get("/", gradingHandler.ListGradingPolicies)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.update", logger)).
					Put("/{policyID}", gradingHandler.UpdateGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.delete", logger)).
					Delete("/{policyID}", gradingHandler.DeleteGradingPolicy)
				r.Route("/{policyID}/boundaries", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.create", logger)).
						Post("/", gradingHandler.CreateGradeBoundary)
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.bulk_create", logger)).
						Post("/bulk", gradingHandler.BulkCreateGradeBoundaries)
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.read", logger)).
						Get("/", gradingHandler.ListGradeBoundaries)
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.delete_all", logger)).
						Delete("/", gradingHandler.DeleteAllGradeBoundaries)
				})
			})
			r.Route("/boundaries", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.read", logger)).
					Get("/{boundaryID}", gradingHandler.GetGradeBoundary)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.update", logger)).
					Put("/{boundaryID}", gradingHandler.UpdateGradeBoundary)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.delete", logger)).
					Delete("/{boundaryID}", gradingHandler.DeleteGradeBoundary)
			})
		})

		// ========== Guardians ==========
		r.Route("/guardians", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.create", logger)).
				Post("/", guardianHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.bulk_create", logger)).
				Post("/bulk", guardianHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read", logger)).
				Get("/{guardianID}", guardianHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read", logger)).
				Get("/students/{studentID}", guardianHandler.GetByStudentID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read", logger)).
				Get("/students/{studentID}/primary", guardianHandler.GetPrimaryGuardian)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read", logger)).
				Get("/", guardianHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.update", logger)).
				Put("/{guardianID}", guardianHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.delete", logger)).
				Delete("/{guardianID}", guardianHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.set_primary", logger)).
				Post("/students/{studentID}/primary/{guardianID}", guardianHandler.SetPrimary)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read", logger)).
				Get("/students/{studentID}/exists", guardianHandler.Exists)
		})

		// ========== Library ==========
		r.Route("/library", func(r chi.Router) {
			r.Route("/categories", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.create", logger)).
					Post("/", libraryHandler.CreateCategory)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.read", logger)).
					Get("/{categoryID}", libraryHandler.GetCategory)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.read", logger)).
					Get("/", libraryHandler.ListCategories)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.update", logger)).
					Put("/{categoryID}", libraryHandler.UpdateCategory)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.delete", logger)).
					Delete("/{categoryID}", libraryHandler.DeleteCategory)
			})
			r.Route("/books", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.create", logger)).
					Post("/", libraryHandler.CreateBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read", logger)).
					Get("/{bookID}", libraryHandler.GetBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read", logger)).
					Get("/isbn/{isbn}", libraryHandler.GetBookByISBN)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read", logger)).
					Get("/", libraryHandler.ListBooks)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.update", logger)).
					Put("/{bookID}", libraryHandler.UpdateBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.delete", logger)).
					Delete("/{bookID}", libraryHandler.DeleteBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read", logger)).
					Get("/{bookID}/available-copies", libraryHandler.GetAvailableCopies)
			})
			r.Route("/copies", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.create", logger)).
					Post("/", libraryHandler.CreateCopy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.read", logger)).
					Get("/{copyID}", libraryHandler.GetCopy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.read", logger)).
					Get("/accession/{accessionNo}", libraryHandler.GetCopyByAccessionNo)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.read", logger)).
					Get("/", libraryHandler.ListCopies)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.update", logger)).
					Put("/{copyID}", libraryHandler.UpdateCopy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.delete", logger)).
					Delete("/{copyID}", libraryHandler.DeleteCopy)
			})
			r.Route("/issues", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.issue.create", logger)).
					Post("/", libraryHandler.IssueBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.issue.read", logger)).
					Get("/{issueID}", libraryHandler.GetIssue)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.issue.read", logger)).
					Get("/", libraryHandler.ListIssues)
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.return.create", logger)).
				Post("/return", libraryHandler.ReturnBook)
			r.Route("/fines", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.fine.create", logger)).
					Post("/", libraryHandler.CreateFine)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.fine.update", logger)).
					Put("/{fineID}/payment", libraryHandler.UpdateFinePayment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.fine.read", logger)).
					Get("/", libraryHandler.ListFines)
			})
			r.Get("/students/{studentID}/overdue", libraryHandler.HasOverdueIssues)
		})

		// ========== Notifications ==========
		r.Route("/notifications", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.create", logger)).
				Post("/", notificationHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/{notificationID}", notificationHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.update", logger)).
				Put("/{notificationID}", notificationHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.delete", logger)).
				Delete("/{notificationID}", notificationHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/user", notificationHandler.ListUserNotifications)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Post("/{notificationID}/read", notificationHandler.MarkAsRead)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Post("/read-all", notificationHandler.MarkAllAsRead)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/read-statuses", notificationHandler.GetReadStatuses)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/counts", notificationHandler.GetCounts)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/user/summary", notificationHandler.GetUserNotificationSummary)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.update", logger)).
				Post("/{notificationID}/targets", notificationHandler.AddTargets)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.update", logger)).
				Delete("/{notificationID}/targets", notificationHandler.RemoveTargets)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/{notificationID}/targets", notificationHandler.GetTargets)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read", logger)).
				Get("/{notificationID}/read-count", notificationHandler.GetReadCount)
		})

		// ========== Rooms ==========
		r.Route("/rooms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.create", logger)).
				Post("/", roomHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.bulk_create", logger)).
				Post("/bulk", roomHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read", logger)).
				Get("/{roomID}", roomHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read", logger)).
				Get("/code/{code}", roomHandler.GetByCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read", logger)).
				Get("/", roomHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.update", logger)).
				Put("/{roomID}", roomHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.delete", logger)).
				Delete("/{roomID}", roomHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.activate", logger)).
				Post("/{roomID}/activate", roomHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.deactivate", logger)).
				Post("/{roomID}/deactivate", roomHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read", logger)).
				Get("/buildings/{building}", roomHandler.ListByBuilding)
		})

		// ========== Sections (CRUD) ==========
		r.Route("/sections", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.create", logger)).
				Post("/", sectionHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.bulk_create", logger)).
				Post("/bulk", sectionHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.upsert", logger)).
				Post("/upsert", sectionHandler.Upsert)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read", logger)).
				Get("/{sectionID}", sectionHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read", logger)).
				Get("/courses/{courseID}", sectionHandler.ListByCourse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read", logger)).
				Get("/terms/{termID}", sectionHandler.ListByTerm)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update", logger)).
				Put("/{sectionID}", sectionHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update", logger)).
				Patch("/{sectionID}/capacity", sectionHandler.UpdateCapacity)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update", logger)).
				Post("/{sectionID}/activate", sectionHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update", logger)).
				Post("/{sectionID}/deactivate", sectionHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.delete", logger)).
				Delete("/{sectionID}", sectionHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read", logger)).
				Post("/{sectionID}/validate-capacity", sectionHandler.ValidateCapacity)
		})

		// ========== Students (CRUD + login) ==========
		r.Route("/students", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.create", logger)).
				Post("/", studentHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.bulk_create", logger)).
				Post("/bulk", studentHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read", logger)).
				Get("/{studentID}", studentHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read", logger)).
				Get("/admission/{admissionNo}", studentHandler.GetByAdmissionNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read", logger)).
				Get("/", studentHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.update", logger)).
				Put("/{studentID}", studentHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.update", logger)).
				Patch("/{studentID}/contact", studentHandler.UpdateContactInfo)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.activate", logger)).
				Post("/{studentID}/activate", studentHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.deactivate", logger)).
				Post("/{studentID}/deactivate", studentHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.promote", logger)).
				Post("/{studentID}/promote", studentHandler.Promote)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.graduate", logger)).
				Post("/{studentID}/graduate", studentHandler.Graduate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.dropout", logger)).
				Post("/{studentID}/dropout", studentHandler.Dropout)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.bulk_promote", logger)).
				Post("/bulk-promote", studentHandler.BulkPromote)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.bulk_update_status", logger)).
				Patch("/bulk-status", studentHandler.BulkUpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.delete", logger)).
				Delete("/{studentID}", studentHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read", logger)).
				Get("/validate-admission", studentHandler.ValidateAdmissionNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read", logger)).
				Get("/search", studentHandler.Search)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.set_password", logger)).
				Post("/{studentID}/set-password", studentHandler.SetPassword)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.reset_password", logger)).
				Post("/{studentID}/reset-password", studentHandler.ResetPassword)
			r.Post("/change-password", studentHandler.ChangePassword)
		})

		// ========== Subjects ==========
		r.Route("/subjects", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.create", logger)).
				Post("/", subjectHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.bulk_create", logger)).
				Post("/bulk", subjectHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read", logger)).
				Get("/{subjectID}", subjectHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read", logger)).
				Get("/code/{code}", subjectHandler.GetByCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read", logger)).
				Get("/", subjectHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.update", logger)).
				Put("/{subjectID}", subjectHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.activate", logger)).
				Post("/{subjectID}/activate", subjectHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.deactivate", logger)).
				Post("/{subjectID}/deactivate", subjectHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.delete", logger)).
				Delete("/{subjectID}", subjectHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read", logger)).
				Get("/validate-code", subjectHandler.ValidateCode)
		})

		// ========== Submissions ==========
		r.Route("/submissions", func(r chi.Router) {
			r.Route("/assignments/{assignmentID}/submissions", func(r chi.Router) {
				r.Post("/", submissionHandler.CreateSubmission)
			})
			r.Get("/{submissionID}", submissionHandler.GetSubmissionByID)
			r.Get("/assignments/{assignmentID}/students/{studentID}/submission", submissionHandler.GetSubmissionByAssignmentAndStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("submission.read", logger)).
				Get("/", submissionHandler.ListSubmissions)
			r.Put("/{submissionID}", submissionHandler.UpdateSubmission)
			r.With(authMiddleware.BitmaskPermissionMiddleware("submission.delete", logger)).
				Delete("/{submissionID}", submissionHandler.DeleteSubmission)
			r.With(authMiddleware.BitmaskPermissionMiddleware("submission.grade", logger)).
				Post("/{submissionID}/grade", submissionHandler.GradeSubmission)
			r.Route("/{submissionID}/comments", func(r chi.Router) {
				r.Post("/", submissionHandler.AddComment)
				r.Get("/", submissionHandler.GetCommentsBySubmission)
			})
		})

		// ========== Teachers ==========
		r.Route("/teachers", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.create", logger)).
				Post("/", teacherHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.bulk_create", logger)).
				Post("/bulk", teacherHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/{teacherID}", teacherHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/user/{userID}", teacherHandler.GetByUserID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/employee/{employeeCode}", teacherHandler.GetByEmployeeCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/", teacherHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.update", logger)).
				Put("/{teacherID}", teacherHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.update_status", logger)).
				Patch("/{teacherID}/status", teacherHandler.UpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.delete", logger)).
				Delete("/{teacherID}", teacherHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.bulk_update_status", logger)).
				Patch("/bulk-status", teacherHandler.BulkUpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/count", teacherHandler.CountByCompany)

			r.Route("/{teacherID}/subjects", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_subjects", logger)).
					Post("/", teacherHandler.AddSubject)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
					Get("/", teacherHandler.GetSubjectsByTeacher)
				r.Route("/{subjectID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_subjects", logger)).
						Delete("/", teacherHandler.RemoveSubject)
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_subjects", logger)).
						Patch("/primary", teacherHandler.UpdateSubjectPrimary)
				})
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/subjects/{subjectID}/teachers", teacherHandler.GetTeachersBySubject)

			r.Route("/{teacherID}/sections", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_sections", logger)).
					Post("/", teacherHandler.AddSection)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
					Get("/", teacherHandler.GetSectionsByTeacher)
				r.Route("/{sectionID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_sections", logger)).
						Delete("/", teacherHandler.RemoveSection)
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_sections", logger)).
						Patch("/class-teacher", teacherHandler.UpdateClassTeacherStatus)
				})
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
				Get("/sections/{sectionID}/teachers", teacherHandler.GetTeachersBySection)

			r.Route("/{teacherID}/schedule-preferences", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences", logger)).
					Post("/", teacherHandler.SetSchedulePreference)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read", logger)).
					Get("/", teacherHandler.GetSchedulePreferences)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences", logger)).
					Delete("/", teacherHandler.ClearSchedulePreferences)
			})
			r.Route("/schedule-preferences/{preferenceID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences", logger)).
					Put("/", teacherHandler.UpdateSchedulePreference)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences", logger)).
					Delete("/", teacherHandler.DeleteSchedulePreference)
			})
		})

		// ========== Terms ==========
		r.Route("/academic-years/{academicYearID}/terms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.create", logger)).
				Post("/", termHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.bulk_create", logger)).
				Post("/bulk", termHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.read", logger)).
				Get("/current", termHandler.GetCurrent)
		})
		r.Route("/terms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.read", logger)).
				Get("/{termID}", termHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.read", logger)).
				Get("/", termHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.update", logger)).
				Put("/{termID}", termHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.set_current", logger)).
				Post("/{termID}/set-current", termHandler.SetCurrent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.delete", logger)).
				Delete("/{termID}", termHandler.Delete)
		})

		// ========== Timetables ==========
		r.Route("/timetables", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.create", logger)).
				Post("/", timetableHandler.CreateTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read", logger)).
				Get("/{timetableID}", timetableHandler.GetTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read", logger)).
				Get("/", timetableHandler.ListTimetables)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.update", logger)).
				Put("/{timetableID}", timetableHandler.UpdateTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.delete", logger)).
				Delete("/{timetableID}", timetableHandler.DeleteTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read", logger)).
				Get("/active", timetableHandler.GetActiveTimetableForSection)

			r.Route("/{timetableID}/slots", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_slots", logger)).
					Post("/", timetableHandler.AddSlot)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read", logger)).
					Get("/", timetableHandler.GetSlotsForTimetable)
			})
			r.Route("/slots/{slotID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_slots", logger)).
					Put("/", timetableHandler.UpdateSlot)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_slots", logger)).
					Delete("/", timetableHandler.RemoveSlot)
			})

			r.Route("/slots/{slotID}/entries", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_entries", logger)).
					Post("/", timetableHandler.AddEntry)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read", logger)).
					Get("/", timetableHandler.GetEntriesForSlot)
			})
			r.Route("/entries/{entryID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_entries", logger)).
					Put("/", timetableHandler.UpdateEntry)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_entries", logger)).
					Delete("/", timetableHandler.RemoveEntry)
			})

			r.Route("/entries/{entryID}/changes", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_changes", logger)).
					Post("/", timetableHandler.AddChange)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read", logger)).
					Get("/", timetableHandler.GetChangesForEntry)
			})
		})

		// ========== Transport ==========
		r.Route("/transport", func(r chi.Router) {
			r.Route("/routes", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.create", logger)).
					Post("/", transportHandler.CreateRoute)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.read", logger)).
					Get("/", transportHandler.ListRoutes)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.read", logger)).
					Get("/{routeID}", transportHandler.GetRouteByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.update", logger)).
					Put("/{routeID}", transportHandler.UpdateRoute)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.delete", logger)).
					Delete("/{routeID}", transportHandler.DeleteRoute)
			})
			r.Route("/stops", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.read", logger)).
					Get("/", transportHandler.ListStops)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.read", logger)).
					Get("/{stopID}", transportHandler.GetStopByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.update", logger)).
					Put("/{stopID}", transportHandler.UpdateStop)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.delete", logger)).
					Delete("/{stopID}", transportHandler.DeleteStop)
			})
			r.Route("/routes/{routeID}/stops", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.create", logger)).
					Post("/", transportHandler.CreateStop)
			})
			r.Route("/vehicles", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.create", logger)).
					Post("/", transportHandler.CreateVehicle)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.read", logger)).
					Get("/", transportHandler.ListVehicles)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.read", logger)).
					Get("/{vehicleID}", transportHandler.GetVehicleByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.update", logger)).
					Put("/{vehicleID}", transportHandler.UpdateVehicle)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.delete", logger)).
					Delete("/{vehicleID}", transportHandler.DeleteVehicle)
			})
			r.Route("/driver-assignments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.read", logger)).
					Get("/", transportHandler.ListDriverAssignments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.read", logger)).
					Get("/{assignmentID}", transportHandler.GetDriverAssignmentByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.update", logger)).
					Put("/{assignmentID}", transportHandler.UpdateDriverAssignment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.delete", logger)).
					Delete("/{assignmentID}", transportHandler.DeleteDriverAssignment)
			})
			r.Route("/vehicles/{vehicleID}/drivers", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.create", logger)).
					Post("/", transportHandler.CreateDriverAssignment)
			})
			r.Route("/student-assignments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.create", logger)).
					Post("/", transportHandler.CreateStudentAssignment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.read", logger)).
					Get("/", transportHandler.ListStudentAssignments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.read", logger)).
					Get("/{assignmentID}", transportHandler.GetStudentAssignmentByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.update", logger)).
					Put("/{assignmentID}", transportHandler.UpdateStudentAssignment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.delete", logger)).
					Delete("/{assignmentID}", transportHandler.DeleteStudentAssignment)
			})
		})

		// ========== Session Generation ==========
		// Fail-fast check: ensure the handler is not nil before registering the route.
		if sessionGenerationHandler == nil {
			logger.Fatal("❌ sessionGenerationHandler is nil – cannot register /sessions/generate. Check factory initialisation and argument order.")
		}
		r.Route("/sessions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.attendance.recalculate", logger)).
				Post("/generate", sessionGenerationHandler.GenerateSession)
		})
	})
}
