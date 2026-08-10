package academics

import (
	"auth-service/internal/academics/handler"
	authMiddleware "auth-service/internal/middleware"

	"github.com/go-chi/chi/v5"
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
) {
	r.Route("/academics", func(r chi.Router) {
		// ========== Academic Years ==========
		r.Route("/academic-years", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Get("/", academicYearHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Get("/count", academicYearHandler.Count)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Get("/exists", academicYearHandler.Exists)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Get("/current", academicYearHandler.GetCurrent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.create")).
				Post("/", academicYearHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.bulk_create")).
				Post("/bulk", academicYearHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.upsert")).
				Post("/upsert", academicYearHandler.Upsert)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Post("/validate-overlap", academicYearHandler.ValidateOverlap)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Get("/by-name", academicYearHandler.GetByName)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
				Get("/all", academicYearHandler.ListByCompany)

			r.Route("/{id}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.read")).
					Get("/", academicYearHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.update")).
					Put("/", academicYearHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.update")).
					Patch("/dates", academicYearHandler.UpdateDates)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.set_current")).
					Post("/set-current", academicYearHandler.SetCurrent)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.academic_year.delete")).
					Delete("/", academicYearHandler.Delete)
			})
		})

		// ========== Admissions ==========
		r.Route("/admissions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read")).
				Get("/", admissionHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.create")).
				Post("/", admissionHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.bulk_create")).
				Post("/bulk", admissionHandler.BulkCreate)
			r.Route("/{admissionID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read")).
					Get("/", admissionHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.update")).
					Put("/", admissionHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.update_status")).
					Patch("/status", admissionHandler.UpdateStatus)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.delete")).
					Delete("/", admissionHandler.Delete)
			})
		})

		r.Route("/students/{studentID}/admissions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read")).
				Get("/", admissionHandler.GetByStudentID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read")).
				Get("/academic-years/{academicYearID}", admissionHandler.GetByStudentAndYear)
		})

		r.Route("/academic-years/{academicYearID}/admissions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.admission.read")).
				Get("/", admissionHandler.GetByAcademicYearID)
		})

		// ========== Assignments ==========
		r.Route("/assignments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.read")).
				Get("/", assignmentHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.create")).
				Post("/", assignmentHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.bulk_create")).
				Post("/bulk", assignmentHandler.BulkCreate)
			r.Route("/{assignmentID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.read")).
					Get("/", assignmentHandler.GetByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.update")).
					Put("/", assignmentHandler.Update)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.delete")).
					Delete("/", assignmentHandler.Delete)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.assignment.publish")).
					Patch("/publish", assignmentHandler.Publish)
			})
		})

		// ========== ANALYTICS ==========
		r.Route("/analytics", func(r chi.Router) {
			// Academic Year Metrics
			r.Route("/academic-years", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetAcademicYearMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListAcademicYearMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshAcademicYearMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/refresh-all", analyticsHandler.RefreshAllAcademicYearMetrics)
			})

			// Exam Metrics
			r.Route("/exams", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetExamMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListExamMetrics)
			})

			// Fee Metrics
			r.Route("/fees", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetFeeMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListFeeMetrics)
			})

			// Grading Metrics
			r.Route("/grading", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetGradingMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListGradingMetrics)
			})

			// Guardian Metrics
			r.Route("/guardians", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetGuardianMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListGuardianMetrics)
			})

			// Library Metrics
			r.Route("/library", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetLibraryMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListLibraryMetrics)
			})

			// Room Metrics
			r.Route("/rooms", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetRoomMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListRoomMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshRoomMetrics)
			})

			// Students Metrics
			r.Route("/students", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetStudentMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListStudentMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshStudentMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{studentID}/academic-years/{academicYearID}/session-summary", analyticsHandler.GetStudentSessionSummary)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/session-summaries", analyticsHandler.ListStudentSessionSummaries)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{studentID}/academic-years/{academicYearID}/session-summary/refresh", analyticsHandler.RefreshStudentSessionSummary)
			})

			// Sections Metrics
			r.Route("/sections", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetSectionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListSectionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshSectionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{sectionID}/session-metrics", analyticsHandler.GetSectionSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/session-metrics", analyticsHandler.ListSectionSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{sectionID}/session-metrics/refresh", analyticsHandler.RefreshSectionSessionMetrics)
			})

			// Subject Metrics
			r.Route("/subjects", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetSubjectMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListSubjectMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshSubjectMetrics)
			})

			// Submission Metrics
			r.Route("/submissions", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetSubmissionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListSubmissionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshSubmissionMetrics)
			})

			// Teachers Metrics
			r.Route("/teachers", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetTeacherMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListTeacherMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshTeacherMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{teacherID}/academic-years/{academicYearID}/session-metrics", analyticsHandler.GetTeacherSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/session-metrics", analyticsHandler.ListTeacherSessionMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{teacherID}/academic-years/{academicYearID}/session-metrics/refresh", analyticsHandler.RefreshTeacherSessionMetrics)
			})

			// Timetable Metrics
			r.Route("/timetables", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetTimetableMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListTimetableMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshTimetableMetrics)
			})

			// Transport Metrics
			r.Route("/transport", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/{academicYearID}/metrics", analyticsHandler.GetTransportMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/metrics", analyticsHandler.ListTransportMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/{academicYearID}/refresh", analyticsHandler.RefreshTransportMetrics)
			})

			// Biometric Device Usage Metrics
			r.Route("/biometric-usage", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/", analyticsHandler.GetBiometricUsageMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.read")).
					Get("/list", analyticsHandler.ListBiometricUsageMetrics)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.analytics.write")).
					Post("/refresh", analyticsHandler.RefreshBiometricUsageMetrics)
			})
		})

		// ========== Courses ==========
		r.Route("/courses", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.create")).
				Post("/", courseHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.bulk_create")).
				Post("/bulk", courseHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read")).
				Get("/{courseID}", courseHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read")).
				Get("/", courseHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.update")).
				Put("/{courseID}", courseHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.delete")).
				Delete("/{courseID}", courseHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.activate")).
				Post("/{courseID}/activate", courseHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.deactivate")).
				Post("/{courseID}/deactivate", courseHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read")).
				Get("/active", courseHandler.ListActive)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read")).
				Get("/by-code", courseHandler.GetByCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.course.read")).
				Post("/validate-code", courseHandler.ValidateUniqueCode)
		})

		// ========== Curriculum ==========
		r.Route("/curriculum", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.assign")).
				Post("/courses/{courseID}/subjects", curriculumHandler.AssignSubject)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.bulk_assign")).
				Post("/subjects/bulk", curriculumHandler.BulkAssignSubjects)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.read")).
				Get("/courses/{courseID}/subjects", curriculumHandler.GetSubjectsByCourse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.read")).
				Get("/subjects/{subjectID}/courses", curriculumHandler.GetCoursesBySubject)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.remove")).
				Delete("/mappings/{mappingID}", curriculumHandler.RemoveMapping)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.remove_all")).
				Delete("/courses/{courseID}/subjects", curriculumHandler.RemoveAllForCourse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.read")).
				Get("/exists", curriculumHandler.Exists)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.curriculum.validate")).
				Post("/courses/{courseID}/validate", curriculumHandler.ValidateCurriculum)
		})

		// ========== Enrollments ==========
		r.Route("/enrollments", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.create")).
				Post("/", enrollmentHandler.EnrollStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_create")).
				Post("/bulk", enrollmentHandler.BulkEnroll)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.upsert")).
				Post("/upsert", enrollmentHandler.UpsertEnrollment)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/{enrollmentID}", enrollmentHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/", enrollmentHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update")).
				Put("/{enrollmentID}", enrollmentHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update")).
				Patch("/{enrollmentID}/roll-number", enrollmentHandler.UpdateRollNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.transfer")).
				Post("/{enrollmentID}/transfer-section", enrollmentHandler.TransferSection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_transfer")).
				Post("/transfer/bulk", enrollmentHandler.BulkTransferSection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.swap")).
				Post("/swap-sections", enrollmentHandler.SwapSections)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.promote")).
				Post("/promote", enrollmentHandler.PromoteStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_promote")).
				Post("/promote/bulk", enrollmentHandler.BulkPromote)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.promote_section")).
				Post("/sections/{sectionID}/promote", enrollmentHandler.PromoteSection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.graduate")).
				Post("/{enrollmentID}/graduate", enrollmentHandler.GraduateStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.mark_alumni")).
				Post("/students/{studentID}/alumni", enrollmentHandler.MarkAlumni)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_update_status")).
				Patch("/status/bulk", enrollmentHandler.BulkUpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.bulk_assign_roll_numbers")).
				Post("/roll-numbers/bulk", enrollmentHandler.BulkAssignRollNumbers)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.search")).
				Get("/search", enrollmentHandler.Search)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/sections/{sectionID}/strength", enrollmentHandler.GetSectionStrength)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/academic-years/{academicYearID}/strength", enrollmentHandler.GetAcademicYearStrength)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/academic-years/{academicYearID}/dropouts", enrollmentHandler.GetDropoutCount)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/academic-years/{academicYearID}/promotion-stats", enrollmentHandler.GetPromotionStats)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update")).
				Post("/{enrollmentID}/activate", enrollmentHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update")).
				Post("/{enrollmentID}/complete", enrollmentHandler.Complete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update")).
				Post("/{enrollmentID}/withdraw", enrollmentHandler.Withdraw)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.update_status")).
				Patch("/{enrollmentID}/status", enrollmentHandler.UpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/count", enrollmentHandler.Count)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/students/{studentID}", enrollmentHandler.ListByStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/sections/{sectionID}", enrollmentHandler.ListBySection)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/academic-years/{academicYearID}", enrollmentHandler.ListByAcademicYear)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/students/{studentID}/academic-years/{academicYearID}", enrollmentHandler.GetByStudentAndYear)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.enrollment.read")).
				Get("/students/{studentID}/active", enrollmentHandler.GetActiveByStudent)
		})

		// ========== Exams ==========
		r.Route("/exams", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.create")).
				Post("/", examHandler.CreateExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.read")).
				Get("/{examID}", examHandler.GetExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.read")).
				Get("/", examHandler.ListExams)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.update")).
				Put("/{examID}", examHandler.UpdateExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.delete")).
				Delete("/{examID}", examHandler.DeleteExam)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.create")).
				Post("/{examID}/schedule", examHandler.CreateExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.read")).
				Get("/schedules/{scheduleID}", examHandler.GetExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.read")).
				Get("/{examID}/schedules", examHandler.ListExamSchedules)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.update")).
				Put("/schedules/{scheduleID}", examHandler.UpdateExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.schedule.delete")).
				Delete("/schedules/{scheduleID}", examHandler.DeleteExamSchedule)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.create")).
				Post("/results", examHandler.CreateExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.bulk_create")).
				Post("/results/bulk", examHandler.BulkCreateExamResults)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.read")).
				Get("/results/{resultID}", examHandler.GetExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.read")).
				Get("/results", examHandler.ListExamResults)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.update")).
				Put("/results/{resultID}", examHandler.UpdateExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.result.delete")).
				Delete("/results/{resultID}", examHandler.DeleteExamResult)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.create")).
				Post("/{examID}/grades", examHandler.CreateExamGrade)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.read")).
				Get("/grades/{gradeID}", examHandler.GetExamGrade)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.read")).
				Get("/{examID}/grades", examHandler.ListExamGrades)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.update")).
				Put("/grades/{gradeID}", examHandler.UpdateExamGrade)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.exam.grade.delete")).
				Delete("/grades/{gradeID}", examHandler.DeleteExamGrade)
		})

		// ========== Fees ==========
		r.Route("/fees", func(r chi.Router) {
			r.Route("/structures", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.create")).
					Post("/", feeHandler.CreateFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.read")).
					Get("/{feeStructureID}", feeHandler.GetFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.read")).
					Get("/", feeHandler.ListFeeStructures)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update")).
					Put("/{feeStructureID}", feeHandler.UpdateFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.delete")).
					Delete("/{feeStructureID}", feeHandler.DeleteFeeStructure)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update")).
					Post("/{feeStructureID}/items", feeHandler.AddFeeStructureItem)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update")).
					Put("/{feeStructureID}/items/{itemID}", feeHandler.UpdateFeeStructureItem)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.structure.update")).
					Delete("/items/{itemID}", feeHandler.DeleteFeeStructureItem)
			})
			r.Route("/invoices", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.create")).
					Post("/", feeHandler.CreateInvoice)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.read")).
					Get("/{invoiceID}", feeHandler.GetInvoice)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.read")).
					Get("/number/{invoiceNo}", feeHandler.GetInvoiceByNumber)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.read")).
					Get("/", feeHandler.ListInvoices)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.invoice.update")).
					Patch("/{invoiceID}/status", feeHandler.UpdateInvoiceStatus)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read")).
					Get("/{invoiceID}/payments", feeHandler.GetPaymentsByInvoice)
			})
			r.Route("/payments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.create")).
					Post("/", feeHandler.CreatePayment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read")).
					Get("/{paymentID}", feeHandler.GetPayment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read")).
					Get("/invoices/{invoiceID}/payments", feeHandler.GetPaymentsByInvoice)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.payment.read")).
					Get("/", feeHandler.ListPayments)
			})
			r.Route("/discounts", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.discount.create")).
					Post("/", feeHandler.CreateDiscount)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.discount.update")).
					Put("/{discountID}", feeHandler.UpdateDiscount)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.discount.delete")).
					Delete("/{discountID}", feeHandler.DeleteDiscount)
			})
			r.Route("/penalties", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.penalty.create")).
					Post("/", feeHandler.CreatePenalty)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.penalty.update")).
					Put("/{penaltyID}", feeHandler.UpdatePenalty)
			})
			r.Route("/receipts", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.receipt.generate")).
					Post("/payments/{paymentID}", feeHandler.GenerateReceipt)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.fee.receipt.read")).
					Get("/{receiptNo}", feeHandler.GetReceiptByNumber)
			})
		})

		// ========== Grading ==========
		r.Route("/grading", func(r chi.Router) {
			r.Route("/policies", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.create")).
					Post("/", gradingHandler.CreateGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.read")).
					Get("/{policyID}", gradingHandler.GetGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.read")).
					Get("/default", gradingHandler.GetDefaultGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.read")).
					Get("/", gradingHandler.ListGradingPolicies)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.update")).
					Put("/{policyID}", gradingHandler.UpdateGradingPolicy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.policy.delete")).
					Delete("/{policyID}", gradingHandler.DeleteGradingPolicy)
				r.Route("/{policyID}/boundaries", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.create")).
						Post("/", gradingHandler.CreateGradeBoundary)
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.bulk_create")).
						Post("/bulk", gradingHandler.BulkCreateGradeBoundaries)
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.read")).
						Get("/", gradingHandler.ListGradeBoundaries)
					r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.delete_all")).
						Delete("/", gradingHandler.DeleteAllGradeBoundaries)
				})
			})
			r.Route("/boundaries", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.read")).
					Get("/{boundaryID}", gradingHandler.GetGradeBoundary)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.update")).
					Put("/{boundaryID}", gradingHandler.UpdateGradeBoundary)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.grading.boundary.delete")).
					Delete("/{boundaryID}", gradingHandler.DeleteGradeBoundary)
			})
		})

		// ========== Guardians ==========
		r.Route("/guardians", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.create")).
				Post("/", guardianHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.bulk_create")).
				Post("/bulk", guardianHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read")).
				Get("/{guardianID}", guardianHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read")).
				Get("/students/{studentID}", guardianHandler.GetByStudentID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read")).
				Get("/students/{studentID}/primary", guardianHandler.GetPrimaryGuardian)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read")).
				Get("/", guardianHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.update")).
				Put("/{guardianID}", guardianHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.delete")).
				Delete("/{guardianID}", guardianHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.set_primary")).
				Post("/students/{studentID}/primary/{guardianID}", guardianHandler.SetPrimary)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.guardian.read")).
				Get("/students/{studentID}/exists", guardianHandler.Exists)
		})

		// ========== Library ==========
		r.Route("/library", func(r chi.Router) {
			r.Route("/categories", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.create")).
					Post("/", libraryHandler.CreateCategory)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.read")).
					Get("/{categoryID}", libraryHandler.GetCategory)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.read")).
					Get("/", libraryHandler.ListCategories)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.update")).
					Put("/{categoryID}", libraryHandler.UpdateCategory)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.category.delete")).
					Delete("/{categoryID}", libraryHandler.DeleteCategory)
			})
			r.Route("/books", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.create")).
					Post("/", libraryHandler.CreateBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read")).
					Get("/{bookID}", libraryHandler.GetBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read")).
					Get("/isbn/{isbn}", libraryHandler.GetBookByISBN)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read")).
					Get("/", libraryHandler.ListBooks)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.update")).
					Put("/{bookID}", libraryHandler.UpdateBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.delete")).
					Delete("/{bookID}", libraryHandler.DeleteBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.book.read")).
					Get("/{bookID}/available-copies", libraryHandler.GetAvailableCopies)
			})
			r.Route("/copies", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.create")).
					Post("/", libraryHandler.CreateCopy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.read")).
					Get("/{copyID}", libraryHandler.GetCopy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.read")).
					Get("/accession/{accessionNo}", libraryHandler.GetCopyByAccessionNo)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.read")).
					Get("/", libraryHandler.ListCopies)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.update")).
					Put("/{copyID}", libraryHandler.UpdateCopy)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.copy.delete")).
					Delete("/{copyID}", libraryHandler.DeleteCopy)
			})
			r.Route("/issues", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.issue.create")).
					Post("/", libraryHandler.IssueBook)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.issue.read")).
					Get("/{issueID}", libraryHandler.GetIssue)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.issue.read")).
					Get("/", libraryHandler.ListIssues)
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.return.create")).
				Post("/return", libraryHandler.ReturnBook)
			r.Route("/fines", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.fine.create")).
					Post("/", libraryHandler.CreateFine)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.fine.update")).
					Put("/{fineID}/payment", libraryHandler.UpdateFinePayment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("academics.library.fine.read")).
					Get("/", libraryHandler.ListFines)
			})
			r.Get("/students/{studentID}/overdue", libraryHandler.HasOverdueIssues)
		})

		// ========== Notifications ==========
		r.Route("/notifications", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.create")).
				Post("/", notificationHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/{notificationID}", notificationHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.update")).
				Put("/{notificationID}", notificationHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.delete")).
				Delete("/{notificationID}", notificationHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/user", notificationHandler.ListUserNotifications)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Post("/{notificationID}/read", notificationHandler.MarkAsRead)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Post("/read-all", notificationHandler.MarkAllAsRead)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/read-statuses", notificationHandler.GetReadStatuses)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/counts", notificationHandler.GetCounts)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/user/summary", notificationHandler.GetUserNotificationSummary)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.update")).
				Post("/{notificationID}/targets", notificationHandler.AddTargets)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.update")).
				Delete("/{notificationID}/targets", notificationHandler.RemoveTargets)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/{notificationID}/targets", notificationHandler.GetTargets)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.notification.read")).
				Get("/{notificationID}/read-count", notificationHandler.GetReadCount)
		})

		// ========== Rooms ==========
		r.Route("/rooms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.create")).
				Post("/", roomHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.bulk_create")).
				Post("/bulk", roomHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read")).
				Get("/{roomID}", roomHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read")).
				Get("/code/{code}", roomHandler.GetByCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read")).
				Get("/", roomHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.update")).
				Put("/{roomID}", roomHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.delete")).
				Delete("/{roomID}", roomHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.activate")).
				Post("/{roomID}/activate", roomHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.deactivate")).
				Post("/{roomID}/deactivate", roomHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.room.read")).
				Get("/buildings/{building}", roomHandler.ListByBuilding)
		})

		// ========== Sections (CRUD) ==========
		r.Route("/sections", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.create")).
				Post("/", sectionHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.bulk_create")).
				Post("/bulk", sectionHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.upsert")).
				Post("/upsert", sectionHandler.Upsert)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read")).
				Get("/{sectionID}", sectionHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read")).
				Get("/courses/{courseID}", sectionHandler.ListByCourse)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read")).
				Get("/terms/{termID}", sectionHandler.ListByTerm)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update")).
				Put("/{sectionID}", sectionHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update")).
				Patch("/{sectionID}/capacity", sectionHandler.UpdateCapacity)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update")).
				Post("/{sectionID}/activate", sectionHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.update")).
				Post("/{sectionID}/deactivate", sectionHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.delete")).
				Delete("/{sectionID}", sectionHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.section.read")).
				Post("/{sectionID}/validate-capacity", sectionHandler.ValidateCapacity)
		})

		// ========== Students (CRUD + login) ==========
		r.Route("/students", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.create")).
				Post("/", studentHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.bulk_create")).
				Post("/bulk", studentHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read")).
				Get("/{studentID}", studentHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read")).
				Get("/admission/{admissionNo}", studentHandler.GetByAdmissionNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read")).
				Get("/", studentHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.update")).
				Put("/{studentID}", studentHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.update")).
				Patch("/{studentID}/contact", studentHandler.UpdateContactInfo)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.activate")).
				Post("/{studentID}/activate", studentHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.deactivate")).
				Post("/{studentID}/deactivate", studentHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.promote")).
				Post("/{studentID}/promote", studentHandler.Promote)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.graduate")).
				Post("/{studentID}/graduate", studentHandler.Graduate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.dropout")).
				Post("/{studentID}/dropout", studentHandler.Dropout)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.bulk_promote")).
				Post("/bulk-promote", studentHandler.BulkPromote)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.bulk_update_status")).
				Patch("/bulk-status", studentHandler.BulkUpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.delete")).
				Delete("/{studentID}", studentHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read")).
				Get("/validate-admission", studentHandler.ValidateAdmissionNumber)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.read")).
				Get("/search", studentHandler.Search)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.set_password")).
				Post("/{studentID}/set-password", studentHandler.SetPassword)
			r.With(authMiddleware.BitmaskPermissionMiddleware("student.reset_password")).
				Post("/{studentID}/reset-password", studentHandler.ResetPassword)
			r.Post("/change-password", studentHandler.ChangePassword)
		})

		// ========== Subjects ==========
		r.Route("/subjects", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.create")).
				Post("/", subjectHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.bulk_create")).
				Post("/bulk", subjectHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read")).
				Get("/{subjectID}", subjectHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read")).
				Get("/code/{code}", subjectHandler.GetByCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read")).
				Get("/", subjectHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.update")).
				Put("/{subjectID}", subjectHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.activate")).
				Post("/{subjectID}/activate", subjectHandler.Activate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.deactivate")).
				Post("/{subjectID}/deactivate", subjectHandler.Deactivate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.delete")).
				Delete("/{subjectID}", subjectHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("subject.read")).
				Get("/validate-code", subjectHandler.ValidateCode)
		})

		// ========== Submissions ==========
		r.Route("/submissions", func(r chi.Router) {
			r.Route("/assignments/{assignmentID}/submissions", func(r chi.Router) {
				r.Post("/", submissionHandler.CreateSubmission)
			})
			r.Get("/{submissionID}", submissionHandler.GetSubmissionByID)
			r.Get("/assignments/{assignmentID}/students/{studentID}/submission", submissionHandler.GetSubmissionByAssignmentAndStudent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("submission.read")).
				Get("/", submissionHandler.ListSubmissions)
			r.Put("/{submissionID}", submissionHandler.UpdateSubmission)
			r.With(authMiddleware.BitmaskPermissionMiddleware("submission.delete")).
				Delete("/{submissionID}", submissionHandler.DeleteSubmission)
			r.With(authMiddleware.BitmaskPermissionMiddleware("submission.grade")).
				Post("/{submissionID}/grade", submissionHandler.GradeSubmission)
			r.Route("/{submissionID}/comments", func(r chi.Router) {
				r.Post("/", submissionHandler.AddComment)
				r.Get("/", submissionHandler.GetCommentsBySubmission)
			})
		})

		// ========== Teachers ==========
		r.Route("/teachers", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.create")).
				Post("/", teacherHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.bulk_create")).
				Post("/bulk", teacherHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/{teacherID}", teacherHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/user/{userID}", teacherHandler.GetByUserID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/employee/{employeeCode}", teacherHandler.GetByEmployeeCode)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/", teacherHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.update")).
				Put("/{teacherID}", teacherHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.update_status")).
				Patch("/{teacherID}/status", teacherHandler.UpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.delete")).
				Delete("/{teacherID}", teacherHandler.Delete)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.bulk_update_status")).
				Patch("/bulk-status", teacherHandler.BulkUpdateStatus)
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/count", teacherHandler.CountByCompany)

			r.Route("/{teacherID}/subjects", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_subjects")).
					Post("/", teacherHandler.AddSubject)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
					Get("/", teacherHandler.GetSubjectsByTeacher)
				r.Route("/{subjectID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_subjects")).
						Delete("/", teacherHandler.RemoveSubject)
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_subjects")).
						Patch("/primary", teacherHandler.UpdateSubjectPrimary)
				})
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/subjects/{subjectID}/teachers", teacherHandler.GetTeachersBySubject)

			r.Route("/{teacherID}/sections", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_sections")).
					Post("/", teacherHandler.AddSection)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
					Get("/", teacherHandler.GetSectionsByTeacher)
				r.Route("/{sectionID}", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_sections")).
						Delete("/", teacherHandler.RemoveSection)
					r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_sections")).
						Patch("/class-teacher", teacherHandler.UpdateClassTeacherStatus)
				})
			})
			r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
				Get("/sections/{sectionID}/teachers", teacherHandler.GetTeachersBySection)

			r.Route("/{teacherID}/schedule-preferences", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences")).
					Post("/", teacherHandler.SetSchedulePreference)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.read")).
					Get("/", teacherHandler.GetSchedulePreferences)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences")).
					Delete("/", teacherHandler.ClearSchedulePreferences)
			})
			r.Route("/schedule-preferences/{preferenceID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences")).
					Put("/", teacherHandler.UpdateSchedulePreference)
				r.With(authMiddleware.BitmaskPermissionMiddleware("teacher.manage_preferences")).
					Delete("/", teacherHandler.DeleteSchedulePreference)
			})
		})

		// ========== Terms ==========
		r.Route("/academic-years/{academicYearID}/terms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.create")).
				Post("/", termHandler.Create)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.bulk_create")).
				Post("/bulk", termHandler.BulkCreate)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.read")).
				Get("/current", termHandler.GetCurrent)
		})
		r.Route("/terms", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.read")).
				Get("/{termID}", termHandler.GetByID)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.read")).
				Get("/", termHandler.List)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.update")).
				Put("/{termID}", termHandler.Update)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.set_current")).
				Post("/{termID}/set-current", termHandler.SetCurrent)
			r.With(authMiddleware.BitmaskPermissionMiddleware("term.delete")).
				Delete("/{termID}", termHandler.Delete)
		})

		// ========== Timetables ==========
		r.Route("/timetables", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.create")).
				Post("/", timetableHandler.CreateTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read")).
				Get("/{timetableID}", timetableHandler.GetTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read")).
				Get("/", timetableHandler.ListTimetables)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.update")).
				Put("/{timetableID}", timetableHandler.UpdateTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.delete")).
				Delete("/{timetableID}", timetableHandler.DeleteTimetable)
			r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read")).
				Get("/active", timetableHandler.GetActiveTimetableForSection)

			r.Route("/{timetableID}/slots", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_slots")).
					Post("/", timetableHandler.AddSlot)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read")).
					Get("/", timetableHandler.GetSlotsForTimetable)
			})
			r.Route("/slots/{slotID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_slots")).
					Put("/", timetableHandler.UpdateSlot)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_slots")).
					Delete("/", timetableHandler.RemoveSlot)
			})

			r.Route("/slots/{slotID}/entries", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_entries")).
					Post("/", timetableHandler.AddEntry)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read")).
					Get("/", timetableHandler.GetEntriesForSlot)
			})
			r.Route("/entries/{entryID}", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_entries")).
					Put("/", timetableHandler.UpdateEntry)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_entries")).
					Delete("/", timetableHandler.RemoveEntry)
			})

			r.Route("/entries/{entryID}/changes", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.manage_changes")).
					Post("/", timetableHandler.AddChange)
				r.With(authMiddleware.BitmaskPermissionMiddleware("timetable.read")).
					Get("/", timetableHandler.GetChangesForEntry)
			})
		})

		// ========== Transport ==========
		r.Route("/transport", func(r chi.Router) {
			r.Route("/routes", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.create")).
					Post("/", transportHandler.CreateRoute)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.read")).
					Get("/", transportHandler.ListRoutes)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.read")).
					Get("/{routeID}", transportHandler.GetRouteByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.update")).
					Put("/{routeID}", transportHandler.UpdateRoute)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.route.delete")).
					Delete("/{routeID}", transportHandler.DeleteRoute)
			})
			r.Route("/stops", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.read")).
					Get("/", transportHandler.ListStops)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.read")).
					Get("/{stopID}", transportHandler.GetStopByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.update")).
					Put("/{stopID}", transportHandler.UpdateStop)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.delete")).
					Delete("/{stopID}", transportHandler.DeleteStop)
			})
			r.Route("/routes/{routeID}/stops", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.stop.create")).
					Post("/", transportHandler.CreateStop)
			})
			r.Route("/vehicles", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.create")).
					Post("/", transportHandler.CreateVehicle)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.read")).
					Get("/", transportHandler.ListVehicles)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.read")).
					Get("/{vehicleID}", transportHandler.GetVehicleByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.update")).
					Put("/{vehicleID}", transportHandler.UpdateVehicle)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.vehicle.delete")).
					Delete("/{vehicleID}", transportHandler.DeleteVehicle)
			})
			r.Route("/driver-assignments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.read")).
					Get("/", transportHandler.ListDriverAssignments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.read")).
					Get("/{assignmentID}", transportHandler.GetDriverAssignmentByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.update")).
					Put("/{assignmentID}", transportHandler.UpdateDriverAssignment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.delete")).
					Delete("/{assignmentID}", transportHandler.DeleteDriverAssignment)
			})
			r.Route("/vehicles/{vehicleID}/drivers", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.driver.create")).
					Post("/", transportHandler.CreateDriverAssignment)
			})
			r.Route("/student-assignments", func(r chi.Router) {
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.create")).
					Post("/", transportHandler.CreateStudentAssignment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.read")).
					Get("/", transportHandler.ListStudentAssignments)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.read")).
					Get("/{assignmentID}", transportHandler.GetStudentAssignmentByID)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.update")).
					Put("/{assignmentID}", transportHandler.UpdateStudentAssignment)
				r.With(authMiddleware.BitmaskPermissionMiddleware("transport.student_assignment.delete")).
					Delete("/{assignmentID}", transportHandler.DeleteStudentAssignment)
			})
		})

		// ========== Session Generation ==========
		// Fail-fast check: ensure the handler is not nil before registering the route.
		r.Route("/sessions", func(r chi.Router) {
			r.With(authMiddleware.BitmaskPermissionMiddleware("academics.attendance.recalculate")).
				Post("/generate", sessionGenerationHandler.GenerateSession)
		})
	})
}
