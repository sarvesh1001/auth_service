// internal/hr/worker/lifecycle_notifier_impl.go
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"auth-service/internal/hr/models/employee"
	hrrepo "auth-service/internal/hr/repository"
	hrservice "auth-service/internal/hr/service"
)

// LifecycleNotifierImpl is the concrete LifecycleNotifier. It renders
// each job type into a ReminderService.Dispatch call.
//
// Every Dispatch is idempotent via the dedupe key
// (type, subject_user_id, scope-date) — a retried job never produces
// a duplicate reminder.
//
// Location scope:
//
//	Before dispatching, the notifier resolves the *subject* employee's
//	current primary_location_id and stamps it on the reminder rows.
//	The ReminderService's RecipientResolver then only delivers to HR
//	users whose scope covers that location, and the List/Counts
//	read paths filter by X-Location-ID — so the write-side and the
//	read-side agree on what "belongs to Mumbai" means.
type LifecycleNotifierImpl struct {
	reminders *hrservice.ReminderService
	repo      hrrepo.ReminderRepository // 👈 used to resolve subject location
	logger    *zap.Logger
}

func NewLifecycleNotifier(
	reminders *hrservice.ReminderService,
	repo hrrepo.ReminderRepository, // 👈 NEW
	logger *zap.Logger,
) LifecycleNotifier {
	if logger == nil {
		logger = zap.L()
	}
	return &LifecycleNotifierImpl{
		reminders: reminders,
		repo:      repo,
		logger:    logger.Named("hr_lifecycle_notifier"),
	}
}

func (n *LifecycleNotifierImpl) Notify(
	ctx context.Context, job *employee.ScheduledJob,
) error {
	if job.UserID == nil {
		return fmt.Errorf("job missing user_id")
	}

	switch job.JobType {
	case employee.JobProbationReminder:
		return n.notifyProbationReminder(ctx, job)
	case employee.JobProbationEndReached:
		return n.notifyProbationEndReached(ctx, job)
	case employee.JobNoticeReminder:
		return n.notifyNoticeReminder(ctx, job)
	case employee.JobOnHoldReminder:
		return n.notifyOnHoldReminder(ctx, job)
	}
	return nil
}

// ----- Probation -----

type probationPayload struct {
	ProbationID  string `json:"probation_id"`
	ProbationEnd string `json:"probation_end"`
}

func (n *LifecycleNotifierImpl) notifyProbationReminder(
	ctx context.Context, job *employee.ScheduledJob,
) error {
	var p probationPayload
	_ = json.Unmarshal(job.Payload, &p)

	end, _ := time.Parse("2006-01-02", p.ProbationEnd)
	daysLeft := int(time.Until(end).Hours() / 24)
	if daysLeft < 0 {
		daysLeft = 0
	}

	severity := hrservice.SeverityInfo
	if daysLeft <= 3 {
		severity = hrservice.SeverityWarning
	}

	title := fmt.Sprintf("Probation ends in %d days", daysLeft)
	if daysLeft == 0 {
		title = "Probation ends today"
	}

	return n.dispatch(ctx, job, hrservice.DispatchInput{
		Type:        hrservice.ReminderProbationT3,
		Severity:    severity,
		Title:       title,
		Body:        fmt.Sprintf("Probation ends on %s. Review and confirm, extend, or fail.", p.ProbationEnd),
		DedupeScope: end,
		ExpiresIn:   30 * 24 * time.Hour,
		Action: &hrservice.ActionPayload{
			Screen:     "probation",
			EmployeeID: job.UserID.String(),
			EntityID:   p.ProbationID,
			EndDate:    p.ProbationEnd,
		},
		Metadata: map[string]interface{}{
			"days_left": daysLeft,
		},
	})
}

func (n *LifecycleNotifierImpl) notifyProbationEndReached(
	ctx context.Context, job *employee.ScheduledJob,
) error {
	var p probationPayload
	_ = json.Unmarshal(job.Payload, &p)

	end, _ := time.Parse("2006-01-02", p.ProbationEnd)

	return n.dispatch(ctx, job, hrservice.DispatchInput{
		Type:        hrservice.ReminderProbationOverdue,
		Severity:    hrservice.SeverityCritical,
		Title:       "Probation ended — action needed",
		Body:        fmt.Sprintf("Probation ended on %s and no decision was recorded. Confirm, extend, or fail now.", p.ProbationEnd),
		DedupeScope: end,
		Action: &hrservice.ActionPayload{
			Screen:     "probation",
			EmployeeID: job.UserID.String(),
			EntityID:   p.ProbationID,
			EndDate:    p.ProbationEnd,
		},
	})
}

// ----- Notice -----

type noticePayload struct {
	NoticeID  string `json:"notice_id"`
	NoticeEnd string `json:"notice_end"`
}

func (n *LifecycleNotifierImpl) notifyNoticeReminder(
	ctx context.Context, job *employee.ScheduledJob,
) error {
	var p noticePayload
	_ = json.Unmarshal(job.Payload, &p)

	end, _ := time.Parse("2006-01-02", p.NoticeEnd)
	daysLeft := int(time.Until(end).Hours() / 24)
	if daysLeft < 0 {
		daysLeft = 0
	}

	title := fmt.Sprintf("Notice period ends in %d days", daysLeft)
	if daysLeft == 0 {
		title = "Notice period ends today"
	}

	return n.dispatch(ctx, job, hrservice.DispatchInput{
		Type:        hrservice.ReminderNoticeExpiring,
		Severity:    hrservice.SeverityWarning,
		Title:       title,
		Body:        fmt.Sprintf("Notice ends on %s. Prepare final settlement and asset recovery.", p.NoticeEnd),
		DedupeScope: end,
		ExpiresIn:   30 * 24 * time.Hour,
		Action: &hrservice.ActionPayload{
			Screen:     "notice",
			EmployeeID: job.UserID.String(),
			EntityID:   p.NoticeID,
			EndDate:    p.NoticeEnd,
		},
		Metadata: map[string]interface{}{
			"days_left": daysLeft,
		},
	})
}

// ----- On-hold -----

type onHoldPayload struct {
	OnHoldID  string `json:"on_hold_id"`
	OnHoldEnd string `json:"on_hold_end"`
}

func (n *LifecycleNotifierImpl) notifyOnHoldReminder(
	ctx context.Context, job *employee.ScheduledJob,
) error {
	var p onHoldPayload
	_ = json.Unmarshal(job.Payload, &p)

	end, _ := time.Parse("2006-01-02", p.OnHoldEnd)
	daysLeft := int(time.Until(end).Hours() / 24)
	if daysLeft < 0 {
		daysLeft = 0
	}

	title := fmt.Sprintf("On-hold ends in %d days", daysLeft)
	if daysLeft == 0 {
		title = "On-hold ends today"
	}

	return n.dispatch(ctx, job, hrservice.DispatchInput{
		Type:        hrservice.ReminderOnHoldExpiring,
		Severity:    hrservice.SeverityWarning,
		Title:       title,
		Body:        fmt.Sprintf("Employee's on-hold period ends on %s. Extend or end early if needed.", p.OnHoldEnd),
		DedupeScope: end,
		ExpiresIn:   30 * 24 * time.Hour,
		Action: &hrservice.ActionPayload{
			Screen:     "on_hold",
			EmployeeID: job.UserID.String(),
			EntityID:   p.OnHoldID,
			EndDate:    p.OnHoldEnd,
		},
		Metadata: map[string]interface{}{
			"days_left": daysLeft,
		},
	})
}

// ----- shared -----

func (n *LifecycleNotifierImpl) dispatch(
	ctx context.Context, job *employee.ScheduledJob, in hrservice.DispatchInput,
) error {
	in.CompanyID = job.CompanyID
	in.SubjectUserID = *job.UserID

	// Resolve the subject employee's current primary_location_id and stamp
	// it on the reminder. A nil result means the employee has no primary
	// location — the reminder is company-wide (location_id = NULL) and only
	// ALL-scope HR users will see it.
	//
	// A resolution error is non-fatal: we log and proceed with nil, which
	// degrades the reminder to company-wide rather than dropping it.
	if n.repo != nil {
		locID, err := n.repo.GetSubjectLocationID(ctx, job.CompanyID, *job.UserID)
		if err != nil {
			n.logger.Warn("resolve subject location failed — falling back to company-wide",
				zap.String("company_id", job.CompanyID.String()),
				zap.String("subject_user_id", job.UserID.String()),
				zap.Error(err),
			)
		} else {
			in.LocationID = locID
		}
	}

	inserted, err := n.reminders.Dispatch(ctx, in)
	if err != nil {
		return fmt.Errorf("reminder dispatch: %w", err)
	}
	if inserted == 0 {
		n.logger.Debug("reminder already existed — dedupe",
			zap.String("type", in.Type),
			zap.String("subject_user_id", job.UserID.String()),
		)
	}
	return nil
}
