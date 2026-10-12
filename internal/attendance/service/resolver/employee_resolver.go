package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
)

type EmployeeDataProvider interface {
	GetEmployee(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (
		active bool,
		positionID *uuid.UUID,
		workCenterCode *string,
		positionLocationID *uuid.UUID,
		primaryLocationID *uuid.UUID,
		err error,
	)
}

type LeaveDataProvider interface {
	GetLeaveStatus(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (isOnLeave bool, isPaid bool, leaveTypeID, leaveRequestID *uuid.UUID, err error)
}

type EmployeeResolver struct {
	workCenterRepo repository.WorkCenterRepository
	scheduleRepo   repository.ScheduleRepository
	policyRepo     repository.PolicyRepository
	employeeRepo   EmployeeDataProvider
	leaveRepo      LeaveDataProvider
	tzProvider     TimezoneProvider
	logger         *zap.Logger
}

func NewEmployeeResolver(
	workCenterRepo repository.WorkCenterRepository,
	scheduleRepo repository.ScheduleRepository,
	policyRepo repository.PolicyRepository,
	employeeRepo EmployeeDataProvider,
	leaveRepo LeaveDataProvider,
	tzProvider TimezoneProvider,
	logger *zap.Logger,
) *EmployeeResolver {
	return &EmployeeResolver{
		workCenterRepo: workCenterRepo,
		scheduleRepo:   scheduleRepo,
		policyRepo:     policyRepo,
		employeeRepo:   employeeRepo,
		leaveRepo:      leaveRepo,
		tzProvider:     tzProvider,
		logger:         logger,
	}
}

// resolveCalendarForUser resolves the effective work calendar for a subject
// on a date. Fallback chain, in order of precedence:
//
//  1. Work center's location calendar (operational — where the person works).
//  2. Position's location calendar (seat — where HR assigned the role).
//  3. Employee's primary location calendar (home — where the person belongs).
//  4. Company-wide calendar (location_id IS NULL).
//  5. nil → no constraint.
func (r *EmployeeResolver) resolveCalendarForUser(
	ctx context.Context,
	companyID, subjectID uuid.UUID,
	workCenterCode *string,
	positionLocationID *uuid.UUID,
	primaryLocationID *uuid.UUID,
	date time.Time,
) *models.WorkCalendar {
	year := date.Year()

	// Step 1: work center's location
	if workCenterCode != nil && *workCenterCode != "" {
		wc, err := r.workCenterRepo.GetByCode(ctx, companyID, *workCenterCode)
		if err != nil {
			r.logger.Warn("calendar: work center lookup failed",
				zap.String("company_id", companyID.String()),
				zap.String("work_center", *workCenterCode),
				zap.Error(err),
			)
		} else if wc != nil && wc.LocationID != nil {
			cal, err := r.scheduleRepo.GetWorkCalendarByLocation(ctx, companyID, *wc.LocationID, year)
			if err != nil {
				r.logger.Warn("calendar: work center location lookup failed",
					zap.String("location_id", wc.LocationID.String()),
					zap.Int("year", year),
					zap.Error(err),
				)
			} else if cal != nil {
				return cal
			}
		}
	}

	// Step 2: position's location
	if positionLocationID != nil && *positionLocationID != uuid.Nil {
		cal, err := r.scheduleRepo.GetWorkCalendarByLocation(ctx, companyID, *positionLocationID, year)
		if err != nil {
			r.logger.Warn("calendar: position location lookup failed",
				zap.String("location_id", positionLocationID.String()),
				zap.Int("year", year),
				zap.Error(err),
			)
		} else if cal != nil {
			r.logger.Debug("calendar resolved via position location",
				zap.String("subject_id", subjectID.String()),
				zap.String("location_id", positionLocationID.String()),
				zap.String("calendar_id", cal.CalendarID.String()),
			)
			return cal
		}
	}

	// Step 3: employee's primary location
	if primaryLocationID != nil && *primaryLocationID != uuid.Nil {
		cal, err := r.scheduleRepo.GetWorkCalendarByLocation(ctx, companyID, *primaryLocationID, year)
		if err != nil {
			r.logger.Warn("calendar: primary location lookup failed",
				zap.String("location_id", primaryLocationID.String()),
				zap.Int("year", year),
				zap.Error(err),
			)
		} else if cal != nil {
			r.logger.Debug("calendar resolved via primary location",
				zap.String("subject_id", subjectID.String()),
				zap.String("location_id", primaryLocationID.String()),
				zap.String("calendar_id", cal.CalendarID.String()),
			)
			return cal
		}
	}

	// Step 4: company-wide fallback
	cal, err := r.scheduleRepo.GetWorkCalendarCompanyWide(ctx, companyID, year)
	if err != nil {
		r.logger.Warn("calendar: company-wide lookup failed",
			zap.String("company_id", companyID.String()),
			zap.Int("year", year),
			zap.Error(err),
		)
		return nil
	}
	return cal
}

func (r *EmployeeResolver) Resolve(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	date time.Time,
) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeEmployee {
		return nil, fmt.Errorf("employee resolver called with subject_type=%s", subjectType)
	}
	r.logger.Info("EmployeeResolver.Resolve called",
		zap.String("company_id", companyID.String()),
		zap.String("subject_id", subjectID.String()),
		zap.String("date", date.Format("2006-01-02")),
	)

	active, positionID, workCenterCode, positionLocationID, primaryLocationID, err :=
		r.employeeRepo.GetEmployee(ctx, companyID, subjectID, date)
	if err != nil {
		r.logger.Error("GetEmployee failed", zap.Error(err))
		return nil, fmt.Errorf("get employee: %w", err)
	}
	if !active {
		return &ResolvedSubject{IsActive: false}, nil
	}

	// ------------------------------------------------------------------
	// Schedules are derived from the rule chain: WC → shift → template.
	// ------------------------------------------------------------------
	var (
		expectedStart  *time.Time
		expectedEnd    *time.Time
		scheduleStatus = "not_schedulable"
		timezone       string
		shiftID        *uuid.UUID
	)

	// Timezone
	if timezone == "" {
		resolvedTz, tzErr := r.tzProvider.ResolveTimezone(
			ctx, companyID, positionID, workCenterCode, nil,
		)
		if tzErr != nil {
			r.logger.Warn("tz resolution failed, defaulting to UTC",
				zap.String("subject_id", subjectID.String()),
				zap.Error(tzErr),
			)
			timezone = "UTC"
		} else if resolvedTz == "" {
			timezone = "UTC"
		} else {
			timezone = resolvedTz
		}
	}

	// Derive window: WC → shift → template
	if workCenterCode != nil && *workCenterCode != "" {
		mapping, mErr := r.scheduleRepo.GetWorkCenterShiftByCode(ctx, companyID, *workCenterCode, date)
		switch {
		case mErr != nil:
			r.logger.Warn("shift mapping lookup failed",
				zap.String("work_center", *workCenterCode),
				zap.String("date", date.Format("2006-01-02")),
				zap.Error(mErr),
			)
		case mapping == nil:
			r.logger.Debug("no shift mapping for date",
				zap.String("work_center", *workCenterCode),
				zap.String("date", date.Format("2006-01-02")),
			)
		default:
			tmpl, tErr := r.scheduleRepo.GetScheduleTemplateOnDate(ctx, mapping.ShiftID, date)
			if tErr != nil || tmpl == nil {
				r.logger.Warn("template not found for date",
					zap.String("shift_id", mapping.ShiftID.String()),
					zap.String("date", date.Format("2006-01-02")),
					zap.Error(tErr),
				)
				break
			}
			start, end, cErr := calculateExpectedTimes(date, tmpl, timezone)
			if cErr != nil {
				r.logger.Warn("expected times failed",
					zap.String("template_id", tmpl.ScheduleTemplateID.String()),
					zap.String("template_type", tmpl.TemplateType),
					zap.Error(cErr),
				)
				break
			}
			expectedStart = start
			expectedEnd = end
			scheduleStatus = "working"
			id := mapping.ShiftID
			shiftID = &id
			r.logger.Debug("schedule resolved via WC shift mapping",
				zap.String("subject_id", subjectID.String()),
				zap.String("work_center", *workCenterCode),
				zap.String("template_id", tmpl.ScheduleTemplateID.String()),
				zap.String("date", date.Format("2006-01-02")),
			)
		}
	}

	// Calendar enforcement
	if cal := r.resolveCalendarForUser(ctx, companyID, subjectID, workCenterCode, positionLocationID, primaryLocationID, date); cal != nil {
		switch {
		case cal.IsHoliday(date):
			scheduleStatus = "holiday"
			expectedStart = nil
			expectedEnd = nil
			r.logger.Debug("calendar marks date as holiday",
				zap.String("subject_id", subjectID.String()),
				zap.String("date", date.Format("2006-01-02")),
				zap.String("calendar_id", cal.CalendarID.String()),
			)
		case !cal.IsWorkingDay(date):
			scheduleStatus = "weekly_off"
			expectedStart = nil
			expectedEnd = nil
			r.logger.Debug("calendar marks date as non-working weekday",
				zap.String("subject_id", subjectID.String()),
				zap.String("date", date.Format("2006-01-02")),
				zap.String("calendar_id", cal.CalendarID.String()),
				zap.Int("weekday", int(date.Weekday())),
			)
		}
	}

	// Leave
	isOnLeave := false
	isLeavePaid := false
	var leaveTypeID, leaveRequestID *uuid.UUID
	if r.leaveRepo != nil {
		onLeave, paid, ltID, lrID, err := r.leaveRepo.GetLeaveStatus(ctx, companyID, subjectID, date)
		if err == nil {
			isOnLeave = onLeave
			isLeavePaid = paid
			leaveTypeID = ltID
			leaveRequestID = lrID
		} else {
			r.logger.Warn("GetLeaveStatus failed", zap.Error(err))
		}
	}
	if isOnLeave {
		scheduleStatus = "on_leave"
	}

	// Policy — date-scoped lookups so a backdated correction uses the
	// policy in force on the day being resolved, not today's.
	var policyID *uuid.UUID
	var policyCode, policyType *string
	var policyRules interface{}

	userPolicy, err := r.policyRepo.GetUserActivePolicy(ctx, subjectID, date)
	if err == nil && userPolicy != nil {
		policyID = &userPolicy.PolicyID
		policyCode = &userPolicy.PolicyCode
		policyType = &userPolicy.PolicyType
		policyRules = userPolicy.Rules
	} else if workCenterCode != nil {
		wcPolicy, err := r.policyRepo.GetWorkCenterPolicyOnDate(ctx, companyID, *workCenterCode, date)
		if err == nil && wcPolicy != nil {
			policyID = &wcPolicy.PolicyID
			policyCode = &wcPolicy.PolicyCode
			policyType = &wcPolicy.PolicyType
			policyRules = wcPolicy.Rules
		}
	} else if positionID != nil {
		posPolicy, err := r.policyRepo.GetPositionPolicyOnDate(ctx, *positionID, date)
		if err == nil && posPolicy != nil {
			policyID = &posPolicy.PolicyID
			policyCode = &posPolicy.PolicyCode
			policyType = &posPolicy.PolicyType
			policyRules = posPolicy.Rules
		}
	}

	// Override — wins over everything.
	//
	// custom_hours stores wall-clock strings ("09:00:00"). We combine them
	// with the day's calendar date and the resolved timezone to build real
	// instants. This is why the row does not store a timestamp — if the
	// user's WC or location timezone changes, past overrides re-interpret
	// in the new tz, which is the correct SAP-aligned behavior.
	var isOverride bool
	var overrideType *string
	override, err := r.scheduleRepo.GetScheduleOverrideByUserDate(ctx, subjectID, date)
	if err == nil && override != nil {
		isOverride = true
		overrideType = &override.OverrideType
		switch override.OverrideType {
		case "off":
			scheduleStatus = "weekly_off"
			expectedStart = nil
			expectedEnd = nil
		case "force_work":
			// Calendar may have cleared the window (weekend/holiday).
			// Recompute from the template so downstream metrics have a
			// real expected_minutes.
			if expectedStart == nil && workCenterCode != nil {
				if m, mErr := r.scheduleRepo.GetWorkCenterShiftByCode(ctx, companyID, *workCenterCode, date); mErr == nil && m != nil {
					if tmpl, tErr := r.scheduleRepo.GetScheduleTemplateOnDate(ctx, m.ShiftID, date); tErr == nil && tmpl != nil {
						if s2, e2, cErr := calculateExpectedTimes(date, tmpl, timezone); cErr == nil {
							expectedStart = s2
							expectedEnd = e2
						}
					}
				}
			}
			scheduleStatus = "working"
		case "holiday_override":
			scheduleStatus = "holiday"
			expectedStart = nil
			expectedEnd = nil
		case "custom_hours":
			scheduleStatus = "working"
			if override.ExpectedStart != nil && override.ExpectedEnd != nil {
				loc, lerr := time.LoadLocation(timezone)
				if lerr != nil || loc == nil {
					loc = time.UTC
				}
				s2, sErr := ParseWallClock(date, *override.ExpectedStart, loc)
				e2, eErr := ParseWallClock(date, *override.ExpectedEnd, loc)
				if sErr == nil && eErr == nil {
					if !e2.After(s2) {
						// window crosses midnight
						e2 = e2.AddDate(0, 0, 1)
					}
					expectedStart = &s2
					expectedEnd = &e2
				} else {
					r.logger.Warn("custom_hours: invalid wall clock",
						zap.String("start", *override.ExpectedStart),
						zap.String("end", *override.ExpectedEnd),
						zap.String("tz", timezone),
						zap.Error(sErr))
				}
			}
		}
	}

	return &ResolvedSubject{
		IsActive:       active,
		Timezone:       timezone,
		ScheduleStatus: scheduleStatus,
		ExpectedStart:  expectedStart,
		ExpectedEnd:    expectedEnd,
		ShiftID:        shiftID,
		WorkCenterCode: workCenterCode,
		PositionID:     positionID,
		IsOnLeave:      isOnLeave,
		IsLeavePaid:    isLeavePaid,
		LeaveTypeID:    leaveTypeID,
		LeaveRequestID: leaveRequestID,
		IsOverride:     isOverride,
		OverrideType:   overrideType,
		PolicyID:       policyID,
		PolicyCode:     policyCode,
		PolicyType:     policyType,
		PolicyRules:    policyRules,
	}, nil
}

// calculateExpectedTimes returns the start/end window for a template on a
// given calendar day in the supplied timezone.
func calculateExpectedTimes(
	date time.Time,
	template *models.ScheduleTemplate,
	timezone string,
) (*time.Time, *time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil || loc == nil {
		loc = time.UTC
	}
	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, loc)

	var start, end time.Time
	switch template.TemplateType {
	case "office":
		if template.Rules.StartTime == nil || template.Rules.EndTime == nil {
			return nil, nil, fmt.Errorf("office template missing start_time/end_time")
		}
		startClock, err := time.Parse("15:04", *template.Rules.StartTime)
		if err != nil {
			return nil, nil, fmt.Errorf("parse start_time: %w", err)
		}
		endClock, err := time.Parse("15:04", *template.Rules.EndTime)
		if err != nil {
			return nil, nil, fmt.Errorf("parse end_time: %w", err)
		}
		start = time.Date(day.Year(), day.Month(), day.Day(), startClock.Hour(), startClock.Minute(), 0, 0, loc)
		end = time.Date(day.Year(), day.Month(), day.Day(), endClock.Hour(), endClock.Minute(), 0, 0, loc)
		if !end.After(start) {
			end = end.AddDate(0, 0, 1)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported template type: %s", template.TemplateType)
	}
	return &start, &end, nil
}

// ParseClockString parses "HH:MM" or "HH:MM:SS" and returns the time-of-day
// component. Used by both the resolver and the scheduling service when
// combining a custom_hours override with the day's calendar date and tz.
func ParseClockString(hhmm string) (time.Time, error) {
	layout := "15:04:05"
	if len(hhmm) == 5 {
		layout = "15:04"
	}
	return time.Parse(layout, hhmm)
}

// ParseWallClock combines a calendar date and an "HH:MM" / "HH:MM:SS"
// string into an instant in the given location.
//
// NOTE: This duplicates the same helper in service/scheduling. Both packages
// need it and neither depends on the other. If a third caller shows up, move
// it to a shared internal/util package.
func ParseWallClock(date time.Time, hhmm string, loc *time.Location) (time.Time, error) {
	clock, err := ParseClockString(hhmm)
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(
		date.Year(), date.Month(), date.Day(),
		clock.Hour(), clock.Minute(), clock.Second(), 0, loc,
	), nil
}
