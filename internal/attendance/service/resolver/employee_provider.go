package resolver

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
	hrRepository "auth-service/internal/hr/repository"
)

type employeeDataProvider struct {
	employeeRepo hrRepository.EmployeeRepository
	scheduleRepo repository.ScheduleRepository
	logger       *zap.Logger
}

func NewEmployeeDataProvider(
	employeeRepo hrRepository.EmployeeRepository,
	scheduleRepo repository.ScheduleRepository,
	logger *zap.Logger,
) EmployeeDataProvider {
	return &employeeDataProvider{
		employeeRepo: employeeRepo,
		scheduleRepo: scheduleRepo,
		logger:       logger,
	}
}

// GetEmployee returns the employee's resolved facts for a specific date.
//
// The date parameter is mandatory. Every "where was this person" fact comes
// from a date-scoped history table:
//
//   - hr.employee_assignment_history  → position_id, primary_location_id
//   - hr.position_history             → work_center_code, position location
//
// If history has no row for the date, we fall back to the current
// company_employees / positions row. That covers pre-migration data only;
// after the backfill every date has a history row.
func (p *employeeDataProvider) GetEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) (
	active bool,
	positionID *uuid.UUID,
	workCenterCode *string,
	positionLocationID *uuid.UUID,
	primaryLocationID *uuid.UUID,
	err error,
) {
	p.logger.Info("GetEmployee called",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
		zap.String("date", date.Format("2006-01-02")),
	)

	// 1. Active check — reads the current membership row. A person who has
	//    left the company should not resolve, regardless of history.
	ce, err := p.employeeRepo.GetCompanyEmployeeByUserID(ctx, userID)
	if err != nil {
		p.logger.Error("GetCompanyEmployeeByUserID failed", zap.Error(err))
		return false, nil, nil, nil, nil, err
	}
	if ce == nil || !ce.IsActive {
		p.logger.Warn("Employee not found or inactive",
			zap.String("user_id", userID.String()))
		return false, nil, nil, nil, nil, nil
	}
	active = true

	// 2. Date-scoped assignment (position + primary location).
	assignment, aErr := p.scheduleRepo.GetEmployeeAssignmentOnDate(
		ctx, companyID, userID, date)
	if aErr != nil {
		p.logger.Warn("GetEmployeeAssignmentOnDate failed",
			zap.String("user_id", userID.String()),
			zap.String("date", date.Format("2006-01-02")),
			zap.Error(aErr))
	}
	if assignment != nil {
		positionID = assignment.PositionID
		primaryLocationID = assignment.PrimaryLocationID
	} else {
		// Pre-migration fallback: no history row yet. Use current state
		// and log it. This branch should disappear after backfill.
		p.logger.Warn("no employee_assignment_history row for date; using current row",
			zap.String("user_id", userID.String()),
			zap.String("date", date.Format("2006-01-02")))
		if ce.PositionID != nil && *ce.PositionID != uuid.Nil {
			positionID = ce.PositionID
		}
		if ce.PrimaryLocationID != nil && *ce.PrimaryLocationID != uuid.Nil {
			primaryLocationID = ce.PrimaryLocationID
		}
	}

	// 3. Position's work_center_code and location_id as of `date`.
	if positionID != nil && *positionID != uuid.Nil {
		posHist, pErr := p.scheduleRepo.GetPositionOnDate(ctx, *positionID, date)
		if pErr != nil {
			p.logger.Warn("GetPositionOnDate failed",
				zap.String("position_id", positionID.String()),
				zap.String("date", date.Format("2006-01-02")),
				zap.Error(pErr))
		}
		if posHist != nil {
			workCenterCode = posHist.WorkCenterCode
			positionLocationID = posHist.LocationID
		} else {
			// Pre-migration fallback: read the current positions row.
			p.logger.Warn("no position_history row for date; using current row",
				zap.String("position_id", positionID.String()),
				zap.String("date", date.Format("2006-01-02")))
			pos, posErr := p.employeeRepo.GetPositionByID(ctx, *positionID)
			if posErr != nil {
				p.logger.Error("GetPositionByID failed", zap.Error(posErr))
			} else if pos != nil {
				workCenterCode = pos.WorkCenterCode
				positionLocationID = pos.LocationID
			}
		}
	} else {
		p.logger.Warn("employee has no position on date",
			zap.String("user_id", userID.String()),
			zap.String("date", date.Format("2006-01-02")))
	}

	p.logger.Info("GetEmployee result",
		zap.Bool("active", active),
		zap.String("position_id", uuidPtrString(positionID)),
		zap.String("work_center_code", strPtrString(workCenterCode)),
		zap.String("position_location_id", uuidPtrString(positionLocationID)),
		zap.String("primary_location_id", uuidPtrString(primaryLocationID)),
	)
	return active, positionID, workCenterCode, positionLocationID, primaryLocationID, nil
}

func uuidPtrString(id *uuid.UUID) string {
	if id == nil {
		return "<nil>"
	}
	return id.String()
}

func strPtrString(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
