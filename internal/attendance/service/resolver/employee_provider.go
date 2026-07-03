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

func (p *employeeDataProvider) GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (active bool, positionID *uuid.UUID, workCenterCode *string, err error) {
	p.logger.Info("GetEmployee called",
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
	)

	// 1. Get company employee record
	ce, err := p.employeeRepo.GetCompanyEmployeeByUserID(ctx, userID)
	if err != nil {
		p.logger.Error("GetCompanyEmployeeByUserID failed", zap.Error(err))
		return false, nil, nil, err
	}
	if ce == nil {
		p.logger.Warn("CompanyEmployee not found", zap.String("user_id", userID.String()))
		return false, nil, nil, nil
	}
	if !ce.IsActive {
		p.logger.Warn("Employee is inactive", zap.String("user_id", userID.String()))
		return false, nil, nil, nil
	}
	active = true
	p.logger.Info("CompanyEmployee found",
		zap.String("employee_id", ce.EmployeeID),
		zap.String("position_id", func() string {
			if ce.PositionID != nil {
				return ce.PositionID.String()
			}
			return "<nil>"
		}()),
	)

	// 2. Get position if available
	if ce.PositionID != nil {
		positionID = ce.PositionID
		p.logger.Info("Fetching position", zap.String("position_id", positionID.String()))
		pos, err := p.employeeRepo.GetPositionByID(ctx, *positionID)
		if err != nil {
			p.logger.Error("GetPositionByID failed", zap.Error(err), zap.String("position_id", positionID.String()))
			// Continue without work center
		} else if pos != nil {
			workCenterCode = pos.WorkCenterCode
			p.logger.Info("Position fetched successfully",
				zap.String("position_id", positionID.String()),
				zap.String("work_center", func() string {
					if workCenterCode != nil {
						return *workCenterCode
					}
					return "<nil>"
				}()),
			)
		} else {
			p.logger.Warn("Position not found (nil)", zap.String("position_id", positionID.String()))
		}
	} else {
		p.logger.Warn("Employee has no position_id", zap.String("user_id", userID.String()))
	}

	// 3. Fallback to work center assignment
	if workCenterCode == nil {
		assigned, err := p.scheduleRepo.GetUserWorkCenterAssignment(ctx, userID, time.Now())
		if err == nil && assigned != nil {
			workCenterCode = &assigned.WorkCenterCode
			p.logger.Info("Work center from assignment", zap.String("work_center", *workCenterCode))
		} else {
			if err != nil {
				p.logger.Warn("GetUserWorkCenterAssignment error", zap.Error(err))
			} else {
				p.logger.Warn("No work center assignment found")
			}
		}
	}

	p.logger.Info("GetEmployee result",
		zap.Bool("active", active),
		zap.String("position_id", func() string {
			if positionID != nil {
				return positionID.String()
			}
			return "<nil>"
		}()),
		zap.String("work_center_code", func() string {
			if workCenterCode != nil {
				return *workCenterCode
			}
			return "<nil>"
		}()),
	)

	return active, positionID, workCenterCode, nil
}

func (p *employeeDataProvider) GetWorkCenterAssignment(ctx context.Context, userID uuid.UUID, date time.Time) (workCenterCode *string, err error) {
	p.logger.Debug("GetWorkCenterAssignment called",
		zap.String("user_id", userID.String()),
		zap.String("date", date.Format("2006-01-02")),
	)
	assignment, err := p.scheduleRepo.GetUserWorkCenterAssignment(ctx, userID, date)
	if err != nil {
		p.logger.Error("GetUserWorkCenterAssignment failed", zap.Error(err))
		return nil, err
	}
	if assignment != nil {
		p.logger.Info("Work center assignment found", zap.String("work_center", assignment.WorkCenterCode))
		return &assignment.WorkCenterCode, nil
	}
	p.logger.Warn("No work center assignment found for user", zap.String("user_id", userID.String()))
	return nil, nil
}
