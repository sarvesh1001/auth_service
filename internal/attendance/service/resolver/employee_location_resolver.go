package resolver

import (
	"context"

	"github.com/google/uuid"

	hrRepo "auth-service/internal/hr/repository"
)

type employeeLocationResolver struct {
	employeeRepo hrRepo.EmployeeRepository
}

// NewEmployeeLocationResolver wraps HR's EmployeeRepository.
// GetEmploymentLocationID already exists on that interface.
func NewEmployeeLocationResolver(employeeRepo hrRepo.EmployeeRepository) SubjectLocationResolver {
	return &employeeLocationResolver{employeeRepo: employeeRepo}
}

func (r *employeeLocationResolver) ResolveLocation(
	ctx context.Context,
	companyID uuid.UUID,
	_ string,
	subjectID uuid.UUID,
) (*uuid.UUID, error) {
	return r.employeeRepo.GetEmploymentLocationID(ctx, companyID, subjectID)
}
