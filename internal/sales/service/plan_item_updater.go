package service

import (
	"context"

	"github.com/google/uuid"
)

// PlanItemUpdater defines the method to update a plan item's product ID.
// This is implemented by the subscription service.
type PlanItemUpdater interface {
	UpdatePlanItemProductID(ctx context.Context, planItemID, productID uuid.UUID) error
}
