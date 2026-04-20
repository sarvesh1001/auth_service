package enums

type MovementType string

const (
	MovementTypePurchaseIn    MovementType = "purchase_in"
	MovementTypeSalesOut      MovementType = "sales_out"
	MovementTypeProductionIn  MovementType = "production_in"
	MovementTypeReturnIn      MovementType = "return_in"
	MovementTypeReturnOut     MovementType = "return_out"
	MovementTypeAdjustmentIn  MovementType = "adjustment_in"
	MovementTypeAdjustmentOut MovementType = "adjustment_out"
	MovementTypeTransfer      MovementType = "transfer"
)

// ValidMovementTypes returns all valid movement types.
func ValidMovementTypes() []MovementType {
	return []MovementType{
		MovementTypePurchaseIn,
		MovementTypeSalesOut,
		MovementTypeProductionIn,
		MovementTypeReturnIn,
		MovementTypeReturnOut,
		MovementTypeAdjustmentIn,
		MovementTypeAdjustmentOut,
		MovementTypeTransfer,
	}
}

// IsValid checks if the movement type is valid.
func (m MovementType) IsValid() bool {
	switch m {
	case MovementTypePurchaseIn, MovementTypeSalesOut, MovementTypeProductionIn,
		MovementTypeReturnIn, MovementTypeReturnOut, MovementTypeAdjustmentIn,
		MovementTypeAdjustmentOut, MovementTypeTransfer:
		return true
	}
	return false
}

// IsInbound returns true if the movement increases stock.
func (m MovementType) IsInbound() bool {
	switch m {
	case MovementTypePurchaseIn, MovementTypeProductionIn, MovementTypeReturnIn, MovementTypeAdjustmentIn:
		return true
	default:
		return false
	}
}

// IsOutbound returns true if the movement decreases stock.
func (m MovementType) IsOutbound() bool {
	switch m {
	case MovementTypeSalesOut, MovementTypeReturnOut, MovementTypeAdjustmentOut, MovementTypeTransfer:
		return true
	default:
		return false
	}
}

func (m MovementType) String() string {
	return string(m)
}
