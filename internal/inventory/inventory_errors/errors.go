package inventory_errors

import "errors"

var (
	ErrNotFound                    = errors.New("record not found")
	ErrInvalidInput                = errors.New("invalid input")
	ErrPermissionDenied            = errors.New("permission denied")
	ErrDuplicate                   = errors.New("duplicate record")
	ErrInsufficientStock           = errors.New("insufficient stock")
	ErrInsufficientFilter          = errors.New("insufficient filter: provide at least warehouse_id or item_id")
	ErrConflict                    = errors.New("conflict")
	ErrExpiryInPast                = errors.New("expiry date must be in the future")
	ErrInvalidStatus               = errors.New("invalid status value")
	ErrInvalidTransition           = errors.New("invalid status transition")
	ErrReorderSkipped              = errors.New("reorder skipped")
	ErrReorderLevelNotMet          = errors.New("stock above reorder level")
	ErrOpenReorderExists           = errors.New("open reorder order already exists")
	ErrInactiveBOM                 = errors.New("BOM is inactive")
	ErrInvalidProductionCompletion = errors.New("invalid production completion data")
	ErrParentWarehouseMismatch     = errors.New("parent location must belong to the same warehouse") // NEW

	EventDropshipRequired     = "inventory.dropship.required"
	EventFulfillmentBackorder = "inventory.fulfillment.backorder"
)

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func IsInvalidInput(err error) bool {
	return errors.Is(err, ErrInvalidInput)
}

func IsPermissionDenied(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

func IsDuplicate(err error) bool {
	return errors.Is(err, ErrDuplicate)
}

func IsInsufficientStock(err error) bool {
	return errors.Is(err, ErrInsufficientStock)
}

func IsInsufficientFilter(err error) bool {
	return errors.Is(err, ErrInsufficientFilter)
}

func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

func IsExpiryInPast(err error) bool {
	return errors.Is(err, ErrExpiryInPast)
}

func IsInvalidStatus(err error) bool {
	return errors.Is(err, ErrInvalidStatus)
}

func IsInvalidTransition(err error) bool {
	return errors.Is(err, ErrInvalidTransition)
}

func IsReorderSkipped(err error) bool {
	return errors.Is(err, ErrReorderSkipped)
}

func IsReorderLevelNotMet(err error) bool {
	return errors.Is(err, ErrReorderLevelNotMet)
}

func IsOpenReorderExists(err error) bool {
	return errors.Is(err, ErrOpenReorderExists)
}

func IsInactiveBOM(err error) bool {
	return errors.Is(err, ErrInactiveBOM)
}

// Optional helper for parent warehouse mismatch
func IsParentWarehouseMismatch(err error) bool {
	return errors.Is(err, ErrParentWarehouseMismatch)
}
