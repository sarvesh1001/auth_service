package enums

type FulfillmentPolicy string

const (
	FulfillmentInventoryRequired FulfillmentPolicy = "inventory_required"
	FulfillmentAllowBackorder    FulfillmentPolicy = "allow_backorder"
	FulfillmentMadeToOrder       FulfillmentPolicy = "made_to_order"
	FulfillmentDropship          FulfillmentPolicy = "dropship"
	FulfillmentServiceOnly       FulfillmentPolicy = "service_only"
	FulfillmentDigitalDelivery   FulfillmentPolicy = "digital_delivery" // NEW
	FulfillmentExternalVendor    FulfillmentPolicy = "external_vendor"  // NEW

)

func ValidFulfillmentPolicies() []FulfillmentPolicy {
	return []FulfillmentPolicy{
		FulfillmentInventoryRequired,
		FulfillmentAllowBackorder,
		FulfillmentMadeToOrder,
		FulfillmentDropship,
		FulfillmentServiceOnly,
		FulfillmentDigitalDelivery, // added
		FulfillmentExternalVendor,  // added
	}
}

func (f FulfillmentPolicy) IsValid() bool {
	switch f {
	case FulfillmentInventoryRequired, FulfillmentAllowBackorder,
		FulfillmentMadeToOrder, FulfillmentDropship, FulfillmentServiceOnly,
		FulfillmentDigitalDelivery, FulfillmentExternalVendor: // added
		return true
	}
	return false
}
