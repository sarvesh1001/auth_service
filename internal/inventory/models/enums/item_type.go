package enums

type ItemType string

const (
	ItemTypeRawMaterial  ItemType = "raw_material"
	ItemTypeFinishedGood ItemType = "finished_good"
	ItemTypeSubAssembly  ItemType = "sub_assembly"
	ItemTypeConsumable   ItemType = "consumable"
	ItemTypeService      ItemType = "service"
)

// ValidItemTypes returns all valid item types.
func ValidItemTypes() []ItemType {
	return []ItemType{
		ItemTypeRawMaterial,
		ItemTypeFinishedGood,
		ItemTypeSubAssembly,
		ItemTypeConsumable,
		ItemTypeService,
	}
}

// IsValid checks if the item type is valid.
func (t ItemType) IsValid() bool {
	switch t {
	case ItemTypeRawMaterial, ItemTypeFinishedGood, ItemTypeSubAssembly, ItemTypeConsumable, ItemTypeService:
		return true
	}
	return false
}

func (t ItemType) String() string {
	return string(t)
}
