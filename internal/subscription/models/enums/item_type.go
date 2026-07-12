package enums

type ItemType string

const (
	ItemTypeBase     ItemType = "base"
	ItemTypeAddon    ItemType = "addon"
	ItemTypeBenefit  ItemType = "benefit"
	ItemTypeDiscount ItemType = "discount"
	ItemTypeTax      ItemType = "tax"
)

func (t ItemType) IsValid() bool {
	switch t {
	case ItemTypeBase, ItemTypeAddon, ItemTypeBenefit, ItemTypeDiscount, ItemTypeTax:
		return true
	}
	return false
}
