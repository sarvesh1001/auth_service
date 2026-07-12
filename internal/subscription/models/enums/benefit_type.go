package enums

type BenefitType string

const (
	BenefitDiscount BenefitType = "discount"
	BenefitFreebie  BenefitType = "freebie"
	BenefitAccess   BenefitType = "access"
	BenefitService  BenefitType = "service"
	BenefitOther    BenefitType = "other"
)

func (b BenefitType) IsValid() bool {
	switch b {
	case BenefitDiscount, BenefitFreebie, BenefitAccess, BenefitService, BenefitOther:
		return true
	}
	return false
}
