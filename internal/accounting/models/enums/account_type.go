package enums

const (
	AccountTypeAsset     = "asset"
	AccountTypeLiability = "liability"
	AccountTypeEquity    = "equity"
	AccountTypeRevenue   = "revenue"
	AccountTypeExpense   = "expense"
)

var ValidAccountTypes = []string{
	AccountTypeAsset, AccountTypeLiability, AccountTypeEquity,
	AccountTypeRevenue, AccountTypeExpense,
}
