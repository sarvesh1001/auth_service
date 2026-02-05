package models

type PayrollComponent struct {
	ComponentCode string `json:"component_code" db:"component_code"`
	ComponentType string `json:"component_type" db:"component_type"`
	Description   string `json:"description,omitempty" db:"description"`
	IsTaxable     bool   `json:"is_taxable" db:"is_taxable"`
	IsSystem      bool   `json:"is_system" db:"is_system"`
	IsActive      bool   `json:"is_active" db:"is_active"`
}

type ComponentFilter struct {
	ComponentType *string
	IsTaxable     *bool
	IsSystem      *bool
	IsActive      *bool
}
