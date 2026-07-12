#!/bin/bash
# setup_models_fix.sh – Adds missing models and fixes compile errors
# Run from the subscription module root.

set -e

# ============================================================
# 1. MISSING LOOKUP MODELS
# ============================================================

cat > models/plan_type.go <<'EOF'
package models

import (
	"time"
)

type PlanType struct {
	PlanTypeID int16     `gorm:"primaryKey" json:"planTypeId"`
	Code       string    `gorm:"type:varchar(30);not null;unique" json:"code"`
	Name       string    `gorm:"type:varchar(100);not null" json:"name"`
	CreatedAt  time.Time `gorm:"default:now()" json:"createdAt"`
}
EOF

cat > models/billing_frequency.go <<'EOF'
package models

import (
	"time"
)

type BillingFrequency struct {
	FrequencyID int16     `gorm:"primaryKey" json:"frequencyId"`
	Code        string    `gorm:"type:varchar(20);not null;unique" json:"code"`
	Name        string    `gorm:"type:varchar(50);not null" json:"name"`
	CreatedAt   time.Time `gorm:"default:now()" json:"createdAt"`
}
EOF

cat > models/pricing_model.go <<'EOF'
package models

import (
	"time"
)

type PricingModel struct {
	ModelID   int16     `gorm:"primaryKey" json:"modelId"`
	Code      string    `gorm:"type:varchar(30);not null;unique" json:"code"`
	Name      string    `gorm:"type:varchar(100);not null" json:"name"`
	CreatedAt time.Time `gorm:"default:now()" json:"createdAt"`
}
EOF

cat > models/status.go <<'EOF'
package models

import (
	"time"
)

type Status struct {
	StatusID  int16     `gorm:"primaryKey" json:"statusId"`
	Code      string    `gorm:"type:varchar(30);not null" json:"code"`
	Category  string    `gorm:"type:varchar(30);not null" json:"category"`
	Name      string    `gorm:"type:varchar(100);not null" json:"name"`
	CreatedAt time.Time `gorm:"default:now()" json:"createdAt"`
}
EOF

# ============================================================
# 2. MISSING ENUM – BENEFIT TYPE
# ============================================================

cat > models/enums/benefit_type.go <<'EOF'
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
EOF

# ============================================================
# 3. FIX BENEFIT.GO TO USE ENUM
# ============================================================

cat > models/benefit.go <<'EOF'
package models

import (
	"time"
	"github.com/google/uuid"
	"auth-service/internal/subscription/models/enums"
)

type Benefit struct {
	BenefitID          uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"benefitId"`
	PlanItemID         uuid.UUID          `gorm:"type:uuid;not null;index" json:"planItemId"`
	BenefitType        enums.BenefitType  `gorm:"type:varchar(50);not null" json:"benefitType"`
	BenefitDescription *string            `gorm:"type:text" json:"benefitDescription,omitempty"`
	Value              JSONB              `gorm:"type:jsonb;not null" json:"value"`
	CreatedAt          time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt          time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
}
EOF

# ============================================================
# 4. FIX COMPILATION ISSUES
# ============================================================

# Fix usage_remaining.go: add missing imports
cat > models/usage_remaining.go <<'EOF'
package models

import (
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// UsageRemaining is a view model, not persisted.
type UsageRemaining struct {
	SubItemID     uuid.UUID        `gorm:"column:sub_item_id" json:"subItemId"`
	SubscriptionID uuid.UUID       `gorm:"column:subscription_id" json:"subscriptionId"`
	PlanItemID    uuid.UUID        `gorm:"column:plan_item_id" json:"planItemId"`
	FeatureKey    string           `gorm:"column:feature_key" json:"featureKey"`
	TotalAllowed  *decimal.Decimal `gorm:"column:total_allowed" json:"totalAllowed,omitempty"`
	Used          decimal.Decimal  `gorm:"column:used" json:"used"`
	Remaining     decimal.Decimal  `gorm:"column:remaining" json:"remaining"`
}
EOF

# Fix feature_registry.go: remove unused import
cat > models/feature_registry.go <<'EOF'
package models

import (
	"time"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
)

type FeatureRegistry struct {
	FeatureKey     string          `gorm:"type:varchar(100);primaryKey" json:"featureKey"`
	Module         string          `gorm:"type:varchar(50);not null" json:"module"`
	FeatureGroup   *string         `gorm:"type:varchar(50)" json:"featureGroup,omitempty"`
	PermissionScope *string        `gorm:"type:varchar(50)" json:"permissionScope,omitempty"`
	Description    *string         `gorm:"type:text" json:"description,omitempty"`
	DefaultLimit   *decimal.Decimal `gorm:"type:numeric(14,4)" json:"defaultLimit,omitempty"`
	DependsOn      datatypes.JSON  `gorm:"type:jsonb" json:"dependsOn,omitempty"`
	Version        int             `gorm:"not null;default:1" json:"version"`
	IsActive       bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt      time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
}
EOF

# ============================================================
# 5. FIX ANALYTICS MODELS – add import and prefix JSONB
# ============================================================

for f in models/analytics/*.go; do
    # Check if file uses JSONB and does not already import the models package
    if grep -q "JSONB" "$f" && ! grep -q '"auth-service/internal/subscription/models"' "$f"; then
        # Replace JSONB with models.JSONB
        sed -i.bak 's/\bJSONB\b/models.JSONB/g' "$f"
        # Insert import after package line using awk
        awk '/^package analytics/ { print; print "import \"auth-service/internal/subscription/models\""; next } 1' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
        rm -f "$f.bak"
    fi
done

echo "✅ All missing models created and fixes applied."