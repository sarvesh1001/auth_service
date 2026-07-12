// FILE: models/plan_version.go

package models

import (
	"time"

	"github.com/google/uuid"
)

// PlanVersion stores historical snapshots of a plan configuration.
// Each version is immutable once created.
type PlanVersion struct {
	VersionID     uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"versionId"`
	CompanyID     uuid.UUID `gorm:"type:uuid;not null;index" json:"companyId"`
	PlanID        uuid.UUID `gorm:"type:uuid;not null;index" json:"planId"`
	VersionNumber int       `gorm:"not null" json:"versionNumber"`
	Snapshot      JSONB     `gorm:"type:jsonb;not null" json:"snapshot"` // full plan configuration at that version

	IsPublished bool       `gorm:"not null;default:false" json:"isPublished"`
	PublishedAt *time.Time `gorm:"type:timestamptz" json:"publishedAt,omitempty"`
	PublishedBy *uuid.UUID `gorm:"type:uuid" json:"publishedBy,omitempty"`

	CreatedAt time.Time  `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt *time.Time `gorm:"index" json:"deletedAt,omitempty"`
}
