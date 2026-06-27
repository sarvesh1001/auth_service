package models

import (
	"time"

	"github.com/google/uuid"
)

type Workflow struct {
	WorkflowID   uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID    uuid.UUID `gorm:"type:uuid;not null;index"`
	WorkflowName string    `gorm:"size:100;not null"`
	TriggerEvent string    `gorm:"size:50;not null;index"`
	IsActive     bool      `gorm:"not null;default:true"`
	CreatedAt    time.Time `gorm:"not null;default:now()"`
	UpdatedAt    time.Time `gorm:"not null;default:now()"`

	Company Company        `gorm:"foreignKey:CompanyID"`
	Steps   []WorkflowStep `gorm:"foreignKey:WorkflowID"`
}

func (Workflow) TableName() string { return "workflows" }
