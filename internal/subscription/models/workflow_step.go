package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type WorkflowStep struct {
	StepID        uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	WorkflowID    uuid.UUID      `gorm:"type:uuid;not null;index"`
	StepOrder     int            `gorm:"not null"`
	StepType      string         `gorm:"size:30;not null"`
	Config        datatypes.JSON `gorm:"type:jsonb;not null"`
	DependsOnStep *uuid.UUID     `gorm:"type:uuid"`
	CreatedAt     time.Time      `gorm:"not null;default:now()"`

	Workflow    Workflow       `gorm:"foreignKey:WorkflowID"`
	Dependency  *WorkflowStep  `gorm:"foreignKey:DependsOnStep"`
}

func (WorkflowStep) TableName() string { return "workflow_steps" }
