package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm" // ✅ added import
)

// Placeholder for Company (from companies module)
type Company struct {
	CompanyID uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

func (Company) TableName() string { return "companies" }

// Placeholder for User (from users module)
type User struct {
	UserID    uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Username  string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

func (User) TableName() string { return "users" }
