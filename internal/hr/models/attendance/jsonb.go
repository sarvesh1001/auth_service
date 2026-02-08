package attendance

// or package attendance IF you want it local (see note below)

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSONB represents a PostgreSQL JSONB column
type JSONB map[string]interface{}

// Value implements driver.Valuer (for INSERT/UPDATE)
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(j)
}

// Scan implements sql.Scanner (for SELECT)
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONB)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid JSONB value")
	}

	return json.Unmarshal(bytes, j)
}
