package sqltypes

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSON is a JSON_TEXT column: raw JSON stored as TEXT, so SQL defaults such as '{}' read back
// (database/sql cannot scan TEXT into json.RawMessage) and SQLite's json functions accept it.
// It marshals as raw JSON, like json.RawMessage.
type JSON []byte

func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return string(j), nil
}

func (j *JSON) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*j = nil
	case string:
		*j = JSON(v)
	case []byte:
		*j = append(JSON(nil), v...)
	default:
		return fmt.Errorf("sqltypes.JSON: cannot scan %T", src)
	}
	return nil
}

func (j JSON) MarshalJSON() ([]byte, error) { return json.RawMessage(j).MarshalJSON() }

func (j *JSON) UnmarshalJSON(b []byte) error { return (*json.RawMessage)(j).UnmarshalJSON(b) }
