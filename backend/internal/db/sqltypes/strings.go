// Package sqltypes holds Go types for SQLite columns that PostgreSQL stored natively.
package sqltypes

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Strings is a TEXT_LIST column: a JSON array of strings. Queries read it with json_each.
type Strings []string

// Value writes nil as [] so NOT NULL columns accept it.
func (s Strings) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(s))
	return string(b), err
}

// Scan reads NULL as nil and a JSON array as a non-nil slice (empty for []), like pgx did for TEXT[].
func (s *Strings) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case nil:
		*s = nil
		return nil
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		return fmt.Errorf("sqltypes.Strings: cannot scan %T", src)
	}
	out := Strings{}
	if err := json.Unmarshal(b, (*[]string)(&out)); err != nil {
		return fmt.Errorf("sqltypes.Strings: %w", err)
	}
	*s = out
	return nil
}
