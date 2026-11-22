// Package scanners parses the outputs of security and code-analysis tools
// into normalized structs.
//
// Parsers decode into generic values and read fields through the tolerant
// accessors below, so unexpected types or missing fields yield zero values
// instead of errors. Only malformed JSON is reported as an error.
package scanners

import (
	"encoding/json"
	"strconv"
	"strings"
)

func decode(data []byte) (any, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// get walks nested objects by key.
func get(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func asObj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asArr(v any) []any {
	a, _ := v.([]any)
	return a
}

func asStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func asNum(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	}
	return 0
}

func asInt(v any) int64 { return int64(asNum(v)) }

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// asStrs accepts an array of strings or a single string.
func asStrs(v any) []string {
	if s, ok := v.(string); ok {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var out []string
	for _, e := range asArr(v) {
		if s := asStr(e); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// asStrMap keeps only string-valued entries of an object.
func asStrMap(v any) map[string]string {
	m := asObj(v)
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, e := range m {
		if s, ok := e.(string); ok {
			out[k] = s
		}
	}
	return out
}
