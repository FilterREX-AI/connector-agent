package brocaderest

import (
	"fmt"
	"regexp"
	"strconv"
)

// validateParams enforces the fixed allowlist and per-parameter schema for an
// Operation. Unknown parameter names, missing required values, or malformed
// values are rejected without ever including the raw value in the error
// message (only the parameter name).
func validateParams(op Operation, in map[string]any) (map[string]string, error) {
	out := make(map[string]string, len(op.AllowedParams))

	// Required checks + unknown-name rejection.
	for name := range in {
		if _, ok := op.AllowedParams[name]; !ok {
			return nil, newErr(ErrCodeInvalidParameter, fmt.Sprintf("unknown parameter %q", name))
		}
	}

	for name, schema := range op.AllowedParams {
		raw, present := in[name]
		if !present {
			if schema.Required {
				return nil, newErr(ErrCodeInvalidParameter, fmt.Sprintf("missing required parameter %q", name))
			}
			continue
		}
		strVal, err := coerce(raw, schema)
		if err != nil {
			return nil, newErr(ErrCodeInvalidParameter, fmt.Sprintf("parameter %q: %s", name, err.Error()))
		}
		if schema.Max > 0 && len(strVal) > schema.Max {
			return nil, newErr(ErrCodeInvalidParameter, fmt.Sprintf("parameter %q exceeds max length", name))
		}
		if schema.Pattern != "" {
			re, err := regexp.Compile(schema.Pattern)
			if err != nil {
				return nil, newErr(ErrCodeInvalidParameter, fmt.Sprintf("parameter %q: bad schema", name))
			}
			if !re.MatchString(strVal) {
				return nil, newErr(ErrCodeInvalidParameter, fmt.Sprintf("parameter %q: value not permitted", name))
			}
		}
		out[name] = strVal
	}
	return out, nil
}

func coerce(v any, s ParamSchema) (string, error) {
	switch s.Type {
	case "string":
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("expected string")
		}
		return str, nil
	case "int":
		switch n := v.(type) {
		case int:
			return strconv.Itoa(n), nil
		case int64:
			return strconv.FormatInt(n, 10), nil
		case float64:
			if n != float64(int64(n)) {
				return "", fmt.Errorf("expected integer")
			}
			return strconv.FormatInt(int64(n), 10), nil
		case string:
			if _, err := strconv.Atoi(n); err != nil {
				return "", fmt.Errorf("expected integer")
			}
			return n, nil
		default:
			return "", fmt.Errorf("expected integer")
		}
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return "", fmt.Errorf("expected bool")
		}
		if b {
			return "true", nil
		}
		return "false", nil
	default:
		return "", fmt.Errorf("unsupported schema type")
	}
}
