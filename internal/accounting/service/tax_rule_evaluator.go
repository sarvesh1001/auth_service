package service

import (
	"fmt"
	"regexp"
	"strings"

	"auth-service/internal/accounting/models/tax"

	"github.com/shopspring/decimal"
)

type ConditionEvaluator struct{}

func (e *ConditionEvaluator) Evaluate(cond *tax.TaxCondition, data map[string]interface{}) (bool, error) {
	fieldVal, ok := data[cond.FieldName]
	if !ok {
		// For is_null / is_not_null, missing field counts as null
		switch cond.Operator {
		case "is_null":
			return true, nil
		case "is_not_null":
			return false, nil
		}
		return false, nil
	}

	switch cond.Operator {
	case "eq":
		return e.equal(fieldVal, cond)
	case "ne":
		eq, err := e.equal(fieldVal, cond)
		if err != nil {
			return false, err
		}
		return !eq, nil
	case "gt":
		return e.greaterThan(fieldVal, cond)
	case "lt":
		return e.lessThan(fieldVal, cond)
	case "gte":
		return e.greaterOrEqual(fieldVal, cond)
	case "lte":
		return e.lessOrEqual(fieldVal, cond)
	case "contains":
		return e.contains(fieldVal, cond)
	case "in":
		return e.inList(fieldVal, cond)
	case "not_in":
		ok, err := e.inList(fieldVal, cond)
		if err != nil {
			return false, err
		}
		return !ok, nil
	case "between":
		return e.between(fieldVal, cond)
	case "starts_with":
		return e.startsWith(fieldVal, cond)
	case "ends_with":
		return e.endsWith(fieldVal, cond)
	case "regex":
		return e.regexMatch(fieldVal, cond)
	case "is_null":
		return e.isNull(fieldVal, cond)
	case "is_not_null":
		return e.isNotNull(fieldVal, cond)
	default:
		return false, fmt.Errorf("unsupported operator: %s", cond.Operator)
	}
}

func (e *ConditionEvaluator) equal(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil {
		return false, nil
	}
	if cond.ValueNumeric != nil {
		fd, err := toDecimal(fieldVal)
		if err == nil {
			return fd.Equal(*cond.ValueNumeric), nil
		}
	}
	if cond.ValueText != nil {
		return fmt.Sprintf("%v", fieldVal) == *cond.ValueText, nil
	}
	return false, nil
}

func (e *ConditionEvaluator) greaterThan(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil {
		return false, nil
	}
	fd, err := toDecimal(fieldVal)
	if err != nil {
		return false, nil
	}
	if cond.ValueNumeric == nil {
		return false, nil
	}
	return fd.GreaterThan(*cond.ValueNumeric), nil
}

func (e *ConditionEvaluator) lessThan(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil {
		return false, nil
	}
	fd, err := toDecimal(fieldVal)
	if err != nil {
		return false, nil
	}
	if cond.ValueNumeric == nil {
		return false, nil
	}
	return fd.LessThan(*cond.ValueNumeric), nil
}

func (e *ConditionEvaluator) greaterOrEqual(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil {
		return false, nil
	}
	fd, err := toDecimal(fieldVal)
	if err != nil {
		return false, nil
	}
	if cond.ValueNumeric == nil {
		return false, nil
	}
	return fd.GreaterThanOrEqual(*cond.ValueNumeric), nil
}

func (e *ConditionEvaluator) lessOrEqual(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil {
		return false, nil
	}
	fd, err := toDecimal(fieldVal)
	if err != nil {
		return false, nil
	}
	if cond.ValueNumeric == nil {
		return false, nil
	}
	return fd.LessThanOrEqual(*cond.ValueNumeric), nil
}

func (e *ConditionEvaluator) contains(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil || cond.ValueText == nil {
		return false, nil
	}
	str := fmt.Sprintf("%v", fieldVal)
	return strings.Contains(str, *cond.ValueText), nil
}

func (e *ConditionEvaluator) inList(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil || cond.ValueText == nil {
		return false, nil
	}
	items := strings.Split(*cond.ValueText, ",")
	valStr := fmt.Sprintf("%v", fieldVal)
	for _, item := range items {
		if strings.TrimSpace(item) == valStr {
			return true, nil
		}
	}
	return false, nil
}

func (e *ConditionEvaluator) between(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil {
		return false, nil
	}
	fd, err := toDecimal(fieldVal)
	if err != nil {
		return false, nil
	}
	if cond.ValueText == nil {
		return false, nil
	}
	parts := strings.Split(*cond.ValueText, ",")
	if len(parts) != 2 {
		return false, nil
	}
	low, err := decimal.NewFromString(strings.TrimSpace(parts[0]))
	if err != nil {
		return false, nil
	}
	high, err := decimal.NewFromString(strings.TrimSpace(parts[1]))
	if err != nil {
		return false, nil
	}
	return fd.GreaterThanOrEqual(low) && fd.LessThanOrEqual(high), nil
}

// startsWith checks if field value string starts with the given prefix (case-sensitive)
func (e *ConditionEvaluator) startsWith(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil || cond.ValueText == nil {
		return false, nil
	}
	str := fmt.Sprintf("%v", fieldVal)
	return strings.HasPrefix(str, *cond.ValueText), nil
}

// endsWith checks if field value string ends with the given suffix (case-sensitive)
func (e *ConditionEvaluator) endsWith(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil || cond.ValueText == nil {
		return false, nil
	}
	str := fmt.Sprintf("%v", fieldVal)
	return strings.HasSuffix(str, *cond.ValueText), nil
}

// regexMatch checks if field value string matches the given regular expression
func (e *ConditionEvaluator) regexMatch(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	if fieldVal == nil || cond.ValueText == nil {
		return false, nil
	}
	str := fmt.Sprintf("%v", fieldVal)
	re, err := regexp.Compile(*cond.ValueText)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}
	return re.MatchString(str), nil
}

// isNull returns true if fieldVal is nil
func (e *ConditionEvaluator) isNull(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	return fieldVal == nil, nil
}

// isNotNull returns true if fieldVal is not nil
func (e *ConditionEvaluator) isNotNull(fieldVal interface{}, cond *tax.TaxCondition) (bool, error) {
	return fieldVal != nil, nil
}

func toDecimal(v interface{}) (decimal.Decimal, error) {
	switch val := v.(type) {
	case decimal.Decimal:
		return val, nil
	case float64:
		return decimal.NewFromFloat(val), nil
	case int:
		return decimal.New(int64(val), 0), nil
	case string:
		return decimal.NewFromString(val)
	default:
		return decimal.Zero, fmt.Errorf("cannot convert %T to decimal", v)
	}
}
