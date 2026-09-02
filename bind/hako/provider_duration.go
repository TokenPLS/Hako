package hako

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func providerUpdateIntervalSeconds(raw any) (int64, error) {
	// Mihomo defines this field by converting seconds to time.Duration. iOS
	// moves HTTP refresh scheduling into the App, but the resource plan must
	// keep the same representable domain instead of accepting a value that
	// would wrap in the upstream provider implementation.
	return providerDurationUnits(raw, time.Second, "provider interval", "second")
}

func providerDurationUnits(raw any, unit time.Duration, label, unitLabel string) (int64, error) {
	value, err := providerIntegerUnits(raw, label, unitLabel)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must not be negative", label)
	}
	if value > int64(math.MaxInt64)/int64(unit) {
		return 0, fmt.Errorf("%s is out of range", label)
	}
	return value, nil
}

// providerNonPositiveDurationAllowedUnits mirrors fields for which upstream
// gives non-positive values a defined default/disable meaning, while still
// rejecting positive values that overflow time.Duration during conversion.
func providerNonPositiveDurationAllowedUnits(raw any, unit time.Duration, label, unitLabel string) (int64, error) {
	value, err := providerIntegerUnits(raw, label, unitLabel)
	if err != nil {
		return 0, err
	}
	if value > int64(math.MaxInt64)/int64(unit) {
		return 0, fmt.Errorf("%s is out of range", label)
	}
	return value, nil
}

func providerIntegerUnits(raw any, label, unitLabel string) (int64, error) {
	if raw == nil {
		return 0, nil
	}
	var value int64
	switch typed := raw.(type) {
	case int:
		value = int64(typed)
	case int32:
		value = int64(typed)
	case int64:
		value = typed
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, fmt.Errorf("%s is out of range", label)
		}
		value = int64(typed)
	case uint32:
		value = int64(typed)
	case uint64:
		if typed > math.MaxInt64 {
			return 0, fmt.Errorf("%s is out of range", label)
		}
		value = int64(typed)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s must be a non-negative %s count", label, unitLabel)
		}
		value = parsed
	default:
		return 0, fmt.Errorf("%s must be a non-negative %s count", label, unitLabel)
	}
	return value, nil
}
