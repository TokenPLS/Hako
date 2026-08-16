package hako

import "fmt"

// Keep Core's public configuration boundary aligned with the immutable Apple
// store. Script JSON is an intermediate representation and receives additional
// headroom for JSON escaping, but it can never be activated directly.
const (
	maximumConfigurationBytes     = 4 * 1024 * 1024
	maximumConfigurationJSONBytes = 16 * 1024 * 1024
)

func validateBoundedText(value, label string, maximum int) error {
	if len(value) > maximum {
		return fmt.Errorf("hako: %s exceeds %d bytes", label, maximum)
	}
	return nil
}

func validateConfigurationInput(value string) error {
	return validateBoundedText(value, "configuration input", maximumConfigurationBytes)
}

func validateConfigurationResult(value string) error {
	return validateBoundedText(value, "configuration result", maximumConfigurationBytes)
}

func validateConfigurationJSONInput(value string) error {
	return validateBoundedText(value, "script JSON input", maximumConfigurationJSONBytes)
}

func validateConfigurationJSONResult(value string) error {
	return validateBoundedText(value, "JSON result", maximumConfigurationJSONBytes)
}
