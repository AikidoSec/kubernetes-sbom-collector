package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type EnvironmentConfig struct {
	ExcludedImageNames   []string
	DisableImageMetadata bool
}

func ParseEnvironmentConfig() (EnvironmentConfig, error) {
	excludedImageNames, err := parseExcludedImageNamesFromEnv()
	if err != nil {
		return EnvironmentConfig{}, err
	}

	disableImageMetadata := false
	if value, exists := os.LookupEnv("DISABLE_IMAGE_METADATA"); exists {
		disableImageMetadata, err = strconv.ParseBool(value)
		if err != nil {
			return EnvironmentConfig{}, fmt.Errorf("invalid DISABLE_IMAGE_METADATA value: %w", err)
		}
	}

	return EnvironmentConfig{
		ExcludedImageNames:   excludedImageNames,
		DisableImageMetadata: disableImageMetadata,
	}, nil
}

func parseExcludedImageNamesFromEnv() ([]string, error) {
	excludedImageNamesStr, exists := os.LookupEnv("EXCLUDED_IMAGE_NAMES")
	if !exists || excludedImageNamesStr == "" {
		return nil, nil
	}

	var excludedImageNames []string
	if err := json.Unmarshal([]byte(excludedImageNamesStr), &excludedImageNames); err != nil {
		return nil, fmt.Errorf("EXCLUDED_IMAGE_NAMES must be a JSON array of strings: %w", err)
	}

	return excludedImageNames, nil
}
