package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type EnvironmentConfig struct {
	ExcludedImageNames []string
}

func ParseEnvironmentConfig() (EnvironmentConfig, error) {
	excludedImageNames, err := parseExcludedImageNamesFromEnv()
	if err != nil {
		return EnvironmentConfig{}, err
	}

	return EnvironmentConfig{
		ExcludedImageNames: excludedImageNames,
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
