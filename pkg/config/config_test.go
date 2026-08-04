package config

import (
	"reflect"
	"testing"
)

func TestParseEnvironmentConfig(t *testing.T) {
	t.Setenv("EXCLUDED_IMAGE_NAMES", `["registry.k8s.io/*","*/pause"]`)

	got, err := ParseEnvironmentConfig()
	if err != nil {
		t.Fatalf("ParseEnvironmentConfig() error = %v", err)
	}

	want := EnvironmentConfig{
		ExcludedImageNames: []string{"registry.k8s.io/*", "*/pause"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseEnvironmentConfig() = %v, want %v", got, want)
	}
}

func TestParseEnvironmentConfigReturnsEmptyConfigWhenUnset(t *testing.T) {
	got, err := ParseEnvironmentConfig()
	if err != nil {
		t.Fatalf("ParseEnvironmentConfig() error = %v", err)
	}

	if !reflect.DeepEqual(got, EnvironmentConfig{}) {
		t.Errorf("ParseEnvironmentConfig() = %v, want empty config", got)
	}
}

func TestParseEnvironmentConfigReturnsErrorForInvalidJSON(t *testing.T) {
	t.Setenv("EXCLUDED_IMAGE_NAMES", "registry.k8s.io/*")

	if _, err := ParseEnvironmentConfig(); err == nil {
		t.Fatal("ParseEnvironmentConfig() error = nil, want error")
	}
}
