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

func TestCollectImageMetadata(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    bool
		wantErr bool
	}{
		{"false", false, false}, {"true", true, false}, {"invalid", false, true}, {"", false, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("COLLECT_IMAGE_METADATA", tc.value)
			got, err := ParseEnvironmentConfig()
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && got.CollectImageMetadata != tc.want {
				t.Errorf("CollectImageMetadata = %v, want %v", got.CollectImageMetadata, tc.want)
			}
		})
	}
}
