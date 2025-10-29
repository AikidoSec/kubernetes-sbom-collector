package models

import "time"

type CollectorConfig struct {
	ExcludedNamespaces         []string      `json:"excludedNamespaces"`
	APIHost                    string        `json:"apiHost"`
	APIToken                   string        `json:"apiToken"`
	ControllerCacheSyncTimeout time.Duration `json:"controllerCacheSyncTimeout"`
}
