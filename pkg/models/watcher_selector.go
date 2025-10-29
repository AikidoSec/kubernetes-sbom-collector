package models

import "k8s.io/apimachinery/pkg/runtime/schema"

type WatcherSelector struct {
	schema.GroupVersionKind
	ExcludedNamespaces []string
}
