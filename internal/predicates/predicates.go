package predicates

import (
	"encoding/json"
	"log/slog"

	"github.com/gobwas/glob"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// IsSpecModified checks if the resource spec has been modified based on the update event
func IsSpecModified(e event.UpdateEvent) bool {
	oldObj, ok := e.ObjectOld.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	newObj, ok := e.ObjectNew.(*unstructured.Unstructured)
	if !ok {
		return false
	}

	oldSpecMap, found, err := unstructured.NestedMap(oldObj.Object, "spec")
	if err != nil || !found {
		return false
	}

	newSpecMap, found, err := unstructured.NestedMap(newObj.Object, "spec")
	if err != nil || !found {
		return false
	}

	oldSpec, err := json.Marshal(oldSpecMap)
	if err != nil {
		return false
	}

	newSpec, err := json.Marshal(newSpecMap)
	if err != nil {
		return false
	}

	return string(oldSpec) != string(newSpec)
}

type NamespaceExclusions struct {
	patterns []glob.Glob
}

func NewNamespaceExclusions(logger *slog.Logger, excludedNamespaces []string) *NamespaceExclusions {
	patterns := make([]glob.Glob, 0, len(excludedNamespaces))
	for _, pattern := range excludedNamespaces {
		glob, err := glob.Compile(pattern)
		if err != nil {
			logger.Warn("Namespace exclusion could not be parsed and will be ignored", "error", err, "pattern", pattern)
		} else {
			patterns = append(patterns, glob)
		}
	}
	return &NamespaceExclusions{patterns: patterns}
}

func (n *NamespaceExclusions) IsObjectExcluded(o client.Object) bool {
	ns := o.GetNamespace()
	if ns == "" {
		return false
	}
	return n.IsExcluded(ns)
}

func (n *NamespaceExclusions) IsExcluded(namespace string) bool {
	for _, pattern := range n.patterns {
		if pattern.Match(namespace) {
			return true
		}
	}
	return false
}
