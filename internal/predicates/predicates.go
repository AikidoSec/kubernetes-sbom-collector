package predicates

import (
	"encoding/json"
	"fmt"
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

type NamespaceFilter struct {
	excludePatterns []glob.Glob
	includePatterns []glob.Glob
}

func NewNamespaceFilter(logger *slog.Logger, excludedNamespaces, includedNamespaces []string) *NamespaceFilter {
	excludePatterns := compilePatterns(logger, excludedNamespaces, "exclusion")
	includePatterns := compilePatterns(logger, includedNamespaces, "inclusion")
	return &NamespaceFilter{excludePatterns: excludePatterns, includePatterns: includePatterns}
}

func compilePatterns(logger *slog.Logger, namespaces []string, label string) []glob.Glob {
	patterns := make([]glob.Glob, 0, len(namespaces))
	for _, pattern := range namespaces {
		compiled, err := glob.Compile(pattern)
		if err != nil {
			logger.Warn(fmt.Sprintf("Namespace %s could not be parsed and will be ignored", label), "error", err, "pattern", pattern)
		} else {
			patterns = append(patterns, compiled)
		}
	}
	return patterns
}

func (n *NamespaceFilter) IsObjectExcluded(o client.Object) bool {
	ns := o.GetNamespace()
	if ns == "" {
		return false
	}
	return n.IsExcluded(ns)
}

func (n *NamespaceFilter) IsExcluded(namespace string) bool {
	if len(n.includePatterns) > 0 {
		for _, pattern := range n.includePatterns {
			if pattern.Match(namespace) {
				return false
			}
		}
		return true
	}

	for _, pattern := range n.excludePatterns {
		if pattern.Match(namespace) {
			return true
		}
	}
	return false
}
