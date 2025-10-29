package predicates

import (
	"encoding/json"
	"slices"

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

// IsObjectFromExcludedNamespace checks if the object is from an excluded namespace
func IsObjectFromExcludedNamespace(o client.Object, excludedNamespaces []string) bool {
	ns := o.GetNamespace()
	if ns == "" {
		return false
	}

	return slices.Contains(excludedNamespaces, ns)
}
