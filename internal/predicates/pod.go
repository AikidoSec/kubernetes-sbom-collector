package predicates

import (
	"log"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func NewPodPredicate(excludedNamespaces []string, currentNode string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// Pods that were not part of the initial snapshot that was received when the informer was created are
			// excluded because they are in a transient state and may not have all fields populated yet.
			if !e.IsInInitialList {
				return false
			}

			pod, err := PodFromUnstructured(e.Object)
			if err != nil {
				log.Println("error converting new object to Pod:", err)
				return false
			}

			// Pods that are not scheduled to the current node are excluded
			if !IsFromCurrentNode(pod, currentNode) {
				return false
			}

			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if IsObjectFromExcludedNamespace(e.ObjectNew, excludedNamespaces) {
				return false
			}

			oldPod, err := PodFromUnstructured(e.ObjectOld)
			if err != nil {
				log.Println("error converting old object to Pod:", err)
				return false
			}

			newPod, err := PodFromUnstructured(e.ObjectNew)
			if err != nil {
				log.Println("error converting new object to Pod:", err)
				return false
			}

			// Check if the Pod is in ready state or if the pod has failed
			// We need to check failed pods as well because they can still execute partially before failing
			if newPod.Status.Phase != v1.PodRunning && newPod.Status.Phase != v1.PodSucceeded && newPod.Status.Phase != v1.PodFailed {
				return false
			}

			// If the Pod status changed to 'Running' from 'Pending', trigger reconciliation
			// In this case the spec did not change but the Pod is now ready, and we want to capture that event
			if newPod.Status.Phase == v1.PodRunning && oldPod.Status.Phase == v1.PodPending {
				return true
			}

			// Pods that are not scheduled to the current node are excluded
			if !IsFromCurrentNode(newPod, currentNode) {
				return false
			}

			return IsSpecModified(e)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
	}
}

func IsFromCurrentNode(pod v1.Pod, nodeName string) bool {
	if nodeName == "" {
		return true
	}

	return pod.Spec.NodeName == nodeName
}

func PodFromAny(obj any) (v1.Pod, error) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return v1.Pod{}, nil
	}

	return PodFromUnstructured(unstructuredObj)
}

func PodFromUnstructured(obj client.Object) (v1.Pod, error) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return v1.Pod{}, nil
	}

	var pod v1.Pod
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.UnstructuredContent(), &pod)
	if err != nil {
		return v1.Pod{}, err
	}

	return pod, nil
}
