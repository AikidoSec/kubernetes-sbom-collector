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

func NewPodPredicate(excludedNamespaces []string, currentNode string, runAsDaemon bool) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// Pods that were not part of the initial snapshot that was received when the informer was created are
			// excluded because they are in a transient state and may not have all fields populated yet.
			if !e.IsInInitialList {
				return false
			}

			if IsObjectFromExcludedNamespace(e.Object, excludedNamespaces) {
				return false
			}

			pod, err := podFromUnstructured(e.Object)
			if err != nil {
				log.Println("error converting object to Pod:", err)
				return false
			}

			if runAsDaemon {
				if !IsFromCurrentNode(pod, currentNode) {
					return false
				}
			}

			// Only reconcile if pod is running, succeeded, or failed.
			// Pending pods from the initial list are filtered out and will be reconciled later via UpdateFunc when
			// they transition to a running state.
			if pod.Status.Phase != v1.PodRunning && pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed {
				return false
			}

			// Make sure that all images are resolved, running pods can still have unresolved images. This can happen if
			// the pods initial list contains pods that were recently created and are still resolving their images.
			return ArePodImagesResolved(pod)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if IsObjectFromExcludedNamespace(e.ObjectNew, excludedNamespaces) {
				return false
			}

			oldPod, err := podFromUnstructured(e.ObjectOld)
			if err != nil {
				log.Println("error converting old object to Pod:", err)
				return false
			}

			newPod, err := podFromUnstructured(e.ObjectNew)
			if err != nil {
				log.Println("error converting new object to Pod:", err)
				return false
			}

			if newPod.Status.Phase != v1.PodRunning && newPod.Status.Phase != v1.PodSucceeded && newPod.Status.Phase != v1.PodFailed {
				return false
			}

			if runAsDaemon {
				if !IsFromCurrentNode(newPod, currentNode) {
					return false
				}
			}

			if !ArePodImagesResolved(newPod) {
				return false
			}

			// Reconcile if any of the following conditions are met:
			// - container status changed (phase or condition change, or images got resolved)
			// - spec changed
			if PodContainerStatusChanged(oldPod, newPod) || IsSpecModified(e) {
				return true
			}

			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return !IsObjectFromExcludedNamespace(e.Object, excludedNamespaces)
		},
	}
}

func IsFromCurrentNode(pod v1.Pod, nodeName string) bool {
	if nodeName == "" {
		return true
	}

	return pod.Spec.NodeName == nodeName
}

func podFromUnstructured(obj client.Object) (v1.Pod, error) {
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

func PodContainerStatusChanged(oldPod, newPod v1.Pod) bool {
	// Phase change (e.g., from Pending to Running)
	if oldPod.Status.Phase != newPod.Status.Phase {
		return true
	}

	// Condition changes
	if ConditionsChanged(oldPod.Status.Conditions, newPod.Status.Conditions) {
		return true
	}

	// ImageID changes
	// Check regular containers
	if ContainerImageIDChanged(oldPod.Status.ContainerStatuses, newPod.Status.ContainerStatuses) {
		return true
	}

	// Check init containers
	if ContainerImageIDChanged(oldPod.Status.InitContainerStatuses, newPod.Status.InitContainerStatuses) {
		return true
	}

	// Check ephemeral containers
	if ContainerImageIDChanged(oldPod.Status.EphemeralContainerStatuses, newPod.Status.EphemeralContainerStatuses) {
		return true
	}

	return false
}

func ConditionsChanged(oldConds, newConds []v1.PodCondition) bool {
	if len(oldConds) != len(newConds) {
		return true
	}

	oldMap := make(map[v1.PodConditionType]v1.ConditionStatus, len(oldConds))
	for _, c := range oldConds {
		oldMap[c.Type] = c.Status
	}

	for _, c := range newConds {
		if oldStatus, ok := oldMap[c.Type]; !ok || oldStatus != c.Status {
			return true
		}
	}
	return false
}

func ContainerImageIDChanged(old []v1.ContainerStatus, new []v1.ContainerStatus) bool {
	if len(old) != len(new) {
		return true
	}

	oldPodImages := make(map[string]string)
	for _, c := range old {
		oldPodImages[c.Name] = c.ImageID
	}

	for _, status := range new {
		if val, ok := oldPodImages[status.Name]; !ok || val != status.ImageID {
			return true
		}
	}

	return false
}

func ArePodImagesResolved(pod v1.Pod) bool {
	if !AreContainersImagesResolved(pod.Status.ContainerStatuses) {
		return false
	}

	if !AreContainersImagesResolved(pod.Status.InitContainerStatuses) {
		return false
	}

	if !AreContainersImagesResolved(pod.Status.EphemeralContainerStatuses) {
		return false
	}

	return true
}

func AreContainersImagesResolved(statuses []v1.ContainerStatus) bool {
	for _, status := range statuses {
		if status.ImageID == "" {
			return false
		}
	}

	return true
}
