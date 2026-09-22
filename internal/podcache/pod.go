package podcache

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const strippedAnnotation = "aikidoSecurity.kubernetes.collector/stripped"

// Strip replaces an excluded pod with an identity-only stub in place. Returning
// a valid Pod keeps atomic informer cache replacements working.
func Strip(pod *v1.Pod) *v1.Pod {
	*pod = v1.Pod{
		TypeMeta: pod.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			UID:             pod.UID,
			ResourceVersion: pod.ResourceVersion,
			Annotations:     map[string]string{strippedAnnotation: "true"},
		},
	}
	return pod
}

// IsStripped recognizes stubs in both typed and unstructured event objects.
func IsStripped(obj metav1.Object) bool {
	return obj.GetAnnotations()[strippedAnnotation] == "true"
}
