package predicates

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestIsObjectFromExcludedNamespace(t *testing.T) {
	tests := []struct {
		name               string
		obj                *unstructured.Unstructured
		excludedNamespaces []string
		want               bool
	}{
		{
			name: "namespace is excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{"kube-system", "kube-public"},
			want:               true,
		},
		{
			name: "namespace is not excluded",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "default",
					},
				},
			},
			excludedNamespaces: []string{"kube-system", "kube-public"},
			want:               false,
		},
		{
			name: "empty namespace",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name": "test-resource",
					},
				},
			},
			excludedNamespaces: []string{"kube-system"},
			want:               false,
		},
		{
			name: "empty excluded list",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: []string{},
			want:               false,
		},
		{
			name: "nil excluded list",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "kube-system",
					},
				},
			},
			excludedNamespaces: nil,
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsObjectFromExcludedNamespace(tt.obj, tt.excludedNamespaces)
			if got != tt.want {
				t.Errorf("IsObjectFromExcludedNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSpecModified(t *testing.T) {
	tests := []struct {
		name  string
		event event.UpdateEvent
		want  bool
	}{
		{
			name: "spec not modified",
			event: event.UpdateEvent{
				ObjectOld: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
						},
					},
				},
				ObjectNew: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "spec modified - image changed",
			event: event.UpdateEvent{
				ObjectOld: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
						},
					},
				},
				ObjectNew: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:2.0",
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "spec modified - field added",
			event: event.UpdateEvent{
				ObjectOld: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
						},
					},
				},
				ObjectNew: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
							"restartPolicy": "Always",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "metadata changed - spec not modified",
			event: event.UpdateEvent{
				ObjectOld: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
							"labels": map[string]any{
								"app": "v1",
							},
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
						},
					},
				},
				ObjectNew: &unstructured.Unstructured{
					Object: map[string]any{
						"metadata": map[string]any{
							"name":      "test-pod",
							"namespace": "default",
							"labels": map[string]any{
								"app": "v2",
							},
						},
						"spec": map[string]any{
							"containers": []any{
								map[string]any{
									"name":  "nginx",
									"image": "nginx:1.0",
								},
							},
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSpecModified(tt.event)
			if got != tt.want {
				t.Errorf("IsSpecModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSpecModified_InvalidObjects(t *testing.T) {
	tests := []struct {
		name  string
		event event.UpdateEvent
		want  bool
	}{
		{
			name: "old object is not unstructured",
			event: event.UpdateEvent{
				ObjectOld: &metav1.PartialObjectMetadata{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
				},
				ObjectNew: &unstructured.Unstructured{
					Object: map[string]any{
						"spec": map[string]any{},
					},
				},
			},
			want: false,
		},
		{
			name: "new object is not unstructured",
			event: event.UpdateEvent{
				ObjectOld: &unstructured.Unstructured{
					Object: map[string]any{
						"spec": map[string]any{},
					},
				},
				ObjectNew: &metav1.PartialObjectMetadata{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSpecModified(tt.event)
			if got != tt.want {
				t.Errorf("IsSpecModified() = %v, want %v", got, tt.want)
			}
		})
	}
}
