package predicates

import (
	"log/slog"
	"os"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestIsFromCurrentNode(t *testing.T) {
	tests := []struct {
		name     string
		pod      v1.Pod
		nodeName string
		want     bool
	}{
		{
			name:     "empty node name returns true",
			pod:      v1.Pod{},
			nodeName: "",
			want:     true,
		},
		{
			name: "matching node name",
			pod: v1.Pod{
				Spec: v1.PodSpec{
					NodeName: "node-1",
				},
			},
			nodeName: "node-1",
			want:     true,
		},
		{
			name: "non-matching node name",
			pod: v1.Pod{
				Spec: v1.PodSpec{
					NodeName: "node-1",
				},
			},
			nodeName: "node-2",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFromCurrentNode(tt.pod, tt.nodeName)
			if got != tt.want {
				t.Errorf("IsFromCurrentNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPodFromUnstructured(t *testing.T) {
	tests := []struct {
		name    string
		obj     *unstructured.Unstructured
		wantErr bool
	}{
		{
			name: "valid pod conversion",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]any{
						"name":      "test-pod",
						"namespace": "default",
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name":  "test-container",
								"image": "nginx:latest",
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod, err := podFromUnstructured(tt.obj)
			if (err != nil) != tt.wantErr {
				t.Errorf("podFromUnstructured() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && pod.Name != "test-pod" {
				t.Errorf("podFromUnstructured() returned pod with name %q, want %q", pod.Name, "test-pod")
			}
		})
	}
}

func TestConditionsChanged(t *testing.T) {
	tests := []struct {
		name     string
		oldConds []v1.PodCondition
		newConds []v1.PodCondition
		want     bool
	}{
		{
			name:     "empty conditions - no change",
			oldConds: []v1.PodCondition{},
			newConds: []v1.PodCondition{},
			want:     false,
		},
		{
			name: "different lengths",
			oldConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
			},
			newConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
				{Type: v1.PodInitialized, Status: v1.ConditionTrue},
			},
			want: true,
		},
		{
			name: "same conditions - no change",
			oldConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
				{Type: v1.PodInitialized, Status: v1.ConditionTrue},
			},
			newConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
				{Type: v1.PodInitialized, Status: v1.ConditionTrue},
			},
			want: false,
		},
		{
			name: "condition status changed",
			oldConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionFalse},
			},
			newConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
			},
			want: true,
		},
		{
			name: "new condition type added",
			oldConds: []v1.PodCondition{
				{Type: v1.PodInitialized, Status: v1.ConditionTrue},
			},
			newConds: []v1.PodCondition{
				{Type: v1.PodReady, Status: v1.ConditionTrue},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConditionsChanged(tt.oldConds, tt.newConds)
			if got != tt.want {
				t.Errorf("ConditionsChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainerImageIDChanged(t *testing.T) {
	tests := []struct {
		name string
		old  []v1.ContainerStatus
		new  []v1.ContainerStatus
		want bool
	}{
		{
			name: "empty containers - no change",
			old:  []v1.ContainerStatus{},
			new:  []v1.ContainerStatus{},
			want: false,
		},
		{
			name: "different lengths",
			old: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
			},
			new: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
				{Name: "container2", ImageID: "sha256:def456"},
			},
			want: true,
		},
		{
			name: "same image IDs - no change",
			old: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
				{Name: "container2", ImageID: "sha256:def456"},
			},
			new: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
				{Name: "container2", ImageID: "sha256:def456"},
			},
			want: false,
		},
		{
			name: "image ID changed",
			old: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
			},
			new: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:xyz789"},
			},
			want: true,
		},
		{
			name: "container name changed",
			old: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
			},
			new: []v1.ContainerStatus{
				{Name: "container2", ImageID: "sha256:abc123"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainerImageIDChanged(tt.old, tt.new)
			if got != tt.want {
				t.Errorf("ContainerImageIDChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAreContainersImagesResolved(t *testing.T) {
	tests := []struct {
		name     string
		statuses []v1.ContainerStatus
		want     bool
	}{
		{
			name:     "empty containers",
			statuses: []v1.ContainerStatus{},
			want:     true,
		},
		{
			name: "all images resolved",
			statuses: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
				{Name: "container2", ImageID: "sha256:def456"},
			},
			want: true,
		},
		{
			name: "one image not resolved",
			statuses: []v1.ContainerStatus{
				{Name: "container1", ImageID: "sha256:abc123"},
				{Name: "container2", ImageID: ""},
			},
			want: false,
		},
		{
			name: "all images not resolved",
			statuses: []v1.ContainerStatus{
				{Name: "container1", ImageID: ""},
				{Name: "container2", ImageID: ""},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AreContainersImagesResolved(tt.statuses)
			if got != tt.want {
				t.Errorf("AreContainersImagesResolved() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArePodImagesResolved(t *testing.T) {
	tests := []struct {
		name string
		pod  v1.Pod
		want bool
	}{
		{
			name: "all images resolved",
			pod: v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:abc123"},
					},
					InitContainerStatuses: []v1.ContainerStatus{
						{Name: "init1", ImageID: "sha256:init123"},
					},
					EphemeralContainerStatuses: []v1.ContainerStatus{
						{Name: "ephemeral1", ImageID: "sha256:eph123"},
					},
				},
			},
			want: true,
		},
		{
			name: "container image not resolved",
			pod: v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: ""},
					},
					InitContainerStatuses: []v1.ContainerStatus{
						{Name: "init1", ImageID: "sha256:init123"},
					},
				},
			},
			want: false,
		},
		{
			name: "init container image not resolved",
			pod: v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:abc123"},
					},
					InitContainerStatuses: []v1.ContainerStatus{
						{Name: "init1", ImageID: ""},
					},
				},
			},
			want: false,
		},
		{
			name: "ephemeral container image not resolved",
			pod: v1.Pod{
				Status: v1.PodStatus{
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:abc123"},
					},
					EphemeralContainerStatuses: []v1.ContainerStatus{
						{Name: "ephemeral1", ImageID: ""},
					},
				},
			},
			want: false,
		},
		{
			name: "empty pod",
			pod:  v1.Pod{},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ArePodImagesResolved(tt.pod)
			if got != tt.want {
				t.Errorf("ArePodImagesResolved() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPodContainerStatusChanged(t *testing.T) {
	tests := []struct {
		name   string
		oldPod v1.Pod
		newPod v1.Pod
		want   bool
	}{
		{
			name: "phase changed",
			oldPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodPending,
				},
			},
			newPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
				},
			},
			want: true,
		},
		{
			name: "conditions changed",
			oldPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{
						{Type: v1.PodReady, Status: v1.ConditionFalse},
					},
				},
			},
			newPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{
						{Type: v1.PodReady, Status: v1.ConditionTrue},
					},
				},
			},
			want: true,
		},
		{
			name: "container image ID changed",
			oldPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{
						{Type: v1.PodReady, Status: v1.ConditionTrue},
					},
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:abc123"},
					},
				},
			},
			newPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{
						{Type: v1.PodReady, Status: v1.ConditionTrue},
					},
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:xyz789"},
					},
				},
			},
			want: true,
		},
		{
			name: "init container image ID changed",
			oldPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					InitContainerStatuses: []v1.ContainerStatus{
						{Name: "init1", ImageID: "sha256:abc123"},
					},
				},
			},
			newPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					InitContainerStatuses: []v1.ContainerStatus{
						{Name: "init1", ImageID: "sha256:xyz789"},
					},
				},
			},
			want: true,
		},
		{
			name: "ephemeral container image ID changed",
			oldPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					EphemeralContainerStatuses: []v1.ContainerStatus{
						{Name: "ephemeral1", ImageID: "sha256:abc123"},
					},
				},
			},
			newPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					EphemeralContainerStatuses: []v1.ContainerStatus{
						{Name: "ephemeral1", ImageID: "sha256:xyz789"},
					},
				},
			},
			want: true,
		},
		{
			name: "no changes",
			oldPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{
						{Type: v1.PodReady, Status: v1.ConditionTrue},
					},
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:abc123"},
					},
				},
			},
			newPod: v1.Pod{
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{
						{Type: v1.PodReady, Status: v1.ConditionTrue},
					},
					ContainerStatuses: []v1.ContainerStatus{
						{Name: "container1", ImageID: "sha256:abc123"},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PodContainerStatusChanged(tt.oldPod, tt.newPod)
			if got != tt.want {
				t.Errorf("PodContainerStatusChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPodPredicate_CreateFunc(t *testing.T) {
	tests := []struct {
		name               string
		excludedNamespaces []string
		currentNode        string
		runAsDaemon        bool
		event              event.CreateEvent
		want               bool
	}{
		{
			name:               "not in initial list",
			excludedNamespaces: []string{},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
				IsInInitialList: false,
			},
			want: false,
		},
		{
			name:               "excluded namespace",
			excludedNamespaces: []string{"kube-system"},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "kube-system", v1.PodRunning, "node-1", true),
				IsInInitialList: true,
			},
			want: false,
		},
		{
			name:               "pod in pending state",
			excludedNamespaces: []string{},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodPending, "node-1", true),
				IsInInitialList: true,
			},
			want: false,
		},
		{
			name:               "pod with unresolved images",
			excludedNamespaces: []string{},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", false),
				IsInInitialList: true,
			},
			want: false,
		},
		{
			name:               "valid running pod",
			excludedNamespaces: []string{},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
				IsInInitialList: true,
			},
			want: true,
		},
		{
			name:               "valid succeeded pod",
			excludedNamespaces: []string{},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodSucceeded, "node-1", true),
				IsInInitialList: true,
			},
			want: true,
		},
		{
			name:               "valid failed pod",
			excludedNamespaces: []string{},
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodFailed, "node-1", true),
				IsInInitialList: true,
			},
			want: true,
		},
		{
			name:               "daemon mode - different node",
			excludedNamespaces: []string{},
			currentNode:        "node-2",
			runAsDaemon:        true,
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
				IsInInitialList: true,
			},
			want: false,
		},
		{
			name:               "daemon mode - same node",
			excludedNamespaces: []string{},
			currentNode:        "node-1",
			runAsDaemon:        true,
			event: event.CreateEvent{
				Object:          createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
				IsInInitialList: true,
			},
			want: true,
		},
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	for _, tt := range tests {
		nsExclusions := NewNamespaceExclusions(logger, tt.excludedNamespaces)
		t.Run(tt.name, func(t *testing.T) {
			predicate := NewPodPredicate(nsExclusions, tt.currentNode, tt.runAsDaemon)
			got := predicate.Create(tt.event)
			if got != tt.want {
				t.Errorf("NewPodPredicate().Create() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPodPredicate_UpdateFunc(t *testing.T) {
	tests := []struct {
		name               string
		excludedNamespaces []string
		currentNode        string
		runAsDaemon        bool
		event              event.UpdateEvent
		want               bool
	}{
		{
			name:               "excluded namespace",
			excludedNamespaces: []string{"kube-system"},
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPod("test-pod", "kube-system", v1.PodPending, "node-1", false),
				ObjectNew: createUnstructuredPod("test-pod", "kube-system", v1.PodRunning, "node-1", true),
			},
			want: false,
		},
		{
			name:               "new pod still pending",
			excludedNamespaces: []string{},
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPod("test-pod", "default", v1.PodPending, "node-1", false),
				ObjectNew: createUnstructuredPod("test-pod", "default", v1.PodPending, "node-1", false),
			},
			want: false,
		},
		{
			name:               "images not resolved",
			excludedNamespaces: []string{},
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPod("test-pod", "default", v1.PodPending, "node-1", false),
				ObjectNew: createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", false),
			},
			want: false,
		},
		{
			name:               "pending to running transition",
			excludedNamespaces: []string{},
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPod("test-pod", "default", v1.PodPending, "node-1", false),
				ObjectNew: createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
			},
			want: true,
		},
		{
			name:               "image ID changed",
			excludedNamespaces: []string{},
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPodWithImage("test-pod", "default", v1.PodRunning, "node-1", "nginx:1.0", "sha256:abc123"),
				ObjectNew: createUnstructuredPodWithImage("test-pod", "default", v1.PodRunning, "node-1", "nginx:1.0", "sha256:xyz789"),
			},
			want: true,
		},
		{
			name:               "daemon mode - different node",
			excludedNamespaces: []string{},
			currentNode:        "node-2",
			runAsDaemon:        true,
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPod("test-pod", "default", v1.PodPending, "node-1", false),
				ObjectNew: createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
			},
			want: false,
		},
		{
			name:               "no changes",
			excludedNamespaces: []string{},
			event: event.UpdateEvent{
				ObjectOld: createUnstructuredPodWithImage("test-pod", "default", v1.PodRunning, "node-1", "nginx:1.0", "sha256:abc123"),
				ObjectNew: createUnstructuredPodWithImage("test-pod", "default", v1.PodRunning, "node-1", "nginx:1.0", "sha256:abc123"),
			},
			want: false,
		},
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	for _, tt := range tests {
		nsExclusions := NewNamespaceExclusions(logger, tt.excludedNamespaces)
		t.Run(tt.name, func(t *testing.T) {
			predicate := NewPodPredicate(nsExclusions, tt.currentNode, tt.runAsDaemon)
			got := predicate.Update(tt.event)
			if got != tt.want {
				t.Errorf("NewPodPredicate().Update() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPodPredicate_DeleteFunc(t *testing.T) {
	tests := []struct {
		name               string
		excludedNamespaces []string
		event              event.DeleteEvent
		want               bool
	}{
		{
			name:               "always skip delete events",
			excludedNamespaces: []string{},
			event: event.DeleteEvent{
				Object: createUnstructuredPod("test-pod", "default", v1.PodRunning, "node-1", true),
			},
			want: false,
		},
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsExclusions := NewNamespaceExclusions(logger, tt.excludedNamespaces)
			predicate := NewPodPredicate(nsExclusions, "", false)
			got := predicate.Delete(tt.event)
			if got != tt.want {
				t.Errorf("NewPodPredicate().Delete() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper functions for creating test objects
func createUnstructuredPod(name, namespace string, phase v1.PodPhase, nodeName string, imagesResolved bool) *unstructured.Unstructured {
	imageID := ""
	if imagesResolved {
		imageID = "sha256:abc123"
	}

	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{
				{
					Name:  "test-container",
					Image: "nginx:latest",
				},
			},
		},
		Status: v1.PodStatus{
			Phase: phase,
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name:    "test-container",
					ImageID: imageID,
				},
			},
		},
	}

	unstructuredObj, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	return &unstructured.Unstructured{Object: unstructuredObj}
}

func createUnstructuredPodWithImage(name, namespace string, phase v1.PodPhase, nodeName, image, imageID string) *unstructured.Unstructured {
	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{
				{
					Name:  "test-container",
					Image: image,
				},
			},
		},
		Status: v1.PodStatus{
			Phase: phase,
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name:    "test-container",
					ImageID: imageID,
				},
			},
		},
	}

	unstructuredObj, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	return &unstructured.Unstructured{Object: unstructuredObj}
}
