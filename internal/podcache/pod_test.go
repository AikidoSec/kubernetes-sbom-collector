package podcache

import (
	"context"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/features"
	featuretesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/tools/cache"
)

func TestStrip(t *testing.T) {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "excluded", Namespace: "default", UID: "uid", ResourceVersion: "42", Labels: map[string]string{"large": "data"}}, Spec: v1.PodSpec{Containers: []v1.Container{{Name: "app", Image: "nginx"}}}, Status: v1.PodStatus{Phase: v1.PodSucceeded}}
	if Strip(pod) != pod {
		t.Fatal("must strip in place")
	}
	if pod.Name != "excluded" || pod.Namespace != "default" || pod.UID != "uid" || pod.ResourceVersion != "42" {
		t.Fatal("lost identity metadata")
	}
	if !reflect.DeepEqual(pod.Spec, v1.PodSpec{}) || !reflect.DeepEqual(pod.Status, v1.PodStatus{}) || pod.Labels != nil || !IsStripped(pod) {
		t.Fatal("expected marked identity-only stub")
	}
	before := pod.DeepCopy()
	Strip(pod)
	if !reflect.DeepEqual(before, pod) {
		t.Fatal("stripping must be idempotent")
	}
}

// A single excluded Pod must not invalidate the atomic initial cache population.
func TestAtomicInitialListWithStrippedPod(t *testing.T) {
	featuretesting.SetFeatureDuringTest(t, features.AtomicFIFO, true)
	pods := []v1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "running-1", ResourceVersion: "1"}, Status: v1.PodStatus{Phase: v1.PodRunning}},
		{ObjectMeta: metav1.ObjectMeta{Name: "excluded", ResourceVersion: "1"}, Status: v1.PodStatus{Phase: v1.PodSucceeded}},
		{ObjectMeta: metav1.ObjectMeta{Name: "running-2", ResourceVersion: "1"}, Status: v1.PodStatus{Phase: v1.PodRunning}},
	}
	lw := &cache.ListWatch{
		ListFunc: func(metav1.ListOptions) (runtime.Object, error) {
			return &v1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: pods}, nil
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			w := watch.NewRaceFreeFake()
			if opts.SendInitialEvents != nil && *opts.SendInitialEvents {
				for i := range pods {
					w.Add(pods[i].DeepCopy())
				}
				w.Action(watch.Bookmark, &v1.Pod{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1", Annotations: map[string]string{metav1.InitialEventsAnnotationKey: "true"}}})
			}
			return w, nil
		},
	}
	informer := cache.NewSharedIndexInformer(lw, &v1.Pod{}, 0, cache.Indexers{})
	if err := informer.SetTransform(func(obj any) (any, error) {
		pod := obj.(*v1.Pod)
		if pod.Status.Phase == v1.PodSucceeded {
			return Strip(pod), nil
		}
		return pod, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); informer.Run(ctx.Done()) }()
	defer func() { cancel(); <-done }()
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		t.Fatal("cache did not sync")
	}
	if got := len(informer.GetStore().List()); got != 3 {
		t.Fatalf("cached %d pods, want 3", got)
	}
	for _, name := range []string{"running-1", "excluded", "running-2"} {
		obj, exists, err := informer.GetStore().GetByKey(name)
		if err != nil || !exists {
			t.Fatalf("missing %s: %v", name, err)
		}
		if IsStripped(obj.(*v1.Pod)) != (name == "excluded") {
			t.Fatalf("wrong stripped state for %s", name)
		}
	}
}
