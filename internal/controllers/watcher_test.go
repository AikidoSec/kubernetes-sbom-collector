package controllers

import "testing"

func TestContainerRuntimeFromID(t *testing.T) {
	tests := map[string]struct {
		containerID string
		want        string
	}{
		"containerd": {
			containerID: "containerd://abc123",
			want:        "containerd",
		},
		"docker": {
			containerID: "docker://abc123",
			want:        "docker",
		},
		"cri-o": {
			containerID: "cri-o://abc123",
			want:        "cri-o",
		},
		"empty": {
			containerID: "",
			want:        "",
		},
		"missing scheme": {
			containerID: "abc123",
			want:        "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ContainerRuntimeFromID(tt.containerID); got != tt.want {
				t.Fatalf("runtime = %q, want %q", got, tt.want)
			}
		})
	}
}
