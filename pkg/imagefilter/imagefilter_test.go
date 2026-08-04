package imagefilter

import "testing"

func TestCompileNamePatternsAndMatch(t *testing.T) {
	patterns, err := CompileNamePatterns([]string{
		"registry.k8s.io/*",
		"*/pause",
		"nginx",
	})
	if err != nil {
		t.Fatalf("error compiling image name patterns: %v", err)
	}

	tests := []struct {
		name      string
		imageName string
		want      bool
	}{
		{
			name:      "matches registry glob",
			imageName: "registry.k8s.io/git-sync/git-sync",
			want:      true,
		},
		{
			name:      "matches repository suffix glob",
			imageName: "docker.io/library/pause",
			want:      true,
		},
		{
			name:      "matches exact image name",
			imageName: "nginx",
			want:      true,
		},
		{
			name:      "does not match tag because matcher receives image name",
			imageName: "docker.io/library/nginx",
			want:      false,
		},
		{
			name:      "does not match unrelated image",
			imageName: "docker.io/library/redis",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := patterns.Match(tt.imageName); got != tt.want {
				t.Errorf("NamePatterns.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompileNamePatternsReturnsErrorForInvalidPattern(t *testing.T) {
	if _, err := CompileNamePatterns([]string{"["}); err == nil {
		t.Fatal("CompileNamePatterns error is nil, want error")
	}
}
