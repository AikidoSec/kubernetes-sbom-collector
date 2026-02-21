package image

import (
	"reflect"
	"testing"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

func TestParseImageReference(t *testing.T) {
	type args struct {
		image string
	}
	tests := []struct {
		name    string
		args    args
		want    models.ImageReference
		wantErr bool
	}{
		{
			name: "simple docker image with tag",
			args: args{
				image: "nginx:1.21.6",
			},
			want: models.ImageReference{
				Registry:            "index.docker.io",
				ShorthandRegistry:   "",
				Repository:          "library/nginx",
				ShorthandRepository: "nginx",
				Tag:                 "1.21.6",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "docker image with registry and tag",
			args: args{
				image: "docker.io/nginx:1.21.6",
			},
			want: models.ImageReference{
				Registry:            "index.docker.io",
				ShorthandRegistry:   "",
				Repository:          "library/nginx",
				ShorthandRepository: "nginx",
				Tag:                 "1.21.6",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "full docker image",
			args: args{
				image: "index.docker.io/library/nginx:1.21.6",
			},
			want: models.ImageReference{
				Registry:            "index.docker.io",
				ShorthandRegistry:   "",
				Repository:          "library/nginx",
				ShorthandRepository: "nginx",
				Tag:                 "1.21.6",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "docker image with digest",
			args: args{
				image: "docker.io/library/nginx@sha256:fb39280b7b9eba5727c884a3c7810002e69e8f961cc373b89c92f14961d903a0",
			},
			want: models.ImageReference{
				Registry:            "index.docker.io",
				ShorthandRegistry:   "",
				Repository:          "library/nginx",
				ShorthandRepository: "nginx",
				Tag:                 "",
				Digest:              "sha256:fb39280b7b9eba5727c884a3c7810002e69e8f961cc373b89c92f14961d903a0",
				ReferenceType:       models.DigestReference,
			},
		},
		{
			name: "ECR private image",
			args: args{
				image: "445567102436.dkr.ecr.eu-west-1.amazonaws.com/httpd:2.4.59-alpine",
			},
			want: models.ImageReference{
				Registry:            "445567102436.dkr.ecr.eu-west-1.amazonaws.com",
				ShorthandRegistry:   "445567102436.dkr.ecr.eu-west-1.amazonaws.com",
				Repository:          "httpd",
				ShorthandRepository: "httpd",
				Tag:                 "2.4.59-alpine",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "ECR public image",
			args: args{
				image: "public.ecr.aws/nginx/nginx:1.21.6",
			},
			want: models.ImageReference{
				Registry:            "public.ecr.aws",
				ShorthandRegistry:   "public.ecr.aws",
				Repository:          "nginx/nginx",
				ShorthandRepository: "nginx/nginx",
				Tag:                 "1.21.6",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "Google Artifact Registry image",
			args: args{
				image: "europe-west1-docker.pkg.dev/gcp-project/httpd/httpd:2.4.51-alpine",
			},
			want: models.ImageReference{
				Registry:            "europe-west1-docker.pkg.dev",
				ShorthandRegistry:   "europe-west1-docker.pkg.dev/gcp-project",
				Repository:          "gcp-project/httpd/httpd",
				ShorthandRepository: "httpd/httpd",
				Tag:                 "2.4.51-alpine",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "Google Artifact Registry image with digest",
			args: args{
				image: "us-docker.pkg.dev/secretmanager-csi/secrets-store-csi-driver-provider-gcp/plugin@sha256:183c92fbe7905ebe09ccec6496e91b7b615b1e88096576bc100d46fe97fe9770",
			},
			want: models.ImageReference{
				Registry:            "us-docker.pkg.dev",
				ShorthandRegistry:   "us-docker.pkg.dev/secretmanager-csi",
				Repository:          "secretmanager-csi/secrets-store-csi-driver-provider-gcp/plugin",
				ShorthandRepository: "secrets-store-csi-driver-provider-gcp/plugin",
				Tag:                 "",
				Digest:              "sha256:183c92fbe7905ebe09ccec6496e91b7b615b1e88096576bc100d46fe97fe9770",
				ReferenceType:       models.DigestReference,
			},
		},
		{
			name: "GCR public image",
			args: args{
				image: "gcr.io/distroless/nodejs22@sha256:42f134f56bfbddb9e6c1a8840322e793a5403261f8b92f131f022ff7ec089631",
			},
			want: models.ImageReference{
				Registry:            "gcr.io",
				ShorthandRegistry:   "gcr.io",
				Repository:          "distroless/nodejs22",
				ShorthandRepository: "distroless/nodejs22",
				Tag:                 "",
				Digest:              "sha256:42f134f56bfbddb9e6c1a8840322e793a5403261f8b92f131f022ff7ec089631",
				ReferenceType:       models.DigestReference,
			},
		},
		{
			name: "docker image with tag and digest",
			args: args{
				image: "docker.io/library/nginx:1.21.6@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
			},
			want: models.ImageReference{
				Registry:            "index.docker.io",
				ShorthandRegistry:   "",
				Repository:          "library/nginx",
				ShorthandRepository: "nginx",
				Tag:                 "1.21.6",
				Digest:              "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
				ReferenceType:       models.DigestReference,
			},
		},
		{
			name: "Cloudsmith image",
			args: args{
				image: "docker.cloudsmith.io/lucian-miron-orga/lucian-miron-repo/alpine",
			},
			want: models.ImageReference{
				Registry:            "docker.cloudsmith.io",
				ShorthandRegistry:   "docker.cloudsmith.io",
				Repository:          "lucian-miron-orga/lucian-miron-repo/alpine",
				ShorthandRepository: "lucian-miron-orga/lucian-miron-repo/alpine",
				Tag:                 "latest",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "Quay.io image",
			args: args{
				image: "quay.io/openshift-release-dev/ocp-v4.0-art-dev:v4.14",
			},
			want: models.ImageReference{
				Registry:            "quay.io",
				ShorthandRegistry:   "quay.io",
				Repository:          "openshift-release-dev/ocp-v4.0-art-dev",
				ShorthandRepository: "openshift-release-dev/ocp-v4.0-art-dev",
				Tag:                 "v4.14",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "GitHub Container Registry image",
			args: args{
				image: "ghcr.io/actions/gha-runner-scale-set-controller:0.13.1",
			},
			want: models.ImageReference{
				Registry:            "ghcr.io",
				ShorthandRegistry:   "ghcr.io",
				Repository:          "actions/gha-runner-scale-set-controller",
				ShorthandRepository: "actions/gha-runner-scale-set-controller",
				Tag:                 "0.13.1",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "Red Hat Registry image",
			args: args{
				image: "registry.redhat.io/redhat/community-operator-index:v4.14",
			},
			want: models.ImageReference{
				Registry:            "registry.redhat.io",
				ShorthandRegistry:   "registry.redhat.io",
				Repository:          "redhat/community-operator-index",
				ShorthandRepository: "redhat/community-operator-index",
				Tag:                 "v4.14",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "Kubernetes Registry image",
			args: args{
				image: "registry.k8s.io/git-sync/git-sync:v4.3.0",
			},
			want: models.ImageReference{
				Registry:            "registry.k8s.io",
				ShorthandRegistry:   "registry.k8s.io",
				Repository:          "git-sync/git-sync",
				ShorthandRepository: "git-sync/git-sync",
				Tag:                 "v4.3.0",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
		{
			name: "Mirror GCR image",
			args: args{
				image: "mirror.gcr.io/aquasec/trivy:0.63.0",
			},
			want: models.ImageReference{
				Registry:            "mirror.gcr.io",
				ShorthandRegistry:   "mirror.gcr.io",
				Repository:          "aquasec/trivy",
				ShorthandRepository: "aquasec/trivy",
				Tag:                 "0.63.0",
				Digest:              "",
				ReferenceType:       models.TagReference,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseImageReference(tt.args.image)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImageReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseImageReference() got = %v, want %v", got, tt.want)
			}
		})
	}
}
