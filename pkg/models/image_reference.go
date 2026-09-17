package models

import (
	"strings"

	stereoscopeImage "github.com/anchore/stereoscope/pkg/image"
)

type ContainerReferenceType int

const (
	DigestReference ContainerReferenceType = iota
	TagReference
)

type ImageReference struct {
	Registry            string                 `json:"registry"`
	ShorthandRegistry   string                 `json:"shorthand_registry"`
	Repository          string                 `json:"repository"`
	ShorthandRepository string                 `json:"shorthand_repository"`
	Tag                 string                 `json:"tag"`
	Digest              string                 `json:"digest"`
	ReferenceType       ContainerReferenceType `json:"reference_type"`
	ResolvedImageID     string                 `json:"resolved_image_id"`
	ResolvedImage       string                 `json:"resolved_image"`
	// ImageNameReference is the reference used by Syft to find the image and generate the SBOM.
	// By default, it is built from the image name and the digest reported in the container status.
	// When the collector runs as a DaemonSet on a containerd node, this may instead use the
	// image name and target digest from local containerd metadata. If that reference is not
	// present in containerd, it falls back to the containerd image name, usually image:tag.
	ImageNameReference string                     `json:"image_name_reference"`
	ImagePlatform      *stereoscopeImage.Platform `json:"-"`
}

func (i *ImageReference) String() string {
	builder := strings.Builder{}

	builder.WriteString(i.Name())

	if i.Tag != "" {
		builder.WriteString(":")
		builder.WriteString(i.Tag)
	}

	if i.Digest != "" {
		builder.WriteString("@")
		builder.WriteString(i.Digest)
	}

	return builder.String()
}

func (i *ImageReference) NameWithDigest() string {
	builder := strings.Builder{}

	builder.WriteString(i.Name())
	builder.WriteString("@")
	builder.WriteString(i.Digest)

	return builder.String()
}

func (i *ImageReference) Name() string {
	builder := strings.Builder{}

	if i.Registry != "" {
		builder.WriteString(i.Registry)
		builder.WriteString("/")
	}

	builder.WriteString(i.Repository)

	return builder.String()
}

func (i *ImageReference) ShorthandName() string {
	builder := strings.Builder{}

	if i.ShorthandRegistry != "" {
		builder.WriteString(i.ShorthandRegistry)
		builder.WriteString("/")
	}

	builder.WriteString(i.ShorthandRepository)

	return builder.String()
}

func (i *ImageReference) Equals(other ImageReference) bool {
	if i.ReferenceType != other.ReferenceType {
		return false
	}

	if i.Registry != other.Registry || i.Repository != other.Repository {
		return false
	}

	switch i.ReferenceType {
	case DigestReference:
		return i.Digest == other.Digest
	case TagReference:
		return i.Tag == other.Tag
	default:
		return false
	}
}
