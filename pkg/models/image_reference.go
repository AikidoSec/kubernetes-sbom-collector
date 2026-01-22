package models

import "strings"

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
}

func (i ImageReference) String() string {
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

func (i ImageReference) Name() string {
	builder := strings.Builder{}

	if i.Registry != "" {
		builder.WriteString(i.Registry)
		builder.WriteString("/")
	}

	builder.WriteString(i.Repository)

	return builder.String()
}

func (i ImageReference) ShorthandName() string {
	builder := strings.Builder{}

	if i.ShorthandRegistry != "" {
		builder.WriteString(i.ShorthandRegistry)
		builder.WriteString("/")
	}

	builder.WriteString(i.ShorthandRepository)

	return builder.String()
}

func (i ImageReference) Equals(other ImageReference) bool {
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
