package models

import "time"

type SBOMPayload struct {
	Payload        []byte    `json:"payload"`
	Image          string    `json:"image"`
	Digest         string    `json:"digest"`
	Tag            string    `json:"tag"`
	PodSourceID    string    `json:"pod_source_id"`
	ImageSizeBytes int64     `json:"image_size_bytes,omitempty"`
	ImageUpdatedAt time.Time `json:"image_updated_at,omitempty,omitzero"`
	AdditionalTags []string  `json:"additional_tags,omitempty"`
}
