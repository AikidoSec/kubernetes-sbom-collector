package models

type SBOMPayload struct {
	Payload      []byte `json:"payload"`
	Image        string `json:"image"`
	Digest       string `json:"digest"`
	Tag          string `json:"tag"`
	Architecture string `json:"architecture"`
	PodSourceID  string `json:"pod_source_id"`
}
