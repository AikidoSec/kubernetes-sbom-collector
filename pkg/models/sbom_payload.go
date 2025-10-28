package models

type SBOMPayload struct {
	Payload []byte `json:"payload"`
	Image   string `json:"image"`
	Digest  string `json:"digest"`
	Tag     string `json:"tag"`
}
