package models

type SBOMPayload struct {
	Payload  []byte `json:"payload"`
	Image    string `json:"image"`
	ImageSHA string `json:"imageSHA"`
}
