package models

type ImageStatus struct {
	Image       string `json:"image"`
	IsProcessed bool   `json:"isProcessed"`
}
