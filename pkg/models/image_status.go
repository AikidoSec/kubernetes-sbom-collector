package models

type ImageStatus struct {
	Image            string `json:"image"`
	Digest           string `json:"digest"`
	Architecture     string `json:"architecture"`
	IsProcessed      bool   `json:"isProcessed"`
	MirrorRepository string `json:"mirrorRepository"`
	IsReserved       bool   `json:"isReserved"`
}
