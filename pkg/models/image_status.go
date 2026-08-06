package models

type ImageStatus struct {
	Image                              string `json:"image"`
	Digest                             string `json:"digest"`
	IsProcessed                        bool   `json:"isProcessed"`
	MirrorRepository                   string `json:"mirrorRepository"`
	IsBeingProcessedByAnotherCollector bool   `json:"isBeingProcessedByAnotherCollector"`
}
