package models

import (
	"encoding/json"
	"io"
	"time"
)

type AgentError struct {
	Error     string    `json:"error"`
	ErrorType string    `json:"error_type"`
	SeenAt    time.Time `json:"seen_at"`
}

func (p *AgentError) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(p)
}

func (p *AgentError) ToJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(p)
}
