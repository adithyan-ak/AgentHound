package model

import "time"

type Scan struct {
	ID          string         `json:"id"`
	Collector   string         `json:"collector"`
	Status      string         `json:"status"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	NodeCount   int            `json:"node_count"`
	EdgeCount   int            `json:"edge_count"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"
)
