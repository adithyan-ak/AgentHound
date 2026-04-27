package ingest

type IngestData struct {
	Meta  IngestMeta `json:"meta"`
	Graph GraphData  `json:"graph"`
}

type IngestMeta struct {
	Version          int    `json:"version"`
	Type             string `json:"type"`
	Collector        string `json:"collector"`
	CollectorVersion string `json:"collector_version"`
	Timestamp        string `json:"timestamp"`
	ScanID           string `json:"scan_id"`
}

type GraphData struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
