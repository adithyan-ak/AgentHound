package ingest

type Node struct {
	ID                 string         `json:"id"`
	Kinds              []string       `json:"kinds"`
	Properties         map[string]any `json:"properties"`
	ObservationDomains []string       `json:"observation_domains,omitempty"`
}
