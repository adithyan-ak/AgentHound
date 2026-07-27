package ingest

import (
	"encoding/json"
	"fmt"
	"io"
)

// DecodeVersion reads only the open wire-version envelope. Callers use it
// before strict current-schema decoding so non-V1 artifacts are rejected
// before any stateful work.
func DecodeVersion(document []byte) (int, error) {
	var envelope struct {
		Meta *struct {
			Version int `json:"version"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		return 0, err
	}
	if envelope.Meta == nil {
		return 0, fmt.Errorf("meta is required")
	}
	return envelope.Meta.Version, nil
}

// DecodeStrict decodes exactly one ingest document and rejects unknown
// structural fields. Version admission is handled separately by the server.
func DecodeStrict(reader io.Reader, data *IngestData) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(data); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}
