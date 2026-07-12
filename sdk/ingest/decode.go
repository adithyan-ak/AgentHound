package ingest

import (
	"encoding/json"
	"fmt"
	"io"
)

// DecodeStrict decodes exactly one ingest-v2 document and rejects unknown
// structural fields. Collector-defined graph properties remain open maps.
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
