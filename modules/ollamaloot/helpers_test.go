package ollamaloot

import (
	"encoding/json"
	"io"
	"net/http"
)

// readAllString drains r.Body into a string. Test-only helper.
func readAllString(r *http.Request) (string, error) {
	defer func() { _ = r.Body.Close() }()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// jsonString emits a JSON-quoted string literal, used to embed
// multi-line modelfile content into stub responses.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
