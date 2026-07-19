package ingest

import (
	"fmt"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/dbtest"
)

// TestMain serializes live publication/campaign integrations with every other
// package that shares Neo4j. Lock is a no-op without a configured URI.
func TestMain(m *testing.M) {
	release, err := dbtest.Lock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "acquire shared integration-test lock:", err)
		os.Exit(1)
	}
	code := m.Run()
	release()
	os.Exit(code)
}
