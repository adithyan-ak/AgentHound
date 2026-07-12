package ingest

import (
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/dbtest"
)

// TestMain serializes the destructive fresh-publication integration with the
// other packages that share Neo4j. It is a no-op without a configured URI.
func TestMain(m *testing.M) {
	release, err := dbtest.Lock()
	if err != nil {
		panic(err)
	}
	code := m.Run()
	release()
	os.Exit(code)
}
