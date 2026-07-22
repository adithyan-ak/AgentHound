package prebuilt

import (
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/dbtest"
)

// TestMain serializes this package's integration tests against the shared Neo4j
// with every other DB-touching package (see server/internal/dbtest). It is a
// no-op without AGENTHOUND_NEO4J_URI, so unit-only runs stay parallel.
func TestMain(m *testing.M) {
	release, err := dbtest.Lock()
	if err != nil {
		panic(err)
	}
	code := m.Run()
	release()
	os.Exit(code)
}
