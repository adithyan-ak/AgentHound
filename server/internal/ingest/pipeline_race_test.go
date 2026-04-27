package ingest

import (
	"sync"
	"testing"
)

// TestPipeline_HasMutex is a structural regression: the Pipeline must
// embed a sync.Mutex so concurrent Ingest() calls serialize. Without
// it, the post-processor's stale-edge cleanup races between scans and
// produces edge flapping. We verify by asserting that p.mu can be
// taken and is a *sync.Mutex.
func TestPipeline_HasMutex(t *testing.T) {
	p := &Pipeline{}
	// Compile-time check: p.mu is a sync.Mutex value. Lock+Unlock must
	// be callable on it. If the field is renamed/removed, this fails
	// to compile.
	var _ sync.Locker = &p.mu
	p.mu.Lock()
	p.mu.Unlock()
}
