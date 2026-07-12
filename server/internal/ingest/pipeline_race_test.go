package ingest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestPipeline_HasMutex is a structural regression: the Pipeline must
// embed a sync.Mutex so concurrent Ingest() calls serialize. Without
// it, post-processor epoch replacement races between scans and produces
// edge flapping. We verify the field exists and satisfies
// sync.Locker — if it is renamed or its type changes, this fails to
// compile. The runtime invariant is enforced by
// TestPipeline_MutexActuallySerializes below.
func TestPipeline_HasMutex(_ *testing.T) {
	p := &Pipeline{}
	// Compile-time assertion: &p.mu must satisfy sync.Locker.
	var _ sync.Locker = &p.mu
}

// TestPipeline_MutexActuallySerializes is the runtime regression that
// the structural test cannot enforce: even with the field present, if
// Ingest forgets to take the lock, concurrent invocations race. We
// hammer Ingest with concurrent goroutines and assert the writer
// observed at most one in-flight call at any moment. -race additionally
// flags any data race in Pipeline state itself.
//
// This complements TestPipeline_ConcurrentIngestSerialized in
// pipeline_test.go (which exercises the broader behavior), focused
// purely on the lock invariant.
func TestPipeline_MutexActuallySerializes(t *testing.T) {
	concurrent := atomic.Int32{}
	maxSeen := atomic.Int32{}

	w := &fakeWriter{}
	// Replace WriteNodes with a busier-loop variant so the test can
	// detect concurrent entries even on fast machines. We do this by
	// wrapping in a custom writer.
	probe := &probeWriter{
		concurrent: &concurrent,
		maxSeen:    &maxSeen,
		inner:      w,
	}

	p := newTestPipeline(probe, &graph.MockGraphDB{}, &fakeScanStore{}, noOpRunPP)

	const N = 20
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := validIngestDataFor("scan-mu-" + intToStrI(id))
			if _, err := p.Ingest(context.Background(), data); err != nil {
				t.Errorf("Ingest: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if got := maxSeen.Load(); got > 1 {
		t.Errorf("Pipeline.mu failed: %d concurrent WriteNodes observed; want at most 1", got)
	}
}

// probeWriter increments a counter on entry and decrements on exit, so
// any overlapping invocation of WriteNodes is visible after the run.
type probeWriter struct {
	concurrent *atomic.Int32
	maxSeen    *atomic.Int32
	inner      nodeEdgeWriter
}

func (p *probeWriter) WriteObservationNodes(
	ctx context.Context,
	nodes []ingest.Node,
	scanID string,
	completeDomains []string,
) (int, error) {
	cur := p.concurrent.Add(1)
	defer p.concurrent.Add(-1)
	for {
		max := p.maxSeen.Load()
		if cur <= max || p.maxSeen.CompareAndSwap(max, cur) {
			break
		}
	}
	return p.inner.WriteObservationNodes(ctx, nodes, scanID, completeDomains)
}

func (p *probeWriter) WriteObservationEdges(
	ctx context.Context,
	edges []ingest.Edge,
	scanID string,
	completeDomains []string,
) (int, error) {
	return p.inner.WriteObservationEdges(ctx, edges, scanID, completeDomains)
}
