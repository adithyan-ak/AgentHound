//go:build darwin || linux

package config

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestDiscoverInstructionsExactTreeRejectsFIFOWithoutBlocking(t *testing.T) {
	project := t.TempDir()
	fifo := filepath.Join(project, ".cursor", "rules", "blocked.mdc")
	makeInstructionFIFO(t, fifo)

	discovery := discoverInstructionsWithin(t, "", project, InstructionScan{})
	root := instructionOutcomeForMethod(
		discovery.Outcomes,
		ingest.InstructionMethodExactProject,
	)
	if root == nil || root.State != ingest.OutcomePartial {
		t.Fatalf("exact project root = %+v, want partial", root)
	}
	if len(discovery.Observations) != 0 {
		t.Fatalf("exact FIFO emitted facts: %+v", discovery.Observations)
	}
}

func TestDiscoverInstructionsDeepStandaloneRejectsFIFOWithoutBlocking(t *testing.T) {
	home := t.TempDir()
	fifo := filepath.Join(home, "nested", "AGENTS.md")
	makeInstructionFIFO(t, fifo)

	discovery := discoverInstructionsWithin(
		t,
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomePartial {
		t.Fatalf("deep root = %+v, want partial", root)
	}
	if len(discovery.Observations) != 0 {
		t.Fatalf("deep FIFO emitted facts: %+v", discovery.Observations)
	}
}

func TestReadBoundedInstructionRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "blocked.md")
	makeInstructionFIFO(t, fifo)

	type result struct {
		state ingest.OutcomeState
		err   string
	}
	done := make(chan result, 1)
	go func() {
		_, state, errText := readBoundedInstruction(fifo)
		done <- result{state: state, err: errText}
	}()

	select {
	case got := <-done:
		if got.state != ingest.OutcomeFailed ||
			got.err != "registered instruction source is not a regular file" {
			t.Fatalf("FIFO read = %+v, want failed non-regular source", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readBoundedInstruction blocked on FIFO")
	}
}

func makeInstructionFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func discoverInstructionsWithin(
	t *testing.T,
	home, project string,
	scan InstructionScan,
) InstructionDiscovery {
	t.Helper()
	done := make(chan InstructionDiscovery, 1)
	engine := testInstrEngine(t)
	go func() {
		done <- DiscoverInstructions(
			context.Background(),
			home,
			project,
			scan,
			engine,
		)
	}()

	select {
	case discovery := <-done:
		return discovery
	case <-time.After(2 * time.Second):
		t.Fatal("instruction discovery blocked on FIFO")
		return InstructionDiscovery{}
	}
}
