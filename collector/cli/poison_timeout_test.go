package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/adithyan-ak/agenthound/modules/mcppoison"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func TestRunPoison_StalledToolsListIsBoundedBeforeReceiptOrMutation(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = 75 * time.Millisecond
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	for _, commit := range []bool{false, true} {
		name := "dry-run"
		if commit {
			name = "commit"
		}
		t.Run(name, func(t *testing.T) {
			var writes atomic.Int32
			listStarted := make(chan struct{})
			var startedOnce sync.Once
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPost:
					startedOnce.Do(func() { close(listStarted) })
					select {
					case <-r.Context().Done():
					case <-time.After(2 * time.Second):
					}
				case http.MethodPut:
					writes.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			engagementID := "ENG-STALL-LIST-DRY"
			if commit {
				engagementID = "ENG-STALL-LIST-COMMIT"
			}
			state, startedAt, err := executeStandaloneMCPPoison(
				t, context.Background(), srv.URL, engagementID, commit,
			)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("run poison error = %v, want context deadline exceeded", err)
			}
			if elapsed := time.Since(startedAt); elapsed > time.Second {
				t.Fatalf("stalled tools/list returned after %v, want under 1s", elapsed)
			}
			select {
			case <-listStarted:
			default:
				t.Fatal("server never accepted the tools/list request")
			}
			if got := writes.Load(); got != 0 {
				t.Fatalf("stalled pre-read issued %d mutating write(s)", got)
			}
			assertPoisonReceiptCount(t, state, engagementID, 0)
		})
	}
}

func TestRunPoison_PropagatesCommandCancellation(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = 2 * time.Second
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	var writes atomic.Int32
	listStarted := make(chan struct{})
	var startedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			startedOnce.Do(func() { close(listStarted) })
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		case http.MethodPut:
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := make(chan struct{})
	go func() {
		select {
		case <-listStarted:
			cancel()
		case <-time.After(time.Second):
		}
		close(cancelled)
	}()

	const engagementID = "ENG-STALL-CANCEL"
	state, startedAt, err := executeStandaloneMCPPoison(
		t, ctx, srv.URL, engagementID, true,
	)
	<-cancelled
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run poison error = %v, want context canceled", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("canceled tools/list returned after %v, want under 1s", elapsed)
	}
	if got := writes.Load(); got != 0 {
		t.Fatalf("canceled pre-read issued %d mutating write(s)", got)
	}
	assertPoisonReceiptCount(t, state, engagementID, 0)
}

func TestRunPoison_StalledWriteIsBoundedAndRetainsRecoveryReceipt(t *testing.T) {
	originalTimeout := standalonePoisonTimeout
	standalonePoisonTimeout = 75 * time.Millisecond
	t.Cleanup(func() { standalonePoisonTimeout = originalTimeout })

	var writes atomic.Int32
	writeStarted := make(chan struct{})
	var startedOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]any{"tools": []map[string]any{
					{"name": "support_lookup", "description": "original"},
				}},
			})
		case r.Method == http.MethodPut:
			writes.Add(1)
			startedOnce.Do(func() { close(writeStarted) })
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			// Deliberately never apply the received body or send a response.
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	const engagementID = "ENG-STALL-WRITE"
	state, startedAt, err := executeStandaloneMCPPoison(
		t, context.Background(), srv.URL, engagementID, true,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run poison error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("stalled write returned after %v, want under 1s", elapsed)
	}
	select {
	case <-writeStarted:
	default:
		t.Fatal("server never accepted the mutating write")
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("mutating write count = %d, want 1", got)
	}

	receipts := assertPoisonReceiptCount(t, state, engagementID, 1)
	receipt, ok := receipts[0].(*action.PoisonReceipt)
	if !ok {
		t.Fatalf("receipt type = %T, want *action.PoisonReceipt", receipts[0])
	}
	if receipt.DryRun {
		t.Fatal("recovery receipt is incorrectly marked dry-run")
	}
}

func executeStandaloneMCPPoison(
	t *testing.T,
	ctx context.Context,
	targetURL string,
	engagementID string,
	commit bool,
) (module.StatefulModule, time.Time, error) {
	t.Helper()
	setupSentinels(t)
	t.Setenv("AGENTHOUND_STATE_DIR", t.TempDir())

	out := &bytes.Buffer{}
	cmd := &cobra.Command{
		Use:           "poison <host>",
		Args:          cobra.ExactArgs(1),
		RunE:          runPoison,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().String("type", "", "")
	cmd.Flags().String("target-id", "", "")
	cmd.Flags().String("inject", "", "")
	cmd.Flags().String("inject-file", "", "")
	cmd.Flags().String("mode", "replace", "")
	cmd.Flags().Bool("commit", false, "")
	cmd.Flags().String("engagement-id", "", "")
	mcppoison.New().RegisterFlags(cmd.Flags())
	cmd.SetContext(ctx)
	cmd.SetIn(bytes.NewReader(nil))
	cmd.SetOut(out)
	cmd.SetErr(out)

	args := []string{
		targetURL,
		"--type", "mcp.tool.description",
		"--target-id", "support_lookup",
		"--inject", "injected",
		"--engagement-id", engagementID,
	}
	if commit {
		args = append(args, "--commit")
	}
	cmd.SetArgs(args)

	startedAt := time.Now()
	err := cmd.Execute()
	return module.NewFileStatefulModule("mcp.poison"), startedAt, err
}

func assertPoisonReceiptCount(
	t *testing.T,
	state module.StatefulModule,
	engagementID string,
	want int,
) []action.Receipt {
	t.Helper()
	receipts, err := state.ReadReceipts(engagementID)
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	if len(receipts) != want {
		t.Fatalf("receipt count = %d, want %d", len(receipts), want)
	}
	return receipts
}
