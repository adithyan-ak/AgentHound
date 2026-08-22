package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// signalContext returns a context cancelled on the first SIGINT (Ctrl-C) or
// SIGTERM, plus a stop func to release the handler (always defer it).
//
// The scan workflow uses this so an interrupted sweep cancels the
// worker pool cleanly and still flushes whatever partial results were gathered
// to --output, instead of the process dying mid-write. syscall.SIGTERM is
// defined on every platform the collector targets (including Windows, where it
// simply never fires), so this stays cross-compile safe.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
