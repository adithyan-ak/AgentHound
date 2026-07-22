package cli

import (
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
)

func TestMain(m *testing.M) {
	cfg = clientcfg.Load()
	os.Exit(m.Run())
}
