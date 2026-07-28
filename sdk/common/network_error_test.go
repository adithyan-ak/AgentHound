package common

import (
	"fmt"
	"syscall"
	"testing"
)

func TestIsConnectionRefused(t *testing.T) {
	if !IsConnectionRefused(
		fmt.Errorf("wrapped dial error: %w", syscall.ECONNREFUSED),
	) {
		t.Fatal("wrapped connection refusal was not recognized")
	}
	if IsConnectionRefused(syscall.ECONNRESET) {
		t.Fatal("connection reset was classified as connection refusal")
	}
}
