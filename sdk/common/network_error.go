package common

import (
	"errors"
	"syscall"
)

// IsConnectionRefused reports whether err proves that the probed TCP endpoint
// actively rejected the connection. Unlike timeouts, TLS failures, DNS
// failures, and connection resets, an explicit refusal is a conclusive
// negative for that host:port at probe time.
func IsConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
