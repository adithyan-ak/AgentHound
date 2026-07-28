package common

import (
	"errors"
	"runtime"
	"syscall"
)

// windowsWSAConnectionRefused is WSAECONNREFUSED. Go's
// syscall.ECONNREFUSED is a synthesized compatibility value on Windows and is
// not the error returned by Winsock.
const windowsWSAConnectionRefused syscall.Errno = 10061

// IsConnectionRefused reports whether err proves that the probed TCP endpoint
// actively rejected the connection. Unlike timeouts, TLS failures, DNS
// failures, and connection resets, an explicit refusal is a conclusive
// negative for that host:port at probe time.
func IsConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		(runtime.GOOS == "windows" &&
			errors.Is(err, windowsWSAConnectionRefused))
}
