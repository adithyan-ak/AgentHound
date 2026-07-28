//go:build windows

package common

import (
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

func TestIsConnectionRefusedRecognizesWinsockError(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "http://127.0.0.1:1",
		Err: &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: os.NewSyscallError(
				"connectex",
				syscall.Errno(10061),
			),
		},
	}
	if !IsConnectionRefused(err) {
		t.Fatalf("wrapped WSAECONNREFUSED was not recognized: %v", err)
	}
}
