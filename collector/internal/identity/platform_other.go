//go:build !linux && !darwin && !windows

package identity

func platformSignals() ([]rawSignal, []rawSignal, bool) { return nil, nil, false }
