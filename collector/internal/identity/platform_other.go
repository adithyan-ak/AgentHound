//go:build !linux && !darwin && !windows

package identity

func platformSignals() ([]rawSignal, []rawSignal) { return nil, nil }
