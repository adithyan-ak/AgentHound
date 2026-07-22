//go:build linux

package identity

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func platformSignals() ([]rawSignal, []rawSignal) {
	var identity []rawSignal
	if value := firstFileValue("/etc/machine-id", "/var/lib/dbus/machine-id"); value != "" {
		identity = append(identity, rawSignal{kind: "os_instance", value: strings.ToLower(value)})
	}
	if value := firstFileValue("/sys/class/dmi/id/product_uuid"); value != "" {
		identity = append(identity, rawSignal{kind: "platform", value: strings.ToLower(value)})
	}
	identity = append(identity, rawSignal{kind: "principal", value: strconv.Itoa(os.Geteuid())})
	if value := linuxContainerIdentity(); value != "" {
		identity = append(identity, rawSignal{kind: "container", value: value})
	}

	network := append(linuxNetworkManagerProfiles(), linuxRouteSignals()...)
	return identity, network
}

func firstFileValue(paths ...string) string {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			if value := strings.TrimSpace(string(data)); value != "" {
				return value
			}
		}
	}
	return ""
}

func linuxContainerIdentity() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, component := range strings.FieldsFunc(line, func(char rune) bool {
			return char == '/' || char == ':'
		}) {
			candidate := strings.TrimSuffix(strings.TrimSuffix(component, ".scope"), ".slice")
			for _, prefix := range []string{"docker-", "cri-containerd-", "crio-", "libpod-"} {
				candidate = strings.TrimPrefix(candidate, prefix)
			}
			if len(candidate) >= 32 && len(candidate) <= 64 {
				if _, err := hex.DecodeString(candidate); err == nil {
					return strings.ToLower(candidate)
				}
			}
		}
	}
	return ""
}

func linuxNetworkManagerProfiles() []rawSignal {
	paths, _ := filepath.Glob("/run/NetworkManager/devices/*")
	var signals []rawSignal
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			for _, prefix := range []string{"connection-uuid=", "connection_uuid="} {
				if strings.HasPrefix(line, prefix) {
					signals = append(signals, rawSignal{
						kind: "network_profile", value: strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, prefix))),
					})
				}
			}
		}
		_ = file.Close()
	}
	return signals
}

func linuxRouteSignals() []rawSignal {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	var signals []rawSignal
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		gateway, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil || gateway == 0 {
			continue
		}
		ip := net.IPv4(byte(gateway), byte(gateway>>8), byte(gateway>>16), byte(gateway>>24))
		signals = append(signals, rawSignal{kind: "default_gateway", value: ip.String()})
	}
	return signals
}
