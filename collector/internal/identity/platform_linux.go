//go:build linux

package identity

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func platformSignals() ([]rawSignal, []rawSignal, bool) {
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
	} else if linuxIsolationDetected() {
		if value := linuxNamespaceFilesystemIdentity(); value != "" {
			identity = append(identity, rawSignal{kind: "filesystem", value: value})
		} else {
			identity = append(identity, rawSignal{kind: "execution_scope_unknown", value: "isolated"})
		}
	}

	routes, routesComplete := linuxRouteSignals()
	network := append(linuxNetworkManagerProfiles(), routes...)
	return identity, network, routesComplete
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
	return linuxContainerIdentityFrom(string(data))
}

func linuxContainerIdentityFrom(data string) string {
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

func linuxIsolationDetected() bool {
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	if value := firstFileValue("/run/systemd/container"); value != "" {
		return true
	}
	if os.Getenv("container") != "" || os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if linuxNamespaceDiffersFromInit("mnt") {
		return true
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lower := strings.ToLower(string(data))
		for _, marker := range []string{"docker", "containerd", "kubepods", "libpod", "lxc"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	switch linuxRootFilesystemType(file) {
	case "aufs", "fuse-overlayfs", "overlay":
		return true
	default:
		return false
	}
}

func linuxNamespaceDiffersFromInit(name string) bool {
	self, selfErr := os.Readlink("/proc/self/ns/" + name)
	init, initErr := os.Readlink("/proc/1/ns/" + name)
	return selfErr == nil && initErr == nil && self != "" && init != "" && self != init
}

func linuxRootFilesystemType(reader io.Reader) string {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 || fields[4] != "/" {
			continue
		}
		for index, field := range fields {
			if field == "-" && index+1 < len(fields) {
				return strings.ToLower(fields[index+1])
			}
		}
	}
	return ""
}

func linuxNamespaceFilesystemIdentity() string {
	var values []string
	for _, name := range []string{"cgroup", "mnt", "pid", "user"} {
		value, err := os.Readlink("/proc/self/ns/" + name)
		if err == nil && value != "" {
			values = append(values, name+"="+value)
		}
	}
	if !containsNamespace(values, "mnt=") {
		return ""
	}
	var stat unix.Statfs_t
	if err := unix.Statfs("/", &stat); err == nil {
		values = append(values, fmt.Sprintf("rootfs=%08x%08x", uint32(stat.Fsid.Val[0]), uint32(stat.Fsid.Val[1])))
	}
	sort.Strings(values)
	return strings.Join(values, "\x00")
}

func containsNamespace(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func linuxNetworkManagerProfiles() []rawSignal {
	paths, _ := filepath.Glob("/run/NetworkManager/devices/*")
	var signals []rawSignal
	for _, path := range paths {
		if profile := linuxNetworkManagerProfile(path); profile != "" {
			signals = append(signals, rawSignal{kind: "network_profile", value: profile})
		}
	}
	return signals
}

func linuxNetworkManagerProfile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for _, prefix := range []string{"connection-uuid=", "connection_uuid="} {
			if strings.HasPrefix(line, prefix) {
				return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
			}
		}
	}
	return ""
}

type linuxRoutePathResolver func(interfaceName string) string

func linuxRoutePathDiscriminator(interfaceName string) string {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ""
	}
	var parts []string
	if profile := linuxNetworkManagerProfile(
		filepath.Join("/run/NetworkManager/devices", strconv.Itoa(iface.Index)),
	); profile != "" {
		parts = append(parts, "profile="+profile)
	}
	if address := stableLinkAddress(iface.HardwareAddr); address != "" {
		parts = append(parts, "link="+address)
	}
	return strings.Join(parts, "\x00")
}

func cachedLinuxRoutePathResolver(resolve linuxRoutePathResolver) linuxRoutePathResolver {
	cache := make(map[string]string)
	return func(interfaceName string) string {
		if value, present := cache[interfaceName]; present {
			return value
		}
		value := resolve(interfaceName)
		cache[interfaceName] = value
		return value
	}
}

func linuxRouteSignals() ([]rawSignal, bool) {
	resolvePath := cachedLinuxRoutePathResolver(linuxRoutePathDiscriminator)
	ipv4, ipv4Complete := linuxIPv4RouteSignals(resolvePath)
	ipv6, ipv6Complete := linuxIPv6RouteSignals(resolvePath)
	return append(ipv4, ipv6...), ipv4Complete && ipv6Complete
}

func linuxIPv4RouteSignals(resolvePath linuxRoutePathResolver) ([]rawSignal, bool) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, false
	}
	defer func() { _ = file.Close() }()
	return parseLinuxIPv4Routes(file, resolvePath)
}

func parseLinuxIPv4Routes(reader io.Reader, resolvePath linuxRoutePathResolver) ([]rawSignal, bool) {
	var signals []rawSignal
	complete := true
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[0] == "Iface" {
			continue
		}
		if len(fields) < 8 {
			if len(fields) > 0 {
				complete = false
			}
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			complete = false
			continue
		}
		if flags&unix.RTF_UP == 0 {
			continue
		}
		destination, destinationOK := parseLinuxIPv4Hex(fields[1])
		gateway, gatewayOK := parseLinuxIPv4Hex(fields[2])
		maskIP, maskOK := parseLinuxIPv4Hex(fields[7])
		if !destinationOK || !gatewayOK || !maskOK {
			complete = false
			continue
		}
		ones, bits := net.IPMask(maskIP.To4()).Size()
		if bits != 32 {
			complete = false
			continue
		}
		routeSignals, routeComplete := canonicalRouteSignals(
			destination,
			ones,
			gateway,
			resolvePath(fields[0]),
		)
		signals = append(signals, routeSignals...)
		complete = complete && routeComplete
	}
	return signals, complete && scanner.Err() == nil
}

func parseLinuxIPv4Hex(value string) (net.IP, bool) {
	if len(value) != 8 {
		return nil, false
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return nil, false
	}
	return net.IPv4(byte(parsed), byte(parsed>>8), byte(parsed>>16), byte(parsed>>24)), true
}

func linuxIPv6RouteSignals(resolvePath linuxRoutePathResolver) ([]rawSignal, bool) {
	file, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		if os.IsNotExist(err) {
			if _, ipv6Err := os.Stat("/proc/net/if_inet6"); os.IsNotExist(ipv6Err) {
				return nil, true
			}
		}
		return nil, false
	}
	defer func() { _ = file.Close() }()
	return parseLinuxIPv6Routes(file, resolvePath)
}

func parseLinuxIPv6Routes(reader io.Reader, resolvePath linuxRoutePathResolver) ([]rawSignal, bool) {
	var signals []rawSignal
	complete := true
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			if len(fields) > 0 {
				complete = false
			}
			continue
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil {
			complete = false
			continue
		}
		if flags&unix.RTF_UP == 0 {
			continue
		}
		destinationBytes, destinationErr := hex.DecodeString(fields[0])
		gatewayBytes, gatewayErr := hex.DecodeString(fields[4])
		prefixLength, prefixErr := strconv.ParseUint(fields[1], 16, 8)
		if destinationErr != nil || gatewayErr != nil || prefixErr != nil || prefixLength > 128 ||
			len(destinationBytes) != net.IPv6len || len(gatewayBytes) != net.IPv6len {
			complete = false
			continue
		}
		routeSignals, routeComplete := canonicalRouteSignals(
			net.IP(destinationBytes),
			int(prefixLength),
			net.IP(gatewayBytes),
			resolvePath(fields[9]),
		)
		signals = append(signals, routeSignals...)
		complete = complete && routeComplete
	}
	return signals, complete && scanner.Err() == nil
}
