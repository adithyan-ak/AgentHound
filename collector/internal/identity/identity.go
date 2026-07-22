// Package identity derives zero-configuration collection provenance from
// native operating-system and network evidence without spawning child
// processes or creating target-side state.
package identity

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

var applicationKey = []byte("AgentHound collection identity v1\x00d2b13d95-1f91-4b6a-a8df-e212ffc8c41b")

type rawSignal struct {
	kind  string
	value string
}

// Derive returns a deterministic record. Missing platform evidence never
// blocks collection: the hostname/MAC fallback is classified weak, and a
// completely opaque environment receives an artifact-local weak identity.
func Derive(scanID string) ingest.CollectionIdentity {
	platform, network, routesComplete := platformSignals()
	interfaceSignals, interfacesComplete := interfaceNetworkSignals()
	if !routesComplete {
		network = append(network, rawSignal{kind: "network_visibility_unknown", value: "route_table"})
	}
	if !interfacesComplete {
		network = append(network, rawSignal{kind: "network_visibility_unknown", value: "interfaces"})
	}
	identity := deriveFromSignals(
		scanID,
		platform,
		network,
		fallbackSignals(),
		append(interfaceSignals, dnsSearchSignals()...),
	)
	identity.Display = collectionDisplayLabels()
	return identity
}

func deriveFromSignals(
	scanID string,
	platform, network, fallback, observedNetwork []rawSignal,
) ingest.CollectionIdentity {
	if !containsKind(platform, "os_instance") {
		platform = append(platform, fallback...)
		platform = keepKinds(platform, "principal", "container", "filesystem", "execution_scope_unknown", "hostname", "mac")
	}
	if len(platform) == 0 {
		platform = []rawSignal{{kind: "artifact", value: scanID}}
	}

	network = append(network, observedNetwork...)
	network = uniqueSignals(network)
	networkClass := classifyNetwork(network)
	if len(network) == 0 {
		networkClass = ingest.NetworkClassOffline
		network = []rawSignal{{kind: "offline", value: "offline"}}
	}

	return ingest.NewCollectionIdentity(
		hashSignals(platform),
		hashSignals(network),
		networkClass,
	)
}

func hashSignals(signals []rawSignal) []ingest.IdentityEvidence {
	signals = uniqueSignals(signals)
	evidence := make([]ingest.IdentityEvidence, 0, len(signals))
	for _, signal := range signals {
		mac := hmac.New(sha256.New, applicationKey)
		_, _ = mac.Write([]byte(signal.kind))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(signal.value))
		evidence = append(evidence, ingest.IdentityEvidence{
			Kind:   signal.kind,
			Digest: fmt.Sprintf("hmac-sha256:%x", mac.Sum(nil)),
		})
	}
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].Kind == evidence[j].Kind {
			return evidence[i].Digest < evidence[j].Digest
		}
		return evidence[i].Kind < evidence[j].Kind
	})
	return evidence
}

func fallbackSignals() []rawSignal {
	var signals []rawSignal
	if hostname, err := os.Hostname(); err == nil {
		if hostname = strings.ToLower(strings.TrimSpace(hostname)); hostname != "" {
			signals = append(signals, rawSignal{kind: "hostname", value: hostname})
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return signals
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		address := append(net.HardwareAddr(nil), iface.HardwareAddr...)
		// Prefer globally administered addresses. Locally administered values
		// are frequently randomized and are unsuitable even as a fallback.
		if address[0]&0x02 != 0 {
			continue
		}
		signals = append(signals, rawSignal{kind: "mac", value: strings.ToLower(address.String())})
	}
	return signals
}

func interfaceNetworkSignals() ([]rawSignal, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	var signals []rawSignal
	complete := true
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			complete = false
			continue
		}
		for _, address := range addresses {
			ip, network, err := net.ParseCIDR(address.String())
			if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			network.IP = ip.Mask(network.Mask)
			kind := "route_public"
			if ip.IsPrivate() {
				kind = "route_private"
			}
			signals = append(signals, rawSignal{kind: kind, value: network.String()})
		}
	}
	return signals, complete
}

func dnsSearchSignals() []rawSignal {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	var signals []rawSignal
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "search" && fields[0] != "domain" {
			continue
		}
		for _, domain := range fields[1:] {
			if domain = strings.ToLower(strings.TrimSuffix(domain, ".")); domain != "" {
				signals = append(signals, rawSignal{kind: "dns_domain", value: domain})
			}
		}
	}
	return signals
}

func classifyNetwork(signals []rawSignal) ingest.NetworkClass {
	var private, public, unknown bool
	for _, signal := range signals {
		switch signal.kind {
		case "route_private", "default_gateway", "network_profile", "dns_domain":
			private = true
		case "route_public":
			public = true
		case "network_visibility_unknown":
			unknown = true
		}
	}
	switch {
	case private && public:
		return ingest.NetworkClassMixed
	case private:
		return ingest.NetworkClassPrivate
	case public:
		return ingest.NetworkClassPublic
	case unknown:
		return ingest.NetworkClassUnknown
	default:
		return ingest.NetworkClassOffline
	}
}

func collectionDisplayLabels() ingest.CollectionDisplayLabels {
	hostname, _ := os.Hostname()
	return ingest.CollectionDisplayLabels{
		Hostname:     boundedDisplayLabel(hostname),
		OS:           boundedDisplayLabel(runtime.GOOS),
		Architecture: boundedDisplayLabel(runtime.GOARCH),
	}
}

func boundedDisplayLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) > 255 {
		runes = runes[:255]
	}
	for _, char := range runes {
		if unicode.Is(unicode.C, char) {
			return ""
		}
	}
	return string(runes)
}

func containsKind(signals []rawSignal, kind string) bool {
	for _, signal := range signals {
		if signal.kind == kind && signal.value != "" {
			return true
		}
	}
	return false
}

func keepKinds(signals []rawSignal, kinds ...string) []rawSignal {
	allowed := make(map[string]bool, len(kinds))
	for _, kind := range kinds {
		allowed[kind] = true
	}
	var out []rawSignal
	for _, signal := range signals {
		if allowed[signal.kind] {
			out = append(out, signal)
		}
	}
	return out
}

func uniqueSignals(signals []rawSignal) []rawSignal {
	seen := make(map[string]bool, len(signals))
	out := make([]rawSignal, 0, len(signals))
	for _, signal := range signals {
		signal.value = strings.TrimSpace(signal.value)
		if signal.kind == "" || signal.value == "" {
			continue
		}
		key := signal.kind + "\x00" + signal.value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, signal)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].kind == out[j].kind {
			return out[i].value < out[j].value
		}
		return out[i].kind < out[j].kind
	})
	return out
}
