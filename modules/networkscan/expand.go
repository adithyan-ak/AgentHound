// Package networkscan implements AgentHound's narrow network scanner for AI
// services. The scanner is intentionally NOT a general-purpose tool — it
// covers a fixed set of high-value AI/ML service ports (Ollama, vLLM,
// Qdrant, MLflow, LiteLLM, Jupyter, LangServe, Open WebUI). For everything
// else, use Nmap.
package networkscan

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

// MaxCIDRBitsWithoutFlag caps unguarded CIDR expansion. Anything larger
// than /16 (IPv4) or /112 (IPv6, ~64k hosts) requires --allow-large-cidr
// because the operator probably did not mean to scan that much address
// space. The cap is on host count: 2^16 = 65,536.
const (
	MaxIPv4PrefixLen = 16
	MaxIPv6PrefixLen = 112
)

// MaxHostsHardCap is an absolute ceiling on the number of hosts a single
// spec may expand to — enforced EVEN WITH --allow-large-cidr. The
// AllowLargeCIDR override raises the prefix-bits gate but must not grant an
// unbounded enumeration: a standard IPv6 /64 (or IPv4 0.0.0.0/0) would
// otherwise materialize an astronomically large slice and exhaust memory.
// 1<<20 (1,048,576) admits legitimate lab ranges up to an IPv4 /12 or IPv6
// /108 while refusing anything larger.
const MaxHostsHardCap = 1 << 20

// ExpandError categorises why a target was rejected. Callers can match on
// the sentinel to distinguish operator error (e.g. forgot a flag) from
// hostile inputs (e.g. trying to scan multicast).
var (
	ErrLargeCIDR         = errors.New("CIDR is larger than the safe cap; pass --allow-large-cidr to override")
	ErrTooManyHosts      = errors.New("target set exceeds the absolute host cap; narrow the range (the cap applies even with --allow-large-cidr)")
	ErrPublicTarget      = errors.New("public IP space refused; pass --allow-public-targets and complete the AUTHORIZED prompt")
	ErrLinkLocal         = errors.New("link-local addresses cannot be scanned (cannot route off-host)")
	ErrMulticast         = errors.New("multicast addresses are not unicast scanning targets")
	ErrInvalidCIDR       = errors.New("invalid CIDR / host / target spec")
	ErrTargetsFileEmpty  = errors.New("targets file contains no valid entries")
	ErrNestedTargetsFile = errors.New("targets file may not reference another @file / file:// (nested includes are not allowed)")
)

// ExpandOptions controls the safety gates on target expansion. The default
// zero value is strict: refuse public IP space, refuse CIDRs larger than
// the safe cap. Callers explicitly opt-in to looser settings.
type ExpandOptions struct {
	AllowLargeCIDR     bool
	AllowPublicTargets bool
}

// Expand turns a single spec (CIDR / host / IP / file://...) into a
// bounded slice of host strings. It refuses link-local, multicast, and
// (by default) public IP space. Hostnames are returned unchanged — the
// scanner resolves them at probe time.
//
// The result is materialized rather than streamed. Callers that need to
// scan a /16 with the override flag should be prepared for ~65k entries.
func Expand(spec string, opts ExpandOptions) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("%w: empty spec", ErrInvalidCIDR)
	}

	// File-of-targets: file://path or @path.
	if strings.HasPrefix(spec, "file://") {
		return expandFile(strings.TrimPrefix(spec, "file://"), opts)
	}
	if strings.HasPrefix(spec, "@") {
		return expandFile(strings.TrimPrefix(spec, "@"), opts)
	}

	// CIDR notation: x.x.x.x/N or x:x::/N.
	if strings.Contains(spec, "/") {
		return expandCIDR(spec, opts)
	}

	// Single IP or hostname.
	return expandSingle(spec, opts)
}

// expandSingle classifies a single host token and returns it as a one-element
// slice if it passes the safety gates.
func expandSingle(host string, opts ExpandOptions) ([]string, error) {
	info := common.ClassifyHost(host)
	if info.IsLinkLocal {
		return nil, fmt.Errorf("%w: %s", ErrLinkLocal, host)
	}
	if info.IsMulticast {
		return nil, fmt.Errorf("%w: %s", ErrMulticast, host)
	}
	// DNS names remain scope=unknown until resolution. Preserve the scanner's
	// fail-closed public-target gate: an unknown name may resolve publicly even
	// though graph evidence must not label it public without that resolution.
	if (info.IsPublic || info.Scope == common.HostScopeUnknown) && !opts.AllowPublicTargets {
		return nil, fmt.Errorf("%w: %s", ErrPublicTarget, host)
	}
	return []string{host}, nil
}

// expandCIDR enumerates every host in the CIDR after applying the safety
// gates. The check happens twice: once on the network address itself
// (catches link-local/multicast/public network bases) and again per-IP as
// it is enumerated (catches CIDRs that span across classifications, which
// shouldn't happen for normal RFC1918 ranges but does happen if the
// operator types something like 169.254.0.0/15 by mistake).
func expandCIDR(spec string, opts ExpandOptions) ([]string, error) {
	var out []string
	err := expandCIDRInto(spec, opts, func(host string) error {
		out = append(out, host)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// expandCIDRInto validates a CIDR and emits its addresses incrementally. File
// expansion uses this path so an aggregate cap can stop a multi-line target
// set without materializing the next complete CIDR first.
func expandCIDRInto(spec string, opts ExpandOptions, emit func(string) error) error {
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCIDR, err)
	}

	bits := prefix.Bits()
	maxLen := MaxIPv4PrefixLen
	if prefix.Addr().Is6() {
		maxLen = MaxIPv6PrefixLen
	}
	if bits < maxLen && !opts.AllowLargeCIDR {
		return fmt.Errorf("%w: %s (prefix /%d, cap is /%d)",
			ErrLargeCIDR, spec, bits, maxLen)
	}

	// Absolute host-count ceiling — applies even when AllowLargeCIDR bypassed
	// the bits gate above, so an override can never request an unbounded
	// enumeration. exp is the host-bit count; uint64(1)<<exp wraps to 0 for
	// exp >= 64, so the short-circuit guard must run first.
	if exp := prefix.Addr().BitLen() - bits; exp >= 64 || uint64(1)<<exp > MaxHostsHardCap {
		return fmt.Errorf("%w: %s (prefix /%d exceeds the %d-host hard cap)",
			ErrTooManyHosts, spec, bits, MaxHostsHardCap)
	}

	// Pre-flight check on the network address.
	netAddr := prefix.Addr().String()
	netInfo := common.ClassifyHost(netAddr)
	if netInfo.IsLinkLocal {
		return fmt.Errorf("%w: %s", ErrLinkLocal, spec)
	}
	if netInfo.IsMulticast {
		return fmt.Errorf("%w: %s", ErrMulticast, spec)
	}
	if netInfo.IsPublic && !opts.AllowPublicTargets {
		return fmt.Errorf("%w: %s", ErrPublicTarget, spec)
	}

	// Enumerate. For /32 (IPv4) or /128 (IPv6) just emit the single addr.
	addr := prefix.Masked().Addr()
	emitted := 0
	for prefix.Contains(addr) {
		// Per-address gate — catches CIDRs that span classifications.
		info := common.ClassifyHost(addr.String())
		if info.IsLinkLocal {
			return fmt.Errorf("%w: %s within %s", ErrLinkLocal, addr, spec)
		}
		if info.IsMulticast {
			return fmt.Errorf("%w: %s within %s", ErrMulticast, addr, spec)
		}
		if info.IsPublic && !opts.AllowPublicTargets {
			return fmt.Errorf("%w: %s within %s", ErrPublicTarget, addr, spec)
		}
		if err := emit(addr.String()); err != nil {
			return err
		}
		emitted++
		next := addr.Next()
		if !next.IsValid() {
			break
		}
		addr = next
	}

	if emitted == 0 {
		return fmt.Errorf("%w: %s expanded to zero hosts", ErrInvalidCIDR, spec)
	}
	return nil
}

// expandFile reads a newline-separated list of specs (one per line), runs
// each through Expand recursively, and concatenates the results. Comments
// (`# ...`) and empty lines are skipped.
func expandFile(path string, opts ExpandOptions) ([]string, error) {
	return expandFileWithLimit(path, opts, MaxHostsHardCap)
}

func expandFileWithLimit(path string, opts ExpandOptions, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("targets file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var out []string
	seen := make(map[string]struct{})
	emit := func(host string) error {
		if _, exists := seen[host]; exists {
			return nil
		}
		if len(out) >= limit {
			return fmt.Errorf(
				"%w: targets file %s exceeds the %d-host hard cap",
				ErrTooManyHosts, path, limit,
			)
		}
		seen[host] = struct{}{}
		out = append(out, host)
		return nil
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Reject nested file includes. A targets file lists hosts and CIDRs,
		// not other @file / file:// references. Without this guard a
		// self-referential or cyclic targets file recurses through Expand
		// unbounded (accumulating open fds + a 64 KiB scanner buffer per
		// level) until the process exhausts memory or file descriptors.
		if strings.HasPrefix(line, "@") || strings.HasPrefix(line, "file://") {
			return nil, fmt.Errorf("%w: %q in %s", ErrNestedTargetsFile, line, path)
		}
		var expandErr error
		if strings.Contains(line, "/") {
			expandErr = expandCIDRInto(line, opts, emit)
		} else {
			var hosts []string
			hosts, expandErr = expandSingle(line, opts)
			if expandErr == nil {
				for _, host := range hosts {
					if expandErr = emit(host); expandErr != nil {
						break
					}
				}
			}
		}
		if expandErr != nil {
			return nil, fmt.Errorf("targets file %s: %w", path, expandErr)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("targets file %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, ErrTargetsFileEmpty
	}
	// Hosts were deduplicated while they were emitted, which also allowed the
	// aggregate hard cap to stop expansion before another full CIDR was held.
	return out, nil
}
