// Package contact enforces the collector's operator-supplied network
// exclusions at both target admission and the final socket dial boundary.
package contact

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// ErrExcluded is returned before an AgentHound-owned connection is made to
// an excluded hostname, address, or CIDR.
var ErrExcluded = errors.New("target excluded by contact policy")

// Resolver is the subset of net.Resolver used by Policy. It is exported so
// callers can deterministically test mixed allowed/excluded DNS answers.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Policy is immutable after construction and safe for concurrent use.
type Policy struct {
	hosts    map[string]struct{}
	prefixes []netip.Prefix
	resolver Resolver
}

// NewPolicy parses exact hostnames, IP literals, and CIDRs. Globs and URLs are
// deliberately rejected: --exclude is a connection boundary, not a matching
// language.
func NewPolicy(exclusions []string) (*Policy, error) {
	return NewPolicyWithResolver(exclusions, net.DefaultResolver)
}

// NewPolicyWithResolver is NewPolicy with an injectable DNS resolver.
func NewPolicyWithResolver(exclusions []string, resolver Resolver) (*Policy, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	p := &Policy{
		hosts:    make(map[string]struct{}),
		resolver: resolver,
	}
	for _, raw := range exclusions {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("exclude value is empty")
		}
		if strings.ContainsAny(value, "*?[]") || strings.Contains(value, "://") {
			return nil, fmt.Errorf("invalid exclusion %q: use an exact hostname, IP, or CIDR", raw)
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			p.prefixes = append(p.prefixes, prefix.Masked())
			continue
		}
		if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			p.prefixes = append(p.prefixes, netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()))
			continue
		}
		host := NormalizeHostname(value)
		if host == "" || strings.ContainsAny(host, "/:@") {
			return nil, fmt.Errorf("invalid exclusion %q: use an exact hostname, IP, or CIDR", raw)
		}
		p.hosts[host] = struct{}{}
	}
	sort.Slice(p.prefixes, func(i, j int) bool {
		return p.prefixes[i].String() < p.prefixes[j].String()
	})
	return p, nil
}

// NormalizeHostname applies the exact hostname comparison rules in the CLI
// contract: ASCII case-insensitive with trailing DNS dots ignored.
func NormalizeHostname(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	host = strings.TrimRight(host, ".")
	return strings.ToLower(host)
}

// Empty reports whether the policy excludes nothing.
func (p *Policy) Empty() bool {
	return p == nil || (len(p.hosts) == 0 && len(p.prefixes) == 0)
}

// ExcludesIP reports whether address falls in an excluded exact address or
// prefix.
func (p *Policy) ExcludesIP(address netip.Addr) bool {
	if p == nil || !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range p.prefixes {
		candidate := address
		if prefix.Addr().Is4() != candidate.Is4() {
			continue
		}
		if prefix.Contains(candidate) {
			return true
		}
	}
	return false
}

// CheckHost performs the pre-resolution admission check.
func (p *Policy) CheckHost(host string) error {
	host = NormalizeHostname(host)
	if host == "" {
		return fmt.Errorf("contact policy: empty host")
	}
	if _, excluded := p.hosts[host]; excluded {
		return fmt.Errorf("%w: hostname %s", ErrExcluded, host)
	}
	if address, err := netip.ParseAddr(host); err == nil && p.ExcludesIP(address) {
		return fmt.Errorf("%w: address %s", ErrExcluded, address)
	}
	return nil
}

// CheckURL validates an absolute HTTP(S) URL before a request or redirect.
func (p *Policy) CheckURL(parsed *url.URL) error {
	if parsed == nil || parsed.Hostname() == "" {
		return fmt.Errorf("contact policy: URL has no host")
	}
	return p.CheckHost(parsed.Hostname())
}

// AdmitAddress checks a URL, host, host:port, IP, or CIDR-shaped target before
// it is inserted into the planner target set. CIDRs are rejected when any part
// overlaps an excluded prefix; concrete expanded hosts are checked again.
func (p *Policy) AdmitAddress(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fmt.Errorf("contact policy: empty target")
	}
	if parsed, err := url.Parse(value); err == nil && parsed.IsAbs() && parsed.Hostname() != "" {
		return p.CheckURL(parsed)
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		for _, excluded := range p.prefixes {
			if prefix.Addr().Is4() != excluded.Addr().Is4() {
				continue
			}
			if prefix.Contains(excluded.Addr()) || excluded.Contains(prefix.Addr()) {
				return fmt.Errorf("%w: CIDR %s overlaps %s", ErrExcluded, prefix, excluded)
			}
		}
		return nil
	}
	host := value
	if parsedHost, _, err := net.SplitHostPort(value); err == nil {
		host = parsedHost
	}
	return p.CheckHost(host)
}

type policyContextKey struct{}

// WithPolicy carries the immutable scan policy into every request and dial.
func WithPolicy(ctx context.Context, policy *Policy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, policyContextKey{}, policy)
}

// FromContext returns the active scan policy, if any.
func FromContext(ctx context.Context) *Policy {
	if ctx == nil {
		return nil
	}
	policy, _ := ctx.Value(policyContextKey{}).(*Policy)
	return policy
}

// Dialer performs final-dial enforcement. Hostnames are resolved once, every
// result is filtered, and only admitted concrete addresses are presented to
// the underlying dialer.
type Dialer struct {
	Base     *net.Dialer
	Resolver Resolver
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	base := d.Base
	if base == nil {
		base = &net.Dialer{}
	}
	policy := FromContext(ctx)
	if policy == nil || policy.Empty() {
		return base.DialContext(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("contact policy: parse dial address %q: %w", address, err)
	}
	if err := policy.CheckHost(host); err != nil {
		return nil, err
	}
	if literal, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if policy.ExcludesIP(literal) {
			return nil, fmt.Errorf("%w: address %s", ErrExcluded, literal)
		}
		return base.DialContext(ctx, network, net.JoinHostPort(literal.String(), port))
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = policy.resolver
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", NormalizeHostname(host))
	if err != nil {
		return nil, err
	}
	var allowed []netip.Addr
	for _, candidate := range addresses {
		candidate = candidate.Unmap()
		if !policy.ExcludesIP(candidate) {
			allowed = append(allowed, candidate)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: all resolved addresses for %s", ErrExcluded, NormalizeHostname(host))
	}
	var lastErr error
	for _, candidate := range allowed {
		conn, dialErr := base.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// HTTPTransport clones base and installs the final-dial guard. A nil base uses
// a clone of http.DefaultTransport when possible.
func HTTPTransport(base *http.Transport) *http.Transport {
	if base == nil {
		if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
			base = defaultTransport
		} else {
			base = &http.Transport{}
		}
	}
	cloned := base.Clone()
	// A proxy would move the destination connection outside this transport's
	// guarded dial boundary. Scan traffic is therefore always direct: the policy
	// must inspect and filter the concrete destination addresses itself.
	cloned.Proxy = nil
	underlying := &net.Dialer{}
	if cloned.DialContext != nil {
		// A custom dialer cannot be safely composed after DNS filtering. Preserve
		// standard transport settings; tests and modules needing custom behavior
		// should pass it through Dialer.Base instead.
		underlying = &net.Dialer{}
	}
	cloned.DialContext = (Dialer{Base: underlying}).DialContext
	return cloned
}

// RoundTripper enforces the hostname exclusion before handing a request to a
// guarded HTTP transport. This catches redirected and derived URLs before any
// destination connection is attempted.
type RoundTripper struct {
	Base http.RoundTripper
}

func (g RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("contact policy: nil request")
	}
	if policy := FromContext(req.Context()); policy != nil {
		if err := policy.CheckURL(req.URL); err != nil {
			return nil, err
		}
	}
	base := g.Base
	if base == nil {
		base = HTTPTransport(nil)
	}
	return base.RoundTrip(req)
}

// GuardTransport returns a request- and dial-guarded transport.
func GuardTransport(base *http.Transport) http.RoundTripper {
	return RoundTripper{Base: HTTPTransport(base)}
}
