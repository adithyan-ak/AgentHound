package contact

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r[host]...), nil
}

func TestPolicyNormalizesAndRejectsTargets(t *testing.T) {
	policy, err := NewPolicy([]string{"EXAMPLE.COM.", "10.20.0.0/16", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"example.com", "Example.Com.", "10.20.1.2", "2001:db8::1"} {
		if err := policy.AdmitAddress(target); !errors.Is(err, ErrExcluded) {
			t.Fatalf("AdmitAddress(%q) error = %v, want ErrExcluded", target, err)
		}
	}
	if err := policy.AdmitAddress("allowed.example"); err != nil {
		t.Fatalf("allowed target rejected: %v", err)
	}
}

func TestPolicyRejectsOverlappingCIDR(t *testing.T) {
	policy, err := NewPolicy([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.AdmitAddress("10.0.0.0/8"); !errors.Is(err, ErrExcluded) {
		t.Fatalf("overlap error = %v, want ErrExcluded", err)
	}
}

func TestPolicyRejectsInvalidMatchingLanguages(t *testing.T) {
	for _, exclusion := range []string{"*.example.com", "https://example.com"} {
		if _, err := NewPolicy([]string{exclusion}); err == nil {
			t.Fatalf("NewPolicy(%q) unexpectedly succeeded", exclusion)
		}
	}
}

func TestMixedDNSFiltersExcludedAddresses(t *testing.T) {
	resolver := staticResolver{
		"mixed.example": {
			netip.MustParseAddr("10.20.1.1"),
			netip.MustParseAddr("192.0.2.4"),
		},
	}
	policy, err := NewPolicyWithResolver([]string{"10.20.0.0/16"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if policy.ExcludesIP(resolver["mixed.example"][0]) != true ||
		policy.ExcludesIP(resolver["mixed.example"][1]) != false {
		t.Fatal("mixed DNS answers were not classified independently")
	}
}

func TestDialerUsesOnlyAllowedMixedDNSAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()
	resolver := staticResolver{"mixed.example": {
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("127.0.0.1"),
	}}
	policy, err := NewPolicyWithResolver([]string{"192.0.2.0/24"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(WithPolicy(context.Background(), policy), time.Second)
	defer cancel()
	conn, err := (Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("mixed.example", fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("allowed DNS result was not dialed")
	}
}

func TestDialerFailsBeforeDialWhenAllDNSAnswersExcluded(t *testing.T) {
	resolver := staticResolver{"blocked.example": {netip.MustParseAddr("192.0.2.10")}}
	policy, err := NewPolicyWithResolver([]string{"192.0.2.0/24"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (Dialer{}).DialContext(
		WithPolicy(context.Background(), policy), "tcp", "blocked.example:443",
	)
	if !errors.Is(err, ErrExcluded) {
		t.Fatalf("error = %v, want ErrExcluded", err)
	}
}

func TestGuardTransportRejectsRedirectBeforeDestinationContact(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationRequests.Add(1)
	}))
	defer destination.Close()
	destinationURL, err := url.Parse(destination.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(destinationURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://excluded.example:"+port+"/target", http.StatusFound)
	}))
	defer source.Close()
	policy, err := NewPolicy([]string{"excluded.example"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(WithPolicy(context.Background(), policy), http.MethodGet, source.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http.Client{Transport: GuardTransport(nil)}).Do(req)
	if !errors.Is(err, ErrExcluded) {
		t.Fatalf("redirect error = %v, want ErrExcluded", err)
	}
	if got := destinationRequests.Load(); got != 0 {
		t.Fatalf("excluded redirect destination received %d request(s)", got)
	}
}

func TestHTTPTransportDisablesProxyBoundary(t *testing.T) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = func(*http.Request) (*url.URL, error) {
		return url.Parse("http://proxy.example")
	}
	if guarded := HTTPTransport(base); guarded.Proxy != nil {
		t.Fatal("guarded transport retained a proxy that could bypass final-dial filtering")
	}
}
