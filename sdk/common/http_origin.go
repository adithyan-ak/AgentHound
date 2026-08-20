package common

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// HTTPOrigin is the exact scheme, hostname, and effective-port boundary used
// when forwarding credentials across redirects or derived URLs.
type HTTPOrigin struct {
	scheme   string
	hostname string
	port     string
}

func ParseHTTPOrigin(endpoint string) (HTTPOrigin, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return HTTPOrigin{}, errors.New("HTTP endpoint is empty")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Hostname() == "" {
		return HTTPOrigin{}, errors.New("endpoint must be absolute HTTP(S)")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return HTTPOrigin{}, errors.New("endpoint must be absolute HTTP(S)")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return HTTPOrigin{}, errors.New("endpoint userinfo and fragments are prohibited")
	}
	return originFromURL(parsed)
}

func (origin HTTPOrigin) Matches(candidate *url.URL) bool {
	if origin.scheme == "" || origin.hostname == "" || origin.port == "" || candidate == nil {
		return false
	}
	other, err := originFromURL(candidate)
	return err == nil && origin == other
}

func originFromURL(value *url.URL) (HTTPOrigin, error) {
	if value == nil || value.Host == "" || value.Hostname() == "" {
		return HTTPOrigin{}, errors.New("missing HTTP authority")
	}
	scheme := strings.ToLower(value.Scheme)
	if scheme != "http" && scheme != "https" {
		return HTTPOrigin{}, fmt.Errorf("unsupported scheme %q", value.Scheme)
	}
	port := value.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return HTTPOrigin{scheme: scheme, hostname: strings.ToLower(value.Hostname()), port: port}, nil
}
