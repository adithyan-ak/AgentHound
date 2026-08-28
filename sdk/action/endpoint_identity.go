package action

import (
	"errors"
	"net"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"
)

// CanonicalEndpointIdentity returns a stable HTTP(S) service identity without
// changing EndpointBaseURL's historical behavior. URL-shaped targets retain
// ordinary HTTP effective-port semantics; the service default applies only to
// host-shaped targets.
func CanonicalEndpointIdentity(t Target, defaultPort int, defaultScheme string) (string, error) {
	base := EndpointBaseURL(t, defaultPort, defaultScheme)
	parsed, err := url.Parse(base)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" {
		return "", errors.New("endpoint identity requires an absolute URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("endpoint identity requires HTTP(S)")
	}

	port := parsed.Port()
	if port != "" {
		parsedPort, parseErr := strconv.Atoi(port)
		if parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", errors.New("endpoint identity has an invalid port")
		}
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	host := strings.ToLower(parsed.Hostname())
	switch {
	case port != "":
		parsed.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		parsed.Host = "[" + host + "]"
	default:
		parsed.Host = host
	}
	parsed.Scheme = scheme
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	cleanPath := pathpkg.Clean(parsed.Path)
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""
	return parsed.String(), nil
}
