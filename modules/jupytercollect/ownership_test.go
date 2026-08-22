package jupytercollect_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/modules/jupytercollect"
	"github.com/adithyan-ak/agenthound/modules/jupyterfp"
	"github.com/adithyan-ak/agenthound/sdk/action"
)

func TestFingerprintAndLooterShareIdentityWithoutOverwritingEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api":
			_, _ = w.Write([]byte(`{"version":"2.20.0"}`))
		case "/api/status":
			_, _ = w.Write([]byte(
				`{"started":"2026-04-01T12:00:00Z",` +
					`"last_activity":"2026-04-01T12:34:56Z",` +
					`"connections":0,"kernels":0}`,
			))
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	target := action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(server.URL, "http://"),
	}
	fingerprinter, err := jupyterfp.New()
	if err != nil {
		t.Fatalf("new fingerprinter: %v", err)
	}
	fingerprint, err := fingerprinter.Fingerprint(context.Background(), target)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	collection, err := (&jupytercollect.Collector{}).Collect(
		context.Background(),
		target,
		action.CollectOptions{},
	)
	if err != nil {
		t.Fatalf("collection: %v", err)
	}

	fingerprintNode := fingerprint.IngestData.Graph.Nodes[0]
	lootNode := collection.IngestData.Graph.Nodes[0]
	if fingerprintNode.ID != lootNode.ID {
		t.Fatalf(
			"fingerprint ID = %q, collection ID = %q",
			fingerprintNode.ID,
			lootNode.ID,
		)
	}
	if !reflect.DeepEqual(fingerprintNode.Kinds, lootNode.Kinds) {
		t.Fatalf(
			"fingerprint kinds = %v, collection kinds = %v",
			fingerprintNode.Kinds,
			lootNode.Kinds,
		)
	}

	for _, fingerprintOwned := range []string{
		"discovered_via",
		"fingerprint_observed",
		"status_access",
		"status_anonymous_access",
		"version",
	} {
		if _, exists := fingerprintNode.Properties[fingerprintOwned]; !exists {
			t.Errorf("fingerprint property %q missing", fingerprintOwned)
		}
		if _, exists := lootNode.Properties[fingerprintOwned]; exists {
			t.Errorf("looter overwrites fingerprint-owned property %q", fingerprintOwned)
		}
	}
	for _, lootOwned := range []string{
		"anonymous_access_observed",
		"auth_assurance",
		"auth_evidence",
		"auth_method",
		"auth_required",
		"contents_access",
		"collection_observed",
		"sessions_access",
	} {
		if _, exists := lootNode.Properties[lootOwned]; !exists {
			t.Errorf("collection property %q missing", lootOwned)
		}
		if _, exists := fingerprintNode.Properties[lootOwned]; exists {
			t.Errorf("fingerprinter overwrites collection-owned property %q", lootOwned)
		}
	}

	shared := map[string]bool{
		"endpoint":     true,
		"name":         true,
		"objectid":     true,
		"service_kind": true,
	}
	for property, fingerprintValue := range fingerprintNode.Properties {
		lootValue, overlaps := lootNode.Properties[property]
		if !overlaps {
			continue
		}
		if !shared[property] {
			t.Errorf("property %q has no declared shared owner", property)
		}
		if !reflect.DeepEqual(fingerprintValue, lootValue) {
			t.Errorf(
				"shared property %q differs: fingerprint=%v collection=%v",
				property,
				fingerprintValue,
				lootValue,
			)
		}
	}

	for _, order := range []struct {
		name  string
		first map[string]any
		last  map[string]any
	}{
		{
			name:  "fingerprint then collection",
			first: fingerprintNode.Properties,
			last:  lootNode.Properties,
		},
		{
			name:  "collection then fingerprint",
			first: lootNode.Properties,
			last:  fingerprintNode.Properties,
		},
	} {
		t.Run(order.name, func(t *testing.T) {
			merged := mergeProperties(order.first, order.last)
			if merged["version"] != "2.20.0" ||
				merged["status_access"] != "anonymous" ||
				merged["auth_method"] != "none" ||
				merged["sessions_access"] != "anonymous" {
				t.Fatalf("merged evidence = %+v", merged)
			}
		})
	}
}

func mergeProperties(first, last map[string]any) map[string]any {
	merged := make(map[string]any, len(first)+len(last))
	for property, value := range first {
		merged[property] = value
	}
	for property, value := range last {
		merged[property] = value
	}
	return merged
}
