package litellmcollect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

// TestCollect_GETOnly is a hard regression guard on the read-only contract
// in sdk/action.ServiceCollector. The looter MUST issue ONLY GET (and HEAD)
// requests — no POST, PUT, PATCH, DELETE, etc. — because mutating
// methods would leave evidence in the LiteLLM gateway's audit log
// and (worse) could change upstream provider state.
//
// This test installs an http.Handler that records every method and
// fails the test if anything other than GET appears.
func TestCollect_GETOnly(t *testing.T) {
	var (
		mu      sync.Mutex
		methods []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/model/info":
			_, _ = w.Write([]byte(happyPathModelInfo))
		case "/key/list":
			_, _ = w.Write([]byte(happyPathKeyList))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{
		Credentials: map[string]string{"master_key": fakeMasterKey},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(methods) == 0 {
		t.Fatal("looter issued zero requests")
	}
	for _, m := range methods {
		if m != "GET" && m != "HEAD" {
			t.Errorf("looter issued non-read-only method %q (Collector contract violation; see sdk/action/collector.go doc)", m)
		}
	}
}
