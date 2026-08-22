package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const customersURI = "postgres://crm/customers"

func main() {
	mode := envOr("MCP_DEMO_MODE", "devtools")
	port := envOr("PORT", defaultPort(mode))
	token := strings.TrimSpace(os.Getenv("MCP_BEARER_TOKEN"))

	server, err := buildServer(mode)
	if err != nil {
		log.Fatal(err)
	}
	mcpHandler := mcpsdk.NewStreamableHTTPHandler(
		func(*http.Request) *mcpsdk.Server { return server },
		&mcpsdk.StreamableHTTPOptions{JSONResponse: true},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/mcp", authorize(token, mcpHandler))

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("starting %s MCP server on %s", mode, httpServer.Addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func buildServer(mode string) (*mcpsdk.Server, error) {
	switch mode {
	case "devtools":
		server := mcpsdk.NewServer(
			&mcpsdk.Implementation{Name: "devtools-mcp", Version: "defcon34"},
			nil,
		)
		server.AddTool(
			&mcpsdk.Tool{
				Name:        "read_file",
				Description: "Read local files, environment variables, and credential configuration files for developer troubleshooting.",
				InputSchema: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"path": {Type: "string", Description: "Local file path"},
					},
					Required: []string{"path"},
				},
			},
			func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
				return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{
					&mcpsdk.TextContent{Text: "demo tool calls are disabled"},
				}}, nil
			},
		)
		return server, nil
	case "crm":
		server := mcpsdk.NewServer(
			&mcpsdk.Implementation{Name: "crm-mcp", Version: "defcon34"},
			nil,
		)
		server.AddTool(
			&mcpsdk.Tool{
				Name:        "query_customers",
				Description: "Query the customers-database resource for synthetic customer records.",
				InputSchema: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"customer_id": {Type: "string", Description: "Synthetic customer identifier"},
					},
					Required: []string{"customer_id"},
				},
			},
			func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
				return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{
					&mcpsdk.TextContent{Text: "synthetic record lookup disabled during enumeration"},
				}}, nil
			},
		)
		server.AddResource(
			&mcpsdk.Resource{
				URI:         customersURI,
				Name:        "customers-database",
				Description: "Synthetic customer database used only by the DEF CON demonstration lab.",
				MIMEType:    "application/json",
			},
			func(_ context.Context, request *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
				if request.Params == nil || request.Params.URI != customersURI {
					return nil, fmt.Errorf("resource not found")
				}
				return &mcpsdk.ReadResourceResult{Contents: []*mcpsdk.ResourceContents{{
					URI:      customersURI,
					MIMEType: "application/json",
					Text:     `{"dataset":"customers-database","classification":"synthetic-demo-only"}`,
				}}}, nil
			},
		)
		return server, nil
	default:
		return nil, fmt.Errorf("unsupported MCP_DEMO_MODE %q", mode)
	}
}

func authorize(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	expected := "Bearer " + token
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != expected {
			w.Header().Set("WWW-Authenticate", `Bearer realm="crm-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, request)
	})
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func defaultPort(mode string) string {
	if mode == "crm" {
		return "8931"
	}
	return "3001"
}
