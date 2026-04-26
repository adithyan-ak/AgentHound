package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestParseNodeRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		kind    string
		nname   string
		wantErr string
	}{
		{"valid MCPServer", "MCPServer:my-server", "MCPServer", "my-server", ""},
		{"valid A2AAgent", "A2AAgent:agent1", "A2AAgent", "agent1", ""},
		{"valid with colon in name", "MCPResource:postgres://prod:5432", "MCPResource", "postgres://prod:5432", ""},
		{"unknown kind", "FakeKind:x", "", "", "unknown node kind"},
		{"no colon", "MCPServer", "", "", "invalid format"},
		{"empty name", "MCPServer:", "", "", "invalid format"},
		{"empty kind", ":name", "", "", "invalid format"},
		{"just colon", ":", "", "", "invalid format"},
		{"empty string", "", "", "", "invalid format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, name, err := parseNodeRef(tt.ref)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !containsSubstring(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kind != tt.kind {
				t.Errorf("kind = %q, want %q", kind, tt.kind)
			}
			if name != tt.nname {
				t.Errorf("name = %q, want %q", name, tt.nname)
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want string
	}{
		{"nil", nil, "<null>"},
		{"string", "hello", "hello"},
		{"integer float", float64(42.0), "42"},
		{"fractional float", float64(3.14159), "3.1416"},
		{"int64", int64(99), "99"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"slice", []any{"a", "b"}, "[a, b]"},
		{"empty slice", []any{}, "[]"},
		{"nested nil in slice", []any{nil, "x"}, "[<null>, x]"},
		{"default type", struct{ X int }{42}, "{42}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatValue(tt.val)
			if got != tt.want {
				t.Errorf("formatValue(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}

func TestOrderedColumns(t *testing.T) {
	t.Run("returns all keys", func(t *testing.T) {
		row := map[string]any{"name": "x", "kind": "MCPServer", "score": 42}
		cols := orderedColumns(row)

		if len(cols) != len(row) {
			t.Fatalf("len = %d, want %d", len(cols), len(row))
		}

		sort.Strings(cols)
		want := []string{"kind", "name", "score"}
		for i, c := range cols {
			if c != want[i] {
				t.Errorf("cols[%d] = %q, want %q", i, c, want[i])
			}
		}
	})

	t.Run("empty map", func(t *testing.T) {
		cols := orderedColumns(map[string]any{})
		if len(cols) != 0 {
			t.Fatalf("expected empty slice, got %v", cols)
		}
	})
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- Capture helpers for stdout/stderr ---

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// --- printRows tests ---

func TestPrintRows_Empty(t *testing.T) {
	out := captureStdout(t, func() {
		err := printRows(nil, "table")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "(no results)") {
		t.Errorf("expected stdout to contain %q, got %q", "(no results)", out)
	}
}

func TestPrintRows_Table(t *testing.T) {
	rows := []map[string]any{
		{"name": "server-a", "count": float64(3)},
		{"name": "server-b", "count": float64(7)},
	}

	var stderrOut string
	stdoutOut := captureStdout(t, func() {
		stderrOut = captureStderr(t, func() {
			err := printRows(rows, "table")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	})

	if !strings.Contains(stdoutOut, "server-a") {
		t.Errorf("stdout missing %q: %q", "server-a", stdoutOut)
	}
	if !strings.Contains(stdoutOut, "server-b") {
		t.Errorf("stdout missing %q: %q", "server-b", stdoutOut)
	}
	if !strings.Contains(stderrOut, "2 row(s)") {
		t.Errorf("stderr missing row count: %q", stderrOut)
	}
}

func TestPrintRows_JSON(t *testing.T) {
	rows := []map[string]any{
		{"id": "node-1", "score": float64(85)},
	}

	out := captureStdout(t, func() {
		err := printRows(rows, "json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	var decoded []map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %q", err, out)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 row, got %d", len(decoded))
	}
	if decoded[0]["id"] != "node-1" {
		t.Errorf("expected id %q, got %v", "node-1", decoded[0]["id"])
	}
}

// --- printJSON tests ---

func TestPrintJSON(t *testing.T) {
	input := map[string]any{"tool": "nmap", "version": float64(7)}

	out := captureStdout(t, func() {
		err := printJSON(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %q", err, out)
	}
	if decoded["tool"] != "nmap" {
		t.Errorf("expected tool %q, got %v", "nmap", decoded["tool"])
	}
}

// --- printPrebuiltList tests ---

func TestPrintPrebuiltList(t *testing.T) {
	out := captureStderr(t, func() {
		printPrebuiltList()
	})

	if !strings.Contains(out, "ID") {
		t.Errorf("expected header %q in output: %q", "ID", out)
	}
	if !strings.Contains(out, "agents-shell-access") {
		t.Errorf("expected %q in output: %q", "agents-shell-access", out)
	}
}

// --- runQuery validation tests ---

func newQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "query",
		RunE: runQuery,
	}
	cmd.Flags().String("prebuilt", "", "")
	cmd.Flags().Bool("findings", false, "")
	cmd.Flags().String("severity", "", "")
	cmd.Flags().Bool("shortest-path", false, "")
	cmd.Flags().String("from", "", "")
	cmd.Flags().String("to", "", "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("fail-on", "", "")
	return cmd
}

func TestRunQuery_InvalidFormat(t *testing.T) {
	cmd := newQueryCmd()
	_ = cmd.Flags().Set("format", "xml")
	err := runQuery(cmd, nil)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("error = %q, want to contain 'invalid format'", err.Error())
	}
}

func TestRunQuery_NoMode(t *testing.T) {
	cmd := newQueryCmd()
	err := runQuery(cmd, nil)
	if err == nil {
		t.Fatal("expected error when no mode specified")
	}
	if !strings.Contains(err.Error(), "specify a query mode") {
		t.Errorf("error = %q, want to contain 'specify a query mode'", err.Error())
	}
}

func TestRunQuery_MultipleModes(t *testing.T) {
	cmd := newQueryCmd()
	_ = cmd.Flags().Set("findings", "true")
	_ = cmd.Flags().Set("prebuilt", "agents-shell-access")
	err := runQuery(cmd, nil)
	if err == nil {
		t.Fatal("expected error when multiple modes specified")
	}
	if !strings.Contains(err.Error(), "specify only one query mode") {
		t.Errorf("error = %q, want to contain 'specify only one query mode'", err.Error())
	}
}

func TestRunFindings_InvalidSeverity(t *testing.T) {
	err := runFindings(context.Background(), "bogus", "table", "")
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("error = %q, want to contain 'invalid severity'", err.Error())
	}
}

func TestRunShortestPath_MissingFlags(t *testing.T) {
	err := runShortestPath(context.Background(), "", "", "table")
	if err == nil {
		t.Fatal("expected error for missing --from/--to")
	}
	if !strings.Contains(err.Error(), "requires both") {
		t.Errorf("error = %q, want to contain 'requires both'", err.Error())
	}
}

func TestRunShortestPath_InvalidFrom(t *testing.T) {
	err := runShortestPath(context.Background(), "badformat", "MCPServer:srv", "table")
	if err == nil {
		t.Fatal("expected error for invalid --from")
	}
	if !strings.Contains(err.Error(), "--from") {
		t.Errorf("error = %q, want to contain '--from'", err.Error())
	}
}

func TestRunShortestPath_InvalidTo(t *testing.T) {
	err := runShortestPath(context.Background(), "MCPServer:srv", "badformat", "table")
	if err == nil {
		t.Fatal("expected error for invalid --to")
	}
	if !strings.Contains(err.Error(), "--to") {
		t.Errorf("error = %q, want to contain '--to'", err.Error())
	}
}
